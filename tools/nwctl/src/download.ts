import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { Client } from "./http.js";
import { CliError, invalid } from "./errors.js";
import { rememberSecret } from "./output.js";
import { privateOutput } from "./private-output.js";
export async function downloadOperation(
  client: Client,
  id: string,
  proof: string,
  token: string,
  output: string,
  remotePath: string,
) {
  if (!/^[a-f0-9-]{36}$/.test(id) || !/^[a-f0-9]{64}$/.test(proof))
    invalid("Invalid download request.");
  rememberSecret(proof);
  rememberSecret(token);
  const file = await privateOutput(output),
    controller = new AbortController(),
    timer = setTimeout(() => controller.abort(), client.timeout);
  const max = 64 * 1024 * 1024;
  let response: Response | undefined;
  try {
    response = await fetch(client.origin + `/api/ops/requests/${id}/execute`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/zip",
      },
      body: JSON.stringify({ proof }),
      signal: controller.signal,
      redirect: "manual",
    });
    if (!response.ok)
      throw new CliError(
        "DOWNLOAD_REJECTED",
        `HTTP ${response.status}; download not saved. Inspect operation status before another request.`,
        6,
        response.status,
      );
    const type = (response.headers.get("Content-Type") ?? "")
      .split(";")[0]
      .trim()
      .toLowerCase();
    if (
      ![
        "application/zip",
        "application/octet-stream",
        "application/x-zip-compressed",
      ].includes(type)
    )
      throw new CliError(
        "INVALID_ARCHIVE",
        "Expected a ZIP response, not JSON or HTML.",
        6,
      );
    const length = response.headers.get("Content-Length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > max))
      throw new CliError(
        "DOWNLOAD_TOO_LARGE",
        "Download exceeds 64 MiB limit or has invalid length.",
        6,
      );
    const reader = response.body?.getReader();
    if (!reader) throw new CliError("EMPTY_DOWNLOAD", "No download body.", 6);
    const hash = createHash("sha256");
    let size = 0,
      prefix = Buffer.alloc(0);
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        await reader.cancel();
        throw new CliError(
          "DOWNLOAD_TOO_LARGE",
          "Download exceeds 64 MiB limit.",
          6,
        );
      }
      if (prefix.length < 4)
        prefix = Buffer.concat([
          prefix,
          Buffer.from(value).subarray(0, 4 - prefix.length),
        ]);
      hash.update(value);
      await file.write(value);
    }
    if (
      size < 22 ||
      !["504b0304", "504b0506"].includes(prefix.toString("hex")) ||
      (length !== null && size !== Number(length))
    )
      throw new CliError(
        "INCOMPLETE_ARCHIVE",
        "Empty, non-ZIP or truncated download; no output committed.",
        6,
      );
    const sha256 = hash.digest("hex"),
      expected = /_([a-f0-9]{5})\.zip$/i.exec(remotePath)?.[1].toLowerCase();
    if (expected && sha256.slice(0, 5) !== expected)
      throw new CliError(
        "CHECKSUM_MISMATCH",
        "Filename checksum prefix mismatch; no output committed.",
        6,
      );
    await file.commit();
    const saved = createHash("sha256");
    for await (const chunk of createReadStream(file.path)) saved.update(chunk);
    if (saved.digest("hex") !== sha256)
      throw new CliError(
        "VERIFY_FAILED",
        "Saved file read-back hash mismatch. Inspect the output; do not repeat automatically.",
        6,
      );
    return {
      output: file.path,
      bytes: size,
      sha256,
      localReadbackVerified: true,
      filenameChecksumVerified: !!expected,
      recoverabilityVerified: false,
    };
  } catch (e) {
    if (e instanceof CliError) throw e;
    throw new CliError(
      controller.signal.aborted ? "TIMEOUT" : "DOWNLOAD_FAILED",
      "Download outcome unknown or local I/O failed. Inspect ops status; no automatic retry. Partial temporary output is removed.",
      5,
    );
  } finally {
    // body.cancel() cannot cancel a stream locked by getReader(); abort transport too.
    controller.abort();
    clearTimeout(timer);
    await response?.body?.cancel().catch(() => {});
    await file.abort();
  }
}

import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { resolve, parse, join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { inspectBackupBytes } from "../../../shared/backup-inspection.js";
import { CliError, invalid } from "./errors.js";
import { Context } from "./context.js";
import { record } from "./contracts.js";
export async function readPrivateArchive(input: string) {
  if (!input || /[\x00-\x1f\x7f]/.test(input))
    invalid("Explicit private backup file required.");
  const path = resolve(input),
    parent = dirname(path);
  let current = parse(parent).root;
  for (const segment of parent
    .slice(current.length)
    .split("/")
    .filter(Boolean)) {
    current = join(current, segment);
    const s = await lstat(current);
    if (!s.isDirectory() || s.isSymbolicLink())
      invalid("Archive path must not contain symlinks.");
  }
  const before = await lstat(path);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    before.mode & 0o077 ||
    (process.getuid && before.uid !== process.getuid()) ||
    before.size > 64 * 1024 * 1024
  )
    invalid(
      "Archive must be an owned private single-link regular file up to 64 MiB.",
    );
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const actual = await fd.stat();
    if (
      actual.ino !== before.ino ||
      actual.dev !== before.dev ||
      actual.size !== before.size ||
      actual.nlink !== 1 ||
      actual.mode & 0o077
    )
      invalid("Archive changed while opening.");
    // A concurrently growing file must not defeat the verified-size bound.
    const buffer = Buffer.alloc(actual.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await fd.read(
        buffer,
        length,
        Math.min(65536, buffer.length - length),
        null,
      );
      if (!bytesRead) break;
      length += bytesRead;
    }
    const bytes = buffer.subarray(0, length);
    const after = await fd.stat();
    if (
      bytes.length !== actual.size ||
      after.size !== actual.size ||
      after.mtimeMs !== actual.mtimeMs
    )
      invalid("Archive changed while reading.");
    return { path, bytes };
  } finally {
    await fd.close();
  }
}
export async function inspectArchive(c: Context, opts: any) {
  const input = await readPrivateArchive(opts.file);
  let parsed: ReturnType<typeof inspectBackupBytes>;
  try {
    parsed = inspectBackupBytes(input.bytes);
  } catch {
    throw new CliError(
      "INVALID_ARCHIVE",
      "Backup format, bounds, CRC, relationships, counts or attachment completeness failed. Raw contents suppressed.",
      6,
    );
  }
  const target = opts.compareInstance
    ? record(await c.query("/api/ops/bulk/restore-preflight"))
    : undefined;
  c.print({
    ...parsed.report,
    file: input.path,
    bytes: input.bytes.length,
    sha256: createHash("sha256").update(input.bytes).digest("hex"),
    ...(target ? { target } : {}),
  });
}

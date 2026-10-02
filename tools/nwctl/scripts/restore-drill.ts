// Source-checkout-only rehearsal: disposable workerd/D1/R2, no production origin or restore endpoint.
import { parseArgs } from "node:util";
import { createHash } from "node:crypto";
import { readPrivateArchive } from "../src/backup-inspection.js";
import { privateOutput } from "../src/private-output.js";
import { inspectBackupBytes } from "../../../shared/backup-inspection.js";
import { workerFixture } from "../test/helpers/worker-fixture.js";
const hash = (v: Uint8Array | string) =>
  createHash("sha256").update(v).digest("hex");
let fixture: Awaited<ReturnType<typeof workerFixture>> | undefined,
  file: Awaited<ReturnType<typeof privateOutput>> | undefined;
try {
  const args = parseArgs({
    options: { file: { type: "string" }, report: { type: "string" } },
    strict: true,
    allowPositionals: false,
  }).values;
  if (!args.file || !args.report)
    throw new Error("Explicit --file and --report required");
  const input = await readPrivateArchive(args.file),
    parsed = inspectBackupBytes(input.bytes);
  file = await privateOutput(args.report);
  fixture = await workerFixture({ restoreDrill: true });
  const response = await fetch(fixture.url + "/__fixture/restore", {
    method: "POST",
    body: input.bytes,
    headers: { "Content-Type": "application/zip" },
    redirect: "error",
    signal: AbortSignal.timeout(90000),
  });
  if (!response.ok) throw new Error("Isolated importer failed");
  const result = (await response.json()) as any;
  if (
    result.object !== "instance-backup-import" ||
    result.skipped.attachments !== 0
  )
    throw new Error("Importer did not completely restore attachments");
  const counts: Record<string, number> = {};
  for (const table of [
    "users",
    "folders",
    "ciphers",
    "attachments",
    "webauthn_credentials",
    "domain_settings",
    "user_revisions",
  ] as const) {
    const row = (await fixture.db
      .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
      .first()) as any;
    counts[table] = row.count;
    if (counts[table] !== (parsed.payload.db[table] || []).length)
      throw new Error("Restored row count disagrees");
  }
  for (const table of ["folders", "ciphers", "attachments"] as const)
    for (const original of parsed.payload.db[table]) {
      const row = (await fixture.db
        .prepare(`SELECT * FROM ${table} WHERE id=?`)
        .bind(original.id)
        .first()) as any;
      if (!row) throw new Error("Restored ciphertext row missing");
      for (const [key, value] of Object.entries(original))
        if (
          !Object.hasOwn(row, key) ||
          JSON.stringify(row[key]) !== JSON.stringify(value)
        )
          throw new Error("Restored ciphertext row differs");
    }
  for (const attachment of parsed.payload.db.attachments) {
    const path = `attachments/${attachment.cipher_id}/${attachment.id}.bin`,
      object = await fixture.r2.get(`${attachment.cipher_id}/${attachment.id}`);
    if (
      !object ||
      hash(new Uint8Array(await object.arrayBuffer())) !==
        hash(parsed.files[path])
    )
      throw new Error("Restored blob hash differs");
  }
  const keys = (await fixture.db
    .prepare(
      "SELECT COUNT(*) AS count FROM users WHERE api_key IS NOT NULL AND api_key<>''",
    )
    .first()) as any;
  if (keys.count !== 0)
    throw new Error("Runtime API keys leaked into restoration");
  for (const table of [
    "devices",
    "refresh_tokens",
    "trusted_two_factor_device_tokens",
    "ops_requests",
  ]) {
    const r = (await fixture.db
      .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
      .first()) as any;
    if (r.count !== 0)
      throw new Error("Unexpected restored authentication runtime state");
  }
  if (hash((await readPrivateArchive(args.file)).bytes) !== hash(input.bytes))
    throw new Error("Input archive changed");
  const report = {
    schemaVersion: 1,
    isolated: true,
    engine: "real workerd + disposable D1/R2; outbound network denied",
    sha256: hash(input.bytes),
    counts,
    restoreVerified: true,
    ciphertextVerified: true,
    attachmentHashesVerified: true,
    apiKeysRestored: false,
    runtimeSessionsRestored: false,
    vaultDecrypted: false,
    productionWriteExecuted: false,
    warning:
      "This proves this archive imports in a disposable target and preserves ciphertext/blob bytes, not vault unlock, 2FA usability or portable backup credential repair.",
  };
  await file.write(JSON.stringify(report, null, 2) + "\n");
  await file.commit();
  console.log(JSON.stringify({ ...report, report: args.report }));
} catch {
  console.error(
    JSON.stringify({
      ok: false,
      error:
        "Isolated restore drill failed; raw backup data suppressed; no production restore performed.",
    }),
  );
  process.exitCode = 1;
} finally {
  await file?.abort();
  await fixture?.close();
}

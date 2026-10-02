import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  realpath,
  writeFile,
  chmod,
  symlink,
  link,
  rm,
  mkdir,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateJson } from "../src/private-input.js";
import { opsParameters } from "../../../shared/ops-schema.js";
import { credentials } from "../../../shared/ops-config-schema.js";
test("private JSON input is bounded, owned, exact 0600, regular and single-link without symlink components", async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-private-")));
  try {
    const file = join(dir, "input.json");
    await writeFile(file, '{"change":{"name":"Test"}}', { mode: 0o600 });
    assert.deepEqual(await privateJson(file), { change: { name: "Test" } });
    await chmod(file, 0o644);
    await assert.rejects(privateJson(file));
    await chmod(file, 0o600);
    await symlink(file, join(dir, "symlink.json"));
    await assert.rejects(privateJson(join(dir, "symlink.json")));
    await link(file, join(dir, "hard.json"));
    await assert.rejects(privateJson(file));
    await rm(join(dir, "hard.json"));
    await mkdir(join(dir, "sub"));
    await symlink(join(dir, "sub"), join(dir, "sub-link"));
    await writeFile(join(dir, "sub", "x.json"), "{}", { mode: 0o600 });
    await assert.rejects(privateJson(join(dir, "sub-link", "x.json")));
    await writeFile(file, "a".repeat(8193), { mode: 0o600 });
    await assert.rejects(privateJson(file));
    await writeFile(file, "not json", { mode: 0o600 });
    await assert.rejects(
      privateJson(file),
      (e) => !String(e).includes("not json"),
    );
    await assert.rejects(privateJson(join(dir, "sub")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("public configuration parameters never accept inline credentials or silent normalization", () => {
  const p = {
    expectedRevision: "a".repeat(64),
    mutation: "update",
    destinationId: "dav",
    change: {
      schedule: {
        intervalHours: 12,
        timezone: "Asia/Shanghai",
        retentionCount: null,
      },
    },
    credentialFields: [],
  };
  assert.equal(opsParameters("backup.configure", p).action, "backup.configure");
  for (const patch of [
    { destination: { password: "invalid" } },
    { destination: { accessKeyId: "invalid" } },
    { schedule: { enabled: "false" } },
    { schedule: { startTime: "3:00" } },
    { schedule: { intervalHours: "12" } },
    { name: " name " },
  ])
    assert.throws(() =>
      opsParameters("backup.configure", { ...p, change: patch }),
    );
  assert.throws(() => credentials({ unexpected: "secret" }, ["unexpected"]));
  assert.throws(() =>
    opsParameters("audit.configure", {
      expectedRevision: "a".repeat(64),
      retentionDays: 90,
      maxEntries: 1000,
    }),
  );
  assert.throws(() =>
    opsParameters("user.status", {
      expectedRevision: "a".repeat(64),
      userId: "user",
      status: "disabled",
    }),
  );
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
const { zipSync, strToU8 } = createRequire(
  new URL("../../../../package.json", import.meta.url),
)("fflate");
test(
  "local restore preflight validates archive and compares target without creating approval or uploading data",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-inspect-"))),
      config = join(dir, "config"),
      output = join(dir, "export.zip");
    try {
      await cli(config, [
        "profile",
        "add",
        "test",
        "--server",
        f.url,
        "--allow-loopback-http",
      ]);
      await cli(
        config,
        ["auth", "ensure", "--credentials-stdin"],
        `user.${f.ids.admin}\n${f.secret}\n`,
      );
      const store = new Store(config),
        p = await store.profile(),
        s = await store.session(p);
      const req = await cli(config, [
        "backup",
        "export",
        "--output",
        output,
        "--include-attachments",
        "--yes",
      ]);
      assert.equal(req.code, 0, req.stdout);
      const approval = await fetch(
        f.url + `/api/ops/requests/${req.data.data.id}/approve`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${s.token}`,
            Origin: f.url,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            approve: true,
            masterPasswordHash: "fixture-password-hash",
          }),
        },
      );
      assert.equal(approval.status, 200, await approval.text());
      const done = await cli(config, [
        "ops",
        "execute",
        req.data.data.id,
        "--yes",
      ]);
      assert.equal(done.code, 0, done.stdout);
      const before = await f.snapshot(),
        requests = await f.db
          .prepare("SELECT COUNT(*) AS count FROM ops_requests")
          .first();
      const local = await cli(join(dir, "no-profile"), [
        "backup",
        "inspect",
        "--file",
        output,
      ]);
      assert.equal(local.code, 0, local.stdout);
      assert.equal(local.data.data.structureValid, true);
      assert.equal(local.data.data.restoreExecuted, false);
      assert.equal(local.data.data.counts.users, 3);
      assert.equal(local.data.data.restoreVerified, false);
      const compare = await cli(config, [
        "backup",
        "inspect",
        "--file",
        output,
        "--compare-instance",
      ]);
      assert.equal(compare.code, 0, compare.stdout);
      assert.equal(compare.data.data.target.requiresReplaceExisting, true);
      assert.equal(compare.data.data.target.writeExecuted, false);
      assert.deepEqual(await f.snapshot(), before);
      assert.deepEqual(
        await f.db
          .prepare("SELECT COUNT(*) AS count FROM ops_requests")
          .first(),
        requests,
      );
      const corrupt = join(dir, "corrupt.zip"),
        bytes = await readFile(output);
      bytes[40] ^= 1;
      await writeFile(corrupt, bytes, { mode: 0o600 });
      const bad = await cli(config, ["backup", "inspect", "--file", corrupt]);
      assert.notEqual(bad.code, 0);
      assert.ok(!bad.stdout.includes("fixture-vault-key"));
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

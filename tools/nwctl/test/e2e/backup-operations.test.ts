import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
test(
  "approved remote download streams one private file; run reads back exact archive; integrity does not overclaim",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture({ backupOperations: true }),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-backup-")));
    try {
      const config = join(dir, "cli");
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
        session = await store.session(p),
        output = join(dir, "backup.zip");
      const approve = async (id: string) => {
        const r = await fetch(f.url + `/api/ops/requests/${id}/approve`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${session.token}`,
            "Content-Type": "application/json",
            Origin: f.url,
          },
          body: JSON.stringify({
            approve: true,
            masterPasswordHash: "fixture-password-hash",
          }),
        });
        assert.equal(r.status, 200, await r.text());
      };
      const before = await f.snapshot();
      const dl = await cli(config, [
        "backup",
        "remote",
        "download",
        "--destination",
        "dav",
        "--path",
        "test.zip",
        "--output",
        output,
        "--yes",
      ]);
      assert.equal(dl.code, 0, dl.stdout);
      await approve(dl.data.data.id);
      const done = await cli(config, [
        "ops",
        "execute",
        dl.data.data.id,
        "--yes",
      ]);
      assert.equal(done.code, 0, done.stdout);
      const bytes = await readFile(output);
      assert.deepEqual(bytes, f.remoteFiles.get("test.zip"));
      assert.equal((await stat(output)).mode & 0o777, 0o600);
      assert.equal(
        done.data.data.sha256,
        createHash("sha256").update(bytes).digest("hex"),
      );
      assert.deepEqual(await f.snapshot(), before);
      const verify = await cli(config, [
        "backup",
        "remote",
        "verify",
        "--destination",
        "dav",
        "--path",
        "test.zip",
        "--yes",
      ]);
      assert.equal(verify.code, 0, verify.stdout);
      await approve(verify.data.data.id);
      const checked = await cli(config, [
        "ops",
        "execute",
        verify.data.data.id,
        "--yes",
      ]);
      assert.equal(checked.code, 7, checked.stdout);
      assert.equal(checked.data.data.verified, false);
      assert.equal(checked.data.data.recoverabilityVerified, false);
      const dry = await cli(config, [
        "backup",
        "run",
        "--destination",
        "dav",
        "--dry-run",
      ]);
      assert.equal(dry.code, 0, dry.stdout);
      assert.match(dry.stdout, /retention|DELETE/i);
      const run = await cli(config, [
        "backup",
        "run",
        "--destination",
        "dav",
        "--yes",
      ]);
      assert.equal(run.code, 0, run.stdout);
      await approve(run.data.data.id);
      const ran = await cli(config, [
        "ops",
        "execute",
        run.data.data.id,
        "--operation-timeout",
        "120000",
        "--yes",
      ]);
      assert.equal(
        ran.code,
        0,
        ran.stdout +
          JSON.stringify(
            await f.db
              .prepare(
                "SELECT metadata FROM audit_logs WHERE action LIKE '%backup%failed'",
              )
              .all(),
          ),
      );
      assert.equal(ran.data.data.verified, true);
      assert.ok(f.remoteFiles.has(ran.data.data.fileName));
      const after = await f.snapshot();
      for (const table of [
        "users",
        "ciphers",
        "folders",
        "attachments",
        "sends",
        "r2",
      ])
        assert.deepEqual(after[table], before[table]);
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

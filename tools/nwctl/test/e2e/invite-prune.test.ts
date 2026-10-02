import { test } from "node:test";
import assert from "node:assert/strict";
import { realpath, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
test(
  "invalid invite cleanup preserves valid and newly-created invites with exact read-back",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-prune-"))),
      config = join(dir, "config");
    try {
      await cli(config, [
        "profile",
        "add",
        "test",
        "--server",
        f.url,
        "--allow-loopback-http",
      ]);
      assert.equal(
        (
          await cli(
            config,
            ["auth", "ensure", "--credentials-stdin"],
            `user.${f.ids.admin}\n${f.secret}\n`,
          )
        ).code,
        0,
      );
      const store = new Store(config),
        profile = await store.profile(),
        ctx = { session: await store.session(profile) },
        now = Date.now();
      async function seed(code: string, used: boolean, expires: number | null) {
        await f.db
          .prepare(
            "INSERT INTO invites(code,created_by,created_at,expires_at,used_by,status,updated_at) VALUES(?,?,?,?,?,?,?)",
          )
          .bind(
            code,
            f.ids.admin,
            new Date(now).toISOString(),
            new Date(expires!).toISOString(),
            used ? f.ids.user : null,
            used ? "used" : "active",
            new Date(now).toISOString(),
          )
          .run();
      }
      await seed("fixture-expired-invite", false, now - 1000);
      await seed("fixture-used-invite", true, now + 86400000);
      await seed("fixture-valid-invite", false, now + 86400000);
      await seed("fixture-long-valid-invite", false, now + 30 * 86400000);
      const dry = await cli(config, ["invites", "prune", "--dry-run"]);
      assert.equal(dry.code, 0, dry.stdout);
      assert.equal(dry.data.data.parameters.targets.length, 2);
      assert.ok(!dry.stdout.includes("fixture-expired-invite"));
      const req = await cli(config, ["invites", "prune", "--yes"]);
      assert.equal(req.code, 0, req.stdout);
      const id = req.data.data.id;
      await seed("fixture-new-expired-invite", false, now - 2000);
      const approval = await fetch(
        f.url + "/api/ops/requests/" + id + "/approve",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${ctx.session.token}`,
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
      const done = await cli(config, ["ops", "execute", id, "--yes"]);
      assert.equal(done.code, 0, done.stdout);
      assert.equal(done.data.data.readbackVerified, true);
      const rows = (
        await f.db.prepare("SELECT code FROM invites ORDER BY code").all()
      ).results.map((r: any) => r.code);
      assert.deepEqual(rows, [
        "fixture-long-valid-invite",
        "fixture-new-expired-invite",
        "fixture-valid-invite",
      ]);
      assert.notEqual(
        (await cli(config, ["ops", "execute", id, "--yes"])).code,
        0,
      );
      for (const value of [dry.stdout, req.stdout, done.stdout])
        assert.ok(!value.includes("fixture-used-invite"));
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
async function login(f: any, dir: string, user: string) {
  await cli(dir, [
    "profile",
    "add",
    "test",
    "--server",
    f.url,
    "--allow-loopback-http",
  ]);
  await cli(
    dir,
    ["auth", "ensure", "--credentials-stdin"],
    `user.${user}\n${f.secret}\n`,
  );
  const s = new Store(dir),
    p = await s.profile();
  return { s, p, session: await s.session(p) };
}
async function approve(f: any, s: any, id: string) {
  const r = await fetch(f.url + `/api/ops/requests/${id}/approve`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${s.session.token}`,
      Origin: f.url,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      approve: true,
      masterPasswordHash: "fixture-password-hash",
    }),
  });
  return r;
}
test(
  "bulk device removal protects current, other accounts and devices created after review",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-bulk-")));
    try {
      const config = join(dir, "main"),
        main = await login(f, config, f.ids.admin),
        a = await login(f, join(dir, "a"), f.ids.admin),
        b = await login(f, join(dir, "b"), f.ids.admin),
        foreign = await login(f, join(dir, "foreign"), f.ids.user);
      const before = await f.snapshot();
      const dry = await cli(config, [
        "devices",
        "remove-batch",
        "--all",
        "--dry-run",
      ]);
      assert.equal(dry.code, 0, dry.stdout);
      assert.equal(dry.data.data.parameters.targets.length, 2);
      assert.ok(
        dry.data.data.parameters.targets.every(
          (t: any) => t.id !== main.p.device,
        ),
      );
      const request = await cli(config, [
        "devices",
        "remove-batch",
        "--all",
        "--yes",
      ]);
      assert.equal(request.code, 0, request.stdout);
      const later = await login(f, join(dir, "later"), f.ids.admin),
        id = request.data.data.id;
      const approval = await approve(f, main, id);
      assert.equal(approval.status, 200, await approval.text());
      const done = await cli(config, ["ops", "execute", id, "--yes"]);
      assert.equal(done.code, 0, done.stdout);
      assert.equal(done.data.data.verified, true);
      for (const target of [a, b]) {
        const r = await fetch(f.url + "/api/accounts/profile", {
          headers: { Authorization: `Bearer ${target.session.token}` },
        });
        assert.equal(r.status, 401);
        assert.equal(
          await f.db
            .prepare(
              "SELECT 1 FROM devices WHERE user_id=? AND device_identifier=?",
            )
            .bind(f.ids.admin, target.p.device)
            .first(),
          null,
        );
      }
      for (const target of [main, later, foreign]) {
        const r = await fetch(f.url + "/api/accounts/profile", {
          headers: { Authorization: `Bearer ${target.session.token}` },
        });
        assert.equal(r.status, 200);
      }
      assert.deepEqual(await f.snapshot(), before);
      assert.notEqual(
        (await cli(config, ["ops", "execute", id, "--yes"])).code,
        0,
      );
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test(
  "bulk remembered-2FA revocation preserves sessions, wrapped keys, current device and other users",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-trust-")));
    try {
      const config = join(dir, "main"),
        main = await login(f, config, f.ids.admin),
        a = await login(f, join(dir, "a"), f.ids.admin),
        foreign = await login(f, join(dir, "foreign"), f.ids.user);
      for (const [account, device, token] of [
        [f.ids.admin, main.p.device, "fixture-current-token"],
        [f.ids.admin, a.p.device, "fixture-other-token"],
        [f.ids.user, foreign.p.device, "fixture-foreign-token"],
      ])
        await f.db
          .prepare(
            "INSERT INTO trusted_two_factor_device_tokens(token,user_id,device_identifier,expires_at) VALUES(?,?,?,?)",
          )
          .bind(token, account, device, Date.now() + 86400000)
          .run();
      await f.db
        .prepare(
          "UPDATE devices SET encrypted_user_key=? WHERE user_id=? AND device_identifier=?",
        )
        .bind("fixture-wrapped-key", f.ids.admin, a.p.device)
        .run();
      const request = await cli(config, [
        "devices",
        "revoke-trust-batch",
        "--all",
        "--yes",
      ]);
      assert.equal(request.code, 0, request.stdout);
      const approval = await approve(f, main, request.data.data.id);
      assert.equal(approval.status, 200, await approval.text());
      const done = await cli(config, [
        "ops",
        "execute",
        request.data.data.id,
        "--yes",
      ]);
      assert.equal(done.code, 0, done.stdout);
      assert.equal(done.data.data.verified, true);
      assert.equal(
        await f.db
          .prepare(
            "SELECT 1 FROM trusted_two_factor_device_tokens WHERE token=?",
          )
          .bind("fixture-other-token")
          .first(),
        null,
      );
      for (const token of ["fixture-current-token", "fixture-foreign-token"])
        assert.ok(
          await f.db
            .prepare(
              "SELECT 1 FROM trusted_two_factor_device_tokens WHERE token=?",
            )
            .bind(token)
            .first(),
        );
      assert.equal(
        (
          (await f.db
            .prepare(
              "SELECT encrypted_user_key FROM devices WHERE user_id=? AND device_identifier=?",
            )
            .bind(f.ids.admin, a.p.device)
            .first()) as any
        ).encrypted_user_key,
        "fixture-wrapped-key",
      );
      const r = await fetch(f.url + "/api/accounts/profile", {
        headers: { Authorization: `Bearer ${a.session.token}` },
      });
      assert.equal(r.status, 200);
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
async function login(f: any, path: string) {
  await cli(path, [
    "profile",
    "add",
    "test",
    "--server",
    f.url,
    "--allow-loopback-http",
  ]);
  await cli(
    path,
    ["auth", "ensure", "--credentials-stdin"],
    `user.${f.ids.admin}\n${f.secret}\n`,
  );
  const store = new Store(path),
    p = await store.profile();
  return { store, p, session: await store.session(p) };
}
async function approve(f: any, s: any, id: string) {
  return fetch(f.url + `/api/ops/requests/${id}/approve`, {
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
}
test(
  "ambiguous current-device removal clears local session after the one execution attempt",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture({ ambiguousSelfLogout: true } as any),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-ambiguous-")));
    try {
      const main = await login(f, join(dir, "main")),
        web = await login(f, join(dir, "web"));
      const req = await cli(join(dir, "main"), [
        "devices",
        "remove-batch",
        "--ids",
        main.p.device,
        "--include-current",
        "--yes",
      ]);
      assert.equal(req.code, 0, req.stdout);
      const r = await approve(f, web, req.data.data.id);
      assert.equal(r.status, 200, await r.text());
      const result = await cli(join(dir, "main"), [
        "ops",
        "execute",
        req.data.data.id,
        "--yes",
      ]);
      assert.notEqual(result.code, 0);
      await assert.rejects(() => main.store.session(main.p));
      assert.equal(
        await f.db
          .prepare(
            "SELECT 1 FROM devices WHERE user_id=? AND device_identifier=?",
          )
          .bind(f.ids.admin, main.p.device)
          .first(),
        null,
      );
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test(
  "changed device revision after Web approval refuses the whole reviewed batch",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-changed-")));
    try {
      const main = await login(f, join(dir, "main")),
        a = await login(f, join(dir, "a")),
        b = await login(f, join(dir, "b"));
      const req = await cli(join(dir, "main"), [
        "devices",
        "remove-batch",
        "--ids",
        a.p.device,
        b.p.device,
        "--yes",
      ]);
      assert.equal(req.code, 0, req.stdout);
      const r = await approve(f, main, req.data.data.id);
      assert.equal(r.status, 200, await r.text());
      await f.db
        .prepare(
          "UPDATE devices SET session_stamp=? WHERE user_id=? AND device_identifier=?",
        )
        .bind("fixture-replacement-session", f.ids.admin, b.p.device)
        .run();
      const result = await cli(join(dir, "main"), [
        "ops",
        "execute",
        req.data.data.id,
        "--yes",
      ]);
      assert.notEqual(result.code, 0);
      assert.equal(result.data.error.httpStatus, 409);
      for (const device of [main.p.device, a.p.device, b.p.device])
        assert.ok(
          await f.db
            .prepare(
              "SELECT 1 FROM devices WHERE user_id=? AND device_identifier=?",
            )
            .bind(f.ids.admin, device)
            .first(),
        );
      assert.ok(await main.store.session(main.p));
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);
test(
  "invitation changed back to valid after approval cannot be pruned",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-invite-cas-")));
    try {
      const main = await login(f, join(dir, "main")),
        now = new Date().toISOString();
      await f.db
        .prepare(
          "INSERT INTO invites(code,created_by,created_at,expires_at,status,updated_at) VALUES(?,?,?,?,?,?)",
        )
        .bind(
          "fixture-review-expired",
          f.ids.admin,
          now,
          "2020-01-01T00:00:00Z",
          "active",
          now,
        )
        .run();
      const req = await cli(join(dir, "main"), ["invites", "prune", "--yes"]);
      assert.equal(req.code, 0, req.stdout);
      const r = await approve(f, main, req.data.data.id);
      assert.equal(r.status, 200, await r.text());
      await f.db
        .prepare("UPDATE invites SET expires_at=?,updated_at=? WHERE code=?")
        .bind(
          new Date(Date.now() + 86400000).toISOString(),
          new Date(Date.now() + 1).toISOString(),
          "fixture-review-expired",
        )
        .run();
      const result = await cli(join(dir, "main"), [
        "ops",
        "execute",
        req.data.data.id,
        "--yes",
      ]);
      assert.notEqual(result.code, 0);
      assert.equal(result.data.error.httpStatus, 409);
      assert.ok(
        await f.db
          .prepare("SELECT 1 FROM invites WHERE code=?")
          .bind("fixture-review-expired")
          .first(),
      );
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

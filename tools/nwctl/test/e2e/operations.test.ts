import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";

test(
  "server logout revokes only this CLI device and old tokens stay invalid after relogin",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture();
    const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-logout-")));
    try {
      const config = join(dir, "cli"),
        other = join(dir, "other");
      for (const d of [config, other]) {
        await cli(d, [
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
              d,
              ["auth", "ensure", "--credentials-stdin"],
              `user.${f.ids.admin}\n${f.secret}\n`,
            )
          ).code,
          0,
        );
      }
      const store = new Store(config),
        p = await store.profile(),
        old = await store.session(p);
      const before = await f.snapshot();
      const devices = await cli(config, ["devices", "list"]);
      assert.equal(devices.code, 0, devices.stdout);
      assert.equal(devices.data.data.count, 2);
      assert.equal(
        devices.data.data.items.filter((d: any) => d.current).length,
        1,
      );
      assert.equal(
        devices.data.data.items.find((d: any) => d.current).id,
        p.device,
      );
      assert.doesNotMatch(
        devices.stdout,
        /encryptedUserKey|encryptedPublicKey/,
      );
      const exited = await cli(config, ["auth", "logout", "--server"]);
      assert.equal(exited.code, 0, exited.stdout);
      assert.equal(exited.data.data.oldAccessRejected, true);
      assert.equal(exited.data.data.serverRevoked, true);
      await assert.rejects(store.session(p), { exitCode: 3 });
      const probe = () =>
        fetch(f.url + "/api/accounts/profile", {
          headers: { Authorization: `Bearer ${old.token}` },
        });
      assert.equal((await probe()).status, 401);
      assert.equal((await cli(other, ["whoami"])).code, 0);
      assert.equal(
        (await f.db.prepare("SELECT count(*) AS n FROM devices").first()).n,
        1,
      );
      assert.deepEqual(await f.snapshot(), before);
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
      assert.equal(
        (await probe()).status,
        401,
        "new login must not resurrect an old JWT",
      );
      assert.equal((await cli(other, ["whoami"])).code, 0);
      assert.equal(
        (
          await cli(config, [
            "auth",
            "logout",
            "--server",
            "--device",
            "another-device",
          ])
        ).code,
        2,
      );
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test(
  "status summarizes identity, expiry, users and backups without treating unknown as healthy",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture();
    const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-status-")));
    try {
      await cli(dir, [
        "profile",
        "add",
        "test",
        "--server",
        f.url,
        "--allow-loopback-http",
      ]);
      const out = await cli(dir, ["status"]);
      assert.equal(out.code, 0, out.stdout);
      assert.equal(out.data.data.auth.loggedIn, false);
      assert.equal(out.data.data.userCount, null);
      assert.equal(out.data.data.backup, null);
      assert.equal(out.data.data.healthy, false);
      assert.equal((await cli(dir, ["status", "--check"])).code, 7);
      assert.equal(
        (await cli(dir, ["status", "--max-age", "invalid"])).code,
        2,
      );
      const before = await f.snapshot();
      await cli(
        dir,
        ["auth", "ensure", "--credentials-stdin"],
        `user.${f.ids.admin}\n${f.secret}\n`,
      );
      const admin = await cli(dir, ["status", "--check", "--max-age", "48h"]);
      assert.equal(admin.code, 7, admin.stdout);
      assert.equal(admin.data.data.auth.identity.role, "admin");
      assert.ok(admin.data.data.auth.remainingSeconds > 0);
      assert.equal(admin.data.data.userCount, 3);
      assert.equal(admin.data.data.backup.count, 2);
      assert.equal(admin.data.data.backup.healthy, false);
      assert.deepEqual(await f.snapshot(), before);
      await cli(dir, ["auth", "logout"]);
      await cli(
        dir,
        ["auth", "ensure", "--credentials-stdin"],
        `user.${f.ids.user}\n${f.secret}\n`,
      );
      const user = await cli(dir, ["status"]);
      assert.equal(user.code, 0, user.stdout);
      assert.equal(user.data.data.auth.identity.role, "user");
      assert.equal(user.data.data.userCount, null);
      assert.equal(user.data.data.healthy, false);
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test(
  "audit filters match real Worker results and reject invalid options before requests",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture();
    const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-audit-")));
    try {
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
        `user.${f.ids.admin}\n${f.secret}\n`,
      );
      const from = new Date(Date.now() - 60000).toISOString(),
        to = new Date(Date.now() + 60000).toISOString();
      const filtered = await cli(dir, [
        "audit",
        "list",
        "--category",
        "system",
        "--level",
        "info",
        "--query",
        "fixture.inspect",
        "--from",
        from,
        "--to",
        to,
      ]);
      assert.equal(filtered.code, 0, filtered.stdout);
      assert.equal(filtered.data.data.count, 5);
      assert.equal(filtered.data.data.total, 5);
      assert.equal(filtered.data.data.hasMore, false);
      assert.ok(
        filtered.data.data.items.every(
          (r: any) =>
            r.category === "system" &&
            r.level === "info" &&
            r.action === "fixture.inspect",
        ),
      );
      assert.ok(
        filtered.data.data.items.every((r: any) => r.metadataOmitted === true),
      );
      assert.ok(!filtered.stdout.includes("fixture-s3-secret"));
      const empty = await cli(dir, [
        "audit",
        "list",
        "--query",
        "definitely-no-such-action",
      ]);
      assert.equal(empty.code, 0, empty.stdout);
      assert.equal(empty.data.data.total, 0);
      for (const args of [
        ["--from", "yesterday"],
        ["--from", "2026-02-30T12:00:00Z"],
        ["--from", "2026-10-01T00:00:00"],
        ["--from", to, "--to", from],
        ["--query", "a\nb"],
        ["--level", ""],
        ["--query", "x".repeat(513)],
      ]) {
        assert.equal(
          (await cli(dir, ["audit", "list", ...args])).code,
          2,
          args.join(" "),
        );
      }
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test(
  "auth ensure uses supplied credentials once and reuses verified sessions",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture();
    const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-ensure-")));
    try {
      await cli(dir, [
        "profile",
        "add",
        "test",
        "--server",
        f.url,
        "--allow-loopback-http",
      ]);
      const input = `user.${f.ids.admin}\n${f.secret}\n`;
      const first = await cli(
        dir,
        ["auth", "ensure", "--credentials-stdin"],
        input,
      );
      assert.equal(first.code, 0, first.stdout);
      assert.equal(first.data.data.reused, false);
      const store = new Store(dir),
        p = await store.profile();
      const before = await store.session(p);
      const reuse = await cli(dir, ["auth", "ensure"]);
      assert.equal(reuse.code, 0, reuse.stdout);
      assert.equal(reuse.data.data.reused, true);
      assert.deepEqual(await store.session(p), before);
      const cached = await cli(dir, ["auth", "ensure", "--cached"]);
      assert.equal(
        cached.code,
        2,
        "cached helper may not run for other origins/config directories",
      );
      assert.deepEqual(await store.session(p), before);
      await store.saveSession(p, { ...before, expiresAt: 1 });
      const again = await cli(
        dir,
        ["auth", "ensure", "--credentials-stdin"],
        input,
      );
      assert.equal(again.code, 0, again.stdout);
      assert.equal(again.data.data.reused, false);
      await f.invalidateDevice(f.ids.admin, p.device);
      const invalidated = await cli(
        dir,
        ["auth", "ensure", "--credentials-stdin"],
        input,
      );
      assert.equal(invalidated.code, 0, invalidated.stdout);
      assert.equal(invalidated.data.data.reused, false);
      for (const r of [first, reuse, again, invalidated])
        assert.ok(!r.stdout.includes(f.secret));
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

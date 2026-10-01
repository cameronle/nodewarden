import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  rm,
  readFile,
  readdir,
  stat,
  realpath,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { randomUUID, randomBytes, createHmac } from "node:crypto";
import { workerFixture } from "../helpers/worker-fixture.js";
import { Store } from "../../src/config.js";
async function cli(
  dir: string,
  args: string[],
  input?: string,
  bin = "bin/nwctl.mjs",
) {
  return new Promise<{
    code: number | null;
    stdout: string;
    stderr: string;
    data: any;
  }>((resolve, reject) => {
    const p = spawn(
      process.execPath,
      [bin, "--config-dir", dir, "--json", ...args],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    let stdout = "",
      stderr = "";
    p.stdout.on("data", (b) => (stdout += b));
    p.stderr.on("data", (b) => (stderr += b));
    p.on("error", reject);
    p.on("close", (code) => {
      try {
        resolve({ code, stdout, stderr, data: JSON.parse(stdout) });
      } catch {
        reject(
          new Error(
            "CLI did not produce a single JSON document: " + stdout + stderr,
          ),
        );
      }
    });
    p.stdin.end(input);
  });
}
test(
  "real isolated Worker: authentication, admin queries, remote browsing and unchanged business data",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture();
    const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-e2e-")));
    const config = join(dir, "private");
    try {
      await cli(config, [
        "profile",
        "add",
        "test",
        "--server",
        f.url,
        "--allow-loopback-http",
      ]);
      assert.equal((await cli(config, ["whoami"])).code, 3);
      assert.equal(
        (
          await cli(
            config,
            ["auth", "login", "--apikey", "--credentials-stdin"],
            `user.${f.ids.admin}\nwrong-fixture-secret\n`,
          )
        ).code,
        3,
      );
      const logged = await cli(
        config,
        ["auth", "login", "--apikey", "--credentials-stdin"],
        `user.${f.ids.admin}\n${f.secret}\n`,
      );
      assert.equal(logged.code, 0, logged.stdout);
      assert.equal(logged.data.data.identity.role, "admin");
      assert.equal(logged.data.data.refreshTokenStored, false);
      assert.equal(
        (await f.db.prepare("SELECT count(*) AS n FROM refresh_tokens").first())
          .n,
        0,
        "login refresh token must actually be removed",
      );
      const before = await f.snapshot();
      for (const args of [
        ["whoami"],
        ["auth", "status"],
        ["doctor"],
        ["users", "list"],
        ["audit", "list", "--limit", "2", "--offset", "0"],
        ["backup", "destinations", "list"],
        ["backup", "status"],
      ]) {
        const r = await cli(config, args);
        assert.equal(r.code, 0, r.stdout);
        assert.equal(r.data.ok, true);
        for (const secret of [
          f.secret,
          f.jwt,
          "fixture-vault-key",
          "fixture-dav-password",
          "fixture-s3-secret",
        ])
          assert.ok(!r.stdout.includes(secret), args.join(" "));
      }
      const page = await cli(config, ["audit", "list", "--limit", "2"]);
      assert.equal(page.data.data.count, page.data.data.items.length);
      assert.equal(page.data.data.hasMore, true);
      const next = await cli(config, [
        "audit",
        "list",
        "--limit",
        "2",
        "--offset",
        "2",
      ]);
      assert.equal(next.data.data.offset, 2);
      for (const id of ["dav", "s3"]) {
        const r = await cli(config, [
          "backup",
          "remote",
          "list",
          "--destination",
          id,
        ]);
        assert.equal(r.code, 0, r.stdout);
        assert.equal(r.data.data.count, 1);
      }
      const empty = await cli(config, [
        "backup",
        "remote",
        "list",
        "--destination",
        "dav",
        "--path",
        "empty",
      ]);
      assert.equal(empty.code, 0, empty.stdout);
      assert.equal(empty.data.data.count, 0);
      const remoteError = await cli(config, [
        "backup",
        "remote",
        "list",
        "--destination",
        "dav",
        "--path",
        "error",
      ]);
      assert.equal(remoteError.code, 6);
      assert.equal(remoteError.data.error.code, "REMOTE_CONFLICT");
      assert.equal(
        (await cli(config, ["backup", "status", "--check"])).code,
        7,
      );
      assert.deepEqual(
        await f.snapshot(),
        before,
        "read-only queries may not change business data",
      );
      const store = new Store(config);
      const p = await store.profile();
      const session = await store.session(p);
      const disk = (
        await Promise.all(
          (await readdir(config)).map((file) =>
            readFile(join(config, file), "utf8"),
          ),
        )
      ).join("");
      for (const secret of [
        f.secret,
        f.jwt,
        "fixture-vault-key",
        "fixture-dav-password",
        "fixture-s3-secret",
      ])
        assert.ok(!disk.includes(secret));
      assert.equal(
        (await stat(join(config, "session-test.json"))).mode & 0o777,
        0o600,
      );
      await cli(config, ["auth", "logout"]);
      assert.equal(
        (await cli(config, ["auth", "status"])).data.data.loggedIn,
        false,
      );
      assert.equal(
        (
          await fetch(f.url + "/api/accounts/profile", {
            headers: { Authorization: `Bearer ${session.token}` },
          })
        ).status,
        200,
        "local logout does not invalidate access token",
      );
      // Prove OAuth revocation with an actual refresh attempt, not just HTTP 200.
      const token = (await (
        await fetch(f.url + "/identity/connect/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "client_credentials",
            scope: "api",
            client_id: `user.${f.ids.admin}`,
            client_secret: f.secret,
            deviceIdentifier: randomUUID(),
            deviceName: "refresh-proof",
            deviceType: "8",
          }),
        })
      ).json()) as any;
      assert.ok(token.refresh_token);
      await fetch(f.url + "/identity/connect/revocation", {
        method: "POST",
        body: new URLSearchParams({ token: token.refresh_token }),
      });
      const refreshed = await fetch(f.url + "/identity/connect/token", {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: token.refresh_token,
          client_id: "cli",
        }),
      });
      assert.equal(refreshed.status, 400);
      // Normal user is denied by backend, and banned user cannot log in.
      assert.equal(
        (
          await cli(
            config,
            ["auth", "login", "--apikey", "--credentials-stdin"],
            `user.${f.ids.user}\n${f.secret}\n`,
          )
        ).code,
        0,
      );
      assert.equal((await cli(config, ["users", "list"])).code, 4);
      assert.equal(
        (
          await cli(
            config,
            ["auth", "login", "--apikey", "--credentials-stdin"],
            `user.${f.ids.banned}\n${f.secret}\n`,
          )
        ).code,
        3,
      );
      // Expiry is checked locally, and a correctly signed expired JWT is rejected by Worker.
      await store.saveSession(p, {
        token: "expired-local-fixture",
        expiresAt: 1,
      });
      assert.equal((await cli(config, ["whoami"])).code, 3);
      const encode = (v: unknown) =>
        Buffer.from(JSON.stringify(v)).toString("base64url");
      const raw =
        encode({ alg: "HS256", typ: "JWT" }) +
        "." +
        encode({
          sub: f.ids.admin,
          email: "admin@example.test",
          sstamp: "fixture-stamp",
          exp: 1,
          iat: 1,
        });
      const expired =
        raw + "." + createHmac("sha256", f.jwt).update(raw).digest("base64url");
      await store.saveSession(p, {
        token: expired,
        expiresAt: Date.now() + 60000,
      });
      assert.equal((await cli(config, ["whoami"])).code, 3);
      await assert.rejects(store.session(p));
      // Delete only the isolated CLI device and invalidate backend cache in fixture.
      await cli(
        config,
        ["auth", "login", "--apikey", "--credentials-stdin"],
        `user.${f.ids.admin}\n${f.secret}\n`,
      );
      await f.invalidateDevice(f.ids.admin, p.device);
      assert.equal((await cli(config, ["whoami"])).code, 3);
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

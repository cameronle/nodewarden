import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
const exec = promisify(execFile);
test(
  "npm pack installs standalone in a clean directory and queries a real Worker",
  { timeout: 120000 },
  async () => {
    const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-pack-")));
    let f: Awaited<ReturnType<typeof workerFixture>> | undefined;
    try {
      const packed = JSON.parse(
        (
          await exec("npm", [
            "pack",
            "--json",
            "--silent",
            "--pack-destination",
            dir,
          ])
        ).stdout,
      )[0];
      assert.deepEqual(packed.files.map((f: any) => f.path).sort(), [
        "LICENSE",
        "README.md",
        "THIRD_PARTY_NOTICES",
        "bin/nwctl.mjs",
        "dist/cli.mjs",
        "package.json",
      ]);
      const archive = join(dir, packed.filename);
      await exec(
        "npm",
        ["install", "--omit=dev", "--ignore-scripts", "--offline", archive],
        {
          cwd: dir,
          env: { ...process.env, npm_config_cache: join(dir, "empty-cache") },
        },
      );
      const bin = join(dir, "node_modules", ".bin", "nwctl");
      assert.match(
        (await exec(bin, ["--help"], { cwd: dir })).stdout,
        /backup/,
      );
      assert.equal(
        (await exec(bin, ["--version"], { cwd: dir })).stdout.trim(),
        "0.3.0",
      );
      const artifact = await readFile(
        join(dir, "node_modules", "nodewarden-ops-cli", "dist", "cli.mjs"),
        "utf8",
      );
      for (const disallowed of [
        "/__fixture/",
        "fixture-vault-key",
        "fixture-s3-secret",
        "cloudflare:workers",
        "StorageService",
      ])
        assert.ok(!artifact.includes(disallowed));
      f = await workerFixture();
      const config = join(dir, "private");
      await exec(
        bin,
        [
          "--config-dir",
          config,
          "profile",
          "add",
          "test",
          "--server",
          f.url,
          "--allow-loopback-http",
        ],
        { cwd: dir },
      );
      const result = JSON.parse(
        (
          await exec(bin, ["--config-dir", config, "--json", "doctor"], {
            cwd: dir,
          })
        ).stdout,
      );
      assert.equal(result.data.apiReachable, true);
      assert.equal(result.data.nodewardenVersion, "unknown");
      const before = await f.snapshot();
      const login = await cli(
        config,
        ["auth", "ensure", "--credentials-stdin"],
        `user.${f.ids.admin}\n${f.secret}\n`,
        bin,
      );
      assert.equal(login.code, 0, login.stdout);
      assert.equal(
        (await cli(config, ["auth", "ensure"], undefined, bin)).data.data
          .reused,
        true,
      );
      assert.equal(
        (await cli(config, ["status", "--check"], undefined, bin)).code,
        7,
      );
      assert.equal(
        (await cli(config, ["devices", "list"], undefined, bin)).data.data
          .count,
        1,
      );
      assert.equal(
        (
          await cli(
            config,
            ["devices", "show", (await new Store(config).profile()).device],
            undefined,
            bin,
          )
        ).code,
        0,
      );
      assert.equal(
        (await cli(config, ["invites", "list"], undefined, bin)).code,
        0,
      );
      assert.equal(
        (
          await cli(
            config,
            ["backup", "run", "--destination", "dav", "--dry-run"],
            undefined,
            bin,
          )
        ).code,
        0,
      );
      assert.equal(
        (await cli(config, ["audit", "settings", "show"], undefined, bin)).code,
        0,
      );
      const audit = await cli(
        config,
        ["audit", "list", "--query", "fixture.inspect", "--category", "system"],
        undefined,
        bin,
      );
      assert.equal(audit.code, 0, audit.stdout);
      assert.equal(audit.data.data.total, 5);
      const store = new Store(config),
        p = await store.profile(),
        old = await store.session(p);
      const logout = await cli(
        config,
        ["auth", "logout", "--server"],
        undefined,
        bin,
      );
      assert.equal(logout.code, 0, logout.stdout);
      assert.equal(logout.data.data.oldAccessRejected, true);
      assert.equal(
        (
          await fetch(f.url + "/api/accounts/profile", {
            headers: { Authorization: `Bearer ${old.token}` },
          })
        ).status,
        401,
      );
      assert.deepEqual(await f.snapshot(), before);
    } finally {
      await f?.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

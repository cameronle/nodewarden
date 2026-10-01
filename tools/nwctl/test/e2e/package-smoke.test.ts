import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { workerFixture } from "../helpers/worker-fixture.js";
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
        "0.1.0",
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
    } finally {
      await f?.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

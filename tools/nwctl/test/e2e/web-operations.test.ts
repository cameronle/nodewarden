import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";

test(
  "device writes require confirmation, honor dry-run, distinguish trust and protect current device",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture();
    const root = await realpath(await mkdtemp(join(tmpdir(), "nw-manage-")));
    try {
      const dirs = [join(root, "cli"), join(root, "other")];
      for (const dir of dirs) {
        await cli(dir, [
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
              dir,
              ["auth", "ensure", "--credentials-stdin"],
              `user.${f.ids.admin}\n${f.secret}\n`,
            )
          ).code,
          0,
        );
      }
      const current = await new Store(dirs[0]).profile(),
        other = await new Store(dirs[1]).profile();
      const snapshot = await f.snapshot();
      const show = await cli(dirs[0], ["devices", "show", other.device]);
      assert.equal(show.code, 0, show.stdout);
      assert.equal(show.data.data.id, other.device);
      assert.equal(show.data.data.hasStoredDevice, true);
      assert.doesNotMatch(
        show.stdout,
        /encryptedUserKey|encryptedPublicKey|pushToken/,
      );
      const rename = [
        "devices",
        "rename",
        other.device,
        "--name",
        "Test phone",
      ];
      assert.equal((await cli(dirs[0], rename)).code, 2);
      assert.equal((await cli(dirs[0], [...rename, "--dry-run"])).code, 0);
      assert.equal(
        (await cli(dirs[0], ["devices", "show", other.device])).data.data.name,
        "nwctl",
      );
      assert.equal((await cli(dirs[0], [...rename, "--yes"])).code, 0);
      assert.equal(
        (await cli(dirs[0], ["devices", "show", other.device])).data.data.name,
        "Test phone",
      );
      await f.db
        .prepare(
          "INSERT INTO trusted_two_factor_device_tokens (token,user_id,device_identifier,expires_at) VALUES (?,?,?,?)",
        )
        .bind("fixture-trust", f.ids.admin, other.device, Date.now() + 600000)
        .run();
      assert.equal(
        (await cli(dirs[0], ["devices", "revoke-trust", other.device, "--yes"]))
          .code,
        0,
      );
      assert.equal(
        (await cli(dirs[0], ["devices", "show", other.device])).data.data
          .rememberedTwoFactor,
        false,
      );
      assert.equal(
        (await cli(dirs[0], ["devices", "remove", current.device, "--yes"]))
          .code,
        2,
      );
      assert.equal(
        (await cli(dirs[0], ["devices", "remove", other.device, "--yes"])).code,
        0,
      );
      assert.notEqual(
        (await cli(dirs[0], ["devices", "show", other.device])).code,
        0,
      );
      assert.equal((await cli(dirs[0], ["whoami"])).code, 0);
      assert.deepEqual(await f.snapshot(), snapshot);
    } finally {
      await f.close();
      await rm(root, { recursive: true, force: true });
    }
  },
);

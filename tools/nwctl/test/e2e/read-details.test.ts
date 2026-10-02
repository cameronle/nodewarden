import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
test("user details and audit policy are metadata-only reads", async () => {
  const f = await workerFixture(),
    dir = await realpath(await mkdtemp(join(tmpdir(), "nw-details-")));
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
    const before = await f.snapshot();
    const user = await cli(dir, ["users", "show", f.ids.user]);
    assert.equal(user.code, 0, user.stdout);
    assert.equal(user.data.data.id, f.ids.user);
    assert.equal(user.data.data.twoFactorEnabled, false);
    assert.equal(typeof user.data.data.creationDate, "string");
    assert.notEqual((await cli(dir, ["users", "show", "missing"])).code, 0);
    const settings = await cli(dir, ["audit", "settings", "show"]);
    assert.equal(settings.code, 0, settings.stdout);
    assert.equal(settings.data.data.retentionDays, 90);
    assert.equal(settings.data.data.maxEntries, null);
    assert.deepEqual(await f.snapshot(), before);
  } finally {
    await f.close();
    await rm(dir, { recursive: true, force: true });
  }
});

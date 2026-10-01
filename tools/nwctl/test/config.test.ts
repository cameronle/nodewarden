import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  chmod,
  symlink,
  stat,
  readFile,
  rm,
  realpath,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/config.js";
async function temp(fn: (s: Store, dir: string) => Promise<void>) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "nwctl-")));
  try {
    await fn(new Store(join(dir, "private")), dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
test("profiles are private, select independently and use stable device identifiers", async () =>
  temp(async (s) => {
    const a = await s.add("prod", "https://nw.example");
    assert.equal((await s.profile()).device, a.device);
    await s.add("test", "https://test.example");
    await s.use("test");
    assert.equal((await s.profile()).server, "https://test.example");
    assert.equal((await stat(s.dir)).mode & 0o777, 0o700);
    assert.equal((await stat(join(s.dir, "config.json"))).mode & 0o777, 0o600);
  }));
test("session is profile/origin bound, expires and clears on server change", async () =>
  temp(async (s) => {
    await s.add("prod", "https://nw.example");
    let p = await s.profile();
    await s.saveSession(p, {
      token: "fixture-access",
      expiresAt: Date.now() + 10000,
    });
    assert.equal((await s.session(p)).token, "fixture-access");
    await assert.rejects(s.session({ ...p, server: "https://other.example" }), {
      exitCode: 3,
    });
    await s.add("prod", "https://other.example");
    p = await s.profile();
    await assert.rejects(s.session(p), { exitCode: 3 });
    await s.saveSession(p, { token: "expired-fixture", expiresAt: 1 });
    await assert.rejects(s.session(p), { exitCode: 3 });
    await s.logout(p);
    await assert.rejects(s.session(p), { exitCode: 3 });
  }));
test("storage rejects symlinks, unsafe modes and invalid names", async () =>
  temp(async (s, dir) => {
    await s.add("prod", "https://nw.example");
    await assert.rejects(s.add("../escape", "https://nw.example"), {
      exitCode: 2,
    });
    await chmod(join(s.dir, "config.json"), 0o644);
    await assert.rejects(s.list(), { exitCode: 2 });
    await chmod(join(s.dir, "config.json"), 0o600);
    await symlink(s.dir, join(dir, "link"));
    await assert.rejects(new Store(join(dir, "link")).list(), { exitCode: 2 });
    await rm(join(s.dir, "config.json"));
    await symlink(join(dir, "outside"), join(s.dir, "config.json"));
    await assert.rejects(s.list(), { exitCode: 2 });
  }));

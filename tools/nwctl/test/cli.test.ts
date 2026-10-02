import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
const run = (...args: string[]) =>
  spawnSync(process.execPath, ["bin/nwctl.mjs", ...args], { encoding: "utf8" });
test("standalone help and version need no network or profile", () => {
  const h = run("--help");
  assert.equal(h.status, 0, h.stderr);
  assert.match(h.stdout, /backup/);
  const v = run("--version");
  assert.equal(v.status, 0, v.stderr);
  assert.equal(v.stdout.trim(), "0.3.0");
});
test("unknown commands and flags return JSON errors without echoing argv", () => {
  for (const args of [
    ["backup", "run"],
    ["--bad-secret-argument"],
    ["audit", "list", "--limit", "201"],
  ]) {
    const r = run("--json", ...args);
    assert.equal(r.status, 2);
    const e = JSON.parse(r.stdout);
    assert.equal(e.ok, false);
    assert.equal(e.error.exitCode, 2);
    assert.ok(!r.stderr.includes("bad-secret"));
  }
});
test("every supported command has help; destructive restore/export/delete stay absent", () => {
  for (const args of [
    ["profile"],
    ["auth"],
    ["doctor"],
    ["status"],
    ["devices", "list"],
    ["devices", "show"],
    ["devices", "rename"],
    ["devices", "revoke-trust"],
    ["devices", "remove"],
    ["invites", "list"],
    ["invites", "create"],
    ["invites", "revoke"],
    ["ops", "status"],
    ["ops", "execute"],
    ["ops", "cancel"],
    ["backup", "run"],
    ["backup", "remote", "download"],
    ["backup", "remote", "verify"],
    ["users", "show"],
    ["audit", "settings", "show"],
    ["auth", "ensure"],
    ["auth", "logout"],
    ["whoami"],
    ["backup", "destinations"],
    ["backup", "status"],
    ["backup", "remote"],
    ["users"],
    ["audit"],
  ]) {
    const r = run(...args, "--help");
    assert.equal(r.status, 0, r.stderr);
  }
  const r = run("backup", "--help");
  assert.doesNotMatch(r.stdout, /restore|export|delete/);
});

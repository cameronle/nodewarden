import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";

test(
  "CLI invitation request needs Web approval, saves private output, reads back and revokes only chosen invite",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-invites-")));
    try {
      const config = join(dir, "cli");
      await cli(config, [
        "profile",
        "add",
        "test",
        "--server",
        f.url,
        "--allow-loopback-http",
      ]);
      await cli(
        config,
        ["auth", "ensure", "--credentials-stdin"],
        `user.${f.ids.admin}\n${f.secret}\n`,
      );
      const store = new Store(config),
        p = await store.profile(),
        session = await store.session(p),
        output = join(dir, "invite.json");
      assert.equal((await cli(config, ["invites", "list"])).code, 0);
      assert.equal(
        (
          await cli(config, [
            "invites",
            "create",
            "--expires",
            "24h",
            "--output",
            output,
            "--dry-run",
          ])
        ).code,
        0,
      );
      assert.equal(
        (await f.db.prepare("SELECT count(*) n FROM ops_requests").first()).n,
        0,
      );
      const pending = await cli(config, [
        "invites",
        "create",
        "--expires",
        "24h",
        "--output",
        output,
        "--yes",
      ]);
      assert.equal(pending.code, 0, pending.stdout);
      assert.equal(pending.data.data.state, "pending");
      const id = pending.data.data.id;
      assert.equal(
        (await cli(config, ["ops", "execute", id, "--yes"])).code,
        6,
      );
      const approve = async (id: string) => {
        const r = await fetch(f.url + `/api/ops/requests/${id}/approve`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${session.token}`,
            "Content-Type": "application/json",
            Origin: f.url,
          },
          body: JSON.stringify({
            approve: true,
            masterPasswordHash: "fixture-password-hash",
          }),
        });
        assert.equal(r.status, 200, await r.text());
      };
      await approve(id);
      assert.equal(
        (await cli(config, ["ops", "status", id])).data.data.state,
        "approved",
      );
      const result = await cli(config, ["ops", "execute", id, "--yes"]);
      assert.equal(result.code, 0, result.stdout);
      assert.equal(result.data.data.verified, true);
      const saved = JSON.parse(await readFile(output, "utf8"));
      assert.match(saved.inviteLink, /\?invite=/);
      assert.equal((await stat(output)).mode & 0o777, 0o600);
      assert.ok(!result.stdout.includes(saved.code));
      const listed = await cli(config, ["invites", "list"]);
      assert.equal(listed.data.data.count, 1);
      assert.ok(!listed.stdout.includes(saved.code));
      const revoke = await cli(config, [
        "invites",
        "revoke",
        listed.data.data.items[0].id,
        "--yes",
      ]);
      assert.equal(revoke.code, 0, revoke.stdout);
      await approve(revoke.data.data.id);
      assert.equal(
        (await cli(config, ["ops", "execute", revoke.data.data.id, "--yes"]))
          .code,
        0,
      );
      assert.equal((await cli(config, ["invites", "list"])).data.data.count, 0);
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

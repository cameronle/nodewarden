import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
const { unzipSync } = createRequire(import.meta.url)("fflate");
test(
  "fresh instance export requires Web approval, is private and contains original encrypted attachments",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-export-")));
    try {
      const cipher = randomUUID(),
        attachment = randomUUID(),
        bytes = Buffer.from("fixture-original-encrypted-attachment");
      await f.db
        .prepare(
          "INSERT INTO ciphers(id,user_id,type,name,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        )
        .bind(
          cipher,
          f.ids.admin,
          1,
          "2.fixture-encrypted-name",
          "{}",
          new Date().toISOString(),
          new Date().toISOString(),
        )
        .run();
      await f.db
        .prepare(
          "INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES(?,?,?,?,?,?)",
        )
        .bind(
          attachment,
          cipher,
          "2.fixture-encrypted-filename",
          bytes.length,
          "1 KB",
          "2.fixture-encrypted-attachment-key",
        )
        .run();
      await f.r2.put(cipher + "/" + attachment, bytes);
      const config = join(dir, "cli"),
        output = join(dir, "complete.zip");
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
      const s = new Store(config),
        p = await s.profile(),
        session = await s.session(p),
        before = await f.snapshot();
      const dry = await cli(config, [
        "backup",
        "export",
        "--include-attachments",
        "--output",
        output,
        "--dry-run",
      ]);
      assert.equal(dry.code, 0, dry.stdout);
      assert.equal(dry.data.data.dryRun, true);
      const req = await cli(config, [
        "backup",
        "export",
        "--include-attachments",
        "--output",
        output,
        "--yes",
      ]);
      assert.equal(req.code, 0, req.stdout);
      assert.equal(req.data.data.action, "backup.export");
      const id = req.data.data.id;
      const denied = await cli(config, ["ops", "execute", id, "--yes"]);
      assert.notEqual(denied.code, 0);
      await assert.rejects(stat(output), { code: "ENOENT" });
      const approved = await fetch(f.url + `/api/ops/requests/${id}/approve`, {
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
      assert.equal(approved.status, 200, await approved.text());
      const done = await cli(config, ["ops", "execute", id, "--yes"]);
      assert.equal(done.code, 0, done.stdout);
      const archive = await readFile(output),
        files = unzipSync(archive),
        data = JSON.parse(Buffer.from(files["db.json"]).toString()),
        manifest = JSON.parse(Buffer.from(files["manifest.json"]).toString());
      assert.deepEqual(
        Buffer.from(files[`attachments/${cipher}/${attachment}.bin`]),
        bytes,
      );
      assert.equal(manifest.includes.attachments, true);
      assert.equal(manifest.tableCounts.attachments, 1);
      assert.equal(data.ciphers[0].name, "2.fixture-encrypted-name");
      assert.ok(data.users.every((u: any) => !Object.hasOwn(u, "api_key")));
      for (const table of [
        "devices",
        "refresh_tokens",
        "auth_requests",
        "trusted_two_factor_device_tokens",
      ])
        assert.equal(data[table], undefined);
      assert.equal((await stat(output)).mode & 0o777, 0o600);
      assert.equal(
        done.data.data.sha256,
        createHash("sha256").update(archive).digest("hex"),
      );
      assert.equal(done.data.data.localReadbackVerified, true);
      assert.equal(done.data.data.recoverabilityVerified, false);
      assert.deepEqual(await f.snapshot(), before);
      assert.notEqual(
        (await cli(config, ["ops", "execute", id, "--yes"])).code,
        0,
      );
      assert.deepEqual(await readFile(output), archive);
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test(
  "missing encrypted source blob fails export stream without publishing a partial archive",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-missing-"))),
      config = join(dir, "config"),
      output = join(dir, "missing.zip");
    try {
      const now = new Date().toISOString();
      await f.db
        .prepare(
          "INSERT INTO ciphers(id,user_id,type,name,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        )
        .bind(
          "missing-cipher",
          f.ids.admin,
          1,
          "fixture-encrypted-name",
          "{}",
          now,
          now,
        )
        .run();
      await f.db
        .prepare(
          "INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES(?,?,?,?,?,?)",
        )
        .bind(
          "missing-attachment",
          "missing-cipher",
          "fixture-encrypted-name",
          4,
          "4B",
          "fixture-wrapped-key",
        )
        .run();
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
      const s = new Store(config),
        p = await s.profile(),
        session = await s.session(p),
        before = await f.snapshot();
      const req = await cli(config, [
        "backup",
        "export",
        "--include-attachments",
        "--output",
        output,
        "--yes",
      ]);
      assert.equal(req.code, 0, req.stdout);
      const approved = await fetch(
        f.url + `/api/ops/requests/${req.data.data.id}/approve`,
        {
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
        },
      );
      assert.equal(approved.status, 200, await approved.text());
      assert.notEqual(
        (await cli(config, ["ops", "execute", req.data.data.id, "--yes"])).code,
        0,
      );
      await assert.rejects(stat(output), { code: "ENOENT" });
      const state = (await f.db
        .prepare("SELECT state FROM ops_requests WHERE id=?")
        .bind(req.data.data.id)
        .first()) as any;
      assert.equal(state.state, "failed");
      assert.deepEqual(await f.snapshot(), before);
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
const run = promisify(execFile);
test(
  "repeatable isolated restore drill exercises actual importer and reads back ciphertext/blob hashes",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-drill-"))),
      config = join(dir, "config"),
      archive = join(dir, "source.zip"),
      report = join(dir, "report.json");
    try {
      const now = new Date().toISOString();
      await f.db
        .prepare(
          "INSERT INTO ciphers(id,user_id,type,name,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        )
        .bind(
          "drill-cipher",
          f.ids.admin,
          1,
          "fixture-ciphertext-name",
          '{"fixture":"encrypted-ciphertext"}',
          now,
          now,
        )
        .run();
      await f.db
        .prepare(
          "INSERT INTO attachments(id,cipher_id,file_name,size,size_name,key) VALUES(?,?,?,?,?,?)",
        )
        .bind(
          "drill-attachment",
          "drill-cipher",
          "fixture-encrypted-name",
          4,
          "4B",
          "fixture-wrapped-attachment-key",
        )
        .run();
      await f.r2.put(
        "drill-cipher/drill-attachment",
        new Uint8Array([1, 2, 3, 4]),
      );
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
        s = await store.session(p),
        req = await cli(config, [
          "backup",
          "export",
          "--output",
          archive,
          "--include-attachments",
          "--yes",
        ]);
      assert.equal(req.code, 0, req.stdout);
      const approval = await fetch(
        f.url + `/api/ops/requests/${req.data.data.id}/approve`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${s.token}`,
            Origin: f.url,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            approve: true,
            masterPasswordHash: "fixture-password-hash",
          }),
        },
      );
      assert.equal(approval.status, 200, await approval.text());
      assert.equal(
        (await cli(config, ["ops", "execute", req.data.data.id, "--yes"])).code,
        0,
      );
      const before = await f.snapshot(),
        input = await readFile(archive);
      const result = await run(
        process.execPath,
        [
          "--import",
          "tsx",
          "scripts/restore-drill.ts",
          "--file",
          archive,
          "--report",
          report,
        ],
        { env: process.env },
      );
      assert.ok(result.stdout.includes('"restoreVerified":true'));
      assert.ok(!result.stdout.includes("fixture-ciphertext-name"));
      const body = JSON.parse(await readFile(report, "utf8"));
      assert.equal(body.restoreVerified, true);
      assert.equal(body.isolated, true);
      assert.equal(body.ciphertextVerified, true);
      assert.equal(body.attachmentHashesVerified, true);
      assert.equal(body.counts.ciphers, 1);
      assert.equal(body.counts.attachments, 1);
      assert.equal(body.productionWriteExecuted, false);
      assert.equal(body.apiKeysRestored, false);
      assert.equal((await stat(report)).mode & 0o777, 0o600);
      assert.deepEqual(await f.snapshot(), before);
      assert.deepEqual(await readFile(archive), input);
      assert.deepEqual(
        new Uint8Array(
          await (await f.r2.get("drill-cipher/drill-attachment")).arrayBuffer(),
        ),
        new Uint8Array([1, 2, 3, 4]),
      );
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

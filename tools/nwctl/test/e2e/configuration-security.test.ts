import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { workerFixture } from "../helpers/worker-fixture.js";
const servicePath = "../../../../src/services/ops-configuration.js";
const { configurationTarget } = await import(servicePath);
async function fixture() {
  const f = await workerFixture();
  const r = await fetch(f.url + "/identity/connect/token", {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "api",
      client_id: "user." + f.ids.admin,
      client_secret: f.secret,
      deviceIdentifier: crypto.randomUUID(),
      deviceName: "Security fixture",
      deviceType: "8",
    }),
  });
  const token = ((await r.json()) as any).access_token;
  const call = (path: string, body?: unknown) =>
    fetch(f.url + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        Authorization: "Bearer" + " " + token,
        ...(body === undefined
          ? {}
          : { Origin: f.url, "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const op = async (
    action: string,
    parameters: unknown,
    credentials?: unknown,
  ) => {
    const proof = randomBytes(32).toString("hex");
    const r = await call("/api/ops/requests", {
      action,
      parameters,
      proofHash: createHash("sha256").update(proof).digest("hex"),
      ...(credentials ? { credentials } : {}),
    });
    assert.equal(r.status, 201, await r.clone().text());
    const o = (await r.json()) as any;
    return { ...o, proof };
  };
  const approve = async (id: string) => {
    const r = await call(`/api/ops/requests/${id}/approve`, {
      approve: true,
      masterPasswordHash: "fixture-password-hash",
    });
    assert.equal(r.status, 200, await r.clone().text());
  };
  return {
    f,
    call,
    op,
    approve,
    env: { DB: f.db, JWT_SECRET: f.jwt },
    actor: { id: f.ids.admin, role: "admin", status: "active" },
  };
}
test(
  "S3 credentials can be added and rotated without altering DAV; row cap mode uses the Web policy contract",
  { timeout: 120000 },
  async () => {
    const { f, call, op, approve } = await fixture();
    try {
      const before = (await (
        await call("/api/ops/config/backup")
      ).json()) as any;
      const add = await op(
        "backup.configure",
        {
          expectedRevision: before.revision,
          mutation: "add",
          destinationId: "s3-new",
          change: {
            type: "s3",
            name: "S3 target",
            includeAttachments: true,
            destination: {
              endpoint: "https://s3new.example",
              bucket: "nw-test",
              addressingStyle: "virtual-hosted-style",
              region: "auto",
              rootPath: "backups",
            },
            schedule: {
              enabled: false,
              intervalHours: 24,
              retentionCount: null,
            },
          },
          credentialFields: ["accessKeyId", "secretAccessKey"],
        },
        { accessKeyId: "s3-fixture-key", secretAccessKey: "s3-fixture-secret" },
      );
      await approve(add.id);
      assert.equal(
        (
          await call(`/api/ops/requests/${add.id}/execute`, {
            proof: add.proof,
          })
        ).status,
        200,
      );
      const next = (await (await call("/api/ops/config/backup")).json()) as any;
      assert.deepEqual(
        next.destinations.find((v: any) => v.id === "dav"),
        before.destinations.find((v: any) => v.id === "dav"),
      );
      const rotate = await op(
        "backup.configure",
        {
          expectedRevision: next.revision,
          mutation: "update",
          destinationId: "s3-new",
          change: { name: "Rotated target" },
          credentialFields: ["secretAccessKey"],
        },
        { secretAccessKey: "s3-fixture-rotated" },
      );
      await approve(rotate.id);
      assert.equal(
        (
          await call(`/api/ops/requests/${rotate.id}/execute`, {
            proof: rotate.proof,
          })
        ).status,
        200,
      );
      assert.ok(
        !(await (await call("/api/ops/config/backup")).text()).includes(
          "s3-fixture",
        ),
      );
      const batches = [];
      for (let i = 0; i < 1005; i++)
        batches.push(
          f.db
            .prepare(
              "INSERT INTO audit_logs(id,action,category,level,metadata,created_at) VALUES (?,'fixture.cap','system','info','{}',?)",
            )
            .bind(
              "cap-" + String(i).padStart(4, "0"),
              new Date(Date.now() - 86400000 + i).toISOString(),
            ),
        );
      await f.db.batch(batches);
      const audit = (await (await call("/api/ops/config/audit")).json()) as any;
      const cap = await op("audit.configure", {
        expectedRevision: audit.revision,
        retentionDays: null,
        maxEntries: 1000,
      });
      await approve(cap.id);
      assert.equal(
        (
          await call(`/api/ops/requests/${cap.id}/execute`, {
            proof: cap.proof,
          })
        ).status,
        200,
      );
      assert.equal(
        await f.db
          .prepare("SELECT id FROM audit_logs WHERE id='cap-0000'")
          .first(),
        null,
      );
      assert.ok(
        await f.db
          .prepare("SELECT id FROM audit_logs WHERE id='cap-1004'")
          .first(),
      );
      const policy = (await (
        await call("/api/ops/config/audit")
      ).json()) as any;
      assert.equal(policy.maxEntries, 1000);
      assert.equal(policy.retentionDays, null);
      const count = (
        (await f.db.prepare("SELECT count(*) n FROM audit_logs").first()) as any
      ).n;
      assert.ok(
        count >= 1000 && count <= 1002,
        "policy cap plus its newly-written audit trail",
      );
    } finally {
      await f.close();
    }
  },
);

test(
  "audit clear removes only reviewed IDs and retains later events plus its own audit trail",
  { timeout: 120000 },
  async () => {
    const { f, call, op, approve } = await fixture();
    try {
      const meta = (await (
        await call("/api/ops/config/audit-clear")
      ).json()) as any;
      const created = await op("audit.clear", {
        expectedRevision: meta.revision,
        throughRowId: meta.throughRowId,
      });
      assert.match(created.summary.effect, /IRREVERSIBLE/);
      await approve(created.id);
      const newer = (
        await f.db
          .prepare("SELECT id FROM audit_logs WHERE rowid>?")
          .bind(meta.throughRowId)
          .all()
      ).results;
      assert.ok(newer.length > 0);
      const result = await call(`/api/ops/requests/${created.id}/execute`, {
        proof: created.proof,
      });
      assert.equal(result.status, 200, await result.clone().text());
      assert.equal(((await result.json()) as any).deleted, meta.count);
      assert.equal(
        (
          (await f.db
            .prepare("SELECT count(*) n FROM audit_logs WHERE rowid<=?")
            .bind(meta.throughRowId)
            .first()) as any
        ).n,
        0,
      );
      for (const row of newer)
        assert.ok(
          await f.db
            .prepare("SELECT id FROM audit_logs WHERE id=?")
            .bind(row.id)
            .first(),
        );
      assert.ok(
        await f.db
          .prepare(
            "SELECT id FROM audit_logs WHERE action='audit.logs.cleared'",
          )
          .first(),
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "audit CAS failure cannot prune logs even when concurrent writer saved identical requested policy",
  { timeout: 120000 },
  async () => {
    const { f, call, op, approve, env, actor } = await fixture();
    try {
      await f.db
        .prepare(
          "INSERT INTO audit_logs(id,action,category,level,metadata,created_at) VALUES ('very-old','fixture','system','info','{}',?)",
        )
        .bind(new Date(Date.now() - 30 * 86400000).toISOString())
        .run();
      const meta = (await (await call("/api/ops/config/audit")).json()) as any;
      const p = {
        expectedRevision: meta.revision,
        retentionDays: 7,
        maxEntries: null,
      };
      const o = await op("audit.configure", p);
      await approve(o.id);
      const plan = await configurationTarget(env, actor, "audit.configure", p);
      await f.db
        .prepare("UPDATE ops_requests SET state='executing' WHERE id=?")
        .bind(o.id)
        .run();
      await f.db
        .prepare(
          "INSERT INTO config(key,value) VALUES ('audit.logs.settings.v1',?)",
        )
        .bind(JSON.stringify({ retentionDays: 7, maxEntries: null }))
        .run();
      await assert.rejects(plan.apply(o.id), (e: any) => e.status === 409);
      assert.ok(
        await f.db
          .prepare("SELECT id FROM audit_logs WHERE id='very-old'")
          .first(),
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "exact write rechecks administrator authorization; revoked actor cannot save or prune",
  { timeout: 120000 },
  async () => {
    const { f, call, op, approve, env, actor } = await fixture();
    try {
      const meta = (await (await call("/api/ops/config/audit")).json()) as any;
      const p = {
        expectedRevision: meta.revision,
        retentionDays: null,
        maxEntries: 1000,
      };
      const o = await op("audit.configure", p);
      await approve(o.id);
      const plan = await configurationTarget(env, actor, "audit.configure", p);
      await f.db
        .prepare("UPDATE ops_requests SET state='executing' WHERE id=?")
        .bind(o.id)
        .run();
      await f.db
        .prepare("UPDATE users SET security_stamp='revoked' WHERE id=?")
        .bind(actor.id)
        .run();
      const logs = (
        (await f.db.prepare("SELECT count(*) n FROM audit_logs").first()) as any
      ).n;
      await assert.rejects(plan.apply(o.id), (e: any) => e.status === 409);
      assert.equal(
        (
          (await f.db
            .prepare("SELECT count(*) n FROM audit_logs")
            .first()) as any
        ).n,
        logs,
      );
      assert.equal(
        await f.db
          .prepare(
            "SELECT value FROM config WHERE key='audit.logs.settings.v1'",
          )
          .first(),
        null,
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "configuration validation rejects inline secrets, provider changes, SSRF, whitespace repair and unsupported audit modes",
  { timeout: 120000 },
  async () => {
    const { f, call } = await fixture();
    try {
      const before = await f.snapshot(),
        meta = (await (await call("/api/ops/config/backup")).json()) as any;
      const base = {
        expectedRevision: meta.revision,
        mutation: "update",
        destinationId: "dav",
        change: { name: "Valid" },
        credentialFields: [],
      };
      for (const change of [
        { destination: { password: "secret-in-public" } },
        { type: "s3" },
        { destination: { baseUrl: "https://127.0.0.1" } },
        { schedule: { intervalHours: 100 } },
        { schedule: { timezone: "invalid/timezone" } },
        { name: " padded " },
        { schedule: { startTime: "3:0" } },
      ]) {
        const r = await call("/api/ops/requests", {
          action: "backup.configure",
          parameters: { ...base, change },
          proofHash: "a".repeat(64),
        });
        assert.equal(r.status, 400, await r.clone().text());
      }
      assert.deepEqual(await f.snapshot(), before);
      assert.equal(
        (
          (await f.db
            .prepare("SELECT count(*) n FROM ops_requests")
            .first()) as any
        ).n,
        0,
      );
      assert.equal((await fetch(f.url + "/api/ops/config/backup")).status, 401);
    } finally {
      await f.close();
    }
  },
);
test(
  "transplanted encrypted credential payload fails authentication and cannot be approved",
  { timeout: 120000 },
  async () => {
    const { f, call, op } = await fixture();
    try {
      const meta = (await (await call("/api/ops/config/backup")).json()) as any;
      const p = {
        expectedRevision: meta.revision,
        mutation: "update",
        destinationId: "dav",
        change: { name: "new name" },
        credentialFields: ["password"],
      };
      const a = await op("backup.configure", p, {
          password: "transplant-fixture-A",
        }),
        b = await op("backup.configure", p, {
          password: "transplant-fixture-B",
        });
      const ciphertext = (
        (await f.db
          .prepare("SELECT payload FROM ops_requests WHERE id=?")
          .bind(a.id)
          .first()) as any
      ).payload;
      await f.db
        .prepare("UPDATE ops_requests SET payload=? WHERE id=?")
        .bind(ciphertext, b.id)
        .run();
      const before = await f.snapshot();
      const denied = await call(`/api/ops/requests/${b.id}/approve`, {
        approve: true,
        masterPasswordHash: "fixture-password-hash",
      });
      assert.equal(denied.status, 500);
      assert.deepEqual(await f.snapshot(), before);
      assert.equal(
        (
          (await f.db
            .prepare("SELECT state FROM ops_requests WHERE id=?")
            .bind(b.id)
            .first()) as any
        ).state,
        "pending",
      );
    } finally {
      await f.close();
    }
  },
);

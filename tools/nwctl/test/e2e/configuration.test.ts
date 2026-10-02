import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { workerFixture } from "../helpers/worker-fixture.js";
import { cli } from "../helpers/cli.js";
import { Store } from "../../src/config.js";
import {
  mkdtemp,
  realpath,
  rm,
  writeFile,
  readFile,
  chmod,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
const cryptoModule = "../../../../src/services/backup-settings-crypto.js";
const { decryptBackupSettingsRuntime } = await import(cryptoModule);
async function setup() {
  const f = await workerFixture();
  const login = await fetch(f.url + "/identity/connect/token", {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "api",
      client_id: "user." + f.ids.admin,
      client_secret: f.secret,
      deviceIdentifier: crypto.randomUUID(),
      deviceName: "config fixture",
      deviceType: "8",
    }),
  });
  assert.equal(login.status, 200);
  const token = ((await login.json()) as any).access_token;
  const call = async (path: string, body?: unknown) =>
    fetch(f.url + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        Authorization: "Bearer" + " " + token,
        ...(body === undefined
          ? {}
          : { "Content-Type": "application/json", Origin: f.url }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const make = async (
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
    return { proof, ...((await r.json()) as any) };
  };
  const approve = async (id: string) => {
    const r = await call(`/api/ops/requests/${id}/approve`, {
      approve: true,
      masterPasswordHash: "fixture-password-hash",
    });
    assert.equal(r.status, 200, await r.clone().text());
  };
  return { f, call, make, approve };
}
test(
  "backup configuration changes only the selected schedule after Web approval, preserves credentials and runtime",
  { timeout: 120000 },
  async () => {
    const { f, call, make, approve } = await setup();
    try {
      const before = await f.snapshot();
      const metaResponse = await call("/api/ops/config/backup");
      assert.equal(
        metaResponse.status,
        200,
        "safe backup configuration metadata route must exist",
      );
      const meta = (await metaResponse.json()) as any;
      assert.ok(!JSON.stringify(meta).includes("fixture-dav-password"));
      assert.ok(!JSON.stringify(meta).includes("fixture-s3-key"));
      const op = await make("backup.configure", {
        expectedRevision: meta.revision,
        mutation: "update",
        destinationId: "dav",
        change: {
          schedule: {
            intervalHours: 12,
            timezone: "Asia/Shanghai",
            retentionCount: 7,
          },
        },
        credentialFields: [],
      });
      assert.deepEqual(
        await f.snapshot(),
        before,
        "creating a request must not change business data",
      );
      assert.equal(
        (await call(`/api/ops/requests/${op.id}/execute`, { proof: op.proof }))
          .status,
        409,
      );
      await approve(op.id);
      const done = await call(`/api/ops/requests/${op.id}/execute`, {
        proof: op.proof,
      });
      assert.equal(done.status, 200, await done.clone().text());
      const after = (await (
        await call("/api/ops/config/backup")
      ).json()) as any;
      assert.equal(
        after.destinations.find((v: any) => v.id === "dav").schedule
          .intervalHours,
        12,
      );
      assert.deepEqual(
        after.destinations.find((v: any) => v.id === "s3"),
        meta.destinations.find((v: any) => v.id === "s3"),
      );
      const snap = await f.snapshot();
      assert.deepEqual(
        (snap.backup as any[]).filter(
          (v: any) => v.key === "backup.runtime.v1",
        ),
        (before.backup as any[]).filter(
          (v: any) => v.key === "backup.runtime.v1",
        ),
      );
      assert.deepEqual(snap.r2, before.r2);
      assert.deepEqual(snap.users, before.users);
      assert.equal(
        (await call(`/api/ops/requests/${op.id}/execute`, { proof: op.proof }))
          .status,
        409,
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "new provider credentials are encrypted at rest, omitted from Web view and discarded on success/deny/cancel",
  { timeout: 120000 },
  async () => {
    const { f, call, make, approve } = await setup();
    try {
      const meta = (await (await call("/api/ops/config/backup")).json()) as any;
      const parameters = {
        expectedRevision: meta.revision,
        mutation: "add",
        destinationId: "new-dav",
        change: {
          type: "webdav",
          name: "New DAV",
          includeAttachments: false,
          destination: { baseUrl: "https://newdav.example", remotePath: "nw" },
          schedule: { enabled: false },
        },
        credentialFields: ["password", "username"],
      };
      const secrets = {
        password: "new-fixture-PASS-value",
        username: "new-fixture-USERNAME-value",
      };
      const op = await make("backup.configure", parameters, secrets);
      assert.ok(!JSON.stringify(op).includes(secrets.password));
      assert.ok(!JSON.stringify(op).includes(secrets.username));
      const row = (await f.db
        .prepare("SELECT * FROM ops_requests WHERE id=?")
        .bind(op.id)
        .first()) as any;
      assert.ok(row.payload);
      assert.ok(!JSON.stringify(row).includes(secrets.password));
      assert.ok(!JSON.stringify(row).includes(secrets.username));
      const web = await (await call("/api/ops/requests/" + op.id)).text();
      assert.ok(!web.includes(secrets.password));
      assert.ok(!web.includes(secrets.username));
      await approve(op.id);
      assert.equal(
        (await call(`/api/ops/requests/${op.id}/execute`, { proof: op.proof }))
          .status,
        200,
      );
      assert.equal(
        (
          (await f.db
            .prepare("SELECT payload FROM ops_requests WHERE id=?")
            .bind(op.id)
            .first()) as any
        ).payload,
        null,
      );
      const raw = (
        (await f.db
          .prepare("SELECT value FROM config WHERE key='backup.settings.v1'")
          .first()) as any
      ).value;
      const settings = JSON.parse(
        await decryptBackupSettingsRuntime(raw, { JWT_SECRET: f.jwt } as any),
      );
      assert.equal(
        settings.destinations.find((d: any) => d.id === "new-dav").destination
          .password,
        secrets.password,
      );
      assert.equal(
        settings.destinations.find((d: any) => d.id === "dav").destination
          .password,
        "fixture-dav-password",
      );
      const next = (await (await call("/api/ops/config/backup")).json()) as any;
      const pending = await make(
        "backup.configure",
        {
          ...parameters,
          expectedRevision: next.revision,
          destinationId: "denied-dav",
        },
        secrets,
      );
      assert.equal(
        (
          await call(`/api/ops/requests/${pending.id}/approve`, {
            approve: false,
            masterPasswordHash: "",
          })
        ).status,
        200,
      );
      assert.equal(
        (
          (await f.db
            .prepare("SELECT payload FROM ops_requests WHERE id=?")
            .bind(pending.id)
            .first()) as any
        ).payload,
        null,
      );
      const cancel = await make(
        "backup.configure",
        {
          ...parameters,
          expectedRevision: next.revision,
          destinationId: "cancel-dav",
        },
        secrets,
      );
      assert.equal(
        (
          await call(`/api/ops/requests/${cancel.id}/cancel`, {
            proof: cancel.proof,
          })
        ).status,
        200,
      );
      assert.equal(
        (
          (await f.db
            .prepare("SELECT payload FROM ops_requests WHERE id=?")
            .bind(cancel.id)
            .first()) as any
        ).payload,
        null,
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "stale configuration is rejected at both approval and execution; runtime updates are preserved",
  { timeout: 120000 },
  async () => {
    const { f, call, make, approve } = await setup();
    try {
      const meta = (await (await call("/api/ops/config/backup")).json()) as any;
      const p = {
        expectedRevision: meta.revision,
        mutation: "update",
        destinationId: "dav",
        change: { name: "Renamed DAV" },
        credentialFields: [],
      };
      const stale = await make("backup.configure", p);
      const chosen = await make("backup.configure", {
        ...p,
        change: { schedule: { enabled: false } },
      });
      await approve(chosen.id);
      // Runtime changes do not invalidate or get overwritten by configuration-only writes.
      await f.db
        .prepare("UPDATE config SET value=? WHERE key='backup.runtime.v1'")
        .bind(
          JSON.stringify({
            version: 1,
            destinations: {
              dav: {
                lastUploadedFileName: "latest.zip",
                lastSuccessAt: new Date().toISOString(),
              },
            },
          }),
        )
        .run();
      const runtime = (
        (await f.db
          .prepare("SELECT value FROM config WHERE key='backup.runtime.v1'")
          .first()) as any
      ).value;
      assert.equal(
        (
          await call(`/api/ops/requests/${chosen.id}/execute`, {
            proof: chosen.proof,
          })
        ).status,
        200,
      );
      assert.equal(
        (
          (await f.db
            .prepare("SELECT value FROM config WHERE key='backup.runtime.v1'")
            .first()) as any
        ).value,
        runtime,
      );
      assert.equal(
        (
          await call(`/api/ops/requests/${stale.id}/approve`, {
            approve: true,
            masterPasswordHash: "fixture-password-hash",
          })
        ).status,
        409,
      );
      const next = (await (await call("/api/ops/config/backup")).json()) as any;
      const a = await make("backup.configure", {
        ...p,
        expectedRevision: next.revision,
      });
      await approve(a.id);
      const b = await make("backup.configure", {
        ...p,
        expectedRevision: next.revision,
        change: { name: "Another name" },
      });
      await approve(b.id);
      const both = await Promise.all(
        [a, b].map((o) =>
          call(`/api/ops/requests/${o.id}/execute`, { proof: o.proof }),
        ),
      );
      assert.deepEqual(both.map((r) => r.status).sort(), [200, 409]);
    } finally {
      await f.close();
    }
  },
);
test(
  "audit policy is strict, requires approval and immediately prunes only outside the selected retention",
  { timeout: 120000 },
  async () => {
    const { f, call, make, approve } = await setup();
    try {
      await f.db
        .prepare(
          "INSERT INTO audit_logs(id,action,category,level,metadata,created_at) VALUES ('old-log','fixture','system','info','{}',?)",
        )
        .bind(new Date(Date.now() - 30 * 86400000).toISOString())
        .run();
      const meta = (await (await call("/api/ops/config/audit")).json()) as any;
      const invalid = await call("/api/ops/requests", {
        action: "audit.configure",
        parameters: {
          expectedRevision: meta.revision,
          retentionDays: 8,
          maxEntries: null,
        },
        proofHash: "a".repeat(64),
      });
      assert.equal(invalid.status, 400);
      const op = await make("audit.configure", {
        expectedRevision: meta.revision,
        retentionDays: 7,
        maxEntries: null,
      });
      assert.match(op.summary.effect, /IMMEDIATELY/);
      assert.ok(
        await f.db
          .prepare("SELECT id FROM audit_logs WHERE id='old-log'")
          .first(),
      );
      await approve(op.id);
      const response = await call(`/api/ops/requests/${op.id}/execute`, {
        proof: op.proof,
      });
      assert.equal(response.status, 200, await response.clone().text());
      assert.equal(
        await f.db
          .prepare("SELECT id FROM audit_logs WHERE id='old-log'")
          .first(),
        null,
      );
      const after = (await (await call("/api/ops/config/audit")).json()) as any;
      assert.equal(after.retentionDays, 7);
      assert.equal(after.maxEntries, null);
      assert.ok(
        (
          (await f.db
            .prepare("SELECT count(*) n FROM audit_logs")
            .first()) as any
        ).n > 0,
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "user ban/unban protects self, invalidates old sessions, and never touches vault ciphertext or attachment blobs",
  { timeout: 120000 },
  async () => {
    const { f, call, make, approve } = await setup();
    try {
      const before = await f.snapshot();
      const own = (await (
        await call("/api/ops/config/user/" + f.ids.admin)
      ).json()) as any;
      assert.equal(
        (
          await call("/api/ops/requests", {
            action: "user.status",
            parameters: {
              expectedRevision: own.revision,
              userId: f.ids.admin,
              status: "banned",
            },
            proofHash: "a".repeat(64),
          })
        ).status,
        400,
      );
      const login = await fetch(f.url + "/identity/connect/token", {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "client_credentials",
          scope: "api",
          client_id: "user." + f.ids.user,
          client_secret: f.secret,
          deviceIdentifier: crypto.randomUUID(),
          deviceName: "old user",
          deviceType: "8",
        }),
      });
      assert.equal(login.status, 200);
      const token = ((await login.json()) as any).access_token;
      const oldAccess = () =>
        fetch(f.url + "/api/accounts/profile", {
          headers: { Authorization: `Bearer ${token}` },
        });
      assert.equal((await oldAccess()).status, 200);
      const u = (await (
        await call("/api/ops/config/user/" + f.ids.user)
      ).json()) as any;
      const ban = await make("user.status", {
        expectedRevision: u.revision,
        userId: f.ids.user,
        status: "banned",
      });
      await approve(ban.id);
      assert.equal(
        (
          await call(`/api/ops/requests/${ban.id}/execute`, {
            proof: ban.proof,
          })
        ).status,
        200,
      );
      assert.equal((await oldAccess()).status, 401);
      const banned = (await (
        await call("/api/ops/config/user/" + f.ids.user)
      ).json()) as any;
      assert.equal(banned.status, "banned");
      const unban = await make("user.status", {
        expectedRevision: banned.revision,
        userId: f.ids.user,
        status: "active",
      });
      await approve(unban.id);
      assert.equal(
        (
          await call(`/api/ops/requests/${unban.id}/execute`, {
            proof: unban.proof,
          })
        ).status,
        200,
      );
      assert.equal((await oldAccess()).status, 401);
      const after = await f.snapshot();
      for (const k of [
        "ciphers",
        "folders",
        "attachments",
        "sends",
        "r2",
        "backup",
      ])
        assert.deepEqual(after[k], before[k]);
      assert.deepEqual(
        (after.users as any[]).filter((v: any) => v.id !== f.ids.user),
        (before.users as any[]).filter((v: any) => v.id !== f.ids.user),
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "real CLI private-file backup CRUD, dry-run, audit policy and user status are browser-approved with exact read-back",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture(),
      dir = await realpath(await mkdtemp(join(tmpdir(), "nw-config-")));
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
        session = await store.session(await store.profile());
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
        assert.equal(r.status, 200, await r.clone().text());
      };
      const file = join(dir, "new-dav.json");
      const credentials = {
        username: "CLI-fixture-USERNAME",
        password: "CLI-fixture-PASSWORD",
      };
      await writeFile(
        file,
        JSON.stringify({
          change: {
            type: "webdav",
            name: "CLI DAV",
            destination: { baseUrl: "https://clidav.example" },
            schedule: { enabled: false },
          },
          credentials,
        }),
        { mode: 0o600 },
      );
      const before = await f.snapshot();
      const dry = await cli(config, [
        "backup",
        "destinations",
        "add",
        "cli-dav",
        "--file",
        file,
        "--dry-run",
      ]);
      assert.equal(dry.code, 0, dry.stdout);
      assert.ok(!dry.stdout.includes(credentials.password));
      assert.deepEqual(await f.snapshot(), before);
      assert.equal(
        (
          (await f.db
            .prepare("SELECT count(*) n FROM ops_requests")
            .first()) as any
        ).n,
        0,
      );
      await chmod(file, 0o644);
      assert.notEqual(
        (
          await cli(config, [
            "backup",
            "destinations",
            "add",
            "cli-dav",
            "--file",
            file,
            "--yes",
          ])
        ).code,
        0,
      );
      await chmod(file, 0o600);
      const link = join(dir, "unsafe.json");
      await symlink(file, link);
      assert.notEqual(
        (
          await cli(config, [
            "backup",
            "destinations",
            "add",
            "cli-dav",
            "--file",
            link,
            "--yes",
          ])
        ).code,
        0,
      );
      const add = await cli(config, [
        "backup",
        "destinations",
        "add",
        "cli-dav",
        "--file",
        file,
        "--yes",
      ]);
      assert.equal(add.code, 0, add.stdout);
      assert.equal(add.data.data.state, "pending");
      assert.ok(!add.stdout.includes(credentials.password));
      const local = JSON.stringify(await store.operation(add.data.data.id));
      assert.ok(!local.includes(credentials.password));
      assert.ok(!local.includes(credentials.username));
      await approve(add.data.data.id);
      const exec = await cli(config, [
        "ops",
        "execute",
        add.data.data.id,
        "--yes",
      ]);
      assert.equal(exec.code, 0, exec.stdout);
      assert.equal(exec.data.data.verified, true);
      const schedule = await cli(config, [
        "backup",
        "schedule",
        "set",
        "cli-dav",
        "--interval-hours",
        "12",
        "--enabled",
        "true",
        "--timezone",
        "Asia/Shanghai",
        "--retention",
        "7",
        "--yes",
      ]);
      assert.equal(schedule.code, 0, schedule.stdout);
      await approve(schedule.data.data.id);
      assert.equal(
        (await cli(config, ["ops", "execute", schedule.data.data.id, "--yes"]))
          .code,
        0,
      );
      const rmOp = await cli(config, [
        "backup",
        "destinations",
        "remove",
        "cli-dav",
        "--yes",
      ]);
      assert.equal(rmOp.code, 0, rmOp.stdout);
      await approve(rmOp.data.data.id);
      assert.equal(
        (await cli(config, ["ops", "execute", rmOp.data.data.id, "--yes"])).data
          .data.verified,
        true,
      );
      const clear = await cli(config, ["audit", "clear", "--dry-run"]);
      assert.equal(clear.code, 0, clear.stdout);
      const policy = await cli(config, [
        "audit",
        "settings",
        "set",
        "--retention-days",
        "30",
        "--yes",
      ]);
      assert.equal(policy.code, 0, policy.stdout);
      await approve(policy.data.data.id);
      assert.equal(
        (await cli(config, ["ops", "execute", policy.data.data.id, "--yes"]))
          .data.data.verified,
        true,
      );
      for (const command of ["ban", "unban"]) {
        const op = await cli(config, ["users", command, f.ids.user, "--yes"]);
        assert.equal(op.code, 0, op.stdout);
        await approve(op.data.data.id);
        assert.equal(
          (await cli(config, ["ops", "execute", op.data.data.id, "--yes"])).data
            .data.verified,
          true,
        );
      }
    } finally {
      await f.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);

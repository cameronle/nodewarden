import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { workerFixture } from "../helpers/worker-fixture.js";

export const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export async function fixtureLogin(
  f: Awaited<ReturnType<typeof workerFixture>>,
  role: "admin" | "user" = "admin",
  device = crypto.randomUUID(),
) {
  const r = await fetch(f.url + "/identity/connect/token", {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "api",
      client_id: `user.${f.ids[role]}`,
      client_secret: f.secret,
      deviceIdentifier: device,
      deviceName: "test",
      deviceType: "8",
    }),
  });
  assert.equal(r.status, 200);
  return { token: ((await r.json()) as any).access_token, device };
}

test(
  "browser step-up binds action, account, token, proof, origin and expiry; one atomic execution",
  { timeout: 120000 },
  async () => {
    const f = await workerFixture();
    try {
      const actor = await fixtureLogin(f),
        web = await fixtureLogin(f),
        other = await fixtureLogin(f, "user");
      const call = (
        path: string,
        body?: unknown,
        token = actor.token,
        origin?: string,
      ) =>
        fetch(f.url + path, {
          method: body === undefined ? "GET" : "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            ...(body === undefined
              ? {}
              : { "Content-Type": "application/json" }),
            ...(origin ? { Origin: origin } : {}),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
      const proof = randomBytes(32).toString("hex");
      const made = await call("/api/ops/requests", {
        action: "invite.create",
        parameters: { expiresInHours: 24 },
        proofHash: digest(proof),
      });
      assert.equal(made.status, 201, await made.clone().text());
      const request = (await made.json()) as any;
      assert.match(request.approvalUrl, /\/cli-approval\//);
      assert.equal(made.headers.get("Cache-Control"), "no-store");
      assert.equal(
        (await f.db.prepare("SELECT count(*) n FROM invites").first()).n,
        0,
      );
      assert.equal(
        (await call(`/api/ops/requests/${request.id}`, undefined, other.token))
          .status,
        403,
      );
      assert.equal(
        (await call(`/api/ops/requests/${request.id}/execute`, { proof }))
          .status,
        409,
      );
      assert.equal(
        (
          await call(
            `/api/ops/requests/${request.id}/approve`,
            { approve: true, masterPasswordHash: "fixture-password-hash" },
            web.token,
            "https://evil.example",
          )
        ).status,
        403,
      );
      assert.equal(
        (
          await call(
            `/api/ops/requests/${request.id}/approve`,
            { approve: true, masterPasswordHash: "wrong" },
            web.token,
            f.url,
          )
        ).status,
        400,
      );
      assert.equal(
        (
          await call(
            `/api/ops/requests/${request.id}/approve`,
            { approve: true, masterPasswordHash: "fixture-password-hash" },
            web.token,
            f.url,
          )
        ).status,
        200,
      );
      assert.equal(
        (
          await call(`/api/ops/requests/${request.id}/execute`, {
            proof: "0".repeat(64),
          })
        ).status,
        403,
      );
      assert.equal(
        (
          await call(
            `/api/ops/requests/${request.id}/execute`,
            { proof },
            web.token,
          )
        ).status,
        403,
      );
      assert.equal(
        (
          await call(`/api/ops/requests/${request.id}/execute`, {
            proof,
            parameters: { expiresInHours: 720 },
          })
        ).status,
        400,
      );
      const concurrent = await Promise.all([
        call(`/api/ops/requests/${request.id}/execute`, { proof }),
        call(`/api/ops/requests/${request.id}/execute`, { proof }),
      ]);
      assert.deepEqual(concurrent.map((r) => r.status).sort(), [201, 409]);
      assert.equal(
        (await f.db.prepare("SELECT count(*) n FROM invites").first()).n,
        1,
      );
      assert.equal(
        (await call(`/api/ops/requests/${request.id}/status`, { proof }))
          .status,
        200,
      );
      assert.equal(
        ((await (await call(`/api/ops/requests/${request.id}`)).json()) as any)
          .state,
        "succeeded",
      );
      // Wire fields or headers cannot forge the internal, per-request approval capability.
      const forged = await call("/api/admin/invites", {
        expiresInHours: 24,
        approved: true,
        opsApproved: true,
      });
      assert.equal(forged.status, 400);
      const create = async (parameters: unknown = { expiresInHours: 24 }) => {
        const r = await call("/api/ops/requests", {
          action: "invite.create",
          parameters,
          proofHash: digest(proof),
        });
        return { r, data: (await r.json()) as any };
      };
      assert.equal(
        (await create({ expiresInHours: 24, extra: true })).r.status,
        400,
      );
      const expired = (await create()).data;
      await f.db
        .prepare("UPDATE ops_requests SET expires_at = 1 WHERE id = ?")
        .bind(expired.id)
        .run();
      assert.equal(
        (
          await call(
            `/api/ops/requests/${expired.id}/approve`,
            { approve: true, masterPasswordHash: "fixture-password-hash" },
            web.token,
            f.url,
          )
        ).status,
        410,
      );
      const denied = (await create()).data;
      assert.equal(
        (
          await call(
            `/api/ops/requests/${denied.id}/approve`,
            { approve: false, masterPasswordHash: "" },
            web.token,
            f.url,
          )
        ).status,
        200,
      );
      assert.equal(
        (await call(`/api/ops/requests/${denied.id}/execute`, { proof }))
          .status,
        409,
      );
      const cancelled = (await create()).data;
      assert.equal(
        (await call(`/api/ops/requests/${cancelled.id}/cancel`, { proof }))
          .status,
        200,
      );
      assert.equal(
        (
          await call(
            `/api/ops/requests/${cancelled.id}/approve`,
            { approve: true, masterPasswordHash: "fixture-password-hash" },
            web.token,
            f.url,
          )
        ).status,
        409,
      );
      const elapsed = (await create()).data;
      assert.equal(
        (
          await call(
            `/api/ops/requests/${elapsed.id}/approve`,
            { approve: true, masterPasswordHash: "fixture-password-hash" },
            web.token,
          )
        ).status,
        403,
        "missing browser origin",
      );
      assert.equal(
        (
          await call(
            `/api/ops/requests/${elapsed.id}/approve`,
            { approve: true, masterPasswordHash: "fixture-password-hash" },
            web.token,
            f.url,
          )
        ).status,
        200,
      );
      await f.db
        .prepare("UPDATE ops_requests SET expires_at=1 WHERE id=?")
        .bind(elapsed.id)
        .run();
      assert.equal(
        (await call(`/api/ops/requests/${elapsed.id}/execute`, { proof }))
          .status,
        410,
      );
      for (const path of [
        "/api/admin/backup/run",
        "/api/admin/backup/remote/download",
        "/api/admin/backup/remote/integrity",
      ])
        assert.equal(
          (
            await call(path, {
              destinationId: "dav",
              path: "test.zip",
              opsApproved: true,
            })
          ).status,
          400,
        );
      const b = await call("/api/ops/requests", {
        action: "backup.run",
        parameters: { destinationId: "dav" },
        proofHash: digest(proof),
      });
      assert.equal(b.status, 201);
      const changed = (await b.json()) as any;
      assert.equal(
        (
          await call(
            `/api/ops/requests/${changed.id}/approve`,
            { approve: true, masterPasswordHash: "fixture-password-hash" },
            web.token,
            f.url,
          )
        ).status,
        200,
      );
      assert.equal(
        (
          await fetch(f.url + "/__fixture/rename-destination", {
            method: "POST",
          })
        ).status,
        200,
      );
      assert.equal(
        (await call(`/api/ops/requests/${changed.id}/execute`, { proof }))
          .status,
        409,
        "changed destination must invalidate approval",
      );
      const revoked = (await create()).data;
      await f.db
        .prepare("DELETE FROM devices WHERE user_id=? AND device_identifier=?")
        .bind(f.ids.admin, actor.device)
        .run();
      assert.equal(
        (await call(`/api/ops/requests/${revoked.id}/status`, { proof }))
          .status,
        401,
        "must bypass stale auth caches",
      );
    } finally {
      await f.close();
    }
  },
);

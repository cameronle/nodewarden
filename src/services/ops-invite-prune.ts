import type { Env, User } from "../types";
import type { OpsParameters } from "../../shared/ops-schema";
import { StorageService } from "./storage";
import { ConfigurationError } from "./ops-configuration";
import { jsonResponse } from "../utils/response";
const hash = async (value: string) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
const FIELDS =
  "json_object('code',code,'createdBy',created_by,'usedBy',used_by,'expiresAt',expires_at,'status',status,'createdAt',created_at,'updatedAt',updated_at)";
const SNAPSHOT = `SELECT json_group_array(snapshot) AS raw FROM (SELECT ${FIELDS} AS snapshot FROM invites WHERE code IN(SELECT value FROM json_each(?)) ORDER BY code)`;
function eligible(v: any) {
  const expiry = Date.parse(v.expiresAt);
  return (
    ["used", "revoked", "expired"].includes(v.status) ||
    (v.status === "active" && Number.isFinite(expiry) && expiry <= Date.now())
  );
}
async function rows(env: Env) {
  const result = await env.DB.prepare(
    `SELECT ${FIELDS} AS snapshot FROM invites ORDER BY code`,
  ).all<{ snapshot: string }>();
  return Promise.all(
    (result.results || []).map(async (r) => {
      const value = JSON.parse(r.snapshot);
      return {
        raw: r.snapshot,
        value,
        id: await hash(value.code),
        revision: await hash(r.snapshot),
      };
    }),
  );
}
export async function invitePruneMetadata(env: Env) {
  return {
    items: (await rows(env)).map((r) => ({
      id: r.id,
      revision: r.revision,
      status: r.value.status,
      expiresAt: r.value.expiresAt,
      used: !!r.value.usedBy,
      eligible: eligible(r.value),
    })),
  };
}
export async function invitePruneTarget(
  env: Env,
  user: User,
  p: OpsParameters,
  current: string,
) {
  const all = await rows(env),
    selected = p.targets!.map((t) => {
      const row = all.find((r) => r.id === t.id);
      if (!row)
        throw new ConfigurationError(
          404,
          "Reviewed invitation no longer exists",
        );
      if (row.revision !== t.revision || !eligible(row.value))
        throw new ConfigurationError(
          409,
          "Invitation changed or is still valid; create a new review",
        );
      return row;
    });
  const codes = selected.map((r) => r.value.code),
    initial = await env.DB.prepare(SNAPSHOT)
      .bind(JSON.stringify(codes))
      .first<{ raw: string }>();
  if (
    !initial ||
    JSON.parse(initial.raw).length !== selected.length ||
    selected.some((r) => !JSON.parse(initial.raw).includes(r.raw))
  )
    throw new ConfigurationError(409, "Invitations changed during review");
  const creator = await new StorageService(env.DB).getDevice(user.id, current);
  if (!creator)
    throw new ConfigurationError(401, "Creator device is no longer active");
  return {
    summary: {
      targets: selected.map((r) => ({
        id: r.id,
        status: r.value.status,
        expiresAt: r.value.expiresAt,
      })),
      count: selected.length,
      effect:
        "Delete only the reviewed used, revoked or expired invitations. Preserve valid invitations and all invitations created later; no delete-all.",
    },
    fingerprint: await hash(initial.raw),
    async apply(opId: string) {
      const guard = env.DB.prepare(
        `UPDATE ops_requests SET state='applying' WHERE id=? AND state='executing' AND (${SNAPSHOT})=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND security_stamp=? AND status='active' AND role='admin') AND EXISTS(SELECT 1 FROM devices WHERE user_id=? AND device_identifier=? AND session_stamp=? AND banned=0)`,
      ).bind(
        opId,
        JSON.stringify(codes),
        initial.raw,
        user.id,
        user.securityStamp,
        user.id,
        current,
        creator.sessionStamp,
      );
      const results = await env.DB.batch([
        guard,
        env.DB.prepare(
          "DELETE FROM invites WHERE code IN(SELECT value FROM json_each(?)) AND EXISTS(SELECT 1 FROM ops_requests WHERE id=? AND state='applying')",
        ).bind(JSON.stringify(codes), opId),
        env.DB.prepare(
          "UPDATE ops_requests SET state='executing' WHERE id=? AND state='applying'",
        ).bind(opId),
      ]);
      if (results[0].meta.changes !== 1)
        throw new ConfigurationError(
          409,
          "Invitations or authorization changed; no invitations deleted",
        );
      const after = await env.DB.prepare(SNAPSHOT)
        .bind(JSON.stringify(codes))
        .first<{ raw: string }>();
      if (!after || JSON.parse(after.raw).length !== 0)
        throw new ConfigurationError(
          409,
          "Cleanup read-back disagrees; do not retry",
        );
      return jsonResponse({
        action: "invite.prune",
        verified: true,
        targets: p.targets!.map((t) => t.id),
        removedInvites: results[1].meta.changes,
      });
    },
  };
}

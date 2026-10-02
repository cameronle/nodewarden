import type { Env, User } from "../types";
import type { OpsAction, OpsParameters } from "../../shared/ops-schema";
import { ConfigurationError } from "./ops-configuration";
import { StorageService } from "./storage";
import { AuthService } from "./auth";
import { notifyUserLogout } from "../durable/notifications-hub";
import { unregisterMobilePushDevice } from "./push-relay";
import { jsonResponse } from "../utils/response";
const hash = async (value: string) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
// A single deterministic SQL snapshot expression is used for both review and the atomic write guard.
const DEVICE_SNAPSHOT = `SELECT json_group_array(snapshot) AS raw FROM (
 SELECT json_object('id',s.value,'device',json((SELECT json_object('name',name,'note',device_note,'type',type,'stamp',session_stamp,'banned',banned,'push',push_uuid,'created',created_at,'userKey',encrypted_user_key,'privateKey',encrypted_private_key,'publicKey',encrypted_public_key) FROM devices WHERE user_id=s.uid AND device_identifier=s.value)),
 'trust',json((SELECT json_group_array(json_array(token,expires_at)) FROM (SELECT token,expires_at FROM trusted_two_factor_device_tokens WHERE user_id=s.uid AND device_identifier=s.value ORDER BY token)))) AS snapshot
 FROM (SELECT value,? AS uid FROM json_each(?) ORDER BY value) s)`;
async function snapshot(env: Env, userId: string, ids: string[]) {
  const row = await env.DB.prepare(DEVICE_SNAPSHOT)
    .bind(userId, JSON.stringify(ids))
    .first<{ raw: string }>();
  const raw = row?.raw || "[]",
    strings = JSON.parse(raw) as string[];
  const items = await Promise.all(
    strings.map(async (text) => {
      const value = JSON.parse(text);
      return {
        id: value.id,
        revision: await hash(text),
        name: value.device?.note || value.device?.name || "Unknown device",
        stored: !!value.device,
        rememberedTwoFactor: value.trust.length > 0,
      };
    }),
  );
  return { raw, strings, items };
}
export async function bulkMetadata(env: Env, user: User) {
  const rows = await env.DB.prepare(
    "SELECT device_identifier AS id FROM devices WHERE user_id=? UNION SELECT device_identifier AS id FROM trusted_two_factor_device_tokens WHERE user_id=? ORDER BY id",
  )
    .bind(user.id, user.id)
    .all<{ id: string }>();
  return {
    items: (
      await snapshot(
        env,
        user.id,
        (rows.results || []).map((r) => r.id),
      )
    ).items,
  };
}
export function isBulk(action: OpsAction) {
  return action === "device.remove" || action === "device.revoke-trust";
}
export async function bulkTarget(
  env: Env,
  user: User,
  action: OpsAction,
  p: OpsParameters,
  current: string,
) {
  const remove = action === "device.remove",
    ids = p.targets!.map((t) => t.id),
    initial = await snapshot(env, user.id, ids);
  if (ids.includes(current) && !p.includeCurrent)
    throw new ConfigurationError(
      400,
      "Current CLI device requires explicit includeCurrent approval",
    );
  for (const item of initial.items) {
    if (!item.stored && !item.rememberedTwoFactor)
      throw new ConfigurationError(404, "Exact own-account device not found");
    if (item.revision !== p.targets!.find((t) => t.id === item.id)!.revision)
      throw new ConfigurationError(409, "Device changed; review a new request");
  }
  const creator = await new StorageService(env.DB).getDevice(user.id, current);
  if (!creator)
    throw new ConfigurationError(401, "Creator device is no longer active");
  return {
    summary: {
      targets: initial.items,
      currentIncluded: ids.includes(current),
      effect: remove
        ? "Remove only the reviewed own-account devices, refresh sessions and remembered-2FA tokens. Preserve devices registered later and every other account. Stale access caches may last 15 seconds."
        : "Revoke only reviewed own-account remembered-2FA tokens. Preserve device sessions, wrapped keys, later devices and other accounts.",
    },
    fingerprint: await hash(initial.raw),
    async apply(opId: string) {
      const guard = env.DB.prepare(
        `UPDATE ops_requests SET state='applying' WHERE id=? AND state='executing' AND (${DEVICE_SNAPSHOT})=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND security_stamp=? AND status='active' AND role='admin') AND EXISTS(SELECT 1 FROM devices WHERE user_id=? AND device_identifier=? AND session_stamp=? AND banned=0)`,
      ).bind(
        opId,
        user.id,
        JSON.stringify(ids),
        initial.raw,
        user.id,
        user.securityStamp,
        user.id,
        current,
        creator.sessionStamp,
      );
      const deletes = (
        remove
          ? ["trusted_two_factor_device_tokens", "refresh_tokens", "devices"]
          : ["trusted_two_factor_device_tokens"]
      ).map((table) =>
        env.DB.prepare(
          `DELETE FROM ${table} WHERE user_id=? AND device_identifier IN(SELECT value FROM json_each(?)) AND EXISTS(SELECT 1 FROM ops_requests WHERE id=? AND state='applying')`,
        ).bind(user.id, JSON.stringify(ids), opId),
      );
      const result = await env.DB.batch([
        guard,
        ...deletes,
        env.DB.prepare(
          "UPDATE ops_requests SET state='executing' WHERE id=? AND state='applying'",
        ).bind(opId),
      ]);
      if (result[0].meta.changes !== 1)
        throw new ConfigurationError(
          409,
          "Device or authorization changed; no devices removed",
        );
      if (remove)
        for (const raw of initial.strings) {
          const item = JSON.parse(raw);
          AuthService.invalidateDeviceCache(user.id, item.id);
          if (item.device) {
            await unregisterMobilePushDevice(env, item.device.push).catch(
              () => {},
            );
            notifyUserLogout(env, user.id, item.id);
          }
        }
      const after = await snapshot(env, user.id, ids);
      if (
        after.items.some(
          (item) => (remove && item.stored) || item.rememberedTwoFactor,
        )
      )
        throw new ConfigurationError(
          409,
          "Device removal read-back disagrees; do not retry",
        );
      return jsonResponse({
        action,
        verified: true,
        targets: ids,
        currentRemoved: remove && ids.includes(current),
        removedDevices: remove ? result[3].meta.changes : 0,
        removedTrust: result[1].meta.changes,
        removedRefreshTokens: remove ? result[2].meta.changes : 0,
      });
    },
  };
}

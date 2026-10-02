import type { Env, User } from "./types";
import {
  configurationMetadata,
  configurationTarget,
  isConfiguration,
  ConfigurationError,
} from "./services/ops-configuration";
import {
  sealOpsCredentials,
  openOpsCredentials,
} from "./services/ops-credentials";
import { credentials } from "../shared/ops-config-schema";
import { StorageService } from "./services/storage";
import { AuthService } from "./services/auth";
import { RateLimitService } from "./services/ratelimit";
import { verifyJWT } from "./utils/jwt";
import { jsonResponse, errorResponse } from "./utils/response";
import {
  opsParameters,
  type OpsAction,
  type OpsParameters,
} from "../shared/ops-schema";
import { loadBackupSettings } from "./services/backup-config";
import { writeAuditEvent } from "./services/audit-events";
import { runApprovedOperation } from "./services/ops-proof";
import {
  handleAdminCreateInvite,
  handleAdminDeleteInvite,
} from "./handlers/admin";
import {
  handleRunAdminConfiguredBackup,
  handleDownloadAdminRemoteBackup,
  handleInspectAdminRemoteBackup,
} from "./handlers/backup";

interface OperationRow {
  id: string;
  user_id: string;
  device_id: string;
  device_stamp: string;
  user_stamp: string;
  token_hash: string;
  proof_hash: string;
  origin: string;
  action: OpsAction;
  parameters: string;
  payload: string | null;
  summary: string;
  fingerprint: string;
  state: string;
  created_at: number;
  expires_at: number;
}
class OpsError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
const fail = (status: number, message: string): never => {
  throw new OpsError(status, message);
};
const hex64 = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
async function digest(value: string) {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function keys(body: Record<string, unknown>, expected: string[]) {
  if (
    Object.keys(body).length !== expected.length ||
    expected.some((k) => !Object.hasOwn(body, k))
  )
    fail(400, "Unexpected or missing operation fields");
}
async function bodyJson(request: Request) {
  if (!request.headers.get("Content-Type")?.startsWith("application/json"))
    fail(415, "JSON required");
  const reader = request.body?.getReader();
  if (!reader) return fail(400, "JSON body required");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 16384) {
        await reader.cancel();
        return fail(413, "Operation payload too large");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const raw = new TextDecoder().decode(bytes);
  try {
    const value = JSON.parse(raw);
    if (value && typeof value === "object" && !Array.isArray(value))
      return value as Record<string, unknown>;
  } catch {}
  return fail(400, "Invalid JSON");
}
async function freshContext(request: Request, env: Env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer "))
    return fail(401, "Authentication required");
  const token = header.slice(7),
    claims = await verifyJWT(token, env.JWT_SECRET);
  if (
    !claims ||
    !Number.isFinite(claims.exp) ||
    claims.exp * 1000 <= Date.now() ||
    !claims.did ||
    !claims.dstamp
  )
    return fail(401, "Device-bound session required");
  const storage = new StorageService(env.DB),
    user = await storage.getUserById(claims.sub),
    device = await storage.getDevice(claims.sub, claims.did);
  if (
    !user ||
    user.status !== "active" ||
    user.securityStamp !== claims.sstamp ||
    !device ||
    device.sessionStamp !== claims.dstamp ||
    !(await env.DB.prepare(
      "SELECT 1 FROM devices WHERE user_id=? AND device_identifier=? AND banned=0",
    )
      .bind(user.id, device.deviceIdentifier)
      .first())
  )
    return fail(401, "Session is no longer active");
  if (user.role !== "admin") return fail(403, "Active administrator required");
  return { user, device, claims, tokenHash: await digest(token), storage };
}
async function target(
  env: Env,
  action: OpsAction,
  p: OpsParameters,
  actor: User,
  secretValue?: unknown,
) {
  if (isConfiguration(action))
    return configurationTarget(env, actor, action, p, secretValue);
  const storage = new StorageService(env.DB);
  if (action === "invite.create")
    return {
      summary: {
        expiresInHours: p.expiresInHours,
        effect: "Create one registration invitation.",
      },
      fingerprint: await digest(JSON.stringify(p)),
      inviteCode: null,
    };
  if (action === "invite.revoke") {
    const invites = await storage.listInvites(true);
    let found = null;
    for (const item of invites)
      if ((await digest(item.code)) === p.inviteId) {
        found = item;
        break;
      }
    if (!found) return fail(404, "Invitation not found");
    return {
      summary: {
        inviteId: p.inviteId,
        status: found.status,
        expiresAt: found.expiresAt,
        effect: "Delete this one invitation.",
      },
      fingerprint: await digest(JSON.stringify(found)),
      inviteCode: found.code,
    };
  }
  const settings = await loadBackupSettings(storage, env, "UTC");
  const d = settings.destinations.find((d) => d.id === p.destinationId);
  if (!d) return fail(404, "Backup destination not found");
  const { runtime: _, ...stable } = d;
  return {
    summary: {
      destinationId: d.id,
      destinationName: d.name,
      provider: d.type,
      path: p.path ?? null,
      includeAttachments: d.includeAttachments,
      retentionCount: d.schedule.retentionCount,
      effect:
        action === "backup.run"
          ? "Create backup; the existing retention policy may DELETE older remote archives."
          : action === "backup.download"
            ? "Download this remote archive. It may reference separately stored attachment blobs."
            : "Check filename checksum prefix only; not proof of recoverability.",
    },
    fingerprint: await digest(JSON.stringify(stable)),
    inviteCode: null,
  };
}
function view(row: OperationRow) {
  return {
    id: row.id,
    action: row.action,
    parameters: JSON.parse(row.parameters),
    summary: JSON.parse(row.summary),
    deviceId: row.device_id,
    origin: row.origin,
    state:
      row.expires_at <= Date.now() &&
      ["pending", "approved"].includes(row.state)
        ? "expired"
        : row.state,
    expiresAt: new Date(row.expires_at).toISOString(),
    createdAt: new Date(row.created_at).toISOString(),
  };
}
async function audit(env: Env, userId: string, id: string, action: string) {
  await writeAuditEvent(new StorageService(env.DB), {
    actorUserId: userId,
    action: "cli.operation." + action,
    category: "security",
    level: "security",
    targetType: "cliOperation",
    targetId: id,
    metadata: null,
  });
}
async function execute(
  env: Env,
  user: User,
  row: OperationRow,
  request: Request,
  inviteCode: string | null,
): Promise<Response> {
  const inner = new Request(row.origin + "/api/ops/internal", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-NodeWarden-Acting-Device-Id": row.device_id,
    },
    body: row.parameters,
  });
  return runApprovedOperation(inner, user.id, row.action, () => {
    if (row.action === "invite.create")
      return handleAdminCreateInvite(inner, env, user);
    if (row.action === "invite.revoke" && inviteCode)
      return handleAdminDeleteInvite(inner, env, user, inviteCode);
    if (row.action === "backup.run")
      return handleRunAdminConfiguredBackup(inner, env, user);
    if (row.action === "backup.download")
      return handleDownloadAdminRemoteBackup(inner, env, user);
    if (row.action === "backup.verify")
      return handleInspectAdminRemoteBackup(inner, env, user);
    return Promise.resolve(
      errorResponse("Operation executor unavailable", 501),
    );
  });
}
export async function handleOpsRoute(
  request: Request,
  env: Env,
): Promise<Response> {
  const response = await route(request, env);
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("Pragma", "no-cache");
  return new Response(response.body, { status: response.status, headers });
}
async function route(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url),
      origin = request.headers.get("Origin");
    if (url.search) fail(400, "Query parameters are not accepted");
    if (origin && origin !== url.origin)
      fail(403, "Cross-origin operation rejected");
    const ctx = await freshContext(request, env);
    if (url.pathname.startsWith("/api/ops/config/")) {
      if (request.method !== "GET")
        return errorResponse("Method not allowed", 405);
      return jsonResponse(await configurationMetadata(env, url.pathname));
    }
    if (url.pathname === "/api/ops/requests") {
      if (request.method !== "POST")
        return errorResponse("Method not allowed", 405);
      const body = await bodyJson(request);
      keys(
        body,
        Object.hasOwn(body, "credentials")
          ? ["action", "parameters", "proofHash", "credentials"]
          : ["action", "parameters", "proofHash"],
      );
      if (!hex64(body.proofHash)) fail(400, "Invalid proof hash");
      let parsed;
      try {
        parsed = opsParameters(body.action, body.parameters);
      } catch {
        return errorResponse("Invalid operation parameters", 400);
      }
      const budget = await new RateLimitService(env.DB).consumeStrictBudget(
        "ops-create:" + ctx.user.id,
        20,
      );
      if (!budget.allowed) fail(429, "Operation request limit reached");
      if (
        Object.hasOwn(body, "credentials") &&
        parsed.action !== "backup.configure"
      )
        fail(400, "Credentials are only allowed for backup configuration");
      let secretValue: Record<string, string> = {};
      if (parsed.action === "backup.configure") {
        try {
          secretValue = credentials(
            body.credentials,
            parsed.parameters.credentialFields!,
          );
        } catch {
          return errorResponse("Invalid credential fields", 400);
        }
      }
      const resolved = await target(
          env,
          parsed.action,
          parsed.parameters,
          ctx.user,
          secretValue,
        ),
        now = Date.now();
      const expires = Math.min(now + 600000, ctx.claims.exp * 1000);
      if (expires - now < 30000)
        fail(401, "Session expires too soon; sign in again");
      // Only transient operation records are pruned; never business data or audit logs.
      await env.DB.prepare("DELETE FROM ops_requests WHERE expires_at < ?")
        .bind(now - 86400000)
        .run();
      const row: OperationRow = {
        id: crypto.randomUUID(),
        user_id: ctx.user.id,
        device_id: ctx.device.deviceIdentifier,
        device_stamp: ctx.device.sessionStamp!,
        user_stamp: ctx.user.securityStamp,
        token_hash: ctx.tokenHash,
        proof_hash: body.proofHash as string,
        origin: url.origin,
        action: parsed.action,
        parameters: JSON.stringify(parsed.parameters),
        payload: null,
        summary: JSON.stringify(resolved.summary),
        fingerprint: resolved.fingerprint,
        state: "pending",
        created_at: now,
        expires_at: expires,
      };
      row.payload = await sealOpsCredentials(
        env,
        row.id,
        row.user_id,
        secretValue,
      );
      await env.DB.prepare(
        "INSERT INTO ops_requests (id,user_id,device_id,device_stamp,user_stamp,token_hash,proof_hash,origin,action,parameters,summary,fingerprint,state,created_at,expires_at,payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      )
        .bind(
          row.id,
          row.user_id,
          row.device_id,
          row.device_stamp,
          row.user_stamp,
          row.token_hash,
          row.proof_hash,
          row.origin,
          row.action,
          row.parameters,
          row.summary,
          row.fingerprint,
          row.state,
          row.created_at,
          row.expires_at,
          row.payload,
        )
        .run();
      await audit(env, ctx.user.id, row.id, "request");
      return jsonResponse(
        { ...view(row), approvalUrl: url.origin + "/cli-approval/" + row.id },
        201,
      );
    }
    const match = url.pathname.match(
      /^\/api\/ops\/requests\/([a-f0-9-]{36})(?:\/(approve|status|execute|cancel))?$/,
    );
    if (!match) return errorResponse("Not found", 404);
    const row = await env.DB.prepare(
      "SELECT * FROM ops_requests WHERE id = ? AND user_id = ?",
    )
      .bind(match[1], ctx.user.id)
      .first<OperationRow>();
    if (!row || row.origin !== url.origin)
      return errorResponse("Operation not found", 404);
    if (row.user_stamp !== ctx.user.securityStamp)
      fail(401, "Account authorization changed");
    const stage = match[2];
    if (!stage && request.method === "GET") return jsonResponse(view(row));
    if (request.method !== "POST")
      return errorResponse("Method not allowed", 405);
    const body = await bodyJson(request);
    if (stage === "approve") {
      if (
        origin !== row.origin ||
        request.headers.get("Sec-Fetch-Site") === "cross-site"
      )
        fail(403, "Same-origin browser confirmation required");
      keys(body, ["approve", "masterPasswordHash"]);
      if (
        typeof body.approve !== "boolean" ||
        typeof body.masterPasswordHash !== "string" ||
        body.masterPasswordHash.length > 1024
      )
        fail(400, "Invalid confirmation");
      if (row.expires_at <= Date.now()) fail(410, "Operation expired");
      if (row.state !== "pending") fail(409, "Operation is no longer pending");
      const budget = await new RateLimitService(env.DB).consumeStrictBudget(
        "ops-approve:" + ctx.user.id,
        10,
      );
      if (!budget.allowed) fail(429, "Verification attempt limit reached");
      if (
        body.approve &&
        !(await new AuthService(env).verifyPassword(
          body.masterPasswordHash as string,
          ctx.user.masterPasswordHash,
          ctx.user.email,
        ))
      )
        fail(400, "Invalid password");
      const creator = await ctx.storage.getDevice(row.user_id, row.device_id);
      if (
        !creator ||
        creator.sessionStamp !== row.device_stamp ||
        !(await env.DB.prepare(
          "SELECT 1 FROM devices WHERE user_id=? AND device_identifier=? AND banned=0",
        )
          .bind(row.user_id, row.device_id)
          .first())
      )
        fail(401, "Requesting CLI session is no longer active");
      if (body.approve) {
        const resolved = await target(
          env,
          row.action,
          JSON.parse(row.parameters),
          ctx.user,
          await openOpsCredentials(env, row.id, row.user_id, row.payload),
        );
        if (resolved.fingerprint !== row.fingerprint)
          fail(409, "Target changed; create a new request");
      }
      const changed = await env.DB.prepare(
        "UPDATE ops_requests SET state=?, payload=CASE WHEN ? THEN payload ELSE NULL END, expires_at=MIN(expires_at,?) WHERE id=? AND state='pending' AND expires_at>? AND EXISTS (SELECT 1 FROM users WHERE id=? AND security_stamp=? AND status='active' AND role='admin')",
      )
        .bind(
          body.approve ? "approved" : "denied",
          body.approve ? 1 : 0,
          Date.now() + 120000,
          row.id,
          Date.now(),
          ctx.user.id,
          row.user_stamp,
        )
        .run();
      if (changed.meta.changes !== 1) fail(409, "Operation changed or expired");
      await audit(env, ctx.user.id, row.id, body.approve ? "approve" : "deny");
      return jsonResponse({
        id: row.id,
        state: body.approve ? "approved" : "denied",
      });
    }
    if (!["status", "execute", "cancel"].includes(stage))
      return errorResponse("Not found", 404);
    keys(body, ["proof"]);
    if (
      !hex64(body.proof) ||
      (await digest(body.proof as string)) !== row.proof_hash ||
      ctx.tokenHash !== row.token_hash ||
      ctx.device.deviceIdentifier !== row.device_id ||
      ctx.device.sessionStamp !== row.device_stamp
    )
      fail(403, "Requesting CLI proof or session mismatch");
    if (stage === "status") return jsonResponse(view(row));
    if (row.expires_at <= Date.now()) fail(410, "Operation expired");
    if (stage === "cancel") {
      const changed = await env.DB.prepare(
        "UPDATE ops_requests SET state='cancelled',payload=NULL WHERE id=? AND state IN ('pending','approved')",
      )
        .bind(row.id)
        .run();
      if (changed.meta.changes !== 1)
        fail(409, "Operation cannot be cancelled");
      await audit(env, ctx.user.id, row.id, "cancel");
      return jsonResponse({ id: row.id, state: "cancelled" });
    }
    if (row.state !== "approved")
      fail(409, "Operation not approved or already attempted");
    const resolved = await target(
      env,
      row.action,
      JSON.parse(row.parameters),
      ctx.user,
      await openOpsCredentials(env, row.id, row.user_id, row.payload),
    );
    if (resolved.fingerprint !== row.fingerprint)
      fail(409, "Target changed; create a new request");
    // Cross-isolate atomic single consumer; a crash leaves executing/unknown, NEVER retryable.
    const consumed = await env.DB.prepare(
      "UPDATE ops_requests SET state='executing' WHERE id=? AND state='approved' AND expires_at>? AND EXISTS (SELECT 1 FROM users WHERE id=? AND security_stamp=? AND status='active' AND role='admin') AND EXISTS (SELECT 1 FROM devices WHERE user_id=? AND device_identifier=? AND session_stamp=? AND banned=0)",
    )
      .bind(
        row.id,
        Date.now(),
        row.user_id,
        row.user_stamp,
        row.user_id,
        row.device_id,
        row.device_stamp,
      )
      .run();
    if (consumed.meta.changes !== 1)
      fail(409, "Operation already consumed, expired or authorization changed");
    try {
      const response =
        "apply" in resolved
          ? await resolved.apply(row.id)
          : await execute(env, ctx.user, row, request, resolved.inviteCode);
      await env.DB.prepare(
        "UPDATE ops_requests SET state=?,payload=NULL WHERE id=? AND state='executing'",
      )
        .bind(response.ok ? "succeeded" : "failed", row.id)
        .run();
      await audit(env, ctx.user.id, row.id, response.ok ? "succeed" : "fail");
      return response;
    } catch (error) {
      if (error instanceof ConfigurationError) {
        await env.DB.prepare(
          "UPDATE ops_requests SET state='failed',payload=NULL WHERE id=? AND state='executing'",
        )
          .bind(row.id)
          .run();
        return errorResponse(error.message, error.status);
      }
      await env.DB.prepare(
        "UPDATE ops_requests SET state='unknown',payload=NULL WHERE id=? AND state='executing'",
      )
        .bind(row.id)
        .run();
      return errorResponse(
        "Operation outcome unknown; inspect target, do not repeat automatically",
        500,
      );
    }
  } catch (error) {
    if (error instanceof OpsError || error instanceof ConfigurationError)
      return errorResponse(error.message, error.status);
    // Avoid logging raw provider errors, password material, or request bodies.
    return errorResponse(
      "Operation failed; inspect status before attempting another request",
      500,
    );
  }
}

import type { Env, User } from "../types";
import type { OpsAction, OpsParameters } from "../../shared/ops-schema";
import { credentials } from "../../shared/ops-config-schema";
import type {
  BackupSettings,
  BackupDestinationRecord,
} from "../../shared/backup-schema";
import { AuthService } from "./auth";
import { StorageService } from "./storage";
import {
  BACKUP_SETTINGS_CONFIG_KEY,
  parseBackupSettings,
  serializeBackupSettings,
  normalizeBackupSettingsInput,
  getDefaultBackupSettings,
} from "./backup-config";
import {
  decryptBackupSettingsRuntime,
  encryptBackupSettingsEnvelope,
  parseBackupSettingsEnvelope,
} from "./backup-settings-crypto";
import { getAuditLogSettings, writeAuditEvent } from "./audit-events";
import { jsonResponse } from "../utils/response";
export class ConfigurationError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
const fail = (status: number, message: string): never => {
  throw new ConfigurationError(status, message);
};
export async function configDigest(v: string) {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)),
    ),
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
export const isConfiguration = (a: OpsAction) =>
  [
    "backup.configure",
    "audit.configure",
    "audit.clear",
    "user.status",
  ].includes(a);
const revision = (raw: string | null) => configDigest(JSON.stringify(raw));
async function backupSnapshot(env: Env) {
  const storage = new StorageService(env.DB),
    raw = await storage.getConfigValue(BACKUP_SETTINGS_CONFIG_KEY);
  // Metadata/dry-run NEVER initializes, migrates or re-encrypts settings.
  let settings: BackupSettings;
  if (raw === null) settings = getDefaultBackupSettings("UTC");
  else {
    if (!parseBackupSettingsEnvelope(raw))
      fail(409, "Backup settings require Web repair before CLI configuration");
    try {
      settings = parseBackupSettings(
        await decryptBackupSettingsRuntime(raw, env),
        "UTC",
      );
    } catch {
      return fail(
        409,
        "Backup settings require Web repair before CLI configuration",
      );
    }
  }
  return { storage, raw, settings, revision: await revision(raw) };
}
function safeDestination(d: BackupDestinationRecord) {
  const { runtime: _, destination, ...meta } = d;
  const safe: Record<string, unknown> = { ...destination };
  const names =
    d.type === "s3"
      ? ["accessKeyId", "secretAccessKey"]
      : ["username", "password"];
  for (const k of names) {
    delete safe[k];
  }
  return {
    ...meta,
    destination: safe,
    credentialsPresent: Object.fromEntries(
      names.map((k) => [
        k,
        !!(destination as unknown as Record<string, string>)[k],
      ]),
    ),
  };
}
async function auditSnapshot(env: Env) {
  const storage = new StorageService(env.DB),
    raw = await storage.getConfigValue("audit.logs.settings.v1");
  return {
    raw,
    revision: await revision(raw),
    policy: await getAuditLogSettings(storage),
  };
}
async function userSnapshot(env: Env, id: string) {
  const user = await new StorageService(env.DB).getUserById(id);
  if (!user) return fail(404, "User not found");
  return {
    user,
    revision: await configDigest(
      JSON.stringify([
        user.id,
        user.email,
        user.role,
        user.status,
        user.updatedAt,
        user.securityStamp,
      ]),
    ),
  };
}
export async function configurationMetadata(env: Env, path: string) {
  if (path === "/api/ops/config/backup") {
    const s = await backupSnapshot(env);
    return {
      object: "ops-backup-config",
      revision: s.revision,
      destinations: s.settings.destinations.map(safeDestination),
    };
  }
  if (path === "/api/ops/config/audit") {
    const s = await auditSnapshot(env);
    return { object: "ops-audit-config", revision: s.revision, ...s.policy };
  }
  const clearPath = path.match(
    /^\/api\/ops\/config\/audit-clear(?:\/([1-9][0-9]{0,15}))?$/,
  );
  if (clearPath) {
    const s = await clearSnapshot(
      env,
      clearPath[1] ? Number(clearPath[1]) : undefined,
    );
    return {
      object: "ops-audit-clear",
      revision: s.revision,
      throughRowId: s.throughRowId,
      count: s.count,
    };
  }
  const match = path.match(
    /^\/api\/ops\/config\/user\/([A-Za-z0-9_-]{1,128})$/,
  );
  if (match) {
    const s = await userSnapshot(env, match[1]);
    return {
      object: "ops-user-config",
      revision: s.revision,
      id: s.user.id,
      email: s.user.email,
      role: s.user.role,
      status: s.user.status,
    };
  }
  return fail(404, "Configuration metadata not found");
}
async function clearSnapshot(env: Env, through?: number) {
  const policy = await auditSnapshot(env);
  const upper =
    through ??
    Number(
      (await env.DB.prepare(
        "SELECT COALESCE(MAX(rowid),0) n FROM audit_logs",
      ).first<{ n: number }>())!.n,
    );
  const count = Number(
    (await env.DB.prepare("SELECT count(*) n FROM audit_logs WHERE rowid<=?")
      .bind(upper)
      .first<{ n: number }>())!.n,
  );
  return {
    policy,
    throughRowId: upper,
    count,
    revision: await configDigest(
      JSON.stringify([policy.revision, upper, count]),
    ),
  };
}
interface Plan {
  summary: Record<string, unknown>;
  fingerprint: string;
  inviteCode: null;
  apply: (operationId: string) => Promise<Response>;
}
const authoritySql =
  "EXISTS (SELECT 1 FROM ops_requests o JOIN users u ON u.id=o.user_id JOIN devices d ON d.user_id=o.user_id AND d.device_identifier=o.device_id WHERE o.id=? AND o.state='executing' AND o.expires_at>? AND u.status='active' AND u.role='admin' AND u.security_stamp=o.user_stamp AND d.session_stamp=o.device_stamp AND d.banned=0)";
function cas(
  env: Env,
  key: string,
  before: string | null,
  after: string,
  operationId: string,
) {
  return before === null
    ? env.DB.prepare(
        "INSERT INTO config (key,value) SELECT ?,? WHERE NOT EXISTS (SELECT 1 FROM config WHERE key=?) AND " +
          authoritySql,
      ).bind(key, after, key, operationId, Date.now())
    : env.DB.prepare(
        "UPDATE config SET value=? WHERE key=? AND value=? AND " + authoritySql,
      ).bind(after, key, before, operationId, Date.now());
}
export async function configurationTarget(
  env: Env,
  actor: User,
  action: OpsAction,
  p: OpsParameters,
  secretValue?: unknown,
): Promise<Plan> {
  if (action === "backup.configure") {
    let secret: Record<string, string>;
    try {
      secret = credentials(secretValue, p.credentialFields!);
    } catch {
      return fail(400, "Invalid private credential fields");
    }
    const snapshot = await backupSnapshot(env);
    if (snapshot.revision !== p.expectedRevision)
      fail(409, "Backup configuration changed; create a new request");
    const current = snapshot.settings.destinations.find(
      (d) => d.id === p.destinationId,
    );
    if (p.mutation === "add" && current)
      fail(409, "Backup destination already exists");
    if (p.mutation !== "add" && !current)
      fail(404, "Backup destination not found");
    if (p.mutation === "add" && !p.change?.name)
      fail(400, "New destination requires an explicit name");
    if (p.mutation === "add" && !p.change?.type)
      fail(400, "New destination requires an explicit provider");
    if (current && p.change?.type && current.type !== p.change.type)
      fail(400, "Provider type is immutable; add a separate destination");
    const type = current?.type || p.change?.type;
    const allowed =
      type === "s3"
        ? ["accessKeyId", "secretAccessKey"]
        : ["username", "password"];
    if (Object.keys(secret).some((k) => !allowed.includes(k)))
      fail(400, "Credential fields do not match provider");
    const publicFields =
      type === "s3"
        ? ["endpoint", "bucket", "addressingStyle", "region", "rootPath"]
        : ["baseUrl", "remotePath"];
    if (
      Object.keys(p.change?.destination || {}).some(
        (k) => !publicFields.includes(k),
      )
    )
      fail(400, "Configuration fields do not match provider");
    let next: BackupSettings;
    try {
      const proposed =
        p.mutation === "remove"
          ? snapshot.settings.destinations.filter(
              (d) => d.id !== p.destinationId,
            )
          : [
              ...snapshot.settings.destinations.filter(
                (d) => d.id !== p.destinationId,
              ),
              {
                ...(current || {}),
                ...p.change,
                id: p.destinationId,
                type,
                destination: {
                  ...(current?.destination || {}),
                  ...p.change?.destination,
                  ...secret,
                },
                schedule: {
                  ...(current?.schedule || {}),
                  ...p.change?.schedule,
                },
              },
            ];
      // Preserve original target ordering as well as untouched config and credentials.
      if (current && p.mutation !== "remove") {
        const changed = proposed.pop()!;
        proposed.splice(
          snapshot.settings.destinations.indexOf(current),
          0,
          changed,
        );
      }
      next = normalizeBackupSettingsInput(
        { destinations: proposed },
        snapshot.settings,
      );
    } catch {
      return fail(
        400,
        "Invalid backup configuration; no secret details are disclosed",
      );
    }
    const selected = next.destinations.find((d) => d.id === p.destinationId);
    const summary = {
      destinationId: p.destinationId,
      mutation: p.mutation,
      before: current ? safeDestination(current) : null,
      after: selected ? safeDestination(selected) : null,
      credentialFieldsChanged: p.credentialFields,
      effect:
        p.mutation === "remove"
          ? "Remove configuration only; remote archives, R2 attachments and runtime history are NOT deleted."
          : "Change only this destination. Retention/attachment policy affects FUTURE runs and may delete older remote backups then. No remote probe or backup is run now.",
    };
    return {
      summary,
      fingerprint: await configDigest(JSON.stringify([snapshot.revision, p])),
      inviteCode: null,
      apply: async (operationId) => {
        const encrypted = await encryptBackupSettingsEnvelope(
          serializeBackupSettings(next),
          env,
          await snapshot.storage.getAllUsers(),
        );
        const saved = await cas(
          env,
          BACKUP_SETTINGS_CONFIG_KEY,
          snapshot.raw,
          encrypted,
          operationId,
        ).run();
        if (saved.meta.changes !== 1)
          fail(409, "Concurrent backup configuration change; not written");
        // Runtime is a separate hot record; never overwrite it with an earlier snapshot.
        const committedRevision = await revision(encrypted);
        const after = {
          object: "ops-backup-config",
          revision: committedRevision,
          destinations: next.destinations.map(safeDestination),
        };
        await writeAuditEvent(new StorageService(env.DB), {
          category: "system",
          action: "backup.config.updated",
          actorUserId: actor.id,
          metadata: {
            operationId,
            destinationId: p.destinationId,
            mutation: p.mutation,
            credentialFields: p.credentialFields,
          },
        });
        return jsonResponse({
          object: "ops-config-result",
          action,
          revision: after.revision,
          configuration: after,
        });
      },
    };
  }
  if (action === "audit.clear") {
    const s = await clearSnapshot(env, p.throughRowId);
    if (s.revision !== p.expectedRevision || !s.count)
      fail(409, "Audit snapshot changed or empty; create a new request");
    return {
      summary: {
        throughRowId: s.throughRowId,
        count: s.count,
        effect:
          "IRREVERSIBLE: clear only the reviewed log snapshot. Logs created after this request and the operation audit trail are preserved.",
      },
      fingerprint: await configDigest(JSON.stringify(p)),
      inviteCode: null,
      apply: async (operationId) => {
        const result = await env.DB.prepare(
          "DELETE FROM audit_logs WHERE rowid<=? AND (SELECT count(*) FROM audit_logs WHERE rowid<=?)=? AND (SELECT value FROM config WHERE key=?) IS ? AND EXISTS (SELECT 1 FROM audit_logs WHERE rowid>?) AND " +
            authoritySql,
        )
          .bind(
            s.throughRowId,
            s.throughRowId,
            s.count,
            "audit.logs.settings.v1",
            s.policy.raw,
            s.throughRowId,
            operationId,
            Date.now(),
          )
          .run();
        if (result.meta.changes !== s.count)
          fail(
            409,
            "Concurrent audit snapshot or authorization change; snapshot not cleared",
          );
        await writeAuditEvent(new StorageService(env.DB), {
          category: "security",
          action: "audit.logs.cleared",
          actorUserId: actor.id,
          metadata: { deleted: result.meta.changes },
        });
        return jsonResponse({
          object: "ops-audit-clear-result",
          action,
          throughRowId: s.throughRowId,
          deleted: result.meta.changes,
        });
      },
    };
  }
  if (action === "audit.configure") {
    const s = await auditSnapshot(env);
    if (s.revision !== p.expectedRevision)
      fail(409, "Audit policy changed; create a new request");
    const next = { retentionDays: p.retentionDays!, maxEntries: p.maxEntries! };
    const raw = JSON.stringify(next);
    return {
      summary: {
        before: s.policy,
        after: next,
        effect:
          "Saving this policy IMMEDIATELY and irreversibly prunes logs outside the new retention window or row cap. Existing log content cannot be restored by this operation.",
      },
      fingerprint: await configDigest(JSON.stringify([s.revision, p])),
      inviteCode: null,
      apply: async (operationId) => {
        const statements = [
          cas(env, "audit.logs.settings.v1", s.raw, raw, operationId),
        ];
        // One guarded DELETE immediately follows CAS in the D1 transaction. A
        // failed CAS cannot prune even if another writer saved the same policy.
        if (next.retentionDays !== null)
          statements.push(
            env.DB.prepare(
              "DELETE FROM audit_logs WHERE created_at<? AND changes()=1",
            ).bind(
              new Date(
                Date.now() - next.retentionDays * 86400000,
              ).toISOString(),
            ),
          );
        else if (next.maxEntries !== null)
          statements.push(
            env.DB.prepare(
              "DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET ?) AND changes()=1",
            ).bind(next.maxEntries),
          );
        const results = await env.DB.batch(statements);
        if (results[0].meta.changes !== 1)
          fail(409, "Concurrent audit policy change; not written");
        await writeAuditEvent(new StorageService(env.DB), {
          category: "security",
          action: "audit.policy.updated",
          actorUserId: actor.id,
          metadata: { operationId, ...next },
        });
        const after = {
          object: "ops-audit-config",
          revision: await revision(raw),
          ...next,
        };
        return jsonResponse({
          object: "ops-config-result",
          action,
          revision: after.revision,
          configuration: after,
        });
      },
    };
  }
  if (action === "user.status") {
    if (p.userId === actor.id)
      fail(400, "Cannot change the requesting account status");
    const s = await userSnapshot(env, p.userId!);
    if (s.revision !== p.expectedRevision)
      fail(409, "User changed; create a new request");
    if (s.user.status === p.status)
      fail(409, "User already has requested status");
    return {
      summary: {
        userId: s.user.id,
        email: s.user.email,
        role: s.user.role,
        before: s.user.status,
        after: p.status,
        effect:
          p.status === "banned"
            ? "Block login, revoke refresh tokens and rotate the session stamp. Vault ciphertext and R2 blobs are NOT modified. Unbanning will require fresh login."
            : "Allow fresh login. Old access/refresh sessions are NOT restored.",
      },
      fingerprint: await configDigest(JSON.stringify([s.revision, p])),
      inviteCode: null,
      apply: async (operationId) => {
        const stamp = crypto.randomUUID(),
          writtenAt = new Date().toISOString();
        const update = env.DB.prepare(
          "UPDATE users SET status=?,security_stamp=?,updated_at=? WHERE id=? AND status=? AND security_stamp=? AND updated_at=? AND role=? AND id<>? AND EXISTS (SELECT 1 FROM users WHERE id=? AND status='active' AND role='admin') AND " +
            authoritySql,
        ).bind(
          p.status,
          stamp,
          writtenAt,
          s.user.id,
          s.user.status,
          s.user.securityStamp,
          s.user.updatedAt,
          s.user.role,
          actor.id,
          actor.id,
          operationId,
          Date.now(),
        );
        const statements = [update];
        statements.push(
          env.DB.prepare(
            "DELETE FROM refresh_tokens WHERE user_id=? AND EXISTS (SELECT 1 FROM users WHERE id=? AND status=? AND security_stamp=?)",
          ).bind(s.user.id, s.user.id, p.status, stamp),
        );
        const result = await env.DB.batch(statements);
        if (result[0].meta.changes !== 1)
          fail(409, "Concurrent user change; status not written");
        await writeAuditEvent(new StorageService(env.DB), {
          category: "security",
          action: p.status === "banned" ? "user.banned" : "user.unbanned",
          actorUserId: actor.id,
          targetType: "user",
          targetId: s.user.id,
          metadata: { operationId, status: p.status },
        });
        AuthService.invalidateUserCache(s.user.id);
        const after = {
          object: "ops-user-config",
          revision: await configDigest(
            JSON.stringify([
              s.user.id,
              s.user.email,
              s.user.role,
              p.status,
              writtenAt,
              stamp,
            ]),
          ),
          id: s.user.id,
          email: s.user.email,
          role: s.user.role,
          status: p.status,
        };
        return jsonResponse({
          object: "ops-config-result",
          action,
          revision: after.revision,
          configuration: after,
        });
      },
    };
  }
  return fail(400, "Unsupported configuration action");
}

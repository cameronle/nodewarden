import type { BackupDestinationType } from "../../../shared/backup-schema.js";
import { incompatible } from "./errors.js";
import { learnSecrets } from "./output.js";
export function record(v: unknown): Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v)) return incompatible();
  return v as Record<string, unknown>;
}
export function text(v: unknown): string {
  if (typeof v !== "string") return incompatible();
  return v;
}
function nullableText(v: unknown): string | null {
  return v === null ? null : text(v);
}
function bool(v: unknown): boolean {
  if (typeof v !== "boolean") return incompatible();
  return v;
}
function num(v: unknown): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0)
    return incompatible();
  return v;
}
function integer(v: unknown): number {
  const n = num(v);
  if (!Number.isSafeInteger(n)) return incompatible();
  return n;
}
function array(v: unknown): unknown[] {
  if (!Array.isArray(v)) return incompatible();
  return v;
}
function type(v: unknown): BackupDestinationType {
  if (v !== "s3" && v !== "webdav") return incompatible();
  return v;
}
function enumText(v: unknown, values: string[]): string {
  const s = text(v);
  if (!values.includes(s)) return incompatible();
  return s;
}
export function identity(v: unknown) {
  const p = record(v);
  learnSecrets(p);
  return {
    id: text(p.id),
    name: nullableText(p.name),
    email: text(p.email),
    role: enumText(p.role, ["admin", "user"]),
    status: enumText(p.status, ["active", "banned"]),
  };
}
export interface Destination {
  id: string;
  name: string;
  type: BackupDestinationType;
  includeAttachments: boolean;
  schedule: {
    enabled: boolean;
    intervalHours: number;
    startTime: string;
    timezone: string;
    retentionCount: number | null;
  };
  runtime: {
    lastAttemptAt: string | null;
    lastSuccessAt: string | null;
    lastErrorAt: string | null;
    lastErrorMessage: string | null;
    lastUploadedFileName: string | null;
    lastUploadedSizeBytes: number | null;
  };
}
export function settings(v: unknown): Destination[] {
  const p = record(v);
  learnSecrets(p);
  const ids = new Set<string>();
  return array(p.destinations).map((value) => {
    const d = record(value),
      s = record(d.schedule),
      r = record(d.runtime);
    const id = text(d.id);
    if (!id || ids.has(id)) return incompatible();
    ids.add(id);
    return {
      id,
      name: text(d.name),
      type: type(d.type),
      includeAttachments: bool(d.includeAttachments),
      schedule: {
        enabled: bool(s.enabled),
        intervalHours: num(s.intervalHours),
        startTime: text(s.startTime),
        timezone: text(s.timezone),
        retentionCount:
          s.retentionCount === null ? null : integer(s.retentionCount),
      },
      runtime: {
        lastAttemptAt: nullableText(r.lastAttemptAt),
        lastSuccessAt: nullableText(r.lastSuccessAt),
        lastErrorAt: nullableText(r.lastErrorAt),
        lastErrorMessage:
          r.lastErrorMessage === null
            ? null
            : (text(r.lastErrorMessage),
              "Server reported a backup error; raw message suppressed."),
        lastUploadedFileName: nullableText(r.lastUploadedFileName),
        lastUploadedSizeBytes:
          r.lastUploadedSizeBytes === null
            ? null
            : num(r.lastUploadedSizeBytes),
      },
    };
  });
}
export function usersPage(v: unknown) {
  const p = record(v);
  learnSecrets(p);
  const items = array(p.data).map(identity);
  return { items, count: items.length };
}
export function auditPage(v: unknown) {
  const p = record(v);
  learnSecrets(p);
  const items = array(p.data).map((value) => {
    const r = record(value);
    return {
      id: text(r.id),
      actorUserId: nullableText(r.actorUserId),
      actorEmail: nullableText(r.actorEmail),
      action: text(r.action),
      category: text(r.category),
      level: text(r.level),
      targetType: nullableText(r.targetType),
      targetId: nullableText(r.targetId),
      targetUserEmail: nullableText(r.targetUserEmail),
      createdAt: text(r.createdAt),
      metadataOmitted: true,
    };
  });
  const total = integer(p.total),
    offset = integer(p.offset),
    limit = integer(p.limit),
    hasMore = bool(p.hasMore);
  if (
    limit < 1 ||
    limit > 200 ||
    items.length > limit ||
    items.length > total ||
    (items.length > 0 && offset + items.length > total) ||
    hasMore !== offset + items.length < total
  )
    return incompatible();
  return { items, count: items.length, total, limit, offset, hasMore };
}
export function remotePage(v: unknown) {
  const p = record(v);
  learnSecrets(p);
  const items = array(p.items).map((value) => {
    const r = record(value);
    return {
      path: text(r.path),
      name: text(r.name),
      isDirectory: bool(r.isDirectory),
      size: r.size === null ? null : num(r.size),
      modifiedAt: nullableText(r.modifiedAt),
    };
  });
  return {
    destinationId: text(p.destinationId),
    destinationName: text(p.destinationName),
    provider: type(p.provider),
    currentPath: text(p.currentPath),
    parentPath: nullableText(p.parentPath),
    items,
    count: items.length,
  };
}
export function loginResponse(v: unknown) {
  const p = record(v);
  learnSecrets(p);
  if (p.token_type !== "Bearer") return incompatible();
  const ttl = num(p.expires_in);
  if (ttl <= 0 || ttl > 604800) return incompatible();
  return {
    token: text(p.access_token),
    ttl,
    refresh: p.refresh_token === undefined ? undefined : text(p.refresh_token),
  };
}

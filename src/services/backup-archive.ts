import { zipSync } from "fflate";
import {
  BACKUP_FORMAT_VERSION,
  type BackupManifestAttachmentBlob,
  type BackupManifest,
  type BackupPayload,
  type BackupArchiveBundle,
  type BackupFileIntegrityCheckResult,
} from "../../shared/backup-validation";
export {
  MAX_BACKUP_ARCHIVE_BYTES,
  parseBackupArchive,
  validateBackupPayloadContents,
  isSafeBackupAttachmentBlobName,
} from "../../shared/backup-validation";
export type {
  BackupManifest,
  BackupManifestAttachmentBlob,
  BackupPayload,
  BackupArchiveBundle,
  BackupFileIntegrityCheckResult,
  ParseBackupArchiveOptions,
  ValidateBackupPayloadOptions,
} from "../../shared/backup-validation";
import type { Env } from "../types";
import { APP_VERSION } from "../../shared/app-version";
import { BACKUP_SETTINGS_CONFIG_KEY } from "./backup-config";
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY } from "./yubico-config";
import { exportPortableBackupSettingsEnvelope } from "./backup-settings-crypto";
import { getAttachmentObjectKey, getBlobStorageKind } from "./blob-store";

// CONTRACT:
// This file defines the exported instance-backup archive shape. Keep it in lock
// step with src/services/backup-import.ts and webapp/src/lib/api/backup.ts.
//
// WHEN CHANGING THIS:
// - Add persistent tables to BackupPayload, export SQL, manifest tableCounts,
//   and validateBackupPayloadContents().
// - Keep secrets and transient runtime rows sanitized before writing db.json.
// - Runtime authentication state (devices, sessions, auth requests, remembered
//   2FA devices, and one-time tokens) must never enter an instance backup.
// - users.api_key is intentionally not exported.
// - backup.settings.v1 is exported as portable-only; the current server runtime
//   envelope must not leave the instance.
type SqlRow = Record<string, string | number | null>;

const BACKUP_RUNNER_LOCK_CONFIG_KEY = "backup.runner.lock.v1";
const BACKUP_FILE_HASH_PREFIX_LENGTH = 5;
// Worker-side backup export must stay well below Cloudflare CPU limits.
// Prefer store-only ZIP entries over heavier compression to keep exports reliable.
const BACKUP_TEXT_COMPRESSION_LEVEL = 0;
const BACKUP_JSON_INDENT = 2;

export interface BuildBackupArchiveOptions {
  includeAttachments?: boolean;
  progress?: BackupArchiveBuildProgressReporter;
  timeZone?: string;
}

export interface BackupArchiveBuildProgressEvent {
  step: string;
  fileName?: string;
  stageTitle: string;
  stageDetail: string;
  includeAttachments: boolean;
}

export type BackupArchiveBuildProgressReporter = (
  event: BackupArchiveBuildProgressEvent,
) => Promise<void>;

async function queryRows(
  db: D1Database,
  sql: string,
  ...values: unknown[]
): Promise<SqlRow[]> {
  const result = await db
    .prepare(sql)
    .bind(...values)
    .all<SqlRow>();
  return (result.results || []).map((row) => ({ ...row }));
}

function sanitizeConfigRowsForExport(rows: SqlRow[]): SqlRow[] {
  const sanitized: SqlRow[] = [];
  for (const row of rows) {
    const key = String(row.key || "").trim();
    if (
      !key ||
      key === BACKUP_RUNNER_LOCK_CONFIG_KEY ||
      key === YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY
    )
      continue;

    if (key === BACKUP_SETTINGS_CONFIG_KEY) {
      const portableOnly = exportPortableBackupSettingsEnvelope(
        typeof row.value === "string" ? row.value : null,
      );
      if (portableOnly) sanitized.push({ ...row, value: portableOnly });
      continue;
    }

    sanitized.push({ ...row });
  }
  return sanitized;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function getDateParts(date: Date, timeZone: string): string {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const parts = formatter.formatToParts(date);
  const pick = (type: string): string =>
    parts.find((part) => part.type === type)?.value || "";
  return `${pick("year")}${pick("month")}${pick("day")}_${pick("hour")}${pick("minute")}${pick("second")}`;
}

function buildBackupFileNameInTimeZone(
  date: Date = new Date(),
  checksumPrefix: string | null = null,
  timeZone: string = "UTC",
): string {
  const parts = getDateParts(date, timeZone);
  const suffix = checksumPrefix ? `_${checksumPrefix}` : "";
  return `nodewarden_backup_${parts}${suffix}.zip`;
}

export function extractBackupFileChecksumPrefix(
  fileName: string,
): string | null {
  const normalized = String(fileName || "").trim();
  const match = normalized.match(/_([0-9a-f]{5})\.zip$/i);
  return match ? match[1].toLowerCase() : null;
}

export async function inspectBackupArchiveFileNameChecksum(
  bytes: Uint8Array,
  fileName: string,
): Promise<BackupFileIntegrityCheckResult> {
  const expectedPrefix = extractBackupFileChecksumPrefix(fileName);
  const actualHash = await sha256Hex(bytes);
  const actualPrefix = actualHash.slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  return {
    hasChecksumPrefix: !!expectedPrefix,
    expectedPrefix,
    actualPrefix,
    matches: !expectedPrefix || actualPrefix === expectedPrefix,
  };
}

export async function verifyBackupArchiveFileNameChecksum(
  bytes: Uint8Array,
  fileName: string,
): Promise<boolean> {
  const result = await inspectBackupArchiveFileNameChecksum(bytes, fileName);
  return result.matches;
}

function createZipEntries(
  files: Record<string, Uint8Array>,
): Record<string, Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]> {
  const entries: Record<
    string,
    Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]
  > = {};
  for (const [path, bytes] of Object.entries(files)) {
    entries[path] = [bytes, { level: BACKUP_TEXT_COMPRESSION_LEVEL }];
  }
  return entries;
}

export async function buildBackupArchive(
  env: Env,
  date: Date = new Date(),
  options: BuildBackupArchiveOptions = {},
): Promise<BackupArchiveBundle> {
  const includeAttachments = options.includeAttachments !== false;
  await options.progress?.({
    step: "collect_data",
    fileName: "",
    stageTitle: "txt_backup_archive_progress_collect_title",
    stageDetail: includeAttachments
      ? "txt_backup_archive_progress_collect_with_attachments_detail"
      : "txt_backup_archive_progress_collect_detail",
    includeAttachments,
  });
  const encoder = new TextEncoder();
  const [
    configRows,
    userRows,
    domainSettingsRows,
    revisionRows,
    folderRows,
    cipherRows,
    attachmentRows,
    accountPasskeyRows,
  ] = await Promise.all([
    queryRows(env.DB, "SELECT key, value FROM config ORDER BY key ASC"),
    queryRows(
      env.DB,
      "SELECT id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5, yubikey_nfc, created_at, updated_at FROM users ORDER BY created_at ASC",
    ),
    queryRows(
      env.DB,
      "SELECT user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at FROM domain_settings ORDER BY user_id ASC",
    ),
    queryRows(
      env.DB,
      "SELECT user_id, revision_date FROM user_revisions ORDER BY user_id ASC",
    ),
    queryRows(
      env.DB,
      "SELECT id, user_id, name, created_at, updated_at FROM folders ORDER BY created_at ASC",
    ),
    queryRows(
      env.DB,
      "SELECT id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at FROM ciphers ORDER BY created_at ASC",
    ),
    queryRows(
      env.DB,
      "SELECT id, cipher_id, file_name, size, size_name, key FROM attachments ORDER BY cipher_id ASC, id ASC",
    ),
    queryRows(
      env.DB,
      "SELECT id, user_id, purpose, name, public_key, credential_id, counter, type, aa_guid, transports, encrypted_user_key, encrypted_public_key, encrypted_private_key, supports_prf, created_at, updated_at FROM webauthn_credentials ORDER BY created_at ASC",
    ),
  ]);
  const exportedConfigRows = sanitizeConfigRowsForExport(configRows);
  const exportedAttachmentRows = includeAttachments ? attachmentRows : [];
  const attachmentBlobs: BackupManifestAttachmentBlob[] =
    exportedAttachmentRows.map((row) => {
      const cipherId = String(row.cipher_id || "").trim();
      const attachmentId = String(row.id || "").trim();
      return {
        cipherId,
        attachmentId,
        blobName: getAttachmentObjectKey(cipherId, attachmentId),
        sizeBytes: Number(row.size || 0) || 0,
      };
    });

  const manifestBase = {
    formatVersion: BACKUP_FORMAT_VERSION,
    exportedAt: date.toISOString(),
    appVersion: APP_VERSION,
    storageKind: getBlobStorageKind(env),
    tableCounts: {
      config: exportedConfigRows.length,
      users: userRows.length,
      domain_settings: domainSettingsRows.length,
      user_revisions: revisionRows.length,
      folders: folderRows.length,
      ciphers: cipherRows.length,
      attachments: exportedAttachmentRows.length,
      webauthn_credentials: accountPasskeyRows.length,
    },
    includes: {
      attachments: includeAttachments,
    },
    blobSummary: {
      attachmentFiles: attachmentBlobs.length,
      totalBytes: attachmentBlobs.reduce(
        (sum, item) => sum + item.sizeBytes,
        0,
      ),
      largestObjectBytes: attachmentBlobs.reduce(
        (max, item) => Math.max(max, item.sizeBytes),
        0,
      ),
    },
    attachmentBlobs: includeAttachments ? attachmentBlobs : [],
  } satisfies BackupManifest;

  const files: Record<string, Uint8Array> = {
    "manifest.json": encoder.encode(
      JSON.stringify(manifestBase, null, BACKUP_JSON_INDENT),
    ),
    "db.json": encoder.encode(
      JSON.stringify(
        {
          config: exportedConfigRows,
          users: userRows,
          domain_settings: domainSettingsRows,
          user_revisions: revisionRows,
          folders: folderRows,
          ciphers: cipherRows,
          attachments: exportedAttachmentRows,
          webauthn_credentials: accountPasskeyRows,
        },
        null,
        BACKUP_JSON_INDENT,
      ),
    ),
  };

  await options.progress?.({
    step: "package_archive",
    fileName: "",
    stageTitle: "txt_backup_archive_progress_package_title",
    stageDetail: includeAttachments
      ? "txt_backup_archive_progress_package_with_attachments_detail"
      : "txt_backup_archive_progress_package_detail",
    includeAttachments,
  });
  const bytes = zipSync(createZipEntries(files));
  const fileHashPrefix = (await sha256Hex(bytes)).slice(
    0,
    BACKUP_FILE_HASH_PREFIX_LENGTH,
  );
  const backupTimeZone = options.timeZone || "UTC";
  const fileName = buildBackupFileNameInTimeZone(
    date,
    fileHashPrefix,
    backupTimeZone,
  );
  await options.progress?.({
    step: "archive_ready",
    fileName,
    stageTitle: "txt_backup_archive_progress_ready_title",
    stageDetail: "txt_backup_archive_progress_ready_detail",
    includeAttachments,
  });

  return {
    bytes,
    fileName,
    manifest: manifestBase,
  };
}

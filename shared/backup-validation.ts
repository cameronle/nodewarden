import { unzipSync, type UnzipFileInfo } from "fflate";
type SqlRow = Record<string, string | number | null>;
export const BACKUP_FORMAT_VERSION = 1;
export const MAX_BACKUP_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_ARCHIVE_ENTRY_COUNT = 10_000;
const MAX_BACKUP_EXTRACTED_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_DB_JSON_BYTES = 32 * 1024 * 1024;
const MAX_BACKUP_PATH_SEGMENT_LENGTH = 128;

export interface BackupManifest {
  formatVersion: 1;
  exportedAt: string;
  appVersion: string;
  storageKind: "r2" | "kv" | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
  attachmentBlobs?: BackupManifestAttachmentBlob[];
}

export interface BackupManifestAttachmentBlob {
  cipherId: string;
  attachmentId: string;
  blobName: string;
  sizeBytes: number;
}

export interface BackupPayload {
  manifest: BackupManifest;
  db: {
    config: SqlRow[];
    users: SqlRow[];
    domain_settings: SqlRow[];
    user_revisions: SqlRow[];
    folders: SqlRow[];
    ciphers: SqlRow[];
    attachments: SqlRow[];
    webauthn_credentials?: SqlRow[];
  };
}

export interface BackupArchiveBundle {
  bytes: Uint8Array;
  fileName: string;
  manifest: BackupManifest;
}

export interface BackupFileIntegrityCheckResult {
  hasChecksumPrefix: boolean;
  expectedPrefix: string | null;
  actualPrefix: string;
  matches: boolean;
}
function validateArchiveSize(bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_BACKUP_ARCHIVE_BYTES) {
    throw new Error(
      `Backup archive is too large. The current restore limit is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))} MiB`,
    );
  }
}

function isSafeBackupPathSegment(value: string): boolean {
  if (!value || value.length > MAX_BACKUP_PATH_SEGMENT_LENGTH) return false;
  if (value === "." || value === "..") return false;
  return /^[A-Za-z0-9._-]+$/.test(value);
}

export function isSafeBackupAttachmentBlobName(value: unknown): boolean {
  const normalized = String(value ?? "").trim();
  const parts = normalized.split("/");
  return parts.length === 2 && parts.every(isSafeBackupPathSegment);
}

function isSafeBackupAttachmentEntryName(value: string): boolean {
  if (!value.startsWith("attachments/") || !value.endsWith(".bin"))
    return false;
  const relative = value.slice("attachments/".length, -".bin".length);
  return isSafeBackupAttachmentBlobName(relative);
}

function validateBackupEntryName(name: string): void {
  const normalized = String(name || "").trim();
  if (normalized !== name || !normalized) {
    throw new Error("Backup archive contains an invalid file name");
  }
  if (
    normalized.includes("\\") ||
    normalized.includes("\0") ||
    normalized.startsWith("/") ||
    normalized.includes("//")
  ) {
    throw new Error(
      `Backup archive contains an unsafe file name: ${normalized}`,
    );
  }
  if (
    normalized !== "manifest.json" &&
    normalized !== "db.json" &&
    !isSafeBackupAttachmentEntryName(normalized)
  ) {
    throw new Error(
      `Backup archive contains an unsupported file: ${normalized}`,
    );
  }
}

function createBackupUnzipFilter(): (file: UnzipFileInfo) => boolean {
  let entryCount = 0;
  let totalOriginalBytes = 0;
  return (file: UnzipFileInfo): boolean => {
    entryCount += 1;
    if (entryCount > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
      throw new Error("Backup archive contains too many files");
    }
    validateBackupEntryName(file.name);
    const originalSize = Number(file.originalSize);
    if (!Number.isFinite(originalSize) || originalSize < 0) {
      throw new Error(
        `Backup archive contains an invalid file size: ${file.name}`,
      );
    }
    if (file.name === "db.json" && originalSize > MAX_BACKUP_DB_JSON_BYTES) {
      throw new Error("Backup archive database payload is too large");
    }
    totalOriginalBytes += originalSize;
    if (totalOriginalBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error(
        "Backup archive expands beyond the current restore limit",
      );
    }
    return true;
  };
}

function getRequiredZipEntries(db: BackupPayload["db"]): string[] {
  const entries: string[] = [];
  for (const row of db.attachments) {
    const cipherId = String(row.cipher_id || "").trim();
    const attachmentId = String(row.id || "").trim();
    if (!cipherId || !attachmentId) continue;
    entries.push(`attachments/${cipherId}/${attachmentId}.bin`);
  }
  return entries;
}

function ensureRowArray(value: unknown, table: string): SqlRow[] {
  if (!Array.isArray(value)) {
    throw new Error(`Backup archive table ${table} is invalid`);
  }
  return value as SqlRow[];
}

function normalizeParsedBackupDb(value: unknown): BackupPayload["db"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Backup archive database payload is invalid");
  }
  const source = value as Record<string, unknown>;
  // Restore uses an explicit allowlist. Extra tables from old or modified
  // archives, especially runtime authentication state, are intentionally ignored.
  return {
    config: source.config as SqlRow[],
    users: source.users as SqlRow[],
    domain_settings: source.domain_settings as SqlRow[],
    user_revisions: source.user_revisions as SqlRow[],
    folders: source.folders as SqlRow[],
    ciphers: source.ciphers as SqlRow[],
    attachments: source.attachments as SqlRow[],
    webauthn_credentials: source.webauthn_credentials as SqlRow[] | undefined,
  };
}
export interface ParseBackupArchiveOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function parseBackupArchive(
  bytes: Uint8Array,
  options: ParseBackupArchiveOptions = {},
): { payload: BackupPayload; files: Record<string, Uint8Array> } {
  validateArchiveSize(bytes);
  let zipped: Record<string, Uint8Array>;
  try {
    zipped = unzipSync(bytes, { filter: createBackupUnzipFilter() });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Backup archive ")) {
      throw error;
    }
    throw new Error("Invalid backup archive");
  }

  const entryNames = Object.keys(zipped);
  if (entryNames.length > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
    throw new Error("Backup archive contains too many files");
  }

  let totalExtractedBytes = 0;
  for (const entry of entryNames) {
    validateBackupEntryName(entry);
    const entryBytes = zipped[entry];
    totalExtractedBytes += entryBytes.byteLength;
    if (
      entry === "db.json" &&
      entryBytes.byteLength > MAX_BACKUP_DB_JSON_BYTES
    ) {
      throw new Error("Backup archive database payload is too large");
    }
    if (totalExtractedBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error(
        "Backup archive expands beyond the current restore limit",
      );
    }
  }

  const manifestBytes = zipped["manifest.json"];
  const dbBytes = zipped["db.json"];
  if (!manifestBytes || !dbBytes) {
    throw new Error("Backup archive is missing manifest.json or db.json");
  }

  const decoder = new TextDecoder();
  let manifest: BackupManifest;
  let rawDb: unknown;
  try {
    manifest = JSON.parse(decoder.decode(manifestBytes)) as BackupManifest;
    rawDb = JSON.parse(decoder.decode(dbBytes));
  } catch {
    throw new Error("Backup archive contains invalid JSON metadata");
  }

  if (manifest?.formatVersion !== BACKUP_FORMAT_VERSION) {
    throw new Error("Unsupported backup format version");
  }
  const db = normalizeParsedBackupDb(rawDb);

  const externalAttachmentKeys = new Set<string>(
    options.allowExternalAttachmentBlobs
      ? (manifest.attachmentBlobs || []).map(
          (item) =>
            `attachments/${String(item.cipherId || "").trim()}/${String(item.attachmentId || "").trim()}.bin`,
        )
      : [],
  );
  const requiredEntries = getRequiredZipEntries(db).filter(
    (entry) => !externalAttachmentKeys.has(entry),
  );
  for (const entry of requiredEntries) {
    if (!zipped[entry]) {
      throw new Error(`Backup archive is missing required file: ${entry}`);
    }
  }

  return {
    payload: { manifest, db },
    files: zipped,
  };
}

export interface ValidateBackupPayloadOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function validateBackupPayloadContents(
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  options: ValidateBackupPayloadOptions = {},
): void {
  const configRows = ensureRowArray(payload.db.config, "config");
  const userRows = ensureRowArray(payload.db.users, "users");
  const revisionRows = ensureRowArray(
    payload.db.user_revisions,
    "user_revisions",
  );
  const domainSettingsRows = ensureRowArray(
    payload.db.domain_settings || [],
    "domain_settings",
  );
  const folderRows = ensureRowArray(payload.db.folders, "folders");
  const cipherRows = ensureRowArray(payload.db.ciphers, "ciphers");
  const attachmentRows = ensureRowArray(payload.db.attachments, "attachments");
  const accountPasskeyRows = ensureRowArray(
    payload.db.webauthn_credentials || [],
    "webauthn_credentials",
  );
  const externalAttachmentKeys = new Set<string>(
    options.allowExternalAttachmentBlobs
      ? (payload.manifest.attachmentBlobs || []).map(
          (item) =>
            `attachments/${String(item.cipherId || "").trim()}/${String(item.attachmentId || "").trim()}.bin`,
        )
      : [],
  );

  const userIds = new Set<string>();
  for (const row of userRows) {
    const id = String(row.id || "").trim();
    const email = String(row.email || "").trim();
    if (!id || !email)
      throw new Error("Backup archive contains an invalid user row");
    if (userIds.has(id))
      throw new Error(`Backup archive contains duplicate user id: ${id}`);
    userIds.add(id);
  }

  for (const row of configRows) {
    const key = String(row.key || "").trim();
    if (!key) throw new Error("Backup archive contains an invalid config row");
  }

  for (const row of revisionRows) {
    const userId = String(row.user_id || "").trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(
        `Backup archive contains a revision for an unknown user: ${userId || "(empty)"}`,
      );
    }
  }

  const domainSettingUserIds = new Set<string>();
  for (const row of domainSettingsRows) {
    const userId = String(row.user_id || "").trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(
        `Backup archive contains domain settings for an unknown user: ${userId || "(empty)"}`,
      );
    }
    if (domainSettingUserIds.has(userId)) {
      throw new Error(
        `Backup archive contains duplicate domain settings for user: ${userId}`,
      );
    }
    domainSettingUserIds.add(userId);
  }

  const folderIds = new Set<string>();
  for (const row of folderRows) {
    const id = String(row.id || "").trim();
    const userId = String(row.user_id || "").trim();
    if (!id || !userIds.has(userId))
      throw new Error("Backup archive contains an invalid folder row");
    if (folderIds.has(id))
      throw new Error(`Backup archive contains duplicate folder id: ${id}`);
    folderIds.add(id);
  }

  const cipherIds = new Set<string>();
  for (const row of cipherRows) {
    const id = String(row.id || "").trim();
    const userId = String(row.user_id || "").trim();
    const folderId = String(row.folder_id || "").trim();
    if (!id || !userIds.has(userId))
      throw new Error("Backup archive contains an invalid cipher row");
    if (folderId && !folderIds.has(folderId)) {
      throw new Error(
        `Backup archive contains a cipher for an unknown folder: ${folderId}`,
      );
    }
    if (cipherIds.has(id))
      throw new Error(`Backup archive contains duplicate cipher id: ${id}`);
    cipherIds.add(id);
  }

  for (const row of attachmentRows) {
    const id = String(row.id || "").trim();
    const cipherId = String(row.cipher_id || "").trim();
    if (
      !id ||
      !cipherId ||
      !isSafeBackupPathSegment(id) ||
      !isSafeBackupPathSegment(cipherId) ||
      !cipherIds.has(cipherId)
    ) {
      throw new Error("Backup archive contains an invalid attachment row");
    }
    const attachmentPath = `attachments/${cipherId}/${id}.bin`;
    if (!files[attachmentPath] && !externalAttachmentKeys.has(attachmentPath)) {
      throw new Error(
        `Backup archive is missing required file: attachments/${cipherId}/${id}.bin`,
      );
    }
  }

  const accountPasskeyIds = new Set<string>();
  const accountPasskeyCredentialIds = new Set<string>();
  for (const row of accountPasskeyRows) {
    const id = String(row.id || "").trim();
    const userId = String(row.user_id || "").trim();
    const purpose =
      row.purpose == null ? "login" : String(row.purpose || "").trim();
    const credentialId = String(row.credential_id || "").trim();
    const publicKey = String(row.public_key || "").trim();
    if (
      !id ||
      !userIds.has(userId) ||
      !credentialId ||
      !publicKey ||
      (purpose !== "login" && purpose !== "twoFactor")
    ) {
      throw new Error("Backup archive contains an invalid account passkey row");
    }
    if (accountPasskeyIds.has(id))
      throw new Error(
        `Backup archive contains duplicate account passkey id: ${id}`,
      );
    if (accountPasskeyCredentialIds.has(credentialId))
      throw new Error(
        `Backup archive contains duplicate account passkey credential id: ${credentialId}`,
      );
    accountPasskeyIds.add(id);
    accountPasskeyCredentialIds.add(credentialId);
  }
}

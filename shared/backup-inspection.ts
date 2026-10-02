import {
  parseBackupArchive,
  validateBackupPayloadContents,
  MAX_BACKUP_ARCHIVE_BYTES,
} from "./backup-validation.js";
const TABLES = [
  "config",
  "users",
  "domain_settings",
  "user_revisions",
  "folders",
  "ciphers",
  "attachments",
  "webauthn_credentials",
] as const;
const fail = (): never => {
  throw new Error("Invalid or incomplete backup archive");
};
const crcTable = Uint32Array.from({ length: 256 }, (_, i) => {
  let c = i;
  for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(bytes: Uint8Array) {
  let c = 0xffffffff;
  for (const b of bytes) c = crcTable[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
// Inspect the central directory before decompression: bounds, duplicate names, local headers and CRC.
export function inspectBackupBytes(bytes: Uint8Array) {
  if (bytes.length < 22 || bytes.length > MAX_BACKUP_ARCHIVE_BYTES) fail();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    u16 = (i: number) => view.getUint16(i, true),
    u32 = (i: number) => view.getUint32(i, true);
  let end = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--)
    if (u32(i) === 0x06054b50 && i + 22 + u16(i + 20) === bytes.length) {
      end = i;
      break;
    }
  if (
    end < 0 ||
    u16(end + 4) !== 0 ||
    u16(end + 6) !== 0 ||
    u16(end + 8) !== u16(end + 10)
  )
    fail();
  const count = u16(end + 10),
    start = u32(end + 16),
    centralSize = u32(end + 12);
  if (count > 10000 || start + centralSize !== end) fail();
  const entries = new Map<string, { crc: number; size: number }>(),
    ranges: Array<[number, number]> = [],
    decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  let pos = start,
    total = 0;
  for (let i = 0; i < count; i++) {
    if (pos + 46 > end || u32(pos) !== 0x02014b50) fail();
    const flags = u16(pos + 8),
      method = u16(pos + 10),
      crc = u32(pos + 16),
      compressed = u32(pos + 20),
      size = u32(pos + 24),
      nameLen = u16(pos + 28),
      extra = u16(pos + 30),
      comment = u16(pos + 32),
      local = u32(pos + 42);
    if (
      (flags & 1) !== 0 ||
      (method !== 0 && method !== 8) ||
      u16(pos + 34) !== 0 ||
      pos + 46 + nameLen + extra + comment > end ||
      local + 30 > start
    )
      fail();
    const name = decoder.decode(bytes.subarray(pos + 46, pos + 46 + nameLen));
    if (
      entries.has(name) ||
      size > MAX_BACKUP_ARCHIVE_BYTES ||
      compressed > MAX_BACKUP_ARCHIVE_BYTES
    )
      fail();
    total += size;
    if (
      total > MAX_BACKUP_ARCHIVE_BYTES ||
      (name === "db.json" && size > 32 * 1024 * 1024)
    )
      fail();
    if (
      u32(local) !== 0x04034b50 ||
      u16(local + 6) !== flags ||
      u16(local + 8) !== method
    )
      fail();
    const localName = u16(local + 26),
      localExtra = u16(local + 28),
      data = local + 30 + localName + localExtra,
      tail = data + compressed;
    if (
      tail > start ||
      decoder.decode(bytes.subarray(local + 30, local + 30 + localName)) !==
        name
    )
      fail();
    let rangeEnd = tail;
    if (flags & 8) {
      const marker = tail + 4 <= start && u32(tail) === 0x08074b50 ? 4 : 0;
      if (
        tail + marker + 12 > start ||
        u32(tail + marker) !== crc ||
        u32(tail + marker + 4) !== compressed ||
        u32(tail + marker + 8) !== size
      )
        fail();
      rangeEnd = tail + marker + 12;
    } else if (
      u32(local + 14) !== crc ||
      u32(local + 18) !== compressed ||
      u32(local + 22) !== size
    )
      fail();
    ranges.push([local, rangeEnd]);
    entries.set(name, { crc, size });
    pos += 46 + nameLen + extra + comment;
  }
  if (pos !== end) fail();
  ranges.sort((a, b) => a[0] - b[0]);
  let last = 0;
  for (const [begin, finish] of ranges) {
    if (begin !== last) fail();
    last = finish;
  }
  if (last !== start) fail();
  const parsed = parseBackupArchive(bytes);
  validateBackupPayloadContents(parsed.payload, parsed.files);
  for (const [name, meta] of entries) {
    const file = parsed.files[name];
    if (!file || file.length !== meta.size || crc32(file) !== meta.crc) fail();
  }
  const { manifest, db } = parsed.payload;
  if (
    !manifest.includes ||
    typeof manifest.includes.attachments !== "boolean" ||
    !manifest.tableCounts ||
    !manifest.blobSummary
  )
    fail();
  const counts = Object.fromEntries(
    TABLES.map((t) => {
      const rows = db[t] || [];
      if (
        rows.some(
          (row) =>
            !row ||
            typeof row !== "object" ||
            Array.isArray(row) ||
            Object.values(row).some(
              (v) =>
                v !== null &&
                typeof v !== "string" &&
                (typeof v !== "number" || !Number.isFinite(v)),
            ),
        )
      )
        fail();
      if (manifest.tableCounts[t] !== rows.length) fail();
      return [t, rows.length];
    }),
  ) as Record<(typeof TABLES)[number], number>;
  const paths = new Set(
    db.attachments.map((r) => `attachments/${r.cipher_id}/${r.id}.bin`),
  );
  if (paths.size !== db.attachments.length) fail();
  let attachmentBytes = 0,
    largest = 0;
  for (const row of db.attachments) {
    const size =
      parsed.files[`attachments/${row.cipher_id}/${row.id}.bin`].length;
    if (Number(row.size) !== size) fail();
    attachmentBytes += size;
    largest = Math.max(largest, size);
  }
  for (const name of entries.keys())
    if (name.startsWith("attachments/") && !paths.has(name)) fail();
  if (
    manifest.blobSummary.attachmentFiles !== paths.size ||
    manifest.blobSummary.totalBytes !== attachmentBytes ||
    manifest.blobSummary.largestObjectBytes !== largest
  )
    fail();
  return {
    payload: parsed.payload,
    files: parsed.files,
    report: {
      formatVersion: 1,
      structureValid: true,
      crcVerified: true,
      counts,
      includesAttachments: manifest.includes.attachments,
      attachmentFiles: paths.size,
      attachmentBytes,
      restoreExecuted: false,
      restoreVerified: false,
      vaultDecrypted: false,
      warning:
        "Structure/CRC checks do not prove credentials or vault unlock. API keys and runtime sessions are not restored; portable backup credentials may need trusted Web repair.",
    },
  };
}

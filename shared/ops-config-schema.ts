// Only non-secret configuration belongs in public operation parameters.
export interface BackupChange {
  type?: "s3" | "webdav";
  name?: string;
  includeAttachments?: boolean;
  destination?: Record<string, string>;
  schedule?: {
    enabled?: boolean;
    intervalHours?: number;
    startTime?: string;
    timezone?: string;
    retentionCount?: number | null;
  };
}
export interface ConfigurationParameters {
  expectedRevision?: string;
  mutation?: "add" | "update" | "remove";
  destinationId?: string;
  change?: BackupChange;
  credentialFields?: string[];
  retentionDays?: number | null;
  maxEntries?: number | null;
  throughRowId?: number;
  userId?: string;
  status?: "active" | "banned";
}
const fail = (): never => {
  throw new Error("Invalid configuration parameters");
};
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return fail();
  return value as Record<string, unknown>;
}
function fields(
  value: Record<string, unknown>,
  allowed: string[],
  required = allowed,
) {
  if (
    Object.keys(value).some((k) => !allowed.includes(k)) ||
    required.some((k) => !Object.hasOwn(value, k))
  )
    return fail();
}
function clean(value: unknown, max = 512): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > max ||
    value !== value.trim() ||
    /[\x00-\x1f\x7f]/.test(value)
  )
    return fail();
  return value;
}
export function backupChange(value: unknown): BackupChange {
  const p = object(value);
  fields(
    p,
    ["type", "name", "includeAttachments", "destination", "schedule"],
    [],
  );
  if (!Object.keys(p).length) return fail();
  const out: BackupChange = {};
  if ("type" in p) {
    if (p.type !== "s3" && p.type !== "webdav") return fail();
    out.type = p.type as "s3" | "webdav";
  }
  if ("name" in p) out.name = clean(p.name, 128);
  if ("includeAttachments" in p) {
    if (typeof p.includeAttachments !== "boolean") return fail();
    out.includeAttachments = p.includeAttachments;
  }
  if ("destination" in p) {
    const d = object(p.destination);
    fields(
      d,
      [
        "endpoint",
        "bucket",
        "addressingStyle",
        "region",
        "rootPath",
        "baseUrl",
        "remotePath",
      ],
      [],
    );
    if (!Object.keys(d).length) return fail();
    out.destination = {};
    for (const k of Object.keys(d).sort()) {
      const v = d[k];
      if ((k === "rootPath" || k === "remotePath") && v === "") {
        out.destination[k] = "";
        continue;
      }
      const s = clean(v, 2048);
      if (k === "endpoint" || k === "baseUrl") {
        const u = new URL(s);
        if (
          u.protocol !== "https:" ||
          u.username ||
          u.password ||
          u.search ||
          u.hash
        )
          return fail();
      }
      if (
        k === "addressingStyle" &&
        !["path-style", "virtual-hosted-style"].includes(s)
      )
        return fail();
      if (
        (k === "rootPath" || k === "remotePath") &&
        (/[\\%?#]/.test(s) ||
          s.split("/").some((x) => !x || x === "." || x === ".."))
      )
        return fail();
      out.destination[k] = s;
    }
  }
  if ("schedule" in p) {
    const s = object(p.schedule);
    fields(
      s,
      ["enabled", "intervalHours", "startTime", "timezone", "retentionCount"],
      [],
    );
    if (!Object.keys(s).length) return fail();
    const schedule: NonNullable<BackupChange["schedule"]> = {};
    if ("enabled" in s) {
      if (typeof s.enabled !== "boolean") return fail();
      schedule.enabled = s.enabled;
    }
    if ("intervalHours" in s) {
      if (
        !Number.isInteger(s.intervalHours) ||
        Number(s.intervalHours) < 1 ||
        Number(s.intervalHours) > 99
      )
        return fail();
      schedule.intervalHours = s.intervalHours as number;
    }
    if ("startTime" in s) {
      const v = clean(s.startTime);
      if (!/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(v)) return fail();
      schedule.startTime = v;
    }
    if ("timezone" in s) {
      const v = clean(s.timezone, 128);
      new Intl.DateTimeFormat("en-US", { timeZone: v });
      schedule.timezone = v;
    }
    if ("retentionCount" in s) {
      const v = s.retentionCount;
      if (
        v !== null &&
        (!Number.isInteger(v) || Number(v) < 1 || Number(v) > 1000)
      )
        return fail();
      schedule.retentionCount = v as number | null;
    }
    out.schedule = schedule;
  }
  return out;
}
export function configurationParameters(
  action: unknown,
  value: unknown,
): {
  action:
    | "backup.configure"
    | "audit.configure"
    | "audit.clear"
    | "user.status";
  parameters: ConfigurationParameters;
} | null {
  if (
    ![
      "backup.configure",
      "audit.configure",
      "audit.clear",
      "user.status",
    ].includes(String(action))
  )
    return null;
  const p = object(value),
    revision = clean(p.expectedRevision, 64);
  if (!/^[a-f0-9]{64}$/.test(revision)) return fail();
  if (action === "backup.configure") {
    fields(p, [
      "expectedRevision",
      "mutation",
      "destinationId",
      "change",
      "credentialFields",
    ]);
    if (!["add", "update", "remove"].includes(String(p.mutation)))
      return fail();
    const id = clean(p.destinationId, 128);
    if (!/^[a-zA-Z0-9_-]+$/.test(id)) return fail();
    if (
      !Array.isArray(p.credentialFields) ||
      p.credentialFields.some(
        (k) =>
          typeof k !== "string" ||
          !["username", "password", "accessKeyId", "secretAccessKey"].includes(
            k,
          ),
      ) ||
      new Set(p.credentialFields).size !== p.credentialFields.length
    )
      return fail();
    const change =
      p.mutation === "remove"
        ? Object.keys(object(p.change)).length === 0
          ? {}
          : fail()
        : backupChange(p.change);
    if (p.mutation === "remove" && p.credentialFields.length) return fail();
    return {
      action,
      parameters: {
        expectedRevision: revision,
        mutation: p.mutation as "add" | "update" | "remove",
        destinationId: id,
        change,
        credentialFields: [...p.credentialFields].sort(),
      },
    };
  }
  if (action === "audit.clear") {
    fields(p, ["expectedRevision", "throughRowId"]);
    if (!Number.isSafeInteger(p.throughRowId) || Number(p.throughRowId) < 1)
      return fail();
    return {
      action,
      parameters: {
        expectedRevision: revision,
        throughRowId: p.throughRowId as number,
      },
    };
  }
  if (action === "audit.configure") {
    fields(p, ["expectedRevision", "retentionDays", "maxEntries"]);
    if (
      p.retentionDays !== null &&
      ![7, 30, 90, 180, 365].includes(p.retentionDays as number)
    )
      return fail();
    if (
      p.maxEntries !== null &&
      ![1000, 5000, 10000, 50000].includes(p.maxEntries as number)
    )
      return fail();
    if (p.retentionDays !== null && p.maxEntries !== null) return fail();
    return {
      action,
      parameters: {
        expectedRevision: revision,
        retentionDays: p.retentionDays as number | null,
        maxEntries: p.maxEntries as number | null,
      },
    };
  }
  fields(p, ["expectedRevision", "userId", "status"]);
  const id = clean(p.userId, 128);
  if (
    !/^[A-Za-z0-9_-]+$/.test(id) ||
    !["active", "banned"].includes(String(p.status))
  )
    return fail();
  return {
    action: "user.status",
    parameters: {
      expectedRevision: revision,
      userId: id,
      status: p.status as "active" | "banned",
    },
  };
}
export function credentials(
  value: unknown,
  keys: string[],
): Record<string, string> {
  if (
    keys.some(
      (k) =>
        !["username", "password", "accessKeyId", "secretAccessKey"].includes(k),
    )
  )
    return fail();
  const c = value === undefined ? {} : object(value);
  fields(c, keys, keys);
  const out: Record<string, string> = {};
  for (const k of [...keys].sort()) {
    const v = c[k];
    if (
      typeof v !== "string" ||
      !v ||
      v.length > 2048 ||
      v === "***" ||
      /[\x00-\x1f\x7f]/.test(v) ||
      (k !== "password" && v !== v.trim())
    )
      return fail();
    out[k] = v;
  }
  return out;
}

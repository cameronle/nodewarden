import type { Command } from "commander";
import { Context, numberOption } from "./context.js";
import { record, text, identity } from "./contracts.js";
import { invalid, incompatible, CliError } from "./errors.js";
import { identifier, mutationOptions } from "./mutations.js";
import { requestOperation } from "./step-up.js";
import { privateJson } from "./private-input.js";
import { rememberSecret } from "./output.js";
import {
  backupChange,
  credentials,
  object,
} from "../../../shared/ops-config-schema.js";
import type { OpsAction, OpsParameters } from "../../../shared/ops-schema.js";
const boolean = (v: unknown): boolean => {
  if (v === "true") return true;
  if (v === "false") return false;
  return invalid("Boolean values must be exactly true or false.");
};
const nullable = (v: unknown, min: number, max: number) =>
  v === "none"
    ? null
    : typeof v === "string"
      ? numberOption(v, min, max)
      : invalid("Explicit policy value required.");
export function configPath(action: OpsAction, p: OpsParameters) {
  if (action === "backup.configure") return "/api/ops/config/backup";
  if (action === "audit.configure") return "/api/ops/config/audit";
  if (action === "audit.clear")
    return "/api/ops/config/audit-clear/" + p.throughRowId;
  if (action === "user.status") return "/api/ops/config/user/" + p.userId;
  return incompatible();
}
export async function readConfiguration(c: Context, path: string) {
  const r = record(await c.query(path));
  if (typeof r.revision !== "string" || !/^[a-f0-9]{64}$/.test(r.revision))
    return incompatible();
  if (path === "/api/ops/config/backup") {
    if (r.object !== "ops-backup-config" || !Array.isArray(r.destinations))
      return incompatible();
    const seen = new Set<string>();
    const destinations = r.destinations.map((v) => {
      const d = record(v),
        id = text(d.id);
      identifier(id);
      if (seen.has(id)) return incompatible();
      seen.add(id);
      let change;
      try {
        change = backupChange({
          type: d.type,
          name: d.name,
          includeAttachments: d.includeAttachments,
          destination: d.destination,
          schedule: d.schedule,
        });
      } catch {
        return incompatible();
      }
      const present = record(d.credentialsPresent);
      const names =
        d.type === "s3"
          ? ["accessKeyId", "secretAccessKey"]
          : ["username", "password"];
      for (const k of names)
        if (typeof present[k] !== "boolean") return incompatible();
      return {
        id,
        ...change,
        credentialsPresent: Object.fromEntries(
          names.map((k) => [k, present[k]]),
        ),
      };
    });
    return { object: r.object, revision: r.revision, destinations };
  }
  if (path.startsWith("/api/ops/config/audit-clear")) {
    if (
      r.object !== "ops-audit-clear" ||
      !Number.isSafeInteger(r.throughRowId) ||
      Number(r.throughRowId) < 0 ||
      !Number.isSafeInteger(r.count) ||
      Number(r.count) < 0
    )
      return incompatible();
    return {
      object: r.object,
      revision: r.revision,
      throughRowId: r.throughRowId,
      count: r.count,
    };
  }
  if (path === "/api/ops/config/audit") {
    if (
      r.object !== "ops-audit-config" ||
      ![null, 7, 30, 90, 180, 365].includes(r.retentionDays as any) ||
      ![null, 1000, 5000, 10000, 50000].includes(r.maxEntries as any) ||
      (r.retentionDays !== null && r.maxEntries !== null)
    )
      return incompatible();
    return {
      object: r.object,
      revision: r.revision,
      retentionDays: r.retentionDays,
      maxEntries: r.maxEntries,
    };
  }
  if (
    r.object !== "ops-user-config" ||
    path !== "/api/ops/config/user/" + r.id ||
    !["user", "admin"].includes(String(r.role)) ||
    !["active", "banned"].includes(String(r.status))
  )
    return incompatible();
  return {
    object: r.object,
    revision: r.revision,
    id: text(r.id),
    email: text(r.email),
    role: r.role,
    status: r.status,
  };
}
export async function verifyConfiguration(
  c: Context,
  action: OpsAction,
  p: OpsParameters,
  result: unknown,
  status: Record<string, unknown>,
) {
  const response = record(result);
  if (action === "audit.clear") {
    const summary = record(status.summary);
    if (
      response.object !== "ops-audit-clear-result" ||
      response.action !== action ||
      response.throughRowId !== p.throughRowId ||
      response.deleted !== summary.count
    )
      return incompatible();
    const after = await readConfiguration(c, configPath(action, p));
    if (after.count !== 0)
      throw new CliError(
        "VERIFY_FAILED",
        "Reviewed audit snapshot may not be fully cleared. Inspect before retrying.",
        6,
      );
    return {
      action,
      verified: true,
      throughRowId: p.throughRowId,
      deleted: response.deleted,
      newerLogsPreserved: true,
    };
  }
  if (
    response.object !== "ops-config-result" ||
    response.action !== action ||
    typeof response.revision !== "string"
  )
    return incompatible();
  const after = await readConfiguration(c, configPath(action, p));
  // Bind read-back to the exact committed revision, not merely an HTTP success.
  if (after.revision !== response.revision)
    throw new CliError(
      "VERIFY_FAILED",
      "Configuration may have changed; exact committed revision read-back failed. Inspect before retrying.",
      6,
    );
  const summary = record(status.summary);
  if (action === "backup.configure") {
    const found = (after as any).destinations.find(
      (d: any) => d.id === p.destinationId,
    );
    if (p.mutation === "remove" ? !!found : !found) incompatible();
    if (found) {
      const expected = record(summary.after);
      if (
        JSON.stringify(found) !==
        JSON.stringify({
          id: expected.id,
          ...backupChange({
            type: expected.type,
            name: expected.name,
            includeAttachments: expected.includeAttachments,
            destination: expected.destination,
            schedule: expected.schedule,
          }),
          credentialsPresent: expected.credentialsPresent,
        })
      )
        incompatible();
    }
  } else if (action === "audit.configure") {
    if (
      (after as any).retentionDays !== p.retentionDays ||
      (after as any).maxEntries !== p.maxEntries
    )
      incompatible();
  } else if (
    (after as any).id !== p.userId ||
    (after as any).status !== p.status
  )
    incompatible();
  return {
    action,
    verified: true,
    revision: after.revision,
    configuration: after,
  };
}
async function backupRequest(
  c: Context,
  opts: any,
  id: string,
  mutation: "add" | "update" | "remove",
  changeValue?: unknown,
  secret?: Record<string, string>,
) {
  identifier(id);
  const before = await readConfiguration(c, "/api/ops/config/backup");
  const target = (before as any).destinations.find((d: any) => d.id === id);
  if (mutation === "add" ? !!target : !target)
    return invalid("Destination does not match the requested mutation.");
  let change = {};
  if (mutation !== "remove") {
    try {
      change = backupChange(changeValue);
    } catch {
      return invalid(
        "Invalid non-secret backup change; inspect the documented JSON schema.",
      );
    }
  }
  await requestOperation(
    c,
    {
      ...opts,
      credentials: secret,
      preview: {
        before: target || null,
        change,
        credentialFieldsChanged: Object.keys(secret || {}),
        effect:
          "Only this configuration changes. Future retention may delete remote archives. Web approval required.",
      },
    },
    "backup.configure",
    {
      expectedRevision: before.revision,
      mutation,
      destinationId: id,
      change,
      credentialFields: Object.keys(secret || {}).sort(),
    },
  );
}
export function backupConfiguration(group: Command, c: Context) {
  const destinations = group.commands.find((x) => x.name() === "destinations")!;
  for (const mutation of ["add", "update"] as const) {
    mutationOptions(
      destinations
        .command(mutation + " <id>")
        .requiredOption(
          "--file <path>",
          "Owned 0600 JSON: {change, credentials?}; no secrets in argv",
        ),
    ).action(
      c.action("backup destinations " + mutation, async (id, opts) => {
        let document: Record<string, unknown>;
        try {
          document = object(await privateJson(opts.file));
        } catch {
          return invalid("Invalid private configuration document.");
        }
        if (
          Object.keys(document).some(
            (k) => !["change", "credentials"].includes(k),
          ) ||
          !Object.hasOwn(document, "change")
        )
          return invalid("Expected {change, credentials?}.");
        let secret: Record<string, string>;
        try {
          const raw =
            document.credentials === undefined
              ? {}
              : object(document.credentials);
          secret = credentials(raw, Object.keys(raw));
          if (
            Object.keys(secret).some(
              (k) =>
                ![
                  "username",
                  "password",
                  "accessKeyId",
                  "secretAccessKey",
                ].includes(k),
            )
          )
            return invalid("Unsupported credential field.");
        } catch {
          return invalid("Invalid credential document; contents suppressed.");
        }
        for (const value of Object.values(secret)) rememberSecret(value);
        await backupRequest(c, opts, id, mutation, document.change, secret);
      }),
    );
  }
  mutationOptions(
    destinations
      .command("remove <id>")
      .description(
        "Remove one configuration only; never remote archives or R2",
      ),
  ).action(
    c.action("backup destinations remove", async (id, opts) =>
      backupRequest(c, opts, id, "remove"),
    ),
  );
  const schedule = group
    .command("schedule")
    .description("Browser-approved schedule and attachment settings");
  schedule.command("show <id>").action(
    c.action("backup schedule show", async (id) => {
      identifier(id);
      const r = await readConfiguration(c, "/api/ops/config/backup");
      const d = (r as any).destinations.find((d: any) => d.id === id);
      if (!d) return invalid("Destination not found.");
      c.print({
        id,
        revision: r.revision,
        schedule: d.schedule,
        includeAttachments: d.includeAttachments,
      });
    }),
  );
  mutationOptions(
    schedule
      .command("set <id>")
      .option("--enabled <true|false>", "Explicit schedule state")
      .option("--interval-hours <n>", "1–99 hours")
      .option("--start-time <HH:mm>", "Canonical 24-hour local start time")
      .option("--timezone <name>", "IANA timezone")
      .option("--retention <n|none>", "1–1000 archives or none (no pruning)")
      .option(
        "--include-attachments <true|false>",
        "Explicit future-backup attachment policy",
      ),
  ).action(
    c.action("backup schedule set", async (id, opts) => {
      const s: Record<string, unknown> = {};
      if (opts.enabled !== undefined) s.enabled = boolean(opts.enabled);
      if (opts.intervalHours !== undefined)
        s.intervalHours = numberOption(opts.intervalHours, 1, 99);
      if (opts.startTime !== undefined) s.startTime = opts.startTime;
      if (opts.timezone !== undefined) s.timezone = opts.timezone;
      if (opts.retention !== undefined)
        s.retentionCount = nullable(opts.retention, 1, 1000);
      const change: Record<string, unknown> = {};
      if (Object.keys(s).length) change.schedule = s;
      if (opts.includeAttachments !== undefined)
        change.includeAttachments = boolean(opts.includeAttachments);
      if (!Object.keys(change).length)
        return invalid("Specify at least one schedule or attachment setting.");
      await backupRequest(c, opts, id, "update", change);
    }),
  );
}
export function auditConfiguration(settings: Command, c: Context) {
  mutationOptions(
    settings
      .command("set")
      .description("IMMEDIATE irreversible pruning after browser approval")
      .option(
        "--retention-days <n|none>",
        "7,30,90,180,365 or none; selects time policy",
      )
      .option(
        "--max-entries <n|none>",
        "1000,5000,10000,50000 or none; selects row policy",
      ),
  ).action(
    c.action("audit settings set", async (opts) => {
      if (
        (opts.retentionDays !== undefined) ===
        (opts.maxEntries !== undefined)
      )
        return invalid("Specify exactly one policy selector.");
      const before = await readConfiguration(c, "/api/ops/config/audit");
      const retentionDays =
        opts.retentionDays === undefined
          ? null
          : nullable(opts.retentionDays, 1, 365);
      const maxEntries =
        opts.maxEntries === undefined
          ? null
          : nullable(opts.maxEntries, 1000, 50000);
      await requestOperation(
        c,
        {
          ...opts,
          preview: {
            before,
            effect:
              "Saving IMMEDIATELY and irreversibly prunes old logs. --yes does not bypass Web approval.",
          },
        },
        "audit.configure",
        { expectedRevision: before.revision, retentionDays, maxEntries },
      );
    }),
  );
}
export function userStatus(group: Command, c: Context) {
  for (const verb of ["ban", "unban"])
    mutationOptions(
      group
        .command(verb + " <id>")
        .description("Explicit user ID; Web approval; no vault deletion"),
    ).action(
      c.action("users " + verb, async (id, opts) => {
        identifier(id);
        const before = await readConfiguration(c, "/api/ops/config/user/" + id);
        if (before.id === identity(await c.query("/api/accounts/profile")).id)
          return invalid("Cannot change current account status.");
        await requestOperation(c, { ...opts, preview: before }, "user.status", {
          expectedRevision: before.revision,
          userId: id,
          status: verb === "ban" ? "banned" : "active",
        });
      }),
    );
}

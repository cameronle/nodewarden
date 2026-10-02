import { bulkParameters, type BulkTarget } from "./ops-bulk-schema.js";
import {
  configurationParameters,
  type ConfigurationParameters,
} from "./ops-config-schema.js";
export type OpsAction =
  | "invite.create"
  | "invite.revoke"
  | "invite.prune"
  | "backup.run"
  | "backup.download"
  | "backup.verify"
  | "backup.export"
  | "device.remove"
  | "device.revoke-trust"
  | "backup.configure"
  | "audit.configure"
  | "audit.clear"
  | "user.status";
export interface OpsParameters extends ConfigurationParameters {
  expiresInHours?: number;
  inviteId?: string;
  targets?: BulkTarget[];
  includeCurrent?: boolean;
  includeAttachments?: boolean;
  destinationId?: string;
  path?: string;
}
export function opsParameters(
  action: unknown,
  value: unknown,
): { action: OpsAction; parameters: OpsParameters } {
  const bulk = bulkParameters(action, value);
  if (bulk) return bulk;
  const configured = configurationParameters(action, value);
  if (configured) return configured;
  const fail = (): never => {
    throw new Error("Invalid operation or parameters");
  };
  if (!value || typeof value !== "object" || Array.isArray(value))
    return fail();
  const p = value as Record<string, unknown>;
  const exact = (keys: string[]) =>
    Object.keys(p).length === keys.length &&
    keys.every((k) => Object.hasOwn(p, k));
  if (action === "backup.export") {
    if (
      !exact(["includeAttachments"]) ||
      typeof p.includeAttachments !== "boolean"
    )
      return fail();
    return { action, parameters: { includeAttachments: p.includeAttachments } };
  }
  if (action === "invite.create") {
    if (
      !exact(["expiresInHours"]) ||
      !Number.isInteger(p.expiresInHours) ||
      Number(p.expiresInHours) < 1 ||
      Number(p.expiresInHours) > 720
    )
      return fail();
    return {
      action,
      parameters: { expiresInHours: p.expiresInHours as number },
    };
  }
  if (action === "invite.revoke") {
    if (
      !exact(["inviteId"]) ||
      typeof p.inviteId !== "string" ||
      !/^[a-f0-9]{64}$/.test(p.inviteId)
    )
      return fail();
    return { action, parameters: { inviteId: p.inviteId } };
  }
  if (
    action === "backup.run" ||
    action === "backup.download" ||
    action === "backup.verify"
  ) {
    if (
      !exact(
        action === "backup.run" ? ["destinationId"] : ["destinationId", "path"],
      ) ||
      typeof p.destinationId !== "string" ||
      !/^[a-zA-Z0-9_-]{1,128}$/.test(p.destinationId)
    )
      return fail();
    if (action === "backup.run")
      return { action, parameters: { destinationId: p.destinationId } };
    if (
      typeof p.path !== "string" ||
      p.path.length > 2048 ||
      p.path !== p.path.trim() ||
      /[\x00-\x1f\x7f\\%?#]/.test(p.path) ||
      p.path.split("/").some((s) => !s || s === "." || s === "..") ||
      !p.path.endsWith(".zip")
    )
      return fail();
    return {
      action,
      parameters: { destinationId: p.destinationId, path: p.path },
    };
  }
  return fail();
}

export type OpsAction =
  | "invite.create"
  | "invite.revoke"
  | "backup.run"
  | "backup.download"
  | "backup.verify";
export interface OpsParameters {
  expiresInHours?: number;
  inviteId?: string;
  destinationId?: string;
  path?: string;
}
export function opsParameters(
  action: unknown,
  value: unknown,
): { action: OpsAction; parameters: OpsParameters } {
  const fail = (): never => {
    throw new Error("Invalid operation or parameters");
  };
  if (!value || typeof value !== "object" || Array.isArray(value))
    return fail();
  const p = value as Record<string, unknown>;
  const exact = (keys: string[]) =>
    Object.keys(p).length === keys.length &&
    keys.every((k) => Object.hasOwn(p, k));
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

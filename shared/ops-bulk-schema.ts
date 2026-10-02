export interface BulkTarget {
  id: string;
  revision: string;
}
export function bulkParameters(action: unknown, value: unknown) {
  if (
    action !== "device.remove" &&
    action !== "device.revoke-trust" &&
    action !== "invite.prune"
  )
    return null;
  const fail = (): never => {
    throw new Error("Invalid bulk parameters");
  };
  if (!value || typeof value !== "object" || Array.isArray(value))
    return fail();
  const p = value as Record<string, unknown>;
  if (
    Object.keys(p).length !== (action === "invite.prune" ? 1 : 2) ||
    !Object.hasOwn(p, "targets") ||
    (action !== "invite.prune" && typeof p.includeCurrent !== "boolean") ||
    !Array.isArray(p.targets) ||
    !p.targets.length ||
    p.targets.length > 50
  )
    return fail();
  const seen = new Set<string>();
  const targets = p.targets.map((v: unknown) => {
    if (!v || typeof v !== "object" || Array.isArray(v)) return fail();
    const t = v as Record<string, unknown>;
    if (
      Object.keys(t).length !== 2 ||
      typeof t.id !== "string" ||
      !t.id ||
      t.id.length > 128 ||
      t.id !== t.id.trim() ||
      /[\x00-\x1f\x7f]/.test(t.id) ||
      seen.has(t.id) ||
      (action === "invite.prune" && !/^[a-f0-9]{64}$/.test(t.id)) ||
      typeof t.revision !== "string" ||
      !/^[a-f0-9]{64}$/.test(t.revision)
    )
      return fail();
    seen.add(t.id);
    return { id: t.id, revision: t.revision };
  });
  return {
    action: action as "device.remove" | "device.revoke-trust" | "invite.prune",
    parameters: {
      targets,
      ...(action === "invite.prune"
        ? {}
        : { includeCurrent: p.includeCurrent as boolean }),
    },
  };
}

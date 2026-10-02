import { createHash } from "node:crypto";
import { Context } from "./context.js";
import { record, text } from "./contracts.js";
import { incompatible } from "./errors.js";
import { rememberSecret } from "./output.js";
export const sha256 = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export async function invitationRows(c: Context) {
  const page = record(
    await c.query("/api/admin/invites", { includeInactive: "true" }),
  );
  if (!Array.isArray(page.data) || page.continuationToken !== null)
    return incompatible();
  const seen = new Set<string>();
  return page.data.map((v) => {
    const d = record(v),
      code = text(d.code);
    rememberSecret(code);
    rememberSecret(d.inviteLink);
    if (!/^[a-f0-9]{40}$/.test(code) || seen.has(code)) return incompatible();
    seen.add(code);
    return {
      id: sha256(code),
      code,
      status: text(d.status),
      expiresAt: text(d.expiresAt),
      createdAt: text(d.createdAt),
      usedBy: d.usedBy === null ? null : text(d.usedBy),
    };
  });
}
export function invitationMetadata(
  rows: Awaited<ReturnType<typeof invitationRows>>,
) {
  return rows.map(({ code: _, ...v }) => v);
}

import type { Env } from "../types";
export async function restorePreflightMetadata(env: Env) {
  const tables = [
    "users",
    "config",
    "folders",
    "ciphers",
    "attachments",
    "sends",
    "webauthn_credentials",
  ];
  const results = await env.DB.batch<{ count: number }>(
    tables.map((t) => env.DB.prepare(`SELECT COUNT(*) AS count FROM ${t}`)),
  );
  const counts = Object.fromEntries(
    tables.map((t, i) => [t, Number(results[i].results[0].count)]),
  );
  const backendFresh = ["ciphers", "folders", "attachments", "sends"].every(
    (t) => counts[t] === 0,
  );
  return {
    counts,
    backendFresh,
    requiresReplaceExisting: !backendFresh || counts.users > 1,
    writeExecuted: false,
    comparisonMode: "whole-instance replacement risks; not merge conflicts",
    replacementConflicts: tables
      .filter((t) => counts[t] > 0)
      .map((table) => ({ table, existingRows: counts[table] })),
    warning:
      "Restore replaces existing accounts/config/vault tables; runtime sessions and sends are not restored. This metadata read neither imports nor repairs backup credentials.",
  };
}

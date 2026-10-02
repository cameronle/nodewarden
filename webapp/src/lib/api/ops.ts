import type { AuthedFetch } from "./shared";
import { pbkdf2, bytesToBase64 } from "../crypto";
import { t } from "../i18n";
export interface CliOperation {
  id: string;
  action: string;
  parameters: Record<string, unknown>;
  summary: Record<string, unknown>;
  deviceId: string;
  origin: string;
  state: string;
  expiresAt: string;
  createdAt: string;
}
function path(id: string) {
  if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error(t("txt_cli_failed"));
  return "/api/ops/requests/" + id;
}
async function checked(r: Response) {
  if (!r.ok) throw new Error(`${t("txt_cli_failed")} (HTTP ${r.status})`);
  return r.json();
}
export async function loadCliOperation(
  fetcher: AuthedFetch,
  id: string,
): Promise<CliOperation> {
  return checked(await fetcher(path(id), { cache: "no-store" }));
}
export async function approveCliOperation(
  fetcher: AuthedFetch,
  id: string,
  email: string,
  password: string,
  approve: boolean,
) {
  let hash = "";
  if (approve) {
    const pre = await fetch("/identity/accounts/prelogin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.trim().toLowerCase() }),
    });
    if (!pre.ok) throw new Error(t("txt_cli_failed"));
    const p = await pre.json();
    // Current Web password login uses PBKDF2. Refuse unknown KDF rather than falling back.
    if (
      p.kdf !== 0 ||
      !Number.isInteger(p.kdfIterations) ||
      p.kdfIterations < 5000 ||
      p.kdfIterations > 2000000
    )
      throw new Error(t("txt_cli_failed"));
    const key = await pbkdf2(
      password,
      email.trim().toLowerCase(),
      p.kdfIterations,
      32,
    );
    try {
      hash = bytesToBase64(await pbkdf2(key, password, 1, 32));
    } finally {
      key.fill(0);
    }
  }
  try {
    return await checked(
      await fetcher(path(id) + "/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approve, masterPasswordHash: hash }),
      }),
    );
  } finally {
    hash = "";
  }
}

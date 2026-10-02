import type { Env } from "../types";
const encode = new TextEncoder();
async function key(env: Env) {
  if (!env.JWT_SECRET) throw new Error("Missing encryption key");
  const material = await crypto.subtle.importKey(
    "raw",
    encode.encode(env.JWT_SECRET),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encode.encode("nodewarden.ops.credentials.v1"),
      info: encode.encode("ephemeral"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
const b64 = (v: Uint8Array) => btoa(String.fromCharCode(...v));
const bytes = (v: string) => Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
export async function sealOpsCredentials(
  env: Env,
  id: string,
  userId: string,
  value: Record<string, string>,
): Promise<string | null> {
  if (!Object.keys(value).length) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: encode.encode(id + ":" + userId + ":backup.configure"),
    },
    await key(env),
    encode.encode(JSON.stringify(value)),
  );
  return JSON.stringify({
    version: 1,
    iv: b64(iv),
    ciphertext: b64(new Uint8Array(data)),
  });
}
export async function openOpsCredentials(
  env: Env,
  id: string,
  userId: string,
  value: string | null | undefined,
): Promise<Record<string, string>> {
  if (!value) return {};
  const p = JSON.parse(value);
  if (p.version !== 1) throw new Error("Invalid envelope");
  const data = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytes(p.iv),
      additionalData: encode.encode(id + ":" + userId + ":backup.configure"),
    },
    await key(env),
    bytes(p.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(data));
}

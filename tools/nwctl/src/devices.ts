import { Client } from "./http.js";
import { Store, type Profile } from "./config.js";
import { identity, record, text } from "./contracts.js";
import { CliError, incompatible } from "./errors.js";
import { learnSecrets } from "./output.js";
import { authenticatedGet } from "./auth.js";

export function devicesPage(value: unknown, current: string) {
  const p = record(value);
  learnSecrets(p);
  if (!Array.isArray(p.data) || p.continuationToken !== null) incompatible();
  const ids = new Set<string>();
  const items = (p.data as unknown[]).map((value) => {
    const d = record(value),
      id = text(d.id);
    if (
      !id ||
      ids.has(id) ||
      !Number.isSafeInteger(d.type) ||
      Number(d.type) < 0 ||
      typeof d.isTrusted !== "boolean"
    )
      incompatible();
    ids.add(id);
    const date = (value: unknown) => {
      if (value === null) return null;
      const s = text(value);
      if (!Number.isFinite(Date.parse(s))) incompatible();
      return s;
    };
    return {
      id,
      name: text(d.name),
      type: d.type,
      current: id === current,
      createdAt: date(d.creationDate),
      lastActivityAt: date(d.lastActivityDate),
      trusted: d.isTrusted,
    };
  });
  return { count: items.length, items };
}

export async function serverLogout(store: Store, p: Profile, timeout: number) {
  const session = await store.session(p);
  const user = identity(
    await authenticatedGet(store, p, "/api/accounts/profile", {}, timeout),
  );
  // The token was verified by the server above; decoding only binds this operation
  // to its dedicated device and account, and is not local JWT authentication.
  let claims;
  try {
    if (session.token.split(".").length !== 3) throw new Error();
    claims = JSON.parse(
      Buffer.from(session.token.split(".")[1], "base64url").toString("utf8"),
    );
  } catch {
    incompatible();
  }
  if (
    claims?.did !== p.device ||
    claims?.sub !== user.id ||
    typeof claims?.dstamp !== "string" ||
    !claims.dstamp
  )
    throw new CliError(
      "DEVICE_BINDING_MISMATCH",
      "Refusing to revoke a device not bound to this CLI session.",
      6,
    );
  const client = new Client(p.server, p.allowLoopback, timeout);
  try {
    const result = record(await client.revokeDevice(p.device, session.token));
    if (result.success !== true)
      throw new CliError(
        "REVOCATION_UNCONFIRMED",
        "Device removal was not confirmed; verify it in a trusted client.",
        6,
      );
    const deadline = Date.now() + timeout;
    while (deadline - Date.now() >= 50) {
      try {
        await new Client(
          p.server,
          p.allowLoopback,
          Math.max(50, deadline - Date.now()),
        ).get("/api/accounts/profile", {}, session.token);
      } catch (e) {
        if (e instanceof CliError && e.status === 401)
          return {
            loggedIn: false,
            serverRevoked: true,
            oldAccessRejected: true,
            device: p.device,
          };
        throw e;
      }
      await new Promise((resolve) =>
        setTimeout(resolve, Math.min(1000, Math.max(0, deadline - Date.now()))),
      );
    }
    throw new CliError(
      "REVOCATION_UNCONFIRMED",
      "Device was removed but old access rejection was not observed within timeout. Local session cleared; verify server state in a trusted client.",
      5,
    );
  } finally {
    // Once deletion is attempted its outcome may be ambiguous; never keep using this token.
    await store.logout(p);
  }
}

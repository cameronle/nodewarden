import { Client } from "./http.js";
import { Store, type Profile } from "./config.js";
import { identity, loginResponse, record } from "./contracts.js";
import { CliError, invalid } from "./errors.js";
import { rememberSecret } from "./output.js";
export async function login(
  store: Store,
  p: Profile,
  clientId: string,
  clientSecret: string,
  timeout = 15000,
) {
  if (
    !clientId.startsWith("user.") ||
    clientId.length <= 5 ||
    !clientSecret ||
    clientSecret.length > 4096
  )
    invalid(
      "A personal user.* client ID and nonempty API Secret are required.",
    );
  rememberSecret(clientSecret);
  const c = new Client(p.server, p.allowLoopback, timeout);
  await store.logout(p);
  const started = Date.now();
  const raw = await c.postForm("/identity/connect/token", {
    grant_type: "client_credentials",
    scope: "api",
    client_id: clientId,
    client_secret: clientSecret,
    deviceIdentifier: p.device,
    deviceName: "nwctl",
    deviceType: "8",
  });
  const body = record(raw);
  // Clean up any issued refresh token even when the rest of the token DTO is invalid.
  if (typeof body.refresh_token === "string" && body.refresh_token) {
    try {
      await c.postForm("/identity/connect/revocation", {
        token: body.refresh_token,
        token_type_hint: "refresh_token",
      });
    } catch {
      throw new CliError(
        "REVOCATION_FAILED",
        "Refresh-token cleanup failed; no session saved. Retry login and check this dedicated CLI device in trusted clients.",
        5,
      );
    }
  }
  const issued = loginResponse(raw);
  const user = identity(await c.get("/api/accounts/profile", {}, issued.token));
  if (user.id !== clientId.slice(5))
    throw new CliError(
      "IDENTITY_MISMATCH",
      "Authenticated identity does not match the supplied client ID; no session saved.",
      6,
    );
  const expiresAt = started + issued.ttl * 1000;
  if (expiresAt <= Date.now())
    throw new CliError("LOGIN_EXPIRED", "Session expired during login.", 3);
  await store.saveSession(p, { token: issued.token, expiresAt });
  return {
    identity: user,
    expiresAt: new Date(expiresAt).toISOString(),
    refreshTokenStored: false,
  };
}
export async function authenticatedGet(
  store: Store,
  p: Profile,
  path: string,
  query: Record<string, string> = {},
  timeout = 15000,
) {
  const session = await store.session(p);
  try {
    return await new Client(p.server, p.allowLoopback, timeout).get(
      path,
      query,
      session.token,
    );
  } catch (e) {
    if (e instanceof CliError && e.status === 401) await store.logout(p);
    throw e;
  }
}

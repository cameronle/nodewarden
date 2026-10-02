import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { promisify } from "node:util";
import { Store, type Profile } from "./config.js";
import { authenticatedGet, login } from "./auth.js";
import { identity } from "./contracts.js";
import { CliError, invalid } from "./errors.js";
const exec = promisify(execFile);
const helper = "/usr/local/sbin/nwctl-prod-login";

// Explicit host integration, never a profile-supplied shell command or a DB fallback.
export async function cachedLogin(store: Store, p: Profile) {
  if (
    process.platform !== "linux" ||
    store.dir !== "/home/hermes/.config/nwctl" ||
    p.name !== "prod" ||
    p.server !== "https://nodewarden.865455.xyz" ||
    p.allowLoopback
  )
    invalid(
      "--cached is bound to this host's approved prod profile and default configuration directory.",
    );
  for (const path of ["/usr", "/usr/local", "/usr/local/sbin", helper]) {
    const s = await lstat(path);
    if (
      s.isSymbolicLink() ||
      s.uid !== 0 ||
      s.mode & 0o022 ||
      (path === helper ? !s.isFile() : !s.isDirectory())
    )
      invalid(
        "Cached login helper must be root-owned and not writable by other users.",
      );
  }
  try {
    // Suppress helper output; verify the saved session against the server ourselves.
    await exec("/usr/bin/sudo", ["-n", helper], {
      timeout: 180000,
      maxBuffer: 65536,
      env: {
        PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
        HOME: "/home/hermes",
        LANG: "C.UTF-8",
      },
    });
  } catch {
    throw new CliError(
      "CACHED_LOGIN_FAILED",
      "Cached login failed. Check local helper, credential binding or account status; no database fallback attempted.",
      3,
    );
  }
}

export async function verifiedSession(
  store: Store,
  p: Profile,
  timeout: number,
) {
  const s = await store.session(p);
  const user = identity(
    await authenticatedGet(store, p, "/api/accounts/profile", {}, timeout),
  );
  return {
    loggedIn: true,
    verified: true,
    identity: user,
    expiresAt: new Date(s.expiresAt).toISOString(),
  };
}

export async function ensureSession(
  store: Store,
  p: Profile,
  timeout: number,
  obtain: () => Promise<{ clientId: string; clientSecret: string }>,
) {
  try {
    return { ...(await verifiedSession(store, p, timeout)), reused: true };
  } catch (e) {
    if (
      !(
        e instanceof CliError &&
        (e.code === "LOGIN_REQUIRED" || e.status === 401)
      )
    )
      throw e;
  }
  const { clientId, clientSecret } = await obtain();
  return {
    ...(await login(store, p, clientId, clientSecret, timeout)),
    loggedIn: true,
    verified: true,
    reused: false,
  };
}

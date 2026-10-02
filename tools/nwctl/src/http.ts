import { CliError, invalid } from "./errors.js";
import { rememberSecret, learnSecrets } from "./output.js";
const reads = new Set([
  "/api/config",
  "/api/version",
  "/api/accounts/profile",
  "/api/devices",
  "/api/devices/authorized",
  "/api/admin/invites",
  "/api/admin/logs/settings",
  "/api/admin/backup/settings",
  "/api/admin/backup/remote",
  "/api/admin/users",
  "/api/admin/logs",
]);
const posts = new Set([
  "/identity/connect/token",
  "/identity/connect/revocation",
]);
export function serverOrigin(server: string, allowLoopback = false): string {
  let url: URL;
  try {
    url = new URL(server);
  } catch {
    return invalid("Invalid server URL.");
  }
  if (
    url.username ||
    url.password ||
    !["", "/"].includes(url.pathname) ||
    url.search ||
    url.hash
  )
    return invalid(
      "Server must be an origin without credentials, path, query or fragment.",
    );
  if (
    url.protocol !== "https:" &&
    !(
      allowLoopback &&
      url.protocol === "http:" &&
      ["127.0.0.1", "[::1]"].includes(url.hostname)
    )
  )
    return invalid(
      "HTTPS is required; explicitly allowed numeric loopback HTTP is for local tests only.",
    );
  return url.origin;
}
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
export class Client {
  readonly origin: string;
  constructor(
    server: string,
    allowLoopback = false,
    readonly timeout = 15000,
  ) {
    this.origin = serverOrigin(server, allowLoopback);
    if (!Number.isInteger(timeout) || timeout < 50 || timeout > 900000)
      invalid("Timeout must be an integer between 50 and 900000 milliseconds.");
  }
  get(path: string, query: Record<string, string> = {}, token?: string) {
    return this.request("GET", path, query, undefined, token);
  }
  postForm(path: string, form: Record<string, string>) {
    return this.request("POST", path, {}, new URLSearchParams(form));
  }
  revokeDevice(device: string, token: string) {
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
        device,
      )
    )
      invalid("Invalid dedicated device identifier.");
    return this.request(
      "DELETE",
      "/api/devices/" + device,
      {},
      undefined,
      token,
    );
  }
  write(
    method: "POST" | "PUT" | "DELETE",
    path: string,
    body: Record<string, unknown>,
    token: string,
  ) {
    learnSecrets(body);
    return this.request(method, path, {}, JSON.stringify(body), token);
  }
  private async request(
    method: "GET" | "POST" | "PUT" | "DELETE",
    path: string,
    query: Record<string, string>,
    body?: URLSearchParams | string,
    token?: string,
  ): Promise<unknown> {
    const segment = "[A-Za-z0-9_%~-]+";
    const allowed =
      method === "GET"
        ? reads.has(path)
        : method === "PUT"
          ? new RegExp(`^/api/devices/${segment}/name$`).test(path)
          : method === "DELETE"
            ? new RegExp(`^/api/devices/(?:authorized/)?${segment}$`).test(
                path,
              ) && path !== "/api/devices/authorized"
            : posts.has(path) ||
              path === "/api/ops/requests" ||
              /^\/api\/ops\/requests\/[a-f0-9-]{36}\/(status|execute|cancel)$/.test(
                path,
              );
    if (!allowed) invalid("Endpoint is not in the operations API allowlist.");
    const url = new URL(path, this.origin);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
    rememberSecret(token);
    if (body instanceof URLSearchParams)
      for (const k of ["client_secret", "token", "refresh_token"])
        rememberSecret(body.get(k));
    const deadline = Date.now() + this.timeout;
    for (let attempt = 0; attempt < 2; attempt++) {
      const remaining = deadline - Date.now();
      if (remaining <= 0)
        throw new CliError("TIMEOUT", "Request timed out.", 5);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), remaining);
      try {
        const response = await fetch(url, {
          method,
          body,
          redirect: "manual",
          signal: controller.signal,
          headers: {
            Accept: "application/json",
            ...(body
              ? {
                  "Content-Type":
                    typeof body === "string"
                      ? "application/json"
                      : "application/x-www-form-urlencoded",
                }
              : {}),
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        });
        if (
          method === "GET" &&
          attempt === 0 &&
          [429, 502, 503, 504].includes(response.status)
        ) {
          const retry = response.headers.get("Retry-After");
          const seconds = retry
            ? /^\d+$/.test(retry)
              ? Number(retry)
              : Math.max(0, (Date.parse(retry) - Date.now()) / 1000)
            : 0.1;
          await response.body?.cancel();
          const delay = Number.isFinite(seconds) ? seconds * 1000 : 100;
          if (delay <= 2000 && delay < deadline - Date.now()) {
            await pause(delay);
            continue;
          }
        }
        if (!response.ok) {
          await response.body?.cancel();
          const status = response.status;
          const exit =
            status === 401 ||
            (status === 400 && path === "/identity/connect/token")
              ? 3
              : status === 403
                ? 4
                : status === 409
                  ? 6
                  : 5;
          throw new CliError(
            status === 409
              ? path === "/api/admin/backup/settings"
                ? "REPAIR_REQUIRED"
                : path === "/api/admin/backup/remote"
                  ? "REMOTE_CONFLICT"
                  : "BUSINESS_CONFLICT"
              : status >= 300 && status < 400
                ? "REDIRECT_REJECTED"
                : "HTTP_ERROR",
            `HTTP ${status}. ${method !== "GET" && path.startsWith("/api/") ? "Write may have partially completed. Inspect the exact target and operation status before repeating; raw response suppressed." : exit === 3 ? "Login required or rejected." : exit === 4 ? "Active administrator permission required." : status === 409 ? (path === "/api/admin/backup/settings" ? "Server configuration needs attention; no repair performed." : "Remote listing or business request conflicted; no modification performed.") : "Request failed; raw response suppressed."}`,
            exit,
            status,
          );
        }
        if (
          response.status === 204 &&
          /^\/api\/ops\/requests\/[a-f0-9-]{36}\/execute$/.test(path)
        )
          return null;
        const reader = response.body?.getReader();
        const chunks: Uint8Array[] = [];
        let size = 0;
        if (reader)
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > 2097152) {
              await reader.cancel();
              throw new CliError(
                "RESPONSE_TOO_LARGE",
                "Response exceeds 2 MiB limit.",
                6,
              );
            }
            chunks.push(value);
          }
        const text = Buffer.concat(chunks).toString("utf8");
        if (path === "/identity/connect/revocation" && !text) return null;
        try {
          return JSON.parse(text);
        } catch {
          throw new CliError(
            "INVALID_JSON",
            "Expected JSON; HTML/login pages and invalid responses are rejected.",
            6,
          );
        }
      } catch (e) {
        if (e instanceof CliError) throw e;
        throw new CliError(
          controller.signal.aborted ? "TIMEOUT" : "NETWORK_ERROR",
          method !== "GET"
            ? "Write outcome unknown; do not retry blindly. Read back the exact target."
            : controller.signal.aborted
              ? "Request timed out."
              : "Network or TLS request failed; raw diagnostics suppressed.",
          5,
        );
      } finally {
        clearTimeout(timer);
      }
    }
    throw new CliError("NETWORK_ERROR", "Request failed.", 5);
  }
}

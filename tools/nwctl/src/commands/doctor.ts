import type { Command } from "commander";
import { Context } from "../context.js";
import { Client } from "../http.js";
import { record, text, identity } from "../contracts.js";
import { CliError } from "../errors.js";
export function doctor(program: Command, c: Context) {
  program
    .command("doctor")
    .description("Public API and optional authentication connectivity")
    .action(
      c.action("doctor", async () => {
        const p = await c.profile();
        const client = new Client(p.server, p.allowLoopback, c.timeout());
        record(await client.get("/api/config"));
        const compatibilityVersion = text(await client.get("/api/version"));
        let auth: unknown = { loggedIn: false, verified: false };
        try {
          await c.store().session(p);
          auth = {
            loggedIn: true,
            verified: true,
            identity: identity(await c.query("/api/accounts/profile")),
          };
        } catch (e) {
          if (!(e instanceof CliError && e.code === "LOGIN_REQUIRED")) throw e;
        }
        c.print(
          {
            cliVersion: "0.2.0",
            server: p.server,
            transport:
              p.allowLoopback && p.server.startsWith("http:")
                ? "local-test-http"
                : "https",
            apiReachable: true,
            compatibilityVersion,
            nodewardenVersion: "unknown",
            deploymentSha: "unknown",
            auth,
          },
          [
            "This is a connectivity check, not a database, Cloudflare or recovery audit.",
          ],
        );
      }),
    );
}

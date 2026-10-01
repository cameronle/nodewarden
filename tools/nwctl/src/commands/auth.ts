import type { Command } from "commander";
import { Context } from "../context.js";
import { login } from "../auth.js";
import { credentials } from "../prompt.js";
import { identity } from "../contracts.js";
import { CliError, invalid } from "../errors.js";
export function authentication(program: Command, c: Context) {
  const group = program
    .command("auth")
    .description("Short-lived personal API Key sessions");
  group
    .command("login")
    .option("--apikey", "Use personal API Key")
    .option(
      "--credentials-stdin",
      "Explicit controlled stdin: client ID and Secret on separate lines",
    )
    .action(
      c.action("auth login", async (opts) => {
        if (!opts.apikey)
          invalid("Specify --apikey. No password/vault login is implemented.");
        const timeout = c.timeout();
        const p = await c.profile();
        const { clientId, clientSecret } = await credentials(
          !!opts.credentialsStdin,
        );
        c.print(await login(c.store(), p, clientId, clientSecret, timeout));
      }),
    );
  group.command("logout").action(
    c.action("auth logout", async () => {
      await c.store().logout(await c.profile());
      c.print({ loggedIn: false }, [
        "Local logout does not immediately revoke an issued access token.",
      ]);
    }),
  );
  group.command("status").action(
    c.action("auth status", async () => {
      const p = await c.profile();
      let session;
      try {
        session = await c.store().session(p);
      } catch (e) {
        if (e instanceof CliError && e.exitCode === 3) {
          c.print({ loggedIn: false, verified: false });
          return;
        }
        throw e;
      }
      const user = identity(await c.query("/api/accounts/profile"));
      c.print({
        loggedIn: true,
        verified: true,
        expiresAt: new Date(session.expiresAt).toISOString(),
        identity: user,
      });
    }),
  );
  program
    .command("whoami")
    .description("Verified identity, never key material")
    .action(
      c.action("whoami", async () =>
        c.print(identity(await c.query("/api/accounts/profile"))),
      ),
    );
}

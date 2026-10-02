import type { Command } from "commander";
import { Context } from "../context.js";
import { login } from "../auth.js";
import { credentials } from "../prompt.js";
import { identity } from "../contracts.js";
import { CliError, invalid } from "../errors.js";
import { cachedLogin, ensureSession, verifiedSession } from "../ensure.js";
import { serverLogout } from "../devices.js";
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
  group
    .command("ensure")
    .description("Reuse a verified session or explicitly acquire credentials")
    .option(
      "--cached",
      "Use this host's approved root-private prod login helper",
    )
    .option(
      "--credentials-stdin",
      "Controlled two-line credential input if login is needed",
    )
    .action(
      c.action("auth ensure", async (opts) => {
        if (opts.cached && opts.credentialsStdin)
          invalid("Choose only one credential source.");
        const timeout = c.timeout(),
          p = await c.profile(),
          store = c.store();
        if (opts.cached) {
          await cachedLogin(store, p);
          c.print({
            ...(await verifiedSession(store, p, timeout)),
            credentialSource: "local-private-helper",
          });
        } else {
          c.print(
            await ensureSession(store, p, timeout, () =>
              credentials(!!opts.credentialsStdin),
            ),
          );
        }
      }),
    );
  group
    .command("logout")
    .option(
      "--server",
      "Revoke only this profile's CLI device and verify old access rejection",
    )
    .action(
      c.action("auth logout", async (opts) => {
        if (opts.server) {
          c.print(
            await serverLogout(c.store(), await c.profile(), c.timeout()),
            [
              "Rejection was verified on this request path; other server caches may briefly lag. The API key is unchanged.",
            ],
          );
          return;
        }
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

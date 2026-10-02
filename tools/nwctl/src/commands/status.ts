import type { Command } from "commander";
import { Context } from "../context.js";
import { Client } from "../http.js";
import { record, text, settings, usersPage } from "../contracts.js";
import { verifiedSession } from "../ensure.js";
import { health, duration } from "../backup-health.js";
import { CliError } from "../errors.js";

export function status(program: Command, c: Context) {
  program
    .command("status")
    .description(
      "Instance, verified identity, session lifetime and backup overview",
    )
    .option(
      "--check",
      "Exit 7 unless authenticated admin and every backup target is healthy",
    )
    .option("--max-age <duration>", "Maximum backup age (m/h/d)", "48h")
    .action(
      c.action("status", async (opts) => {
        const maxAge = duration(opts.maxAge),
          timeout = c.timeout();
        const p = await c.profile(),
          client = new Client(p.server, p.allowLoopback, timeout);
        record(await client.get("/api/config"));
        const compatibilityVersion = text(await client.get("/api/version"));
        let session: Awaited<ReturnType<typeof verifiedSession>> | null = null;
        try {
          session = await verifiedSession(c.store(), p, timeout);
        } catch (e) {
          if (!(e instanceof CliError && e.code === "LOGIN_REQUIRED")) throw e;
        }
        let userCount: number | null = null;
        let backup: {
          count: number;
          healthy: boolean;
          maxAgeSeconds: number;
          destinations: unknown[];
        } | null = null;
        const warnings: string[] = [];
        if (session?.identity.role === "admin") {
          userCount = usersPage(await c.query("/api/admin/users")).count;
          const h = health(
            settings(await c.query("/api/admin/backup/settings")),
            Date.now(),
            maxAge,
          );
          backup = {
            count: h.count,
            healthy: h.healthy,
            maxAgeSeconds: h.maxAgeSeconds,
            destinations: h.destinations.map((d) => ({
              id: d.id,
              name: d.name,
              type: d.type,
              enabled: d.schedule.enabled,
              timezone: d.schedule.timezone,
              health: d.health,
              lastSuccessAt: d.runtime.lastSuccessAt,
              ageSeconds: d.ageSeconds,
            })),
          };
        } else
          warnings.push(
            "Administrative user/backup data unavailable without a verified admin session; not treated as healthy.",
          );
        const remainingSeconds = session
          ? Math.max(
              0,
              Math.floor((Date.parse(session.expiresAt) - Date.now()) / 1000),
            )
          : 0;
        const healthy =
          remainingSeconds > 0 &&
          session?.identity.role === "admin" &&
          backup?.healthy === true;
        c.print(
          {
            server: p.server,
            checkedAt: new Date().toISOString(),
            apiReachable: true,
            compatibilityVersion,
            auth: session
              ? { ...session, remainingSeconds }
              : { loggedIn: false, verified: false, remainingSeconds: 0 },
            userCount,
            backup,
            healthy,
          },
          warnings,
        );
        if (opts.check && !healthy) process.exitCode = 7;
      }),
    );
}

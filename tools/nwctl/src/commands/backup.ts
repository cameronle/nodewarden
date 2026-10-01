import type { Command } from "commander";
import { Context } from "../context.js";
import { settings, remotePage } from "../contracts.js";
import { duration, health } from "../backup-health.js";
import { invalid, incompatible } from "../errors.js";
export function backups(program: Command, c: Context) {
  const group = program
    .command("backup")
    .description("Read-only backup inspection");
  group
    .command("destinations")
    .description("Configured destinations (credentials omitted)")
    .command("list")
    .action(
      c.action("backup destinations list", async () => {
        const destinations = settings(
          await c.query("/api/admin/backup/settings"),
        );
        c.print({ destinations, count: destinations.length });
      }),
    );
  group
    .command("status")
    .option("--check", "Exit 7 if not all destinations are healthy")
    .option(
      "--max-age <duration>",
      "Maximum success age for enabled destinations",
      "48h",
    )
    .action(
      c.action("backup status", async (opts) => {
        const maxAge = duration(opts.maxAge);
        const result = health(
          settings(await c.query("/api/admin/backup/settings")),
          Date.now(),
          maxAge,
        );
        c.print(result);
        if (opts.check && !result.healthy) process.exitCode = 7;
      }),
    );
  group
    .command("remote")
    .description("Browse one remote directory without downloads")
    .command("list")
    .requiredOption("--destination <id>", "Configured destination ID")
    .option("--path <path>", "Explicit directory path", "")
    .action(
      c.action("backup remote list", async (opts) => {
        if (!/^[a-zA-Z0-9_-]{1,128}$/.test(opts.destination))
          invalid("Invalid destination ID.");
        if (
          opts.path.length > 2048 ||
          /[\x00-\x1f\x7f\\]/.test(opts.path) ||
          opts.path.split("/").some((v: string) => v === "..")
        )
          invalid("Invalid remote directory path.");
        const page = remotePage(
          await c.query("/api/admin/backup/remote", {
            destinationId: opts.destination,
            path: opts.path,
          }),
        );
        if (page.destinationId !== opts.destination) incompatible();
        c.print(page);
      }),
    );
}

import { inspectArchive } from "../backup-inspection.js";
import { backupConfiguration } from "../configuration.js";
import type { Command } from "commander";
import { Context } from "../context.js";
import { settings, remotePage } from "../contracts.js";
import { duration, health } from "../backup-health.js";
import { invalid, incompatible } from "../errors.js";
import { mutationOptions } from "../mutations.js";
import { requestOperation } from "../step-up.js";
import { opsParameters } from "../../../../shared/ops-schema.js";
export function backups(program: Command, c: Context) {
  const group = program
    .command("backup")
    .description("Backup inspection and browser-approved operations");
  mutationOptions(
    group
      .command("run")
      .requiredOption("--destination <id>", "Exact destination ID"),
  ).action(
    c.action("backup run", async (opts) => {
      const d = settings(await c.query("/api/admin/backup/settings")).find(
        (d) => d.id === opts.destination,
      );
      if (!d) return invalid("Destination not found.");
      await requestOperation(c, { ...opts, preview: d }, "backup.run", {
        destinationId: d.id,
      });
    }),
  );
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
  mutationOptions(
    group
      .command("export")
      .requiredOption("--output <file>", "Private ZIP output; no overwrite")
      .option(
        "--include-attachments",
        "Include original encrypted attachment blobs",
        false,
      ),
  ).action(
    c.action("backup export", async (opts) => {
      await requestOperation(c, opts, "backup.export", {
        includeAttachments: opts.includeAttachments,
      });
    }),
  );
  group
    .command("inspect")
    .requiredOption(
      "--file <file>",
      "Owned private ZIP; never uploads archive or restores",
    )
    .option("--compare-instance", "Read only target replacement-risk counts")
    .action(
      c.action("backup inspect", async (opts) => inspectArchive(c, opts)),
    );
  backupConfiguration(group, c);
  const remote = group
    .command("remote")
    .description("List or request approved archive operations");
  for (const action of ["download", "verify"] as const) {
    const cmd = remote
      .command(action)
      .requiredOption("--destination <id>", "Exact destination ID")
      .requiredOption("--path <path>", "Exact ZIP path from remote list");
    if (action === "download")
      cmd.requiredOption(
        "--output <file>",
        "Private output file; no overwrite",
      );
    mutationOptions(cmd).action(
      c.action("backup remote " + action, async (opts) => {
        const parameters = { destinationId: opts.destination, path: opts.path };
        try {
          opsParameters("backup." + action, parameters);
        } catch {
          invalid("Invalid destination or archive path.");
        }
        await requestOperation(c, opts, `backup.${action}`, parameters);
      }),
    );
  }
  remote
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

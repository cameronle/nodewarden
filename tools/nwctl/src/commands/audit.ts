import type { Command } from "commander";
import { Context, numberOption } from "../context.js";
import { auditPage, record } from "../contracts.js";
import { incompatible } from "../errors.js";
import { auditFilters } from "../audit-filters.js";
export function audit(program: Command, c: Context) {
  const group = program
    .command("audit")
    .description("Read audit metadata and retention settings");
  group
    .command("settings")
    .command("show")
    .action(
      c.action("audit settings show", async () => {
        const s = record(await c.query("/api/admin/logs/settings"));
        if (
          s.object !== "auditLogSettings" ||
          ![null, 7, 30, 90, 180, 365].includes(s.retentionDays as any) ||
          ![null, 1000, 5000, 10000, 50000].includes(s.maxEntries as any) ||
          (s.retentionDays !== null && s.maxEntries !== null)
        )
          incompatible();
        c.print({ retentionDays: s.retentionDays, maxEntries: s.maxEntries });
      }),
    );
  group
    .command("list")
    .option("--limit <n>", "Page size 1–200", "50")
    .option("--offset <n>", "Nonnegative offset", "0")
    .option(
      "--category <name>",
      "Event category, e.g. security, device, system",
    )
    .option("--level <name>", "Event level, e.g. info, security")
    .option("--query <text>", "Search text (do not include secrets)")
    .option("--from <iso-time>", "Inclusive start; ISO timestamp with timezone")
    .option("--to <iso-time>", "Inclusive end; ISO timestamp with timezone")
    .action(
      c.action("audit list", async (opts) => {
        const limit = numberOption(opts.limit, 1, 200),
          offset = numberOption(opts.offset, 0, Number.MAX_SAFE_INTEGER);
        const filters = auditFilters(opts);
        const page = auditPage(
          await c.query("/api/admin/logs", {
            limit: String(limit),
            offset: String(offset),
            ...filters,
          }),
        );
        if (page.limit !== limit || page.offset !== offset) incompatible();
        c.print(page, [
          "Unstructured audit metadata omitted to avoid secret disclosure.",
        ]);
      }),
    );
}

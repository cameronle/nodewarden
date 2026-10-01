import type { Command } from "commander";
import { Context, numberOption } from "../context.js";
import { auditPage } from "../contracts.js";
import { incompatible } from "../errors.js";
export function audit(program: Command, c: Context) {
  program
    .command("audit")
    .description("Read one audit page; metadata intentionally omitted")
    .command("list")
    .option("--limit <n>", "Page size 1–200", "50")
    .option("--offset <n>", "Nonnegative offset", "0")
    .action(
      c.action("audit list", async (opts) => {
        const limit = numberOption(opts.limit, 1, 200),
          offset = numberOption(opts.offset, 0, Number.MAX_SAFE_INTEGER);
        const page = auditPage(
          await c.query("/api/admin/logs", {
            limit: String(limit),
            offset: String(offset),
          }),
        );
        if (page.limit !== limit || page.offset !== offset) incompatible();
        c.print(page, [
          "Unstructured audit metadata omitted to avoid secret disclosure.",
        ]);
      }),
    );
}

import type { Command } from "commander";
import { Context } from "../context.js";
import { usersPage } from "../contracts.js";
export function users(program: Command, c: Context) {
  program
    .command("users")
    .description("Read-only user management inspection")
    .command("list")
    .action(
      c.action("users list", async () =>
        c.print(usersPage(await c.query("/api/admin/users"))),
      ),
    );
}

import { userStatus } from "../configuration.js";
import type { Command } from "commander";
import { Context } from "../context.js";
import { usersPage, record, text, identity } from "../contracts.js";
import { invalid, incompatible } from "../errors.js";
import { identifier } from "../mutations.js";
export function users(program: Command, c: Context) {
  const group = program
    .command("users")
    .description("User metadata and browser-approved ban/unban");
  userStatus(group, c);
  group.command("show <id>").action(
    c.action("users show", async (id) => {
      identifier(id);
      const page = record(await c.query("/api/admin/users"));
      if (!Array.isArray(page.data) || page.continuationToken !== null)
        return incompatible();
      const matches = page.data.map(record).filter((u) => u.id === id);
      if (matches.length !== 1) return invalid("Exact user not found.");
      const u = matches[0];
      if (typeof u.twoFactorEnabled !== "boolean") return incompatible();
      c.print({
        ...identity(u),
        twoFactorEnabled: u.twoFactorEnabled,
        creationDate: text(u.creationDate),
        revisionDate: text(u.revisionDate),
      });
    }),
  );
  group
    .command("list")
    .action(
      c.action("users list", async () =>
        c.print(usersPage(await c.query("/api/admin/users"))),
      ),
    );
}

import { pruneInvites } from "../bulk.js";
import type { Command } from "commander";
import { Context } from "../context.js";
import { invitationRows, invitationMetadata } from "../invites.js";
import { mutationOptions } from "../mutations.js";
import { requestOperation } from "../step-up.js";
import { invalid } from "../errors.js";
export function invites(program: Command, c: Context) {
  const group = program
    .command("invites")
    .description(
      "Registration invitations; codes omitted from ordinary output",
    );
  mutationOptions(
    group
      .command("prune")
      .description(
        "Review up to 50 currently invalid invitations; preserve valid/new invitations.",
      )
      .option(
        "--ids <references...>",
        "Optional exact non-secret SHA-256 references",
      ),
  ).action(c.action("invites prune", async (opts) => pruneInvites(c, opts)));
  group.command("list").action(
    c.action("invites list", async () => {
      const items = invitationMetadata(await invitationRows(c));
      c.print({ count: items.length, items });
    }),
  );
  mutationOptions(
    group
      .command("create")
      .requiredOption("--expires <duration>", "Whole hours or days, 1h–30d")
      .requiredOption("--output <file>", "Private invitation output file"),
  ).action(
    c.action("invites create", async (opts) => {
      const m = /^([1-9][0-9]*)(h|d)$/.exec(opts.expires);
      if (!m) return invalid("Expiry must be whole hours or days.");
      const hours = Number(m[1]) * (m[2] === "d" ? 24 : 1);
      if (hours > 720) invalid("Maximum expiry is 30 days.");
      await requestOperation(c, opts, "invite.create", {
        expiresInHours: hours,
      });
    }),
  );
  mutationOptions(
    group
      .command("revoke <id>")
      .description(
        "Exact SHA-256 reference from invites list; never a raw invite code",
      ),
  ).action(
    c.action("invites revoke", async (id, opts) => {
      if (!/^[a-f0-9]{64}$/.test(id))
        invalid("Use the exact non-secret reference from invites list.");
      if (!(await invitationRows(c)).some((i) => i.id === id))
        invalid("Invitation not found.");
      await requestOperation(c, opts, "invite.revoke", { inviteId: id });
    }),
  );
}

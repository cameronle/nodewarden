import type { Command } from "commander";
import { Context } from "../context.js";
export function profiles(program: Command, c: Context) {
  const group = program
    .command("profile")
    .description("Local instance profiles");
  group
    .command("add <name>")
    .requiredOption("--server <origin>", "HTTPS server origin")
    .option(
      "--allow-loopback-http",
      "Allow numeric loopback HTTP for tests only",
    )
    .action(
      c.action("profile add", async (name, opts) => {
        const p = await c
          .store()
          .add(name, opts.server, !!opts.allowLoopbackHttp);
        c.profileName = p.name;
        c.print({
          name: p.name,
          server: p.server,
          allowLoopback: p.allowLoopback,
        });
      }),
    );
  group.command("use <name>").action(
    c.action("profile use", async (name) => {
      const p = await c.store().use(name);
      c.profileName = p.name;
      c.print({ active: p.name, server: p.server });
    }),
  );
  group
    .command("list")
    .action(
      c.action("profile list", async () => c.print(await c.store().list())),
    );
}

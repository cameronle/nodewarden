import type { Command } from "commander";
import { Context } from "../context.js";
import { devicesPage } from "../devices.js";
export function devices(program: Command, c: Context) {
  program
    .command("devices")
    .description("Own-account device metadata only")
    .command("list")
    .action(
      c.action("devices list", async () => {
        const p = await c.profile();
        c.print(devicesPage(await c.query("/api/devices"), p.device));
      }),
    );
}

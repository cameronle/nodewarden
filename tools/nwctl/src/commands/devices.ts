import type { Command } from "commander";
import { Context } from "../context.js";
import { devicesPage } from "../devices.js";
import { record, text } from "../contracts.js";
import { CliError, incompatible, invalid } from "../errors.js";
import { learnSecrets } from "../output.js";
import {
  confirmMutation,
  identifier,
  mutationOptions,
  write,
} from "../mutations.js";
export function authorizedDevices(value: unknown, current: string) {
  const page = record(value);
  learnSecrets(page);
  if (!Array.isArray(page.data) || page.continuationToken !== null)
    incompatible();
  const seen = new Set<string>();
  return (page.data as unknown[]).map((v) => {
    const d = record(v),
      id = text(d.identifier);
    if (!id || seen.has(id)) incompatible();
    seen.add(id);
    for (const key of ["online", "trusted", "hasStoredDevice", "isTrusted"])
      if (typeof d[key] !== "boolean") incompatible();
    return {
      id,
      name: text(d.name),
      systemName: text(d.systemName),
      current: id === current,
      hasStoredDevice: d.hasStoredDevice,
      online: d.online,
      rememberedTwoFactor: d.trusted,
      hasWrappedKeys: d.hasStoredDevice ? d.isTrusted : false,
      trustedUntil: d.trustedUntil === null ? null : text(d.trustedUntil),
      createdAt: d.creationDate === "" ? null : text(d.creationDate),
      lastActivityAt:
        d.lastActivityDate === null ? null : text(d.lastActivityDate),
    };
  });
}
export function devices(program: Command, c: Context) {
  const group = program
    .command("devices")
    .description("Own-account devices; exact-target management");
  group.command("list").action(
    c.action("devices list", async () => {
      const p = await c.profile();
      c.print(devicesPage(await c.query("/api/devices"), p.device));
    }),
  );
  async function all() {
    const p = await c.profile();
    return authorizedDevices(
      await c.query("/api/devices/authorized"),
      p.device,
    );
  }
  async function target(id: string) {
    identifier(id);
    const d = (await all()).find((d) => d.id === id);
    if (!d)
      throw new CliError("NOT_FOUND", "Exact own-account device not found.", 6);
    return d;
  }
  group.command("show <id>").action(
    c.action("devices show", async (id) => {
      c.print(await target(id));
    }),
  );
  for (const action of ["rename", "revoke-trust", "remove"]) {
    const cmd = mutationOptions(group.command(`${action} <id>`));
    if (action === "rename")
      cmd.requiredOption("--name <name>", "New device note (1–128 characters)");
    cmd.action(
      c.action(`devices ${action}`, async (id, opts) => {
        const d = await target(id);
        if (action === "remove" && d.current)
          invalid("Use auth logout --server for the current CLI device.");
        if (
          action === "rename" &&
          (!d.hasStoredDevice ||
            !opts.name ||
            opts.name !== opts.name.trim() ||
            opts.name.length > 128 ||
            /[\x00-\x1f\x7f]/.test(opts.name))
        )
          invalid("A stored device and a 1–128 character note are required.");
        if (
          !(await confirmMutation(c, opts, {
            action: `devices ${action}`,
            device: d,
            ...(action === "rename" ? { newName: opts.name } : {}),
            effect:
              action === "revoke-trust"
                ? "Forget remembered 2FA; does not log out the device."
                : action === "remove"
                  ? "Remove this device; stale auth caches may last 15 seconds."
                  : "Update device note.",
          }))
        )
          return;
        const encoded = encodeURIComponent(id);
        const trustOnly =
          action === "revoke-trust" ||
          (action === "remove" && !d.hasStoredDevice);
        const path = trustOnly
          ? `/api/devices/authorized/${encoded}`
          : action === "rename"
            ? `/api/devices/${encoded}/name`
            : `/api/devices/${encoded}`;
        const result = record(
          await write(
            c,
            action === "rename" ? "PUT" : "DELETE",
            path,
            action === "rename" ? { name: opts.name } : {},
          ),
        );
        if (action !== "rename" && result.success !== true) incompatible();
        const after = (await all()).find((d) => d.id === id);
        if (
          action === "rename"
            ? after?.name !== opts.name
            : action === "remove"
              ? !!after
              : !!after?.rememberedTwoFactor
        )
          throw new CliError(
            "VERIFY_FAILED",
            "Write returned, but target read-back disagrees. Do not retry blindly.",
            6,
          );
        c.print(
          { action, id, verified: true, device: after ?? null },
          action === "remove"
            ? [
                "Target removed from server list; cross-instance token caches may remain for 15 seconds.",
              ]
            : [],
        );
      }),
    );
  }
}

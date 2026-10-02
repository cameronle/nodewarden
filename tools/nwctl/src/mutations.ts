import type { Command } from "commander";
import { createInterface } from "node:readline/promises";
import { Context } from "./context.js";
import { Client } from "./http.js";
import { CliError, invalid } from "./errors.js";
import { identity } from "./contracts.js";
import { humanText } from "./output.js";
export function mutationOptions(cmd: Command) {
  return cmd
    .option("--dry-run", "Read and show the exact operation; do not write")
    .option(
      "--yes",
      "Confirm this exact operation (never bypasses server verification)",
    );
}
export function identifier(value: string) {
  if (
    !value ||
    value !== value.trim() ||
    value.length > 256 ||
    /[\x00-\x20\x7f/\\?#%]/.test(value) ||
    value === "." ||
    value === ".."
  )
    invalid("Invalid exact identifier.");
  return value;
}
export async function confirmMutation(
  c: Context,
  opts: { dryRun?: boolean; yes?: boolean },
  plan: Record<string, unknown>,
) {
  const p = await c.profile();
  const actor = identity(await c.query("/api/accounts/profile"));
  const preview = { server: p.server, account: actor.email, ...plan };
  if (opts.dryRun) {
    c.print({ dryRun: true, ...preview });
    return false;
  }
  process.stderr.write(humanText(preview));
  if (opts.yes) return true;
  if (!process.stdin.isTTY || !process.stderr.isTTY)
    invalid(
      "Confirmation required. Inspect --dry-run, then explicitly use --yes.",
    );
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    if ((await rl.question("Type yes to proceed: ")) !== "yes")
      throw new CliError(
        "CANCELLED",
        "Operation cancelled; no target write sent.",
        2,
      );
  } finally {
    rl.close();
  }
  return true;
}
export async function write(
  c: Context,
  method: "POST" | "PUT" | "DELETE",
  path: string,
  body: Record<string, unknown> = {},
  timeout = c.timeout(),
) {
  const p = await c.profile(),
    store = c.store(),
    session = await store.session(p);
  try {
    return await new Client(p.server, p.allowLoopback, timeout).write(
      method,
      path,
      body,
      session.token,
    );
  } catch (e) {
    if (e instanceof CliError && e.status === 401) await store.logout(p);
    throw e;
  }
}

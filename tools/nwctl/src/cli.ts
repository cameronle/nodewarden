import { Command, CommanderError } from "commander";
import { Context } from "./context.js";
import { CliError } from "./errors.js";
import { clean, safeText } from "./output.js";
import { profiles } from "./commands/profile.js";
import { authentication } from "./commands/auth.js";
import { doctor } from "./commands/doctor.js";
import { backups } from "./commands/backup.js";
import { users } from "./commands/users.js";
import { audit } from "./commands/audit.js";
import { devices } from "./commands/devices.js";
import { status } from "./commands/status.js";
const program = new Command()
  .name("nwctl")
  .description("NodeWarden inspection and dedicated CLI session management")
  .version("0.2.0")
  .option("--json", "Machine-readable JSON envelope")
  .option("--profile <name>", "Select a configured instance")
  .option(
    "--config-dir <directory>",
    "Private configuration directory (default ~/.config/nwctl)",
  )
  .option(
    "--timeout <ms>",
    "Total timeout per HTTP request in milliseconds",
    "15000",
  )
  .showSuggestionAfterError(false)
  .configureOutput({ writeErr: () => {}, outputError: () => {} })
  .exitOverride();
const c = new Context(program);
for (const register of [
  profiles,
  authentication,
  doctor,
  backups,
  users,
  audit,
  devices,
  status,
])
  register(program, c);
try {
  await program.parseAsync();
} catch (e) {
  if (e instanceof CommanderError && e.exitCode === 0) {
    process.exitCode = 0;
  } else {
    const err =
      e instanceof CliError
        ? e
        : e instanceof CommanderError
          ? new CliError(
              "INVALID_ARGUMENT",
              "Invalid command/options; use --help. Arguments suppressed.",
              2,
            )
          : new CliError(
              "LOCAL_ERROR",
              "Local operation failed; raw diagnostics suppressed. Check storage access and configuration.",
              5,
            );
    process.exitCode = err.exitCode;
    if (program.opts().json || process.argv.includes("--json"))
      process.stdout.write(
        JSON.stringify(
          clean({
            schemaVersion: 1,
            ok: false,
            command: c.command,
            profile: c.profileName,
            error: {
              code: err.code,
              message: err.message,
              exitCode: err.exitCode,
              ...(err.status ? { httpStatus: err.status } : {}),
            },
          }),
        ) + "\n",
      );
    else process.stderr.write(safeText(err.message) + "\n");
  }
}

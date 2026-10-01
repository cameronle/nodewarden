import { StringDecoder } from "node:string_decoder";
import { CliError, invalid } from "./errors.js";
export function credentialsFromText(value: string) {
  const lines = value.replace(/\r\n/g, "\n").split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length !== 2 || !lines[0] || !lines[1] || value.length > 8192)
    return invalid(
      "Credentials stdin must contain exactly client ID and API Secret on two lines.",
    );
  return { clientId: lines[0], clientSecret: lines[1] };
}
async function hiddenCredentials(): Promise<{
  clientId: string;
  clientSecret: string;
}> {
  if (!process.stdin.isTTY || !process.stderr.isTTY)
    return invalid(
      "Interactive login requires a TTY; use explicit --credentials-stdin for controlled pipes.",
    );
  const old = process.stdin.isRaw;
  // Keep echo disabled across both prompts, including pasted multi-line input.
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    const values = ["", ""];
    const decoder = new StringDecoder("utf8");
    let index = 0;
    let skipLf = false;
    let finished = false;
    const done = (error?: Error) => {
      if (finished) return;
      finished = true;
      process.stdin.removeListener("data", data);
      process.stdin.removeListener("end", interrupt);
      process.stdin.removeListener("error", inputError);
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
      process.stdin.setRawMode(old);
      process.stdin.pause();
      process.stderr.write("\n");
      error
        ? reject(error)
        : resolve({ clientId: values[0], clientSecret: values[1] });
    };
    const interrupt = () =>
      done(new CliError("INTERRUPTED", "Login interrupted.", 130));
    const inputError = () =>
      done(new CliError("INPUT_ERROR", "Terminal input failed.", 5));
    const data = (chunk: Buffer) => {
      for (const c of decoder.write(chunk)) {
        if (skipLf && c === "\n") {
          skipLf = false;
          continue;
        }
        skipLf = false;
        if (c === "\u0003" || c === "\u0004") {
          interrupt();
          return;
        }
        if (c === "\r" || c === "\n") {
          skipLf = c === "\r";
          if (index === 1) {
            done();
            return;
          }
          index = 1;
          process.stderr.write("\nAPI Secret (hidden): ");
          continue;
        }
        if (c === "\u007f" || c === "\b")
          values[index] = Array.from(values[index]).slice(0, -1).join("");
        else if (c >= " ") values[index] += c;
        if (values[index].length > 4096) {
          done(new CliError("INVALID_ARGUMENT", "Input too long.", 2));
          return;
        }
      }
    };
    process.stdin.on("data", data);
    process.stdin.once("end", interrupt);
    process.stdin.once("error", inputError);
    process.once("SIGINT", interrupt);
    process.once("SIGTERM", interrupt);
    // Announce readiness only after echo is disabled and listeners are attached.
    process.stderr.write("Personal client ID (hidden): ");
  });
}
export async function credentials(stdin: boolean) {
  if (!stdin) return hiddenCredentials();
  if (process.stdin.isTTY)
    return invalid("--credentials-stdin requires a controlled non-TTY pipe.");
  let data = "";
  const decoder = new StringDecoder("utf8");
  for await (const chunk of process.stdin) {
    data += decoder.write(chunk);
    if (data.length > 8192) return invalid("Credentials input too long.");
  }
  return credentialsFromText(data + decoder.end());
}

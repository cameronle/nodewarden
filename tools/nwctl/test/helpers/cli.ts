import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
export async function cli(
  dir: string,
  args: string[],
  input?: string,
  bin = fileURLToPath(new URL("../../bin/nwctl.mjs", import.meta.url)),
) {
  return new Promise<{
    code: number | null;
    stdout: string;
    stderr: string;
    data: any;
  }>((resolve, reject) => {
    const p = spawn(
      process.execPath,
      [bin, "--config-dir", dir, "--json", ...args],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    let stdout = "",
      stderr = "";
    const timer = setTimeout(() => {
      p.kill();
      reject(new Error("CLI test deadline exceeded"));
    }, 45000);
    p.stdout.on("data", (b) => (stdout += b));
    p.stderr.on("data", (b) => (stderr += b));
    p.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    p.on("close", (code) => {
      clearTimeout(timer);
      try {
        resolve({ code, stdout, stderr, data: JSON.parse(stdout) });
      } catch {
        reject(new Error("Invalid CLI JSON: " + stdout + stderr));
      }
    });
    p.stdin.on("error", () => {});
    p.stdin.end(input);
  });
}

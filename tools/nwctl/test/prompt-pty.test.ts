import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import assert from "node:assert/strict";
const exec = promisify(execFile);
for (const scenario of [
  "submit",
  "paste",
  "backspace",
  "ctrl-c",
  "ctrl-c-secret",
  "ctrl-d",
  "sigterm",
  "oversize",
]) {
  test(`real TTY: ${scenario} hides credentials and restores terminal`, async () => {
    const result = await exec(
      "python3",
      ["test/helpers/prompt-pty.py", process.execPath, scenario],
      { timeout: 15000 },
    );
    assert.equal(result.stdout.trim(), "PTY masking and restoration passed");
  });
}

import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { resolve, parse, join } from "node:path";
import { invalid } from "./errors.js";
// A bounded descriptor read prevents symlink swaps and oversized input allocation.
export async function privateJson(value: string): Promise<unknown> {
  if (!value || /[\x00-\x1f\x7f]/.test(value))
    return invalid("Explicit private JSON file required.");
  const path = resolve(value);
  let current = parse(path).root;
  for (const part of path.slice(current.length).split("/")) {
    current = join(current, part);
    const s = await lstat(current);
    if (s.isSymbolicLink())
      return invalid("Private input must not contain symlinks.");
  }
  const fd = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const s = await fd.stat();
    if (
      !s.isFile() ||
      s.nlink !== 1 ||
      (s.mode & 0o777) !== 0o600 ||
      (process.getuid && s.uid !== process.getuid()) ||
      s.size > 8192
    )
      return invalid(
        "Input must be an owned, single-link 0600 regular file up to 8192 bytes.",
      );
    const buffer = Buffer.alloc(8193);
    let used = 0;
    while (used < buffer.length) {
      const r = await fd.read(buffer, used, buffer.length - used, used);
      if (!r.bytesRead) break;
      used += r.bytesRead;
    }
    if (used > 8192) return invalid("Private JSON file too large.");
    try {
      return JSON.parse(buffer.subarray(0, used).toString("utf8"));
    } catch {
      return invalid("Invalid private JSON; contents suppressed.");
    } finally {
      buffer.fill(0);
    }
  } finally {
    await fd.close();
  }
}

import { constants } from "node:fs";
import { lstat, open, unlink, link } from "node:fs/promises";
import { dirname, join, resolve, parse } from "node:path";
import { randomUUID } from "node:crypto";
import { invalid } from "./errors.js";
export async function validateOutput(value: string) {
  if (!value || /[\x00-\x1f\x7f]/.test(value))
    invalid("Explicit output file required.");
  const path = resolve(value),
    parent = dirname(path);
  let current = parse(parent).root;
  for (const part of parent.slice(current.length).split("/").filter(Boolean)) {
    current = join(current, part);
    const s = await lstat(current);
    if (s.isSymbolicLink() || !s.isDirectory())
      invalid("Output parent must not contain symlinks.");
  }
  const ps = await lstat(parent);
  if ((process.getuid && ps.uid !== process.getuid()) || ps.mode & 0o022)
    invalid("Output parent must be owned by you and not group/world writable.");
  try {
    await lstat(path);
    invalid("Output already exists; refusing overwrite.");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  return path;
}
export async function privateOutput(value: string) {
  const path = await validateOutput(value),
    temp = join(dirname(path), ".nwctl-" + randomUUID() + ".part");
  const fd = await open(
    temp,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600,
  );
  let closed = false;
  const close = async () => {
    if (!closed) {
      closed = true;
      await fd.close();
    }
  };
  return {
    path,
    write: async (data: string | Uint8Array) => {
      await fd.writeFile(data);
    },
    commit: async () => {
      await fd.sync();
      await close();
      await link(temp, path);
      await unlink(temp);
    },
    abort: async () => {
      await close().catch(() => {});
      await unlink(temp).catch(() => {});
    },
  };
}

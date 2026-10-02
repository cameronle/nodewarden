import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, appendFile, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readPrivateArchive } from "../src/backup-inspection.js";
test("concurrent archive growth never reads more than the verified size plus one byte", async () => {
  const dir = await mkdtemp(join(tmpdir(), "archive-growth-")),
    path = join(dir, "backup.zip");
  await writeFile(path, Buffer.alloc(128), { mode: 0o600 });
  const probe = await open(path, "r"),
    prototype = Object.getPrototypeOf(probe);
  await probe.close();
  const originalReadFile = prototype.readFile,
    originalRead = prototype.read;
  let total = 0,
    grown = false;
  async function grow() {
    if (!grown) {
      grown = true;
      await appendFile(path, Buffer.alloc(5 * 1024 * 1024));
    }
  }
  prototype.readFile = async function (...args: any[]) {
    await grow();
    const result = await originalReadFile.apply(this, args);
    total += result.length;
    return result;
  };
  prototype.read = async function (...args: any[]) {
    await grow();
    const result = await originalRead.apply(this, args);
    total += result.bytesRead;
    return result;
  };
  try {
    await assert.rejects(readPrivateArchive(path), /changed/i);
    assert.ok(total <= 129, "file reader ignored its verified-size bound");
  } finally {
    prototype.readFile = originalReadFile;
    prototype.read = originalRead;
    await rm(dir, { recursive: true, force: true });
  }
});

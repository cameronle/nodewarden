import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, realpath, rm, stat, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "../src/http.js";
import { downloadOperation } from "../src/download.js";
test("fresh export never publishes ZIP-prefix-only response when a complete HTTP body lacks central directory", async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-short-"))),
    server = createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/zip" });
      res.write(
        Buffer.concat([Buffer.from("504b0304", "hex"), Buffer.alloc(30)]),
      );
      res.end();
    });
  try {
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address() as any,
      output = join(dir, "archive.zip");
    await assert.rejects(() =>
      downloadOperation(
        new Client(`http://127.0.0.1:${address.port}`, true, 1000),
        "00000000-0000-0000-0000-000000000000",
        "a".repeat(64),
        "fixture-token",
        output,
        "",
      ),
    );
    await assert.rejects(stat(output), { code: "ENOENT" });
    assert.deepEqual(await readdir(dir), []);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});

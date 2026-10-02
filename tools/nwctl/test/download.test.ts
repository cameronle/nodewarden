import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  mkdtemp,
  realpath,
  rm,
  readFile,
  readdir,
  symlink,
  mkdir,
  open,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { Client } from "../src/http.js";
import { downloadOperation } from "../src/download.js";
import { privateOutput } from "../src/private-output.js";
test("disk-full write failure cancels locked download stream and removes partial output", async (t) => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-disk-full-")));
  const probe = await open(join(dir, "probe"), "w");
  const prototype = Object.getPrototypeOf(probe);
  await probe.close();
  await rm(join(dir, "probe"));
  t.mock.method(prototype, "writeFile", async () => {
    throw Object.assign(new Error("simulated full disk"), { code: "ENOSPC" });
  });
  let closed = false,
    calls = 0;
  const server = createServer((req, res) => {
    calls++;
    req.resume();
    res.on("close", () => {
      closed = true;
    });
    res.writeHead(200, { "Content-Type": "application/zip" });
    res.write(
      Buffer.concat([Buffer.from("504b0304", "hex"), Buffer.alloc(100)]),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const client = new Client(
      `http://127.0.0.1:${(server.address() as any).port}`,
      true,
      10000,
    );
    await assert.rejects(
      downloadOperation(
        client,
        randomUUID(),
        "a".repeat(64),
        "fixture-token",
        join(dir, "out.zip"),
        "test.zip",
      ),
      { code: "DOWNLOAD_FAILED" },
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      closed,
      true,
      "failed file write must abort a reader-locked HTTP body",
    );
    assert.equal(calls, 1);
    assert.deepEqual(await readdir(dir), []);
  } finally {
    t.mock.restoreAll();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});
test("download refuses redirects, HTML, oversized or truncated streams without retries or residue", async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-stream-")));
  let mode = "html",
    calls = 0;
  const server = createServer((req, res) => {
    calls++;
    req.resume();
    if (mode === "redirect") {
      res.writeHead(302, { Location: "/other" });
      res.end();
      return;
    }
    if (mode === "html") {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html>login</html>");
      return;
    }
    res.setHeader("Content-Type", "application/zip");
    if (mode === "oversize") {
      res.setHeader("Content-Length", String(64 * 1024 * 1024 + 1));
      res.end();
      return;
    }
    const zip = Buffer.concat([
      Buffer.from("504b0304", "hex"),
      Buffer.alloc(100),
    ]);
    if (mode === "truncated") {
      res.setHeader("Content-Length", zip.length + 100);
      res.write(zip);
      setTimeout(() => res.destroy(), 20);
      return;
    }
    if (mode === "timeout") {
      res.write(zip);
      return;
    }
    res.end(zip);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const client = new Client(
    `http://127.0.0.1:${(server.address() as any).port}`,
    true,
    150,
  );
  try {
    for (mode of ["redirect", "html", "oversize", "truncated", "timeout"]) {
      const before = calls;
      await assert.rejects(
        downloadOperation(
          client,
          randomUUID(),
          "a".repeat(64),
          "fixture-token",
          join(dir, "out.zip"),
          "test.zip",
        ),
      );
      assert.equal(calls, before + 1);
      assert.deepEqual(await readdir(dir), []);
    }
    mode = "zip";
    const out = join(dir, "out.zip");
    const ok = await downloadOperation(
      client,
      randomUUID(),
      "a".repeat(64),
      "fixture-token",
      out,
      "test.zip",
    );
    assert.equal(ok.bytes, 104);
    assert.equal((await readFile(out)).length, 104);
    const before = calls;
    await assert.rejects(
      downloadOperation(
        client,
        randomUUID(),
        "a".repeat(64),
        "fixture-token",
        out,
        "test.zip",
      ),
    );
    assert.equal(calls, before);
    await assert.rejects(
      downloadOperation(
        client,
        randomUUID(),
        "a".repeat(64),
        "fixture-token",
        join(dir, "bad.zip"),
        "test_fffff.zip",
      ),
    );
    assert.deepEqual(await readdir(dir), ["out.zip"]);
    await symlink(out, join(dir, "link"));
    await assert.rejects(privateOutput(join(dir, "link")));
    await mkdir(join(dir, "parent"));
    await symlink(join(dir, "parent"), join(dir, "symlink"));
    await assert.rejects(privateOutput(join(dir, "symlink", "output")));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type RequestListener } from "node:http";
import { Client, serverOrigin } from "../src/http.js";
async function fixture(
  handler: RequestListener,
  fn: (url: string) => Promise<void>,
) {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const a = server.address() as { port: number };
  try {
    await fn(`http://127.0.0.1:${a.port}`);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
}
test("origins require HTTPS, reject embedded credentials and paths, allow explicit numeric loopback", () => {
  assert.equal(serverOrigin("https://nw.example/"), "https://nw.example");
  for (const url of [
    "http://nw.example",
    "https://u:p@nw.example",
    "https://nw.example/api",
    "https://nw.example?x=1",
    "https://nw.example#x",
  ])
    assert.throws(() => serverOrigin(url), { exitCode: 2 });
  assert.throws(() => serverOrigin("http://127.0.0.1:1234"), { exitCode: 2 });
  assert.equal(
    serverOrigin("http://127.0.0.1:1234", true),
    "http://127.0.0.1:1234",
  );
});
test("requests enforce the read-only allowlist before connecting", async () => {
  const c = new Client("https://nw.example");
  await assert.rejects(c.get("/api/admin/backup/run"), { exitCode: 2 });
  await assert.rejects(c.postForm("/api/admin/backup/settings", {}), {
    exitCode: 2,
  });
});
test("HTTP status mapping never leaks the error body", async () => {
  for (const [status, exitCode] of [
    [401, 3],
    [403, 4],
    [409, 6],
    [429, 5],
    [500, 5],
  ])
    await fixture(
      (_, res) => {
        res.writeHead(status);
        res.end("TOP_SECRET_RESPONSE");
      },
      async (url) => {
        await assert.rejects(
          new Client(url, true, 200).get("/api/config"),
          (e: any) =>
            e.exitCode === exitCode && !e.message.includes("TOP_SECRET"),
        );
      },
    );
});
test("HTML and malformed JSON fail contract validation; redirects are not followed", async () => {
  for (const [status, content, headers] of [
    [200, "<html>login</html>", {}],
    [200, "broken", {}],
    [302, "", { Location: "https://other.example" }],
  ] as const)
    await fixture(
      (_, res) => {
        res.writeHead(status, headers);
        res.end(content);
      },
      async (url) => {
        await assert.rejects(
          new Client(url, true, 200).get("/api/config"),
          (e: any) => [5, 6].includes(e.exitCode),
        );
      },
    );
});
test("GET retries once but POST never retries; slow bodies respect deadline", async () => {
  let calls = 0;
  await fixture(
    (_, res) => {
      calls++;
      res.writeHead(calls === 1 ? 503 : 200);
      res.end("{}");
    },
    async (url) => {
      await new Client(url, true, 1000).get("/api/config");
      assert.equal(calls, 2);
    },
  );
  calls = 0;
  await fixture(
    (_, res) => {
      calls++;
      res.writeHead(503);
      res.end("");
    },
    async (url) => {
      await assert.rejects(
        new Client(url, true, 500).postForm("/identity/connect/token", {}),
      );
      assert.equal(calls, 1);
    },
  );
  await fixture(
    (_, res) => {
      res.writeHead(200);
      res.write("{");
    },
    async (url) => {
      await assert.rejects(new Client(url, true, 100).get("/api/config"), {
        exitCode: 5,
      });
    },
  );
});

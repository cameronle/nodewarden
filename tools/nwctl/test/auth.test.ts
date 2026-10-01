import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, readdir, rm, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/config.js";
import { login } from "../src/auth.js";
test("login revokes refresh before persisting a short session and never saves key material", async () => {
  const calls: string[] = [];
  let revokeFails = false;
  let malformed = false;
  const server = createServer((req, res) => {
    calls.push(req.url!);
    res.setHeader("Content-Type", "application/json");
    if (req.url === "/identity/connect/token")
      res.end(
        JSON.stringify({
          access_token: "fixture-access",
          refresh_token: "fixture-refresh",
          expires_in: malformed ? "bad" : 60,
          token_type: "Bearer",
          Key: "fixture-key",
          PrivateKey: "fixture-private",
        }),
      );
    else if (req.url === "/identity/connect/revocation") {
      res.statusCode = revokeFails ? 503 : 200;
      res.end();
    } else
      res.end(
        JSON.stringify({
          id: "a",
          name: null,
          email: "a@example.test",
          role: "admin",
          status: "active",
          key: "fixture-key",
        }),
      );
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-auth-")));
  try {
    const s = new Store(join(dir, "private"));
    await s.add(
      "test",
      `http://127.0.0.1:${(server.address() as any).port}`,
      true,
    );
    const p = await s.profile();
    await login(s, p, "user.a", "fixture-api-secret");
    assert.deepEqual(calls, [
      "/identity/connect/token",
      "/identity/connect/revocation",
      "/api/accounts/profile",
    ]);
    const disk = (
      await Promise.all(
        (await readdir(s.dir)).map((f) => readFile(join(s.dir, f), "utf8")),
      )
    ).join("");
    for (const secret of [
      "fixture-refresh",
      "fixture-key",
      "fixture-private",
      "fixture-api-secret",
    ])
      assert.ok(!disk.includes(secret));
    assert.equal((await s.session(p)).token, "fixture-access");
    malformed = true;
    calls.length = 0;
    await assert.rejects(login(s, p, "user.a", "fixture-api-secret"), {
      exitCode: 6,
    });
    assert.deepEqual(calls, [
      "/identity/connect/token",
      "/identity/connect/revocation",
    ]);
    malformed = false;
    revokeFails = true;
    await assert.rejects(login(s, p, "user.a", "fixture-api-secret"), {
      exitCode: 5,
    });
    await assert.rejects(s.session(p), { exitCode: 3 });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    await rm(dir, { recursive: true, force: true });
  }
});

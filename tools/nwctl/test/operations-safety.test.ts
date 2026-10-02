import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/config.js";
import { ensureSession, cachedLogin } from "../src/ensure.js";
import { devicesPage, serverLogout } from "../src/devices.js";
import { Client } from "../src/http.js";
import { auditFilters } from "../src/audit-filters.js";
const user = {
  id: "test-account",
  name: null,
  email: "test@example.test",
  role: "admin",
  status: "active",
};
async function fixture(
  handler: (q: IncomingMessage, r: ServerResponse) => void,
) {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const dir = await realpath(await mkdtemp(join(tmpdir(), "nw-safety-")));
  const store = new Store(dir);
  const p = await store.add(
    "test",
    `http://127.0.0.1:${(server.address() as any).port}`,
    true,
  );
  const token =
    "e30." +
    Buffer.from(
      JSON.stringify({ sub: user.id, did: p.device, dstamp: "test-stamp" }),
    ).toString("base64url") +
    ".testsignature";
  await store.saveSession(p, { token, expiresAt: Date.now() + 60000 });
  return {
    store,
    p,
    token,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
      await rm(dir, { recursive: true, force: true });
    },
  };
}

test("auth ensure never reacquires credentials on permission/network/contract errors", async () => {
  let status = 403,
    acquired = 0;
  const f = await fixture((_q, r) => {
    r.statusCode = status;
    r.end(status === 200 ? "<html>login</html>" : "private-error");
  });
  try {
    for (status of [403, 503, 200]) {
      await assert.rejects(
        ensureSession(f.store, f.p, 1000, async () => {
          acquired++;
          return {
            clientId: "user.test-account",
            clientSecret: "synthetic-secret",
          };
        }),
      );
    }
    assert.equal(acquired, 0);
    assert.equal((await f.store.session(f.p)).token, f.token);
    await assert.rejects(
      cachedLogin(f.store, {
        ...f.p,
        name: "prod",
        server: "https://nodewarden.865455.xyz",
        allowLoopback: false,
      }),
      { exitCode: 2 },
    );
  } finally {
    await f.close();
  }
});

test("server logout waits for stale auth cache, sends one exact DELETE and clears locally", async () => {
  const calls: string[] = [];
  let removed = false,
    probes = 0;
  const f = await fixture((q, r) => {
    calls.push(q.method + " " + q.url);
    if (q.method === "DELETE") {
      removed = true;
      r.end('{"success":true}');
    } else if (removed && ++probes > 1) {
      r.statusCode = 401;
      r.end("private-error");
    } else r.end(JSON.stringify(user));
  });
  try {
    const result = await serverLogout(f.store, f.p, 2000);
    assert.equal(result.oldAccessRejected, true);
    assert.deepEqual(
      calls.filter((v) => v.startsWith("DELETE")),
      ["DELETE /api/devices/" + f.p.device],
    );
    assert.equal(probes, 2);
    await assert.rejects(f.store.session(f.p), { exitCode: 3 });
  } finally {
    await f.close();
  }
});

test("server logout refuses JWT/profile mismatch before DELETE", async () => {
  let deletes = 0;
  const f = await fixture((q, r) => {
    if (q.method === "DELETE") deletes++;
    r.end(JSON.stringify(user));
  });
  try {
    await assert.rejects(
      serverLogout(
        f.store,
        { ...f.p, device: "00000000-0000-0000-0000-000000000000" },
        100,
      ),
      { exitCode: 3 },
    );
    const mismatch =
      "e30." +
      Buffer.from(
        JSON.stringify({ sub: user.id, did: "other", dstamp: "stamp" }),
      ).toString("base64url") +
      ".sig";
    await f.store.saveSession(f.p, {
      token: mismatch,
      expiresAt: Date.now() + 60000,
    });
    await assert.rejects(serverLogout(f.store, f.p, 100), {
      code: "DEVICE_BINDING_MISMATCH",
    });
    assert.equal(deletes, 0);
    assert.equal((await f.store.session(f.p)).token, mismatch);
  } finally {
    await f.close();
  }
});

test("server logout never reports success or retries DELETE on ambiguous outcomes", async () => {
  for (const mode of [
    "keeps-accepting",
    "delete-503",
    "malformed",
    "false",
    "probe-503",
  ]) {
    let deletes = 0,
      removed = false;
    const f = await fixture((q, r) => {
      if (q.method === "DELETE") {
        deletes++;
        removed = true;
        r.statusCode = mode === "delete-503" ? 503 : 200;
        r.end(
          mode === "malformed"
            ? "not-json"
            : JSON.stringify({ success: mode !== "false" }),
        );
      } else {
        r.statusCode = removed && mode === "probe-503" ? 503 : 200;
        r.end(JSON.stringify(user));
      }
    });
    try {
      await assert.rejects(serverLogout(f.store, f.p, 100));
      assert.equal(deletes, 1, mode);
      await assert.rejects(f.store.session(f.p), { exitCode: 3 });
    } finally {
      await f.close();
    }
  }
});

test("device contracts expose metadata only and reject incomplete/duplicate lists", () => {
  const device = {
    id: "synthetic-device",
    name: "CLI",
    type: 8,
    isTrusted: false,
    creationDate: "2026-10-01T00:00:00Z",
    lastActivityDate: null,
    encryptedUserKey: "fixture-secret-device-key",
  };
  assert.deepEqual(
    devicesPage({ data: [device], continuationToken: null }, device.id),
    {
      count: 1,
      items: [
        {
          id: device.id,
          name: "CLI",
          type: 8,
          current: true,
          createdAt: device.creationDate,
          lastActivityAt: null,
          trusted: false,
        },
      ],
    },
  );
  for (const value of [
    { data: [device], continuationToken: "next" },
    { data: [device, device], continuationToken: null },
    { data: [{ ...device, type: "8" }], continuationToken: null },
    { data: [{ ...device, creationDate: "bad" }], continuationToken: null },
  ])
    assert.throws(() => devicesPage(value, device.id), { exitCode: 6 });
  const client = new Client("https://example.test");
  for (const id of [
    "",
    "../accounts",
    "all",
    "a?other=1",
    "00000000-0000-0000-0000-000000000000/extra",
  ])
    assert.throws(() => client.revokeDevice(id, "fixture-access"), {
      exitCode: 2,
    });
});

test("audit ISO boundaries normalize equivalent timezones and preserve search input", () => {
  assert.deepEqual(
    auditFilters({
      from: "2026-10-01T08:00:00+08:00",
      to: "2026-10-01T00:00:00Z",
      query: "a + b&c",
    }),
    {
      from: "2026-10-01T00:00:00.000Z",
      to: "2026-10-01T00:00:00.000Z",
      q: "a + b&c",
    },
  );
  for (const from of [
    "2026-02-30T00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2026-10-01T24:00:00Z",
    "2026-10-01",
    "2026-10-01T00:00:00",
  ])
    assert.throws(() => auditFilters({ from }), { exitCode: 2 });
});

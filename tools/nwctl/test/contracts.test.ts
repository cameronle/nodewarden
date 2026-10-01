import { test } from "node:test";
import assert from "node:assert/strict";
import {
  identity,
  settings,
  auditPage,
  remotePage,
  usersPage,
} from "../src/contracts.js";
test("identity uses an output allowlist; missing mandatory fields fail closed", () => {
  const p = {
    id: "a",
    name: null,
    email: "a@example.test",
    role: "admin",
    status: "active",
    key: "VAULT_SECRET",
  };
  assert.deepEqual(identity(p), {
    id: "a",
    name: null,
    email: "a@example.test",
    role: "admin",
    status: "active",
  });
  assert.throws(() => identity({}), { exitCode: 6 });
});
test("lists reject missing or contradictory page fields rather than fabricate empty success", () => {
  assert.throws(() => settings({}), { exitCode: 6 });
  assert.deepEqual(settings({ destinations: [] }), []);
  assert.throws(() => usersPage({}), { exitCode: 6 });
  assert.throws(() => remotePage({}), { exitCode: 6 });
  assert.throws(
    () =>
      auditPage({ data: [], limit: 50, offset: 0, total: 1, hasMore: false }),
    { exitCode: 6 },
  );
  assert.deepEqual(
    auditPage({ data: [], limit: 50, offset: 0, total: 0, hasMore: false }),
    { items: [], count: 0, total: 0, limit: 50, offset: 0, hasMore: false },
  );
});

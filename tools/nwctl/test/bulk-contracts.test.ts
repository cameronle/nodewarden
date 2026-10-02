import { test } from "node:test";
import assert from "node:assert/strict";
import { deviceBulk, pruneInvites } from "../src/bulk.js";
test("bulk previews expose only typed metadata, never unrecognized wrapped-key fields", async () => {
  const printed: any[] = [],
    actor = {
      id: "fixture-id",
      name: "Admin",
      email: "admin@example.test",
      role: "admin",
      status: "active",
    };
  let page: any = {
    items: [
      {
        id: "other",
        revision: "a".repeat(64),
        name: "Phone",
        stored: true,
        rememberedTwoFactor: true,
        unknown: "unexpected-wrapped-ciphertext",
      },
    ],
  };
  const ctx: any = {
    profile: async () => ({
      device: "current",
      server: "https://example.test",
    }),
    query: async (path: string) =>
      path === "/api/accounts/profile" ? actor : page,
    print: (value: any) => printed.push(value),
  };
  await deviceBulk(ctx, { all: true, dryRun: true });
  assert.ok(!JSON.stringify(printed).includes("unexpected-wrapped-ciphertext"));
  page = {
    items: [
      {
        id: "b".repeat(64),
        revision: "c".repeat(64),
        status: "used",
        expiresAt: new Date().toISOString(),
        used: true,
        eligible: true,
        unknown: "unexpected-wrapped-ciphertext",
      },
    ],
  };
  await pruneInvites(ctx, { dryRun: true });
  assert.ok(!JSON.stringify(printed).includes("unexpected-wrapped-ciphertext"));
});

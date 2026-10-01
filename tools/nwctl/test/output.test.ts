import { test } from "node:test";
import assert from "node:assert/strict";
import { clean, rememberSecret, humanText } from "../src/output.js";
test("output redacts sensitive fields, known secret values and terminal control sequences", () => {
  rememberSecret("unique-fixture-value");
  const result = JSON.stringify(
    clean({
      secretAccessKey: "s3-secret",
      password: "dav-secret",
      privateKey: "vault-key",
      name: "\x1b[31mhello\x07",
      nested: { note: "unique-fixture-value" },
      url: "https://u:p@nw.example/?token=abc",
    }),
  );
  for (const value of [
    "s3-secret",
    "dav-secret",
    "vault-key",
    "unique-fixture-value",
    "u:p",
    "token=abc",
    "\\u001b",
    "\\u0007",
  ])
    assert.ok(!result.includes(value), value);
});
test("human output is compact labeled text, not a raw JSON document", () => {
  const h = humanText({
    healthy: false,
    destinations: [{ name: "DAV", health: "disabled", password: "hidden" }],
  });
  assert.match(h, /healthy: false/);
  assert.match(h, /name: DAV/);
  assert.doesNotMatch(h, /[{}]/);
  assert.ok(!h.includes("hidden"));
});

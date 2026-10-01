import { test } from "node:test";
import assert from "node:assert/strict";
import { credentialsFromText } from "../src/prompt.js";
test("explicit stdin requires exactly two bounded lines and preserves secret bytes", () => {
  assert.deepEqual(credentialsFromText("user.a\n space-secret \n"), {
    clientId: "user.a",
    clientSecret: " space-secret ",
  });
  for (const s of ["one", "user.a\n\n", "user.a\nx\nextra"])
    assert.throws(() => credentialsFromText(s), { exitCode: 2 });
});

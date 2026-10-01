import { test } from "node:test";
import assert from "node:assert/strict";
import { health, duration } from "../src/backup-health.js";
import type { Destination } from "../src/contracts.js";
const now = Date.parse("2026-10-02T00:00:00Z");
function d(): Destination {
  return {
    id: "one",
    name: "test",
    type: "webdav",
    includeAttachments: false,
    schedule: {
      enabled: true,
      intervalHours: 24,
      startTime: "03:00",
      timezone: "UTC",
      retentionCount: 30,
    },
    runtime: {
      lastAttemptAt: null,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastErrorMessage: null,
      lastUploadedFileName: null,
      lastUploadedSizeBytes: null,
    },
  };
}
test("health distinguishes empty, never succeeded, failed, stale, disabled and unknown", () => {
  assert.equal(health([], now, 48 * 3600000).healthy, false);
  const a = d();
  assert.equal(
    health([a], now, 48 * 3600000).destinations[0].health,
    "never-succeeded",
  );
  a.runtime.lastSuccessAt = "2026-10-01T00:00:00Z";
  assert.equal(health([a], now, 48 * 3600000).healthy, true);
  a.runtime.lastErrorAt = "2026-10-01T01:00:00Z";
  assert.equal(health([a], now, 48 * 3600000).destinations[0].health, "failed");
  a.runtime.lastErrorAt = null;
  a.runtime.lastSuccessAt = "2026-09-28T00:00:00Z";
  assert.equal(health([a], now, 48 * 3600000).destinations[0].health, "stale");
  a.schedule.enabled = false;
  assert.equal(
    health([a], now, 48 * 3600000).destinations[0].health,
    "disabled",
  );
  a.schedule.enabled = true;
  a.runtime.lastSuccessAt = "bad";
  assert.equal(
    health([a], now, 48 * 3600000).destinations[0].health,
    "unknown",
  );
  a.runtime.lastSuccessAt = "2026-10-03T00:00:00Z";
  assert.equal(
    health([a], now, 48 * 3600000).destinations[0].health,
    "unknown",
  );
});
test("max-age parsing is positive and bounded", () => {
  assert.equal(duration("48h"), 172800000);
  for (const s of ["0h", "-2d", "abc", "1e20h"])
    assert.throws(() => duration(s), { exitCode: 2 });
});

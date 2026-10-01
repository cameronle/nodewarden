import type { Destination } from "./contracts.js";
import { invalid } from "./errors.js";
export function duration(value: string): number {
  const m = /^(\d+)(m|h|d)$/.exec(value);
  if (!m)
    return invalid("max-age must be a positive duration such as 48h or 7d.");
  const ms =
    Number(m[1]) *
    { m: 60000, h: 3600000, d: 86400000 }[m[2] as "m" | "h" | "d"];
  if (!Number.isSafeInteger(ms) || ms < 60000 || ms > 31536000000)
    return invalid("max-age must be between one minute and 365 days.");
  return ms;
}
export function health(
  destinations: Destination[],
  now: number,
  maxAge: number,
) {
  const items = destinations.map((d) => {
    const r = d.runtime;
    const success =
      r.lastSuccessAt === null ? null : Date.parse(r.lastSuccessAt);
    const error = r.lastErrorAt === null ? null : Date.parse(r.lastErrorAt);
    const dates = [r.lastAttemptAt, r.lastSuccessAt, r.lastErrorAt]
      .filter((v): v is string => v !== null)
      .map(Date.parse);
    const state = !d.schedule.enabled
      ? "disabled"
      : dates.some((v) => !Number.isFinite(v) || v > now)
        ? "unknown"
        : success === null
          ? "never-succeeded"
          : error !== null && error >= success
            ? "failed"
            : now - success > maxAge
              ? "stale"
              : "healthy";
    return {
      ...d,
      health: state,
      ageSeconds:
        success !== null && Number.isFinite(success) && success <= now
          ? Math.floor((now - success) / 1000)
          : null,
    };
  });
  return {
    checkedAt: new Date(now).toISOString(),
    maxAgeSeconds: maxAge / 1000,
    count: items.length,
    healthy: items.length > 0 && items.every((d) => d.health === "healthy"),
    destinations: items,
  };
}

import { invalid } from "./errors.js";
export function auditFilters(opts: {
  category?: string;
  level?: string;
  query?: string;
  from?: string;
  to?: string;
}) {
  const out: Record<string, string> = {};
  for (const field of ["category", "level"] as const) {
    const v = opts[field];
    if (v === undefined) continue;
    if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(v))
      invalid(
        "Category/level must be a lowercase identifier of at most 64 characters.",
      );
    out[field] = v;
  }
  if (opts.query !== undefined) {
    if (
      !opts.query.trim() ||
      opts.query.length > 512 ||
      /[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(opts.query)
    )
      invalid(
        "Audit query must contain 1–512 characters without control characters.",
      );
    out.q = opts.query;
  }
  for (const field of ["from", "to"] as const) {
    const v = opts[field];
    if (v === undefined) continue;
    const m =
      /^(\d{4}-\d{2}-\d{2})T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.\d{1,3})?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(
        v,
      );
    if (
      !m ||
      !Number.isFinite(Date.parse(v)) ||
      !Number.isFinite(Date.parse(m[1] + "T00:00:00Z")) ||
      new Date(m[1] + "T00:00:00Z").toISOString().slice(0, 10) !== m[1]
    )
      invalid(
        "Audit timestamps must be valid ISO dates including seconds and an explicit timezone.",
      );
    out[field] = new Date(v).toISOString();
  }
  if (out.from && out.to && out.from > out.to)
    invalid("Audit --from must not be later than --to.");
  return out;
}

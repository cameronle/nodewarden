const secrets = new Set<string>();
const sensitive =
  /password|secret|token|authorization|cookie|api[_-]?key|accessKeyId|privateKey|publicKey|accountKeys|^key$|securityStamp|userDecryptionOptions|masterPasswordHash/i;
export function rememberSecret(value: unknown): void {
  if (typeof value === "string" && value.length >= 3 && !/^\*+$/.test(value))
    secrets.add(value);
}
export function learnSecrets(value: unknown): void {
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    if (sensitive.test(key)) rememberSecret(item);
    else learnSecrets(item);
  }
}
export function safeText(value: string): string {
  let text = value;
  for (const secret of secrets) text = text.split(secret).join("[REDACTED]");
  return text
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, "")
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      /((?:password|secret|token|api[_-]?key|authorization)\s*[=:]\s*)(?:Bearer\s+)?[^\s&,;]+/gi,
      "$1[REDACTED]",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      "[REDACTED]",
    );
}
export function clean(value: unknown): unknown {
  if (typeof value === "string") return safeText(value);
  if (Array.isArray(value)) return value.map(clean);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        safeText(k),
        sensitive.test(k) &&
        v !== null &&
        typeof v !== "boolean" &&
        typeof v !== "number"
          ? "[REDACTED]"
          : clean(v),
      ]),
    );
  return value;
}
export function envelope(
  command: string,
  profile: string | null,
  data: unknown,
  warnings: string[] = [],
) {
  return clean({
    schemaVersion: 1,
    ok: true,
    command,
    profile,
    data,
    warnings,
  });
}
export function humanText(value: unknown): string {
  function rows(v: unknown, indent: string): string[] {
    if (Array.isArray(v))
      return v.length
        ? v.flatMap((item, i) => [
            indent + `[${i + 1}]`,
            ...rows(item, indent + "  "),
          ])
        : [indent + "(none)"];
    if (v && typeof v === "object")
      return Object.entries(v).flatMap(([k, item]) =>
        item !== null && typeof item === "object"
          ? [indent + k + ":", ...rows(item, indent + "  ")]
          : [indent + k + ": " + (item === null ? "unknown" : String(item))],
      );
    return [indent + String(v)];
  }
  return rows(clean(value), "").join("\n") + "\n";
}
export function render(
  command: string,
  profile: string | null,
  data: unknown,
  json: boolean,
  warnings: string[] = [],
) {
  if (json)
    process.stdout.write(
      JSON.stringify(envelope(command, profile, data, warnings)) + "\n",
    );
  else {
    process.stdout.write(humanText(data));
    for (const w of warnings)
      process.stderr.write("Warning: " + safeText(w) + "\n");
  }
}

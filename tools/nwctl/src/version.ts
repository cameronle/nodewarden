import { readFileSync } from "node:fs";
// Both source and bundled dist sit one directory below package.json.
// Read the installed metadata, so --version and doctor cannot drift on a bump.
const metadata = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
if (
  typeof metadata.version !== "string" ||
  !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(
    metadata.version,
  )
) {
  throw new Error("Invalid CLI package version metadata");
}
export const CLI_VERSION: string = metadata.version;

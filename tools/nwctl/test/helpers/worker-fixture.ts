import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { randomUUID, randomBytes, createHash } from "node:crypto";
// Test dependencies come from the existing Worker package; CLI runtime has none.
const repo = fileURLToPath(new URL("../../../../", import.meta.url));
const require = createRequire(repo + "package.json");
const { Miniflare, createFetchMock, Log, LogLevel } = require("miniflare");
const { build } = require("esbuild");
export async function workerFixture() {
  const secret = randomBytes(32).toString("base64url"),
    jwt = randomBytes(48).toString("base64url");
  const ids = { admin: randomUUID(), user: randomUUID(), banned: randomUUID() };
  const bundle = await build({
    stdin: {
      contents: `
  import worker,{NotificationsHub,BackupTransferRunner} from './src/index.ts';
  import {StorageService} from './src/services/storage.ts';
  import {saveBackupSettings} from './src/services/backup-config.ts';
  import {AuthService} from './src/services/auth.ts';
  export {NotificationsHub,BackupTransferRunner};
  export default {async fetch(request,env,ctx) {
   const path=new URL(request.url).pathname;
   if(path==='/__fixture/settings') {const s=new StorageService(env.DB);await saveBackupSettings(s,env,await request.json());return new Response('{}');}
   if(path==='/__fixture/device') {const {user,device}=await request.json();await new StorageService(env.DB).deleteDevice(user,device);AuthService.invalidateDeviceCache(user,device);return new Response('{}');}
   return worker.fetch(request,env,ctx);
  }};`,
      resolveDir: repo,
      sourcefile: "nwctl-isolated-fixture.ts",
    },
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    external: ["cloudflare:workers"],
    write: false,
    logLevel: "silent",
  });
  const mock = createFetchMock();
  mock.disableNetConnect();
  mock
    .get("https://identity.bitwarden.com")
    .intercept({ path: "/connect/token", method: "POST" })
    .reply(
      200,
      JSON.stringify({ access_token: "fixture-push-access", expires_in: 3600 }),
    )
    .persist();
  mock
    .get("https://push.bitwarden.com")
    .intercept({ path: "/push/delete", method: "POST" })
    .reply(200, "{}")
    .persist();
  mock
    .get("https://api.bitwarden.com")
    .intercept({ path: "/installations", method: "POST" })
    .reply(
      200,
      JSON.stringify({
        id: "fixture-installation",
        key: "fixture-installation-key",
      }),
    )
    .persist();
  const dav = mock.get("https://dav.example");
  const xml = (path: string) =>
    `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/backups/${path}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>${path ? "" : "<d:response><d:href>/backups/test.zip</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>12</d:getcontentlength><d:getlastmodified>Thu, 01 Oct 2026 00:00:00 GMT</d:getlastmodified></d:prop></d:propstat></d:response>"}</d:multistatus>`;
  dav
    .intercept({ path: "/backups", method: "PROPFIND" })
    .reply(207, xml(""), { headers: { "Content-Type": "application/xml" } })
    .persist();
  dav
    .intercept({ path: "/backups/empty", method: "PROPFIND" })
    .reply(207, xml("empty/"), {
      headers: { "Content-Type": "application/xml" },
    })
    .persist();
  dav
    .intercept({ path: "/backups/error", method: "PROPFIND" })
    .reply(503, "fixture-dav-password")
    .persist();
  mock
    .get("https://s3.example")
    .intercept({ path: () => true, method: "GET" })
    .reply(
      200,
      "<ListBucketResult><Contents><Key>test.zip</Key><Size>12</Size><LastModified>2026-10-01T00:00:00Z</LastModified></Contents></ListBucketResult>",
      { headers: { "Content-Type": "application/xml" } },
    )
    .persist();
  const mf = new Miniflare({
    modules: true,
    script: bundle.outputFiles[0].text,
    host: "127.0.0.1",
    port: 0,
    compatibilityDate: "2026-06-25",
    d1Databases: { DB: "nwctl-fixture" },
    r2Buckets: ["ATTACHMENTS"],
    kvNamespaces: ["ATTACHMENTS_KV"],
    bindings: { JWT_SECRET: jwt },
    durableObjects: {
      NOTIFICATIONS_HUB: { className: "NotificationsHub", useSQLite: true },
      BACKUP_TRANSFER_RUNNER: {
        className: "BackupTransferRunner",
        useSQLite: true,
      },
    },
    fetchMock: mock,
    log: new Log(LogLevel.ERROR),
  });
  try {
    const url = (await mf.ready).origin;
    const init = await fetch(url + "/api/version");
    if (init.status !== 200)
      throw new Error("Worker fixture initialization failed.");
    const db = await mf.getD1Database("DB");
    const hash = "sha256:" + createHash("sha256").update(secret).digest("hex");
    for (const [role, id] of Object.entries(ids))
      await db
        .prepare(
          "INSERT INTO users (id,email,name,master_password_hash,key,kdf_type,kdf_iterations,security_stamp,role,status,api_key,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(
          id,
          role + "@example.test",
          role,
          "fixture-password-hash",
          "fixture-vault-key",
          0,
          600000,
          "fixture-stamp",
          role === "admin" ? "admin" : "user",
          role === "banned" ? "banned" : "active",
          hash,
          "2026-10-01T00:00:00Z",
          "2026-10-01T00:00:00Z",
        )
        .run();
    for (let i = 0; i < 5; i++)
      await db
        .prepare(
          "INSERT INTO audit_logs (id,actor_user_id,action,category,level,metadata,created_at) VALUES (?,?,?,?,?,?,?)",
        )
        .bind(
          randomUUID(),
          ids.admin,
          "fixture.inspect",
          "system",
          "info",
          JSON.stringify({ note: "fixture-s3-secret" }),
          new Date().toISOString(),
        )
        .run();
    const runtime = {
      lastAttemptAt: null,
      lastAttemptLocalDate: null,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastErrorMessage: null,
      lastUploadedFileName: null,
      lastUploadedSizeBytes: null,
      lastUploadedDestination: null,
    };
    const schedule = {
      enabled: true,
      intervalHours: 24,
      startTime: "03:00",
      timezone: "UTC",
      retentionCount: 30,
    };
    const seeded = await fetch(url + "/__fixture/settings", {
      method: "POST",
      body: JSON.stringify({
        destinations: [
          {
            id: "dav",
            name: "Fixture DAV",
            type: "webdav",
            includeAttachments: false,
            destination: {
              baseUrl: "https://dav.example",
              username: "fixture",
              password: "fixture-dav-password",
              remotePath: "backups",
            },
            schedule,
            runtime,
          },
          {
            id: "s3",
            name: "Fixture S3",
            type: "s3",
            includeAttachments: true,
            destination: {
              endpoint: "https://s3.example",
              bucket: "fixture",
              addressingStyle: "path-style",
              region: "auto",
              accessKeyId: "fixture-s3-key",
              secretAccessKey: "fixture-s3-secret",
              rootPath: "",
            },
            schedule: { ...schedule, enabled: false },
            runtime,
          },
        ],
      }),
    });
    if (seeded.status !== 200)
      throw new Error("Worker fixture settings seed failed.");
    const r2 = await mf.getR2Bucket("ATTACHMENTS");
    await r2.put("fixture-sentinel", "unchanged");
    async function snapshot() {
      const tables: Record<string, unknown> = {};
      for (const t of ["users", "ciphers", "folders", "attachments", "sends"])
        tables[t] = (
          await db.prepare(`SELECT * FROM ${t} ORDER BY id`).all()
        ).results;
      tables.backup = (
        await db
          .prepare(
            "SELECT * FROM config WHERE key IN ('backup.settings.v1','backup.runtime.v1') ORDER BY key",
          )
          .all()
      ).results;
      tables.r2 = (await r2.list()).objects.map((v: any) => ({
        key: v.key,
        size: v.size,
        etag: v.etag,
      }));
      return tables;
    }
    return {
      url,
      db,
      ids,
      secret,
      jwt,
      snapshot,
      invalidateDevice: async (user: string, device: string) => {
        const r = await fetch(url + "/__fixture/device", {
          method: "POST",
          body: JSON.stringify({ user, device }),
        });
        if (!r.ok) throw new Error("Fixture device invalidation failed.");
      },
      close: async () => {
        await mf.dispose();
        await mock.close();
      },
    };
  } catch (e) {
    await mf.dispose();
    await mock.close();
    throw e;
  }
}

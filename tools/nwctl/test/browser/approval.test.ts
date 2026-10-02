import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { randomBytes, createHash, pbkdf2Sync } from "node:crypto";
import { existsSync } from "node:fs";
import { chromium } from "playwright-core";
import { workerFixture } from "../helpers/worker-fixture.js";
const repo = fileURLToPath(new URL("../../../../", import.meta.url));
const require = createRequire(repo + "package.json");
test(
  "real Chromium approval page: desktop/mobile, wrong password, approval, denial and expiry",
  { timeout: 180000 },
  async () => {
    const cwd = process.cwd();
    process.chdir(repo);
    const f = await workerFixture();
    let vite: any, browser: any;
    try {
      const password = randomBytes(24).toString("base64url"),
        key = pbkdf2Sync(password, "admin@example.test", 600000, 32, "sha256");
      const hash = pbkdf2Sync(key, password, 1, 32, "sha256").toString(
        "base64",
      );
      key.fill(0);
      await f.db
        .prepare("UPDATE users SET master_password_hash=? WHERE id=?")
        .bind(hash, f.ids.admin)
        .run();
      const login = await fetch(f.url + "/identity/connect/token", {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "client_credentials",
          scope: "api",
          client_id: "user." + f.ids.admin,
          client_secret: f.secret,
          deviceIdentifier: crypto.randomUUID(),
          deviceName: "Browser fixture",
          deviceType: "8",
        }),
      });
      assert.equal(login.status, 200);
      const token = ((await login.json()) as any).access_token;
      const { createServer } = await import(require.resolve("vite"));
      vite = await createServer({
        configFile: repo + "webapp/vite.config.ts",
        server: {
          host: "127.0.0.1",
          port: 0,
          proxy: {
            "/api": { target: f.url, changeOrigin: false },
            "/identity": { target: f.url, changeOrigin: false },
          },
        },
        plugins: [
          {
            name: "isolated-cli-qa",
            configureServer(server: any) {
              server.middlewares.use(async (req: any, res: any, next: any) => {
                if (!req.url.startsWith("/__cli-qa.html")) return next();
                const html = await server.transformIndexHtml(
                  req.url,
                  `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module">
import {h,render} from 'preact';
import CliApprovalPage from '/src/components/CliApprovalPage.tsx';
import {initI18n} from '/src/lib/i18n.ts';
import '/src/tailwind.css';import '/src/styles.css';
await initI18n();
const fetcher=(path,init={})=>{const headers=new Headers(init.headers);headers.set('Authorization','Bearer '+${JSON.stringify(token)});return fetch(path,{...init,headers});};
render(h(CliApprovalPage,{id:new URL(location.href).searchParams.get('id'),email:'admin@example.test',isAdmin:true,authedFetch:fetcher,onBack:()=>{}}),document.getElementById('root'));
</script></body></html>`,
                );
                res.setHeader("Content-Type", "text/html");
                res.end(html);
              });
            },
          },
        ],
      });
      await vite.listen();
      const origin = "http://127.0.0.1:" + vite.httpServer.address().port;
      const make = async (
        action = "invite.create",
        parameters: Record<string, unknown> = { expiresInHours: 24 },
        credentials?: Record<string, string>,
      ) => {
        const proof = randomBytes(32).toString("hex");
        const response = await fetch(origin + "/api/ops/requests", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            action,
            parameters,
            ...(credentials ? { credentials } : {}),
            proofHash: createHash("sha256").update(proof).digest("hex"),
          }),
        });
        assert.equal(response.status, 201, await response.clone().text());
        return response.json() as Promise<any>;
      };
      const executablePath =
        process.env.NWCTL_CHROMIUM ??
        [
          "/usr/bin/chromium",
          "/usr/bin/google-chrome",
          "/usr/bin/chromium-browser",
        ].find(existsSync);
      assert.ok(executablePath, "Install Chromium or set NWCTL_CHROMIUM");
      browser = await chromium.launch({
        executablePath,
        args: ["--no-sandbox"],
        headless: true,
      });
      const page = await browser.newPage({
          viewport: { width: 1280, height: 900 },
        }),
        errors: string[] = [];
      page.on("pageerror", (e: Error) => errors.push(e.message));

      let op = await make();
      await page.goto(origin + "/cli-approval/" + op.id);
      await page.locator("input[type=password]").first().waitFor();
      assert.equal(
        new URL(page.url()).pathname,
        "/cli-approval/" + op.id,
        "Login must preserve approval route",
      );
      await page.goto(origin + "/__cli-qa.html?id=" + op.id);
      await page.locator("#cli-password").waitFor();
      assert.equal(
        await page.locator("button[type=submit]").isDisabled(),
        true,
      );
      await page.locator("#cli-password").fill("synthetic-wrong-password");
      await page.locator("button[type=submit]").click();
      await page.locator("[role=alert]").waitFor();
      assert.equal(await page.locator("#cli-password").inputValue(), "");
      await page.locator("#cli-password").fill(password);
      await page.locator("button[type=submit]").click();
      await page.locator("[role=status]").waitFor();
      assert.equal(
        await page.locator("[data-testid=cli-state]").textContent(),
        "approved",
      );
      assert.equal(
        (await f.db.prepare("SELECT count(*) n FROM invites").first()).n,
        0,
        "Web approval must not execute invitation creation",
      );
      await page.setViewportSize({ width: 390, height: 844 });
      op = await make();
      await page.goto(origin + "/__cli-qa.html?id=" + op.id);
      await page.locator("#cli-password").waitFor();
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
        true,
        "Mobile horizontal overflow",
      );
      await page.locator("form button[type=button]").click();
      await page.waitForFunction(
        () =>
          document.querySelector("[data-testid=cli-state]")?.textContent ===
          "denied",
      );
      assert.equal(await page.locator("#cli-password").count(), 0);
      op = await make();
      await f.db
        .prepare("UPDATE ops_requests SET expires_at=1 WHERE id=?")
        .bind(op.id)
        .run();
      await page.goto(origin + "/__cli-qa.html?id=" + op.id);
      await page.waitForFunction(
        () =>
          document.querySelector("[data-testid=cli-state]")?.textContent ===
          "expired",
      );
      assert.equal(await page.locator("#cli-password").count(), 0);
      const read = async (path: string) => {
        const r = await fetch(origin + path, {
          headers: { Authorization: "Bearer" + " " + token },
        });
        assert.equal(r.status, 200);
        return r.json() as Promise<any>;
      };

      const config = await read("/api/ops/config/backup"),
        policy = await read("/api/ops/config/audit"),
        user = await read("/api/ops/config/user/" + f.ids.user);
      const secret = {
        username: "browser-fixture-USERNAME",
        password: "browser-fixture-PASSWORD",
      };
      const scenarios: [
        string,
        Record<string, unknown>,
        Record<string, string>?,
      ][] = [
        [
          "backup.configure",
          {
            expectedRevision: config.revision,
            mutation: "add",
            destinationId: "browser-dav",
            change: {
              type: "webdav",
              name: "Browser DAV",
              destination: { baseUrl: "https://browserdav.example" },
              schedule: { enabled: false },
            },
            credentialFields: ["password", "username"],
          },
          secret,
        ],
        [
          "audit.configure",
          {
            expectedRevision: policy.revision,
            retentionDays: 30,
            maxEntries: null,
          },
        ],
        [
          "user.status",
          {
            expectedRevision: user.revision,
            userId: f.ids.user,
            status: "banned",
          },
        ],
      ];
      const deviceTime = new Date().toISOString();
      for (let i = 0; i < 50; i++) {
        const id = crypto.randomUUID();
        await f.db
          .prepare(
            "INSERT INTO devices(user_id,device_identifier,name,type,session_stamp,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
          )
          .bind(
            f.ids.admin,
            id,
            "Long reviewed device " + i,
            8,
            "fixture-session-stamp-" + i,
            deviceTime,
            deviceTime,
          )
          .run();
        await f.db
          .prepare(
            "INSERT INTO trusted_two_factor_device_tokens(token,user_id,device_identifier,expires_at) VALUES(?,?,?,?)",
          )
          .bind(
            "fixture-browser-trust-" + i,
            f.ids.admin,
            id,
            Date.now() + 86400000,
          )
          .run();
        await f.db
          .prepare(
            "INSERT INTO invites(code,created_by,used_by,expires_at,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
          )
          .bind(
            "fixture-browser-used-code-" + i,
            f.ids.admin,
            f.ids.user,
            deviceTime,
            "used",
            deviceTime,
            deviceTime,
          )
          .run();
      }
      const deviceMetadata = await read("/api/ops/bulk/devices"),
        inviteMetadata = await read("/api/ops/bulk/invites");
      const deviceTargets = deviceMetadata.items
        .filter((v: any) => v.name !== "Browser fixture")
        .map((v: any) => ({ id: v.id, revision: v.revision }));
      const inviteTargets = inviteMetadata.items.map((v: any) => ({
        id: v.id,
        revision: v.revision,
      }));
      assert.equal(deviceTargets.length, 50);
      assert.equal(inviteTargets.length, 50);
      scenarios.push(
        ["backup.export", { includeAttachments: true }],
        ["device.remove", { targets: deviceTargets, includeCurrent: false }],
        [
          "device.revoke-trust",
          { targets: deviceTargets, includeCurrent: false },
        ],
        ["invite.prune", { targets: inviteTargets }],
      );
      const untouched = await f.snapshot();
      for (const width of [1280, 390]) {
        if (width === 390) {
          // More scenarios now cross the real 10-attempt approval budget. Prove
          // the ceiling, then wait for its genuine fixed-window expiry; never
          // weaken the production limiter or erase fixture budget rows.
          const limited = await make();
          const approve = () =>
            fetch(origin + "/api/ops/requests/" + limited.id + "/approve", {
              method: "POST",
              headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json",
                Origin: origin,
              },
              body: JSON.stringify({
                approve: true,
                masterPasswordHash: "synthetic-wrong-password",
              }),
            });
          await approve();
          const bucket = await f.db
            .prepare(
              "SELECT bucket_key,expires_at FROM rate_limit_buckets WHERE bucket_key LIKE ? AND expires_at>? ORDER BY expires_at DESC LIMIT 1",
            )
            .bind("ops-approve:" + f.ids.admin + ":%", Date.now())
            .first();
          assert.ok(bucket);
          await f.db
            .prepare(
              "UPDATE rate_limit_buckets SET count=10 WHERE bucket_key=?",
            )
            .bind(bucket.bucket_key)
            .run();
          assert.equal((await approve()).status, 429);
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              Math.max(0, bucket.expires_at - Date.now()) + 200,
            ),
          );
        }
        for (const [action, parameters, credentials] of scenarios) {
          await page.setViewportSize({ width, height: 844 });
          const request = await make(action, parameters, credentials);
          await page.goto(origin + "/__cli-qa.html?id=" + request.id);
          await page.locator("#cli-password").waitFor();
          const body = await page.locator("body").textContent();
          assert.ok(body?.includes(action));
          assert.ok(!body?.includes(secret.password));
          assert.ok(!body?.includes(secret.username));
          assert.equal(
            await page.evaluate(
              () => document.documentElement.scrollWidth <= window.innerWidth,
            ),
            true,
          );
          await page.locator("#cli-password").fill(password);
          await page.locator("button[type=submit]").click();
          await page
            .locator("[role=status]")
            .waitFor()
            .catch(async (error: Error) => {
              console.error(
                JSON.stringify({
                  action,
                  width,
                  alert: await page
                    .locator("[role=alert]")
                    .textContent()
                    .catch(() => null),
                  state: await page
                    .locator("[data-testid=cli-state]")
                    .textContent(),
                }),
              );
              throw error;
            });
          assert.equal(
            await page.locator("[data-testid=cli-state]").textContent(),
            "approved",
          );
        }
      }
      assert.deepEqual(
        await f.snapshot(),
        untouched,
        "Web approval must not mutate business data",
      );
      assert.deepEqual(errors, []);
    } finally {
      await browser?.close();
      await vite?.close();
      await f.close();
      process.chdir(cwd);
    }
  },
);

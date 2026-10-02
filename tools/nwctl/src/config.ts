import { constants } from "node:fs";
import { lstat, mkdir, open, rename, unlink } from "node:fs/promises";
import { join, resolve, parse } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { CliError, invalid } from "./errors.js";
import { serverOrigin } from "./http.js";
export interface Profile {
  name: string;
  server: string;
  allowLoopback: boolean;
  device: string;
}
interface Config {
  version: 1;
  active: string | null;
  profiles: Record<string, Profile>;
}
export interface Session {
  token: string;
  expiresAt: number;
}
function checkName(name: string) {
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(name))
    invalid(
      "Profile names must be 1–32 lowercase letters, digits, underscores or hyphens, starting with a letter.",
    );
}
function privateStat(s: Awaited<ReturnType<typeof lstat>>, directory = false) {
  if (
    s.isSymbolicLink() ||
    (directory ? !s.isDirectory() : !s.isFile()) ||
    (process.getuid && s.uid !== process.getuid()) ||
    (Number(s.mode) & 0o777) !== (directory ? 0o700 : 0o600)
  )
    invalid(
      "Storage must be owned by this user, non-symlink, mode 0700 directories / 0600 files.",
    );
}
export class Store {
  readonly dir: string;
  constructor(dir = join(homedir(), ".config", "nwctl")) {
    this.dir = resolve(dir);
  }
  private async ensure() {
    let path = parse(this.dir).root;
    for (const part of this.dir.slice(path.length).split("/").filter(Boolean)) {
      path = join(path, part);
      try {
        const s = await lstat(path);
        if (s.isSymbolicLink() || !s.isDirectory())
          invalid("Symlink/non-directory storage path rejected.");
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
        await mkdir(path, { mode: 0o700 });
      }
    }
    privateStat(await lstat(this.dir), true);
  }
  private async read(name: string): Promise<unknown | null> {
    await this.ensure();
    const path = join(this.dir, name);
    let before;
    try {
      before = await lstat(path);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
    privateStat(before);
    const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const current = await fd.stat();
      privateStat(current);
      if (
        current.ino !== before.ino ||
        current.dev !== before.dev ||
        current.size > 1048576
      )
        invalid("Unsafe or oversized storage file.");
      try {
        return JSON.parse(await fd.readFile("utf8"));
      } catch {
        return invalid("Invalid local JSON configuration.");
      }
    } finally {
      await fd.close();
    }
  }
  private async write(name: string, value: unknown) {
    await this.ensure();
    const target = join(this.dir, name);
    try {
      privateStat(await lstat(target));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    const temp = join(this.dir, `.write-${randomUUID()}`);
    const fd = await open(
      temp,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await fd.writeFile(JSON.stringify(value) + "\n");
      await fd.sync();
      await fd.close();
      await rename(temp, target);
    } finally {
      await fd.close().catch(() => {});
      await unlink(temp).catch(() => {});
    }
  }
  private async config(): Promise<Config> {
    const raw = await this.read("config.json");
    if (raw === null) return { version: 1, active: null, profiles: {} };
    if (typeof raw !== "object" || !raw || Array.isArray(raw))
      return invalid("Invalid profile configuration.");
    const c = raw as Config;
    if (
      c.version !== 1 ||
      !c.profiles ||
      typeof c.profiles !== "object" ||
      Array.isArray(c.profiles) ||
      !(c.active === null || typeof c.active === "string")
    )
      invalid("Invalid profile configuration.");
    for (const [name, p] of Object.entries(c.profiles)) {
      checkName(name);
      if (
        !p ||
        p.name !== name ||
        typeof p.device !== "string" ||
        typeof p.server !== "string" ||
        typeof p.allowLoopback !== "boolean"
      )
        invalid("Invalid stored profile.");
      if (serverOrigin(p.server, p.allowLoopback) !== p.server)
        invalid("Invalid stored origin.");
    }
    if (c.active !== null && !Object.hasOwn(c.profiles, c.active))
      invalid("Active profile is missing.");
    return c;
  }
  async add(
    name: string,
    server: string,
    allowLoopback = false,
  ): Promise<Profile> {
    checkName(name);
    const origin = serverOrigin(server, allowLoopback);
    const c = await this.config();
    const old = c.profiles[name];
    const p = {
      name,
      server: origin,
      allowLoopback,
      device: old?.device || randomUUID(),
    };
    if (old && old.server !== origin) await this.logout(old);
    c.profiles[name] = p;
    c.active ??= name;
    await this.write("config.json", c);
    return p;
  }
  async use(name: string) {
    checkName(name);
    const c = await this.config();
    if (!Object.hasOwn(c.profiles, name)) invalid("Profile does not exist.");
    c.active = name;
    await this.write("config.json", c);
    return c.profiles[name];
  }
  async list() {
    const c = await this.config();
    return {
      active: c.active,
      profiles: Object.values(c.profiles).map((p) => ({
        name: p.name,
        server: p.server,
        allowLoopback: p.allowLoopback,
      })),
    };
  }
  async profile(name?: string): Promise<Profile> {
    const c = await this.config();
    const n = name || c.active;
    if (!n || !Object.hasOwn(c.profiles, n))
      return invalid("Add/select a profile first.");
    return c.profiles[n];
  }
  async saveSession(p: Profile, session: Session) {
    await this.write(`session-${p.name}.json`, {
      version: 1,
      profile: p.name,
      server: p.server,
      device: p.device,
      token: session.token,
      expiresAt: session.expiresAt,
    });
  }
  async session(p: Profile): Promise<Session> {
    const s = (await this.read(`session-${p.name}.json`)) as
      | (Session & {
          version: number;
          profile: string;
          server: string;
          device: string;
        })
      | null;
    if (
      !s ||
      s.version !== 1 ||
      s.profile !== p.name ||
      s.server !== p.server ||
      s.device !== p.device ||
      typeof s.token !== "string" ||
      !s.token ||
      !Number.isFinite(s.expiresAt) ||
      s.expiresAt <= Date.now()
    )
      throw new CliError(
        "LOGIN_REQUIRED",
        "No valid session for this profile; log in again.",
        3,
      );
    return { token: s.token, expiresAt: s.expiresAt };
  }
  async saveOperation(id: string, value: unknown) {
    if (!/^[a-f0-9-]{36}$/.test(id)) invalid("Invalid operation ID.");
    await this.write(`operation-${id}.json`, value);
  }
  async operation(id: string) {
    if (!/^[a-f0-9-]{36}$/.test(id)) invalid("Invalid operation ID.");
    return this.read(`operation-${id}.json`);
  }
  async logout(p: Profile) {
    await this.ensure();
    const file = `session-${p.name}.json`;
    if ((await this.read(file)) !== null) await unlink(join(this.dir, file));
  }
}

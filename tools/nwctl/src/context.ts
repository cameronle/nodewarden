import type { Command } from "commander";
import { Store } from "./config.js";
import { authenticatedGet } from "./auth.js";
import { invalid } from "./errors.js";
import { render } from "./output.js";
export class Context {
  command = "cli";
  profileName: string | null = null;
  constructor(readonly program: Command) {}
  options() {
    return this.program.opts();
  }
  store() {
    return new Store(this.options().configDir);
  }
  timeout() {
    const v = String(this.options().timeout);
    if (!/^\d+$/.test(v)) invalid("Timeout must be integer milliseconds.");
    const n = Number(v);
    if (n < 50 || n > 120000)
      invalid("Timeout must be 50–120000 milliseconds.");
    return n;
  }
  async profile() {
    const p = await this.store().profile(this.options().profile);
    this.profileName = p.name;
    return p;
  }
  async query(path: string, query: Record<string, string> = {}) {
    const p = await this.profile();
    return authenticatedGet(this.store(), p, path, query, this.timeout());
  }
  print(data: unknown, warnings: string[] = []) {
    render(
      this.command,
      this.profileName,
      data,
      !!this.options().json,
      warnings,
    );
  }
  action(label: string, fn: (...args: any[]) => Promise<void>) {
    return async (...args: any[]) => {
      this.command = label;
      await fn(...args);
    };
  }
}
export function numberOption(value: string, min: number, max: number): number {
  if (!/^\d+$/.test(value)) return invalid("Expected an integer option.");
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max)
    return invalid(`Integer option must be between ${min} and ${max}.`);
  return n;
}

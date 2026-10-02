import { Context } from "./context.js";
import { record } from "./contracts.js";
import { invalid, incompatible, CliError } from "./errors.js";
import { requestOperation } from "./step-up.js";
import { Client } from "./http.js";
import type { OpsAction, OpsParameters } from "../../../shared/ops-schema.js";
function metadata(value: unknown, invitation = false) {
  const r = record(value);
  if (
    typeof r.id !== "string" ||
    !r.id ||
    typeof r.revision !== "string" ||
    !/^[a-f0-9]{64}$/.test(r.revision)
  )
    return incompatible();
  if (invitation) {
    if (
      !/^[a-f0-9]{64}$/.test(r.id) ||
      typeof r.status !== "string" ||
      typeof r.expiresAt !== "string" ||
      typeof r.used !== "boolean" ||
      typeof r.eligible !== "boolean"
    )
      return incompatible();
    return {
      id: r.id,
      revision: r.revision,
      status: r.status,
      expiresAt: r.expiresAt,
      used: r.used,
      eligible: r.eligible,
    };
  }
  if (
    typeof r.name !== "string" ||
    typeof r.stored !== "boolean" ||
    typeof r.rememberedTwoFactor !== "boolean"
  )
    return incompatible();
  return {
    id: r.id,
    revision: r.revision,
    name: r.name,
    stored: r.stored,
    rememberedTwoFactor: r.rememberedTwoFactor,
  };
}
export async function deviceBulk(
  c: Context,
  opts: any,
  action: OpsAction = "device.remove",
) {
  if (!!opts.all === !!opts.ids)
    invalid("Choose --all or explicit --ids, not both.");
  const profile = await c.profile(),
    page = record(await c.query("/api/ops/bulk/devices"));
  if (!Array.isArray(page.items)) incompatible();
  const all = (page.items as unknown[]).map((v) => metadata(v)),
    selected = opts.all
      ? all.filter(
          (t) =>
            (action === "device.remove" || t.rememberedTwoFactor === true) &&
            (opts.includeCurrent || t.id !== profile.device),
        )
      : opts.ids.map((id: string) => {
          const item = all.find((t) => t.id === id);
          if (!item) invalid("Exact own-account device not found.");
          return item;
        });
  if (!selected.length) {
    c.print({ changed: false, count: 0, reason: "No eligible devices" });
    return;
  }
  if (
    !opts.includeCurrent &&
    selected.some((t: any) => t.id === profile.device)
  )
    invalid(
      "Current CLI device requires --include-current and separate Web approval.",
    );
  await requestOperation(c, { ...opts, preview: selected }, action, {
    targets: selected.map((t: any) => ({ id: t.id, revision: t.revision })),
    includeCurrent: !!opts.includeCurrent,
  });
}
export async function pruneInvites(c: Context, opts: any) {
  const page = record(await c.query("/api/ops/bulk/invites"));
  if (!Array.isArray(page.items)) incompatible();
  const all = (page.items as unknown[]).map((v) => metadata(v, true)),
    eligible = all.filter((t) => t.eligible === true);
  const selected = opts.ids
    ? opts.ids.map((id: string) => {
        if (!/^[a-f0-9]{64}$/.test(id))
          invalid("Use an exact non-secret invitation reference.");
        const item = eligible.find((t) => t.id === id);
        if (!item) invalid("Invitation not found or still valid.");
        return item;
      })
    : eligible.slice(0, 50);
  if (!selected.length) {
    c.print({ changed: false, count: 0, reason: "No invalid invitations" });
    return;
  }
  await requestOperation(
    c,
    {
      ...opts,
      preview: {
        selected,
        batchLimit: 50,
        remainingCandidates: eligible.length - selected.length,
      },
    },
    "invite.prune",
    { targets: selected.map((t: any) => ({ id: t.id, revision: t.revision })) },
  );
}
export async function verifyBulk(
  c: Context,
  action: OpsAction,
  p: OpsParameters,
  value: unknown,
  timeout: number,
) {
  const r = record(value),
    ids = p.targets!.map((t) => t.id),
    profile = await c.profile();
  if (
    r.action !== action ||
    r.verified !== true ||
    JSON.stringify(r.targets) !== JSON.stringify(ids)
  )
    incompatible();
  if (action === "device.remove" && ids.includes(profile.device)) {
    const session = await c.store().session(profile);
    try {
      const deadline = Date.now() + Math.min(timeout, 30000);
      let rejected = false;
      while (Date.now() < deadline) {
        try {
          await new Client(
            profile.server,
            profile.allowLoopback,
            Math.min(5000, deadline - Date.now()),
          ).get("/api/accounts/profile", {}, session.token);
        } catch (e) {
          if (e instanceof CliError && e.status === 401) {
            rejected = true;
            break;
          }
          throw e;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      if (!rejected)
        throw new CliError(
          "VERIFY_FAILED",
          "Current session removal needs verification; local session cleared. Do not repeat automatically.",
          6,
        );
      return { ...r, oldAccessRejected: true, localSessionCleared: true };
    } finally {
      await c.store().logout(profile);
    }
  }
  const page = record(
    await c.query(
      action === "invite.prune"
        ? "/api/ops/bulk/invites"
        : "/api/ops/bulk/devices",
    ),
  );
  if (
    !Array.isArray(page.items) ||
    page.items.some(
      (v: unknown) =>
        ids.includes(record(v).id as string) &&
        (action !== "device.revoke-trust" ||
          record(v).rememberedTwoFactor === true),
    )
  )
    throw new CliError(
      "VERIFY_FAILED",
      "Exact device removal read-back disagrees; no automatic retry.",
      6,
    );
  return { ...r, readbackVerified: true };
}

import { verifyConfiguration } from "./configuration.js";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import type { Command } from "commander";
import { Context, numberOption } from "./context.js";
import { record, text, settings, remotePage } from "./contracts.js";
import { CliError, incompatible, invalid } from "./errors.js";
import { confirmMutation, mutationOptions, write } from "./mutations.js";
import {
  opsParameters,
  type OpsAction,
  type OpsParameters,
} from "../../../shared/ops-schema.js";
import { invitationRows, sha256 } from "./invites.js";
import { privateOutput, validateOutput } from "./private-output.js";
import { rememberSecret } from "./output.js";
import { Client } from "./http.js";
import { downloadOperation } from "./download.js";
export async function requestOperation(
  c: Context,
  opts: any,
  action: OpsAction,
  parameters: OpsParameters,
) {
  try {
    parameters = opsParameters(action, parameters).parameters;
  } catch {
    invalid("Invalid operation parameters.");
  }
  if (opts.output) await validateOutput(opts.output);
  if (
    !(await confirmMutation(c, opts, {
      action,
      parameters,
      ...(opts.preview ? { target: opts.preview } : {}),
      effect:
        action === "backup.run"
          ? "Existing retention policy may delete old archives. Web confirmation is also required."
          : "A single-use browser confirmation is required; --yes does not bypass it.",
    }))
  )
    return;
  const p = await c.profile(),
    session = await c.store().session(p),
    proof = randomBytes(32).toString("hex");
  rememberSecret(proof);
  const result = record(
    await write(c, "POST", "/api/ops/requests", {
      action,
      parameters,
      proofHash: sha256(proof),
      ...(opts.credentials && Object.keys(opts.credentials).length
        ? { credentials: opts.credentials }
        : {}),
    }),
  );
  const id = text(result.id),
    approvalUrl = text(result.approvalUrl);
  if (
    !/^[a-f0-9-]{36}$/.test(id) ||
    result.state !== "pending" ||
    approvalUrl !== p.server + "/cli-approval/" + id ||
    result.action !== action ||
    JSON.stringify(result.parameters) !== JSON.stringify(parameters)
  )
    incompatible();
  await c.store().saveOperation(id, {
    version: 1,
    id,
    server: p.server,
    profile: p.name,
    device: p.device,
    sessionDigest: sha256(session.token),
    proof,
    action,
    parameters,
    output: opts.output ? resolve(opts.output) : null,
  });
  c.print(
    {
      id,
      action,
      parameters,
      state: "pending",
      approvalUrl,
      expiresAt: result.expiresAt,
      summary: result.summary,
      next: `nwctl --profile ${p.name} ops execute ${id} --yes`,
    },
    [
      "No target operation has run. Open the approval URL in your own trusted browser; never send a password in chat.",
    ],
  );
}
async function localOperation(c: Context, id: string) {
  const p = await c.profile(),
    session = await c.store().session(p),
    op = record(await c.store().operation(id));
  if (
    op.version !== 1 ||
    op.id !== id ||
    op.server !== p.server ||
    op.profile !== p.name ||
    op.device !== p.device ||
    op.sessionDigest !== sha256(session.token) ||
    typeof op.proof !== "string" ||
    !/^[a-f0-9]{64}$/.test(op.proof)
  )
    invalid(
      "Operation is not bound to this profile and original CLI session. Create a new request.",
    );
  rememberSecret(op.proof);
  let parsed;
  try {
    parsed = opsParameters(op.action, op.parameters);
  } catch {
    return invalid("Invalid local operation.");
  }
  return { op, parsed, p, proof: text(op.proof) };
}
export function operations(program: Command, c: Context) {
  const group = program
    .command("ops")
    .description("Browser-approved, action-bound management requests");
  group.command("status <id>").action(
    c.action("ops status", async (id) => {
      const { proof } = await localOperation(c, id);
      c.print(
        await write(c, "POST", `/api/ops/requests/${id}/status`, { proof }),
      );
    }),
  );
  mutationOptions(group.command("cancel <id>")).action(
    c.action("ops cancel", async (id, opts) => {
      const { proof } = await localOperation(c, id);
      if (
        !(await confirmMutation(c, opts, {
          action: "Cancel pending request",
          id,
        }))
      )
        return;
      const r = record(
        await write(c, "POST", `/api/ops/requests/${id}/cancel`, { proof }),
      );
      const after = record(
        await write(c, "POST", `/api/ops/requests/${id}/status`, { proof }),
      );
      if (after.state !== "cancelled") incompatible();
      c.print(r);
    }),
  );
  mutationOptions(
    group
      .command("execute <id>")
      .option("--output <file>", "Private output path; no overwrite")
      .option(
        "--operation-timeout <ms>",
        "Execution/transfer timeout, 1000–900000 ms",
        "120000",
      ),
  ).action(
    c.action("ops execute", async (id, opts) => {
      const operationTimeout = numberOption(
        opts.operationTimeout,
        1000,
        900000,
      );
      const { op, parsed, p, proof } = await localOperation(c, id);
      const status = record(
        await write(c, "POST", `/api/ops/requests/${id}/status`, { proof }),
      );
      if (
        status.action !== parsed.action ||
        JSON.stringify(status.parameters) !== JSON.stringify(parsed.parameters)
      )
        incompatible();
      if (status.state !== "approved")
        throw new CliError(
          "STEP_UP_REQUIRED",
          "Request is not approved (or was already attempted). Inspect ops status; do not repeat automatically.",
          6,
        );
      const output = opts.output ?? op.output;
      if (
        ["invite.create", "backup.download"].includes(parsed.action) &&
        typeof output !== "string"
      )
        invalid("This operation requires a private --output file.");
      if (
        output &&
        !["invite.create", "backup.download"].includes(parsed.action)
      )
        invalid("This operation does not produce a file.");
      if (output) await validateOutput(output);
      if (
        !(await confirmMutation(c, opts, {
          id,
          action: parsed.action,
          parameters: parsed.parameters,
          summary: status.summary,
        }))
      )
        return;
      if (parsed.action === "backup.download") {
        const session = await c.store().session(p);
        const result = await downloadOperation(
          new Client(p.server, p.allowLoopback, operationTimeout),
          id,
          proof,
          session.token,
          output as string,
          parsed.parameters.path!,
        );
        c.print({ id, action: parsed.action, ...result }, [
          "ZIP may reference separate attachment blobs. Download and filename checksum do not prove recoverability.",
        ]);
        return;
      }
      const file = output ? await privateOutput(output) : null;
      try {
        const result = await write(
          c,
          "POST",
          `/api/ops/requests/${id}/execute`,
          { proof },
          operationTimeout,
        );
        if (parsed.action === "invite.create") {
          const response = record(result),
            code = text(response.code);
          rememberSecret(code);
          rememberSecret(response.inviteLink);
          if (!/^[a-f0-9]{40}$/.test(code)) incompatible();
          const match = (await invitationRows(c)).find((i) => i.code === code);
          if (!match || match.expiresAt !== response.expiresAt)
            throw new CliError(
              "VERIFY_FAILED",
              "Invitation may have been created; read-back failed. Check the Web UI before retrying.",
              6,
            );
          await file!.write(
            JSON.stringify({
              code,
              inviteLink: p.server + "/?invite=" + encodeURIComponent(code),
              expiresAt: match.expiresAt,
            }) + "\n",
          );
          await file!.commit();
          c.print({
            id,
            action: parsed.action,
            verified: true,
            inviteId: match.id,
            output: file!.path,
          });
        } else if (parsed.action === "invite.revoke") {
          if (
            result !== null ||
            (await invitationRows(c)).some(
              (i) => i.id === parsed.parameters.inviteId,
            )
          )
            throw new CliError(
              "VERIFY_FAILED",
              "Invitation removal could not be verified.",
              6,
            );
          c.print({ id, action: parsed.action, verified: true });
        } else if (
          [
            "backup.configure",
            "audit.configure",
            "audit.clear",
            "user.status",
          ].includes(parsed.action)
        ) {
          c.print({
            id,
            ...(await verifyConfiguration(
              c,
              parsed.action,
              parsed.parameters,
              result,
              status,
            )),
          });
        } else if (parsed.action === "backup.verify") {
          const response = record(result),
            integrity = record(response.integrity);
          if (
            response.destinationId !== parsed.parameters.destinationId ||
            response.path !== parsed.parameters.path ||
            typeof integrity.matches !== "boolean" ||
            typeof integrity.hasChecksumPrefix !== "boolean"
          )
            incompatible();
          const verified =
            integrity.hasChecksumPrefix === true && integrity.matches === true;
          c.print(
            {
              id,
              action: parsed.action,
              destinationId: response.destinationId,
              path: response.path,
              verified,
              integrity,
              recoverabilityVerified: false,
            },
            [
              "Only the short filename checksum prefix is checked, not a trusted full hash, ZIP contents or restore.",
            ],
          );
          if (!verified) process.exitCode = 7;
        } else if (parsed.action === "backup.run") {
          const response = record(result),
            ran = record(response.result),
            fileName = text(ran.fileName);
          if (
            response.object !== "backup-run" ||
            typeof ran.fileSize !== "number" ||
            !Number.isSafeInteger(ran.fileSize) ||
            ran.fileSize < 1 ||
            !/^nodewarden_[^/\\]+\.zip$/.test(fileName)
          )
            incompatible();
          const d = settings(await c.query("/api/admin/backup/settings")).find(
            (d) => d.id === parsed.parameters.destinationId,
          );
          const page = remotePage(
            await c.query("/api/admin/backup/remote", {
              destinationId: parsed.parameters.destinationId!,
              path: "",
            }),
          );
          const found = page.items.find(
            (i) => !i.isDirectory && i.path === fileName && i.name === fileName,
          );
          if (
            !d ||
            page.destinationId !== d.id ||
            d.runtime.lastUploadedFileName !== fileName ||
            d.runtime.lastUploadedSizeBytes !== ran.fileSize ||
            !d.runtime.lastSuccessAt ||
            Date.parse(d.runtime.lastSuccessAt) <
              Date.parse(text(status.createdAt)) ||
            !found ||
            found.size !== ran.fileSize
          )
            throw new CliError(
              "VERIFY_FAILED",
              "Backup may have completed; exact runtime/archive read-back did not match. Inspect before retrying.",
              6,
            );
          c.print({
            id,
            action: parsed.action,
            destinationId: d.id,
            fileName,
            fileSize: ran.fileSize,
            verified: true,
            recoverabilityVerified: false,
          });
        } else {
          incompatible();
        }
      } finally {
        await file?.abort();
      }
    }),
  );
}

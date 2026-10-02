import type { Env } from "../types";
import { buildBackupArchive, MAX_BACKUP_ARCHIVE_BYTES } from "./backup-archive";
import { getBlobObject } from "./blob-store";
import { ConfigurationError } from "./ops-configuration";
import { unzipSync, Zip, ZipPassThrough } from "fflate";
import type { OpsParameters } from "../../shared/ops-schema";
async function snapshot(env: Env, p: OpsParameters) {
  const archive = await buildBackupArchive(env, new Date(), {
    includeAttachments: p.includeAttachments,
  });
  const files = unzipSync(archive.bytes);
  const revision = Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", files["db.json"])),
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const refs = archive.manifest.attachmentBlobs || [];
  if (
    refs.length + 2 > 10000 ||
    archive.bytes.length + refs.reduce((n, r) => n + r.sizeBytes + 256, 0) >
      MAX_BACKUP_ARCHIVE_BYTES
  )
    throw new ConfigurationError(
      413,
      "Complete instance export exceeds the 64 MiB archive limit",
    );
  return { archive, files, revision, refs };
}
export async function exportTarget(env: Env, p: OpsParameters) {
  const initial = await snapshot(env, p);
  return {
    summary: {
      includeAttachments: p.includeAttachments,
      tableCounts: initial.archive.manifest.tableCounts,
      attachmentFiles: initial.refs.length,
      attachmentBytes: initial.archive.manifest.blobSummary.totalBytes,
      effect:
        "Export current encrypted instance data. API keys and runtime sessions are excluded. Read attachment blobs only; no R2 mutation. Not a restore rehearsal.",
    },
    fingerprint: initial.revision,
    async apply(id: string): Promise<Response> {
      const current = await snapshot(env, p);
      if (current.revision !== initial.revision)
        throw new ConfigurationError(
          409,
          "Instance changed; create a new export request",
        );
      async function* chunks(): AsyncGenerator<Uint8Array> {
        const pending: Uint8Array[] = [];
        let failure: Error | null = null,
          total = 0;
        const zip = new Zip((error, data) => {
          if (error) failure = error;
          else pending.push(data);
        });
        function* drain() {
          if (failure) throw failure;
          while (pending.length) {
            const data = pending.shift()!;
            total += data.byteLength;
            if (total > MAX_BACKUP_ARCHIVE_BYTES)
              throw new Error("Archive limit exceeded");
            yield data;
          }
        }
        for (const name of ["manifest.json", "db.json"]) {
          const entry = new ZipPassThrough(name);
          zip.add(entry);
          yield* drain();
          const bytes = current.files[name];
          for (let offset = 0; offset < bytes.length; offset += 65536) {
            entry.push(
              bytes.subarray(offset, offset + 65536),
              offset + 65536 >= bytes.length,
            );
            yield* drain();
          }
        }
        for (const ref of current.refs) {
          const object = await getBlobObject(env, ref.blobName);
          if (!object || !object.body || object.size !== ref.sizeBytes)
            throw new Error("Attachment missing or size changed");
          const entry = new ZipPassThrough(
            `attachments/${ref.cipherId}/${ref.attachmentId}.bin`,
          );
          zip.add(entry);
          yield* drain();
          const reader = object.body.getReader();
          let size = 0;
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              size += value.byteLength;
              if (size > ref.sizeBytes)
                throw new Error("Attachment size changed");
              entry.push(value);
              yield* drain();
            }
            if (size !== ref.sizeBytes)
              throw new Error("Incomplete attachment");
            entry.push(new Uint8Array(), true);
            yield* drain();
          } finally {
            await reader.cancel().catch(() => {});
            reader.releaseLock();
          }
        }
        zip.end();
        yield* drain();
      }
      const iterator = chunks();
      let closed = false;
      async function finish(state: string) {
        if (closed) return;
        closed = true;
        await env.DB.prepare(
          "UPDATE ops_requests SET state=?,payload=NULL WHERE id=? AND state='executing'",
        )
          .bind(state, id)
          .run();
      }
      const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
          try {
            const next = await iterator.next();
            if (next.done) {
              await finish("succeeded");
              controller.close();
            } else controller.enqueue(next.value);
          } catch {
            await finish("failed");
            await iterator.return(undefined);
            controller.error(
              new Error("Instance export incomplete; no automatic retry"),
            );
          }
        },
        async cancel() {
          await iterator.return(undefined);
          await finish("failed");
        },
      });
      return new Response(stream, {
        headers: {
          "Content-Type": "application/zip",
          "Content-Disposition": `attachment; filename="${current.archive.fileName.replace(/_[a-f0-9]{5}\.zip$/, ".zip")}"`,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
          "X-Nwctl-Stream": "1",
        },
      });
    },
  };
}

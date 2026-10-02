import { useEffect, useState } from "preact/hooks";
import {
  loadCliOperation,
  approveCliOperation,
  type CliOperation,
} from "@/lib/api/ops";
import type { AuthedFetch } from "@/lib/api/shared";
import { t } from "@/lib/i18n";
export default function CliApprovalPage(props: {
  id: string;
  email: string;
  isAdmin: boolean;
  authedFetch: AuthedFetch;
  onBack: () => void;
}) {
  const [operation, setOperation] = useState<CliOperation | null>(null),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    setOperation(null);
    setPassword("");
    setError("");
    if (props.isAdmin)
      void loadCliOperation(props.authedFetch, props.id)
        .then((v) => {
          if (active) setOperation(v);
        })
        .catch(() => {
          if (active) setError(t("txt_cli_failed"));
        });
    return () => {
      active = false;
    };
  }, [props.id, props.isAdmin, props.authedFetch]);
  async function respond(approve: boolean) {
    if (
      busy ||
      !operation ||
      operation.state !== "pending" ||
      (approve && !password)
    )
      return;
    setBusy(true);
    setError("");
    const entered = password;
    setPassword("");
    try {
      await approveCliOperation(
        props.authedFetch,
        props.id,
        props.email,
        entered,
        approve,
      );
      setOperation(await loadCliOperation(props.authedFetch, props.id));
    } catch {
      setError(t("txt_cli_failed"));
    } finally {
      setBusy(false);
    }
  }
  return (
    <main
      className="stack"
      style={{ maxWidth: "720px", margin: "24px auto", padding: "16px" }}
    >
      <section className="card stack" aria-labelledby="cli-approval-title">
        <h1 id="cli-approval-title">{t("txt_cli_approval")}</h1>
        <p>{t("txt_cli_warning")}</p>
        <p style={{ overflowWrap: "anywhere" }}>{props.email}</p>
        {!props.isAdmin && <p role="alert">{t("txt_cli_failed")}</p>}
        {error && <p role="alert">{error}</p>}
        {operation && (
          <>
            <dl style={{ overflowWrap: "anywhere" }}>
              <dt>{t("txt_cli_instance")}</dt>
              <dd>{operation.origin}</dd>
              <dt>{t("txt_cli_action")}</dt>
              <dd>{operation.action}</dd>
              <dt>{t("txt_cli_device")}</dt>
              <dd>{operation.deviceId}</dd>
              <dt>{t("txt_cli_expires")}</dt>
              <dd>{new Date(operation.expiresAt).toLocaleString()}</dd>
              <dt>{t("txt_cli_state")}</dt>
              <dd data-testid="cli-state">{operation.state}</dd>
            </dl>
            <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
              {JSON.stringify(operation.summary, null, 2)}
            </pre>
            {operation.state === "pending" && (
              <form
                className="stack"
                onSubmit={(e) => {
                  e.preventDefault();
                  void respond(true);
                }}
              >
                <label htmlFor="cli-password">{t("txt_cli_password")}</label>
                <input
                  id="cli-password"
                  type="password"
                  value={password}
                  autoComplete="current-password"
                  disabled={busy}
                  onInput={(e) => setPassword(e.currentTarget.value)}
                />
                <div style={{ display: "flex", flexWrap: "wrap", gap: "12px" }}>
                  <button
                    className="btn btn-primary"
                    type="submit"
                    disabled={busy || !password}
                  >
                    {t("txt_cli_approve")}
                  </button>
                  <button
                    className="btn btn-secondary"
                    type="button"
                    disabled={busy}
                    onClick={() => void respond(false)}
                  >
                    {t("txt_cli_deny")}
                  </button>
                </div>
              </form>
            )}
            {operation.state === "approved" && (
              <p role="status">{t("txt_cli_approved")}</p>
            )}
          </>
        )}
        <button className="btn btn-secondary" onClick={props.onBack}>
          {t("txt_back")}
        </button>
      </section>
    </main>
  );
}

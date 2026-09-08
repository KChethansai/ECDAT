import React, { useState } from "react";
import { ApiError, api } from "../lib/api.js";
import { str } from "../lib/report.js";
import { validationSummary } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import { SectionEmpty } from "../components/States.jsx";
import { PageHead, RequireReport } from "./_shared.jsx";

function fmtWhen(ts) {
  if (typeof ts !== "number" || !Number.isFinite(ts)) return "—";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return "—";
  }
}

export default function Validation() {
  const { report, scanId } = useStore();
  const vsum = validationSummary(report);
  const [findingIds, setFindingIds] = useState("");
  const [targets, setTargets] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [running, setRunning] = useState(false);
  const [run, setRun] = useState(null);
  const [error, setError] = useState("");

  async function revalidate(event) {
    event?.preventDefault();
    if (!scanId) return;
    setError("");
    setRun(null);
    setRunning(true);
    try {
      const ids = findingIds.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
      const urls = targets.split(/\n+/).map((s) => s.trim()).filter(Boolean)
        .map((url) => ({ url }));
      const body = await api.createValidation({
        report_id: scanId,
        ...(ids.length > 0 ? { finding_ids: ids } : {}),
        ...(urls.length > 0 ? { targets: urls } : {}),
        policy: { dry_run: dryRun },
      });
      setRun(body.run || null);
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }

  const results = run?.results || [];
  const blocked = run?.blocked_targets || [];
  return (
    <>
      <PageHead eyebrow="ACTIVE VALIDATION" title="Validation" sub="Observation and correlation only — validation never changes severity or priority." />
      <RequireReport report={report} title="NO VALIDATION DATA">
        <div className="card" aria-label="Validation from this scan">
          <p className="eyebrow">THIS SCAN</p>
          {vsum ? (
            <p>{vsum.total} check(s): {Object.entries(vsum.byStatus || {}).map(([k, v]) => `${k}=${v}`).join(", ")}</p>
          ) : (
            <SectionEmpty>
              Static only — this scan ran no validation probes. Use the form below to re-validate without rescanning.
            </SectionEmpty>
          )}
        </div>
        <div className="card" aria-label="Re-validate without rescanning">
          <p className="eyebrow">RE-VALIDATE (NEW IMMUTABLE RUN)</p>
          <form onSubmit={revalidate}>
            <div className="cmdbar-body" style={{ padding: 0 }}>
              <label className="field grow" htmlFor="v-findings">
                Finding IDs (blank = all validatable)
                <input id="v-findings" value={findingIds} onChange={(e) => setFindingIds(e.target.value)} placeholder="id1, id2…" autoComplete="off" spellCheck="false" className="mono" />
              </label>
              <label className="field grow" htmlFor="v-targets">
                Probe targets, one per line (blank = runtime correlation only, no network)
                <input id="v-targets" value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="https://127.0.0.1:8443" autoComplete="off" spellCheck="false" className="mono" />
              </label>
            </div>
            <label className="check" htmlFor="v-dryrun" style={{ marginTop: 8 }}>
              <input id="v-dryrun" type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
              dry run (map strategies, send zero requests)
            </label>
            <div className="cta-row" style={{ padding: "12px 0 0" }}>
              <button type="submit" className="btn" disabled={running}>{running ? "Validating…" : "Run validation"}</button>
            </div>
          </form>
          <p className="cell-sub">Loopback targets only unless the backend policy allowlists a host or you acknowledge non-loopback probing server-side. Results never mutate findings.</p>
          {error ? <p role="alert" className="alert alert-error">{error}</p> : null}
        </div>
        {run ? (
          <div className="card" aria-label="Validation run result">
            <p className="eyebrow">RUN {str(run.run_id)}</p>
            <p>
              dry run: <b>{run.dry_run ? "yes (zero requests sent)" : "no"}</b> ·{" "}
              requests: <b>{run.summary?.requests ?? "—"}</b> · started {fmtWhen(run.started)}
            </p>
            {blocked.length > 0 ? (
              <>
                <p><b>Blocked targets (policy):</b></p>
                <ul>
                  {blocked.map((b, i) => (
                    <li key={i}><code className="evidence">{str(b.url)}</code> — {str(b.reason)}</li>
                  ))}
                </ul>
              </>
            ) : null}
            {results.length > 0 ? (
              <div className="table-wrap">
                <table className="data">
                  <caption>Validation results for this run</caption>
                  <thead><tr><th scope="col">Finding</th><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Target / detail</th></tr></thead>
                  <tbody>
                    {results.slice(0, 100).map((r, i) => (
                      <tr key={r.validation_id || i}>
                        <td className="mono">{str(r.finding_id).slice(0, 20)}</td>
                        <td className="mono">{str(r.validation_type, "?")}</td>
                        <td><b>{str(r.status, "?")}</b></td>
                        <td className="cell-sub">{str(r.target) || str(r.error) || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="cell-sub">No per-finding results in this run.</p>
            )}
          </div>
        ) : null}
      </RequireReport>
    </>
  );
}

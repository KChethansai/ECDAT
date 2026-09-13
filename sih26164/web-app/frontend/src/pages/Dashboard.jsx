import React, { useEffect, useState } from "react";
import { href } from "../lib/router.js";
import { api } from "../lib/api.js";
import { criticalHighCount, familyCount, getComponents, immediateCount, migration, repoIdentity, runtimeCount, runtimeProvenance, scanTargetLabel, scannerSources, validationSummary, workItems } from "../lib/selectors.js";
import { arr, num, str, unknownsCount } from "../lib/report.js";
import { useStore } from "../store.jsx";
import { ExecutiveMetrics, ExposurePanel, FixFirstCard } from "../components/Metrics.jsx";
import RepoPanel from "../components/RepoPanel.jsx";
import Pipeline from "../components/Pipeline.jsx";
import { ErrorState } from "../components/States.jsx";
import { PageHead, RequireReport } from "./_shared.jsx";

export function ScanStatusCard() {
  const { loading, elapsed, error, hasReport, scanId, scannedTarget } = useStore();
  return (
    <div className="card" aria-label="Current scan status">
      <p className="eyebrow">CURRENT SCAN</p>
      {loading ? (
        <p role="status">Working — {elapsed}s elapsed. The backend answers with a single report; progress within the run is not exposed.</p>
      ) : hasReport ? (
        <p>Complete: <b className="mono">{scanTargetLabel(null, scannedTarget) || scannedTarget}</b>
          {scanId ? <> · report <b className="mono">{scanId}</b></> : null}</p>
      ) : (
        <p>No scan yet. <a href={href("scan")}>Start from the Scan workspace</a>.</p>
      )}
      <ErrorState message={error} />
    </div>
  );
}

export function TargetCard({ report, scanId, scannedTarget }) {
  return (
    <div className="card" aria-label="Scan target">
      <p className="eyebrow">CURRENT TARGET</p>
      <p>
        <b className="mono">{scanTargetLabel(report, scannedTarget)}</b>
        {" "}· profile local · report <b className="mono">{scanId}</b>
      </p>
      <p className="cell-sub">
        scanned {str(report?.scannedAt, "—")} · sources: {scannerSources(report).join(", ") || "—"}
      </p>
    </div>
  );
}

export function PostureTrend() {
  const [history, setHistory] = useState(null);
  useEffect(() => {
    let live = true;
    api.scanHistory().then(
      (body) => { if (live) setHistory(arr(body.history)); },
      () => { if (live) setHistory([]); },
    );
    return () => { live = false; };
  }, []);
  if (history === null) return null; // still loading: say nothing rather than something wrong
  const ordered = [...history].sort((a, b) => num(a.timestamp) - num(b.timestamp));
  const rows = ordered.slice(-8);
  return (
    <div className="card" aria-label="Security posture trend">
      <p className="eyebrow">POSTURE TREND (PERSISTED SCANS)</p>
      {rows.length === 0 ? (
        <p className="cell-sub">No scan history yet.</p>
      ) : rows.length === 1 ? (
        <p className="cell-sub">One scan persisted ({num(rows[0].counts?.total)} findings). Run another scan to compare security posture.</p>
      ) : (
        <>
          <TrendVerdict rows={rows} />
          <ul>
            {rows.map((h) => (
              <li key={str(h.scan_id)}>
                <span className="mono">{str(h.target) || str(h.scan_id).slice(0, 12)}</span>
                {" "}· {num(h.counts?.total)} findings · {num(h.counts?.critical)} critical · {num(h.counts?.high)} high
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="cell-sub"><a href={href("history")}>Full history &amp; compare</a></p>
    </div>
  );
}

function TrendVerdict({ rows }) {
  const prev = rows[rows.length - 2];
  const cur = rows[rows.length - 1];
  const dTotal = num(cur.counts?.total) - num(prev.counts?.total);
  const dCrit = num(cur.counts?.critical) - num(prev.counts?.critical);
  const dHigh = num(cur.counts?.high) - num(prev.counts?.high);
  const fmt = (d) => (d > 0 ? `+${d}` : `${d}`);
  let verdict;
  if (dCrit > 0 || (dTotal <= 0 && (dCrit > 0 || dHigh > 0))) {
    verdict = "POSTURE REQUIRES ATTENTION — severity increased even though totals moved.";
  } else if (dTotal < 0 && dCrit <= 0 && dHigh <= 0) {
    verdict = "Posture improved on measured counts (fewer findings, severity not worse).";
  } else if (dTotal === 0 && dCrit === 0 && dHigh === 0) {
    verdict = "Posture unchanged across the last two scans.";
  } else {
    verdict = "Mixed movement — check severity mix before concluding anything.";
  }
  return (
    <p>
      {str(prev.target) || "previous"} → <b>{str(cur.target) || "current"}</b>:{" "}
      total {fmt(dTotal)} · critical {fmt(dCrit)} · high {fmt(dHigh)}. <b>{verdict}</b>
    </p>
  );
}

export default function Dashboard() {
  const { report, scanId, scannedTarget, loading, sessionScans, downloadSarif, hasReport } = useStore();
  const repo = repoIdentity(report);
  const components = getComponents(report);
  const top3 = components.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 3);
  const prov = runtimeProvenance(report);
  const vsum = validationSummary(report);
  return (
    <>
      <PageHead eyebrow="CRYPTOGRAPHIC SECURITY INTELLIGENCE" title="Dashboard" sub="What is wrong, how serious is it, and what should be fixed first." />
      <ScanStatusCard />
      {repo ? <RepoPanel report={report} scanId={scanId} onSarif={downloadSarif} /> : null}
      {!repo && report ? <TargetCard report={report} scanId={scanId} scannedTarget={scannedTarget} /> : null}
      <RequireReport report={report} loading={loading} title="NO REPORT">
        <div className="section">
          <ExecutiveMetrics
            report={report}
            criticallyHigh={criticalHighCount(report)}
            runtimeCount={runtimeCount(report)}
            immediateCount={immediateCount(migration(report))}
            familyCount={familyCount(report)}
            candidateCount={workItems(migration(report)).length}
            unknownCount={unknownsCount(migration(report))}
          />
        </div>
        <div className="section">
          <div className="grid two-col">
            <FixFirstCard findings={top3} runtimeAvailable={Boolean(prov.available)} />
            <ExposurePanel report={report} components={components} />
          </div>
        </div>
        <div className="card" aria-label="Validation status">
          <p className="eyebrow">VALIDATION STATUS</p>
          <p>
            {vsum && num(vsum.total) > 0 ? `${num(vsum.total)} check(s): ${Object.entries(vsum.byStatus || {}).map(([k, v]) => `${k}=${v}`).join(", ")}` : "No validation checks in this scan."}{" "}
            <a href={href("validation")}>Open Validation</a>
          </p>
          <p className="cell-sub">Target: <b className="mono">{scanTargetLabel(report, scannedTarget)}</b> · sources: {scannerSources(report).join(", ") || "—"}</p>
        </div>
        <Pipeline hasReport={hasReport} loading={loading} />
      </RequireReport>
      <PostureTrend />
      <div className="card" aria-label="Recent scans this session">
        <p className="eyebrow">RECENT SCANS (THIS BROWSER SESSION)</p>
        {sessionScans.length === 0 ? (
          <p className="cell-sub">No scans run yet in this session.</p>
        ) : (
          <ul>
            {sessionScans.slice(0, 5).map((s, i) => (
              <li key={`${s.at}-${i}`}>
                <span className="mono">{str(s.target)}</span> · {s.ok ? (s.total === null || s.total === undefined ? "done" : `${s.total} finding(s)`) : "failed"} ·{" "}
                <span className="cell-sub">{s.at ? new Date(s.at).toLocaleString() : ""}</span>
                {s.id ? <> · <a href={href("reports", s.id)} className="mono">report</a></> : null}
              </li>
            ))}
          </ul>
        )}
        <p className="cell-sub"><a href={href("history")}>Full history &amp; compare</a></p>
      </div>
    </>
  );
}

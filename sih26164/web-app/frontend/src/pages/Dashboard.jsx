import React from "react";
import { href } from "../lib/router.js";
import { criticalHighCount, familyCount, getComponents, immediateCount, migration, repoIdentity, runtimeCount, runtimeProvenance, scanTargetLabel, scannerSources, topFinding, validationSummary, workItems } from "../lib/selectors.js";
import { num, str, unknownsCount } from "../lib/report.js";
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

export default function Dashboard() {
  const { report, scanId, scannedTarget, loading, sessionScans, downloadSarif, hasReport } = useStore();
  const repo = repoIdentity(report);
  const finding = topFinding(report);
  const prov = runtimeProvenance(report);
  const vsum = validationSummary(report);
  return (
    <>
      <PageHead eyebrow="CRYPTOGRAPHIC SECURITY INTELLIGENCE" title="Dashboard" sub="What is wrong, how serious is it, and what should be fixed first." />
      <ScanStatusCard />
      {repo ? <RepoPanel report={report} scanId={scanId} onSarif={downloadSarif} /> : null}
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
            <FixFirstCard finding={finding} runtimeAvailable={Boolean(prov.available)} />
            <ExposurePanel report={report} components={getComponents(report)} />
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

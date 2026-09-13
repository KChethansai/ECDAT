import React, { useEffect, useRef, useState } from "react";
import { href } from "../lib/router.js";
import { api } from "../lib/api.js";
import { arr, num, str } from "../lib/report.js";
import {
  criticalHighCount, getComponents, immediateCount, migration,
  repoIdentity, scanTargetLabel, validationSummary,
} from "../lib/selectors.js";
import { FALLBACK_SCANNERS } from "../lib/report.js";
import { useStore } from "../store.jsx";
import ScanCommandBar from "../components/ScanCommandBar.jsx";
import Pipeline from "../components/Pipeline.jsx";
import { ErrorState, LoadingStages } from "../components/States.jsx";
import { PageHead } from "./_shared.jsx";

function ScanResult({ scanId }) {
  const { report, scannedTarget } = useStore();
  const [delta, setDelta] = useState("loading");
  useEffect(() => {
    let live = true;
    setDelta("loading");
    api.scanHistory().then(
      (body) => {
        if (!live) return;
        const prev = arr(body.history).find((h) => str(h.scan_id) && str(h.scan_id) !== scanId);
        if (!prev) { setDelta(null); return; }
        api.scanDelta(str(prev.scan_id), scanId).then(
          (d) => { if (live) setDelta({ prev, d }); },
          () => { if (live) setDelta(null); },
        );
      },
      () => { if (live) setDelta(null); },
    );
    return () => { live = false; };
  }, [scanId]);
  if (!report) return null;
  const components = getComponents(report);
  const repo = repoIdentity(report);
  const vsum = validationSummary(report);
  const top = components.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 3);
  const codeCount = arr(report?.codeAnalysis?.findings).length;
  return (
    <section className="card" aria-label="Scan result summary">
      <p className="eyebrow">SCAN COMPLETE</p>
      <p>
        <b className="mono">{scanTargetLabel(report, scannedTarget)}</b>
        {" "}· report <b className="mono">{scanId}</b> · scanned {str(report?.scannedAt, "—")}
        {repo ? <> · commit <b className="mono">{str(repo.sha).slice(0, 12)}</b> · profile {str(repo.profile)}</> : null}
      </p>
      <p>
        <b>{components.length}</b> findings · <b>{criticalHighCount(report)}</b> critical/high ·{" "}
        <b>{codeCount}</b> code findings · <b>{immediateCount(migration(report))}</b> immediate migration items ·{" "}
        {num(vsum?.total) > 0 ? `${num(vsum.total)} validation check(s)` : "no validation probes ran"}
      </p>
      {top.length > 0 ? (
        <>
          <p className="eyebrow">TOP SECURITY PRIORITIES</p>
          <ul>
            {top.map((f) => (
              <li key={str(f.id)}>
                <b className="mono">{str(f.algorithm)}</b> · {str(f.severity)} ·{" "}
                <span className="mono">{str(f.file_path)}:{str(f.line)}</span> ·{" "}
                <a href={href("findings", str(f.id))}>Open finding</a>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {delta && delta !== "loading" ? (
        <p>
          vs previous scan (<span className="mono">{str(delta.prev.target) || str(delta.prev.scan_id).slice(0, 12)}</span>):{" "}
          <b>{num(delta.prev.counts?.total)}</b> → <b>{components.length}</b> findings ·{" "}
          critical <b>{num(delta.prev.counts?.critical)}</b> →{" "}
          <b>{components.filter((f) => f.severity === "critical").length}</b> ·{" "}
          {num(delta.d.summary?.new)} new · {num(delta.d.summary?.resolved)} resolved ·{" "}
          {num(delta.d.summary?.changed)} changed · {num(delta.d.summary?.regressions)} regression(s) ·{" "}
          <a href={href("history")}>Compare in History</a>
        </p>
      ) : null}
      <div className="export-actions">
        <a className="btn btn-secondary" href={href("dashboard")}>View dashboard</a>{" "}
        <a className="btn btn-secondary" href={href("findings")}>View findings</a>{" "}
        <a className="btn btn-secondary" href={href("migration")}>View migration</a>{" "}
        <a className="btn btn-secondary" href={href("reports")}>View report</a>
      </div>
    </section>
  );
}

export default function Scan() {
  const { health, loading, elapsed, error, report, runScan, cancelScan, hasReport } = useStore();
  const [target, setTarget] = useState("sample");
  const [runtime, setRuntime] = useState(false);
  const [validate, setValidate] = useState(false);
  const [validationUrls, setValidationUrls] = useState("");
  const [allowNonLoopback, setAllowNonLoopback] = useState(false);
  const [codeAnalysis, setCodeAnalysis] = useState(false);
  const [source, setSource] = useState("local");
  const [githubUrl, setGithubUrl] = useState("");
  const [githubRef, setGithubRef] = useState("");
  const [profile, setProfile] = useState("full");
  const [stage, setStage] = useState(0);
  const [localError, setLocalError] = useState("");
  const [doneId, setDoneId] = useState(null);
  const targetRef = useRef(null);
  const stageTimer = useRef(null);

  React.useEffect(() => {
    if (!loading) {
      if (stageTimer.current) clearInterval(stageTimer.current);
      return undefined;
    }
    setStage(0);
    stageTimer.current = setInterval(() => {
      setStage((s) => (s < 5 ? s + 1 : s));
    }, 850);
    return () => clearInterval(stageTimer.current);
  }, [loading]);

  async function onSubmit(event) {
    event?.preventDefault();
    const cleanTarget = target.trim() || "sample";
    const isGithub = source === "github";
    if (isGithub && !githubUrl.trim()) {
      setLocalError("Enter a GitHub repository URL (https://github.com/owner/repository).");
      targetRef.current?.focus();
      return;
    }
    setLocalError("");
    setDoneId(null);
    const known = Array.isArray(health.scanners) && health.scanners.length > 0
      ? health.scanners.filter((s) => s !== "runtime")
      : FALLBACK_SCANNERS;
    const endpoints = validationUrls.split(/\n+/).map((s) => s.trim()).filter(Boolean);
    const payload = isGithub
      ? { runtime, validate, validation_targets: endpoints,
          validation_policy: allowNonLoopback ? { allow_non_loopback: true } : null,
          code_analysis: codeAnalysis,
          source: { type: "github", url: githubUrl.trim(),
                    ...(githubRef.trim() ? { ref: githubRef.trim() } : {}) },
          profile }
      : { target: cleanTarget, scanners: known, runtime, validate,
          validation_targets: endpoints,
          validation_policy: allowNonLoopback ? { allow_non_loopback: true } : null,
          code_analysis: codeAnalysis };
    const result = await runScan({ payload, isGithub, fallbackTarget: isGithub ? githubUrl.trim() : cleanTarget });
    if (result.ok) setDoneId(result.id);
  }

  return (
    <>
      <PageHead eyebrow="SCAN WORKSPACE" title="Run a scan" sub="Local directory or public GitHub repository. Static discovery only unless you opt into probes." />
      <ScanCommandBar target={target} onTarget={setTarget} runtime={runtime} onRuntime={setRuntime} loading={loading} onSubmit={onSubmit} targetRef={targetRef} validate={validate} onValidate={setValidate} validationUrls={validationUrls} onValidationUrls={setValidationUrls} allowNonLoopback={allowNonLoopback} onAllowNonLoopback={setAllowNonLoopback} codeAnalysis={codeAnalysis} onCodeAnalysis={setCodeAnalysis} source={source} onSource={setSource} githubUrl={githubUrl} onGithubUrl={setGithubUrl} githubRef={githubRef} onGithubRef={setGithubRef} profile={profile} onProfile={setProfile} />
      {loading ? (
        <p role="status" className="section-sub">
          Working — {elapsed}s elapsed{source === "github" ? " (acquiring repository, then analyzing; large repos take minutes)" : ""}.{" "}
          <button type="button" className="btn btn-secondary" onClick={cancelScan}>Cancel</button>
        </p>
      ) : null}
      <Pipeline hasReport={hasReport} loading={loading} />
      {loading ? <LoadingStages active={stage} runtime={runtime} /> : null}
      <ErrorState message={localError || error} onRetry={() => targetRef.current?.focus()} />
      {loading && hasReport ? (
        <p className="alert alert-stale" role="status">
          Scanning — the current report below stays visible until the new scan completes; a failed scan never replaces it.
        </p>
      ) : null}
      {report?.mockWarning ? <p className="alert alert-mock">MOCK: {report.mockWarning}</p> : null}
      {!loading && doneId ? <ScanResult scanId={doneId} /> : null}
      <p className="section-sub">
        Completed scans persist in History across backend restarts. <a href={href("dashboard")}>Open the Dashboard</a>.
      </p>
    </>
  );
}

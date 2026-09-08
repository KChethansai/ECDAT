import React, { useRef, useState } from "react";
import { href } from "../lib/router.js";
import { FALLBACK_SCANNERS } from "../lib/report.js";
import { useStore } from "../store.jsx";
import ScanCommandBar from "../components/ScanCommandBar.jsx";
import Pipeline from "../components/Pipeline.jsx";
import { ErrorState, LoadingStages } from "../components/States.jsx";
import { PageHead } from "./_shared.jsx";

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
    if (result.ok) window.location.hash = "#/dashboard";
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
      <p className="section-sub">
        After completion you land on the <a href={href("dashboard")}>Dashboard</a>. Backend reports are in-memory: restarting the API clears them.
      </p>
    </>
  );
}

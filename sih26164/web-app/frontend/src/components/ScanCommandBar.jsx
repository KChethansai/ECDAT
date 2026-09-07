import React from "react";
import { IconLock, IconScan } from "./icons.jsx";

const PROFILES = [
  { id: "quick", desc: "Metadata & high-risk signals", eta: "~15s" },
  { id: "crypto", desc: "Exhaustive CBOM, PQC risk, keys", eta: "~30s" },
  { id: "codebase", desc: "Dead code, duplication, complexity", eta: "~20s" },
  { id: "full", desc: "Comprehensive crypto + codebase", eta: "~45s", tag: "RECOMMENDED" },
  { id: "full-validation", desc: "Full pipeline + live probes", eta: "~90s" },
];

export default function ScanCommandBar({ target, onTarget, runtime, onRuntime, loading, onSubmit, targetRef, validate, onValidate, validationUrls, onValidationUrls, allowNonLoopback, onAllowNonLoopback, codeAnalysis, onCodeAnalysis, source, onSource, githubUrl, onGithubUrl, githubRef, onGithubRef, profile, onProfile }) {
  const isGithub = source === "github";
  return (
    <form onSubmit={onSubmit} className="cmdbar" aria-label="Scan command center">
      <div className="cmdbar-top" aria-hidden="true">
        <span className="lights">
          <span />
          <span />
          <span />
        </span>
        <span className="cmdbar-title">ecdat — scan console</span>
      </div>
      <div className="console-eyebrow">
        <span className="eyebrow">COMMAND CONSOLE</span>
        <span className="eyebrow dim">DETERMINISTIC ACQUISITION</span>
      </div>
      <div className="cmdbar-body">
        <div className="field" role="radiogroup" aria-label="Scan source" id="scan-source">
          <span>Source</span>
          <span className="segmented">
            <label className={`seg-opt${!isGithub ? " active" : ""}`} htmlFor="src-local">
              <input id="src-local" type="radio" name="scan-source" checked={!isGithub} onChange={() => onSource("local")} />
              <span className="seg-dot" aria-hidden="true" />
              LOCAL DIRECTORY
            </label>
            <label className={`seg-opt${isGithub ? " active" : ""}`} htmlFor="src-github">
              <input id="src-github" type="radio" name="scan-source" checked={isGithub} onChange={() => onSource("github")} />
              <span className="seg-dot" aria-hidden="true" />
              GITHUB REPOSITORY
            </label>
          </span>
        </div>
        {isGithub ? (
          <>
            <label className="field grow" htmlFor="github-url">
              Repository URL
              <input
                id="github-url"
                ref={targetRef}
                value={githubUrl}
                onChange={(e) => onGithubUrl(e.target.value)}
                aria-label="GitHub repository URL"
                placeholder="https://github.com/owner/repository"
                autoComplete="off"
                spellCheck="false"
                className="mono"
              />
            </label>
            <label className="field" htmlFor="github-ref">
              Ref
              <input
                id="github-ref"
                value={githubRef}
                onChange={(e) => onGithubRef(e.target.value)}
                aria-label="Branch, tag, or commit SHA (empty = default branch)"
                placeholder="main"
                autoComplete="off"
                spellCheck="false"
                className="mono"
              />
            </label>
          </>
        ) : (
          <label className="field grow" htmlFor="scan-target">
            Scan target
            <input
              id="scan-target"
              ref={targetRef}
              value={target}
              onChange={(e) => onTarget(e.target.value)}
              aria-label="Scan target"
              placeholder="sample or workspace-contained path"
              autoComplete="off"
              spellCheck="false"
              className="mono"
            />
          </label>
        )}
      </div>
      {isGithub ? (
      <div className="cmdbar-body profile-block">
        <div className="field" role="radiogroup" aria-label="Scan profile" id="scan-profile">
          <span>Profile</span>
          <span className="profile-grid">
            {PROFILES.map((p) => (
              <label key={p.id} className={`profile-card${profile === p.id ? " selected" : ""}`} htmlFor={`profile-${p.id}`}>
                <input
                  id={`profile-${p.id}`}
                  type="radio"
                  name="scan-profile"
                  checked={profile === p.id}
                  onChange={() => onProfile(p.id)}
                  aria-label={`${p.id} profile: ${p.desc}, ${p.eta}`}
                />
                <span className="profile-top">
                  <b className="mono">{p.id.toUpperCase()}</b>
                  {p.tag ? <span className="badge" data-tone="cyan">{p.tag}</span> : null}
                  <span className="profile-eta mono">{p.eta}</span>
                </span>
                <span className="profile-desc">{p.desc}</span>
              </label>
            ))}
          </span>
        </div>
      </div>
      ) : null}
      <div className="cmdbar-body opts-row">
        <label className="check" htmlFor="runtime-probe" title="Runs the bundled first-party probe under timeout and isolation. Static scans never execute target code.">
          <input id="runtime-probe" type="checkbox" checked={runtime} onChange={(e) => onRuntime(e.target.checked)} aria-label="Run controlled runtime probe" />
          runtime probe
        </label>
        <label className="check" htmlFor="validate-probe" title="Runs bounded TLS/HTTP probes against the explicit endpoints below. Loopback only unless acknowledged. Never changes findings or scores.">
          <input id="validate-probe" type="checkbox" checked={validate} onChange={(e) => onValidate(e.target.checked)} aria-label="Run active validation probes" />
          validate
        </label>
        <label className="check" htmlFor="code-analysis" title="Deterministic static codebase analysis (dead code, duplication, complexity, efficiency). No AI, never executes code, never changes crypto findings.">
          <input id="code-analysis" type="checkbox" checked={codeAnalysis} onChange={(e) => onCodeAnalysis(e.target.checked)} aria-label="Run codebase analysis" />
          code analysis
        </label>
      </div>
      {validate ? (
        <div className="cmdbar-body" style={{ paddingTop: 0 }}>
          <label className="field grow" htmlFor="validation-urls">
            Validation endpoints (one per line, explicit only)
            <input
              id="validation-urls"
              value={validationUrls}
              onChange={(e) => onValidationUrls(e.target.value)}
              aria-label="Validation endpoints"
              placeholder="https://127.0.0.1:8443"
              autoComplete="off"
              spellCheck="false"
              className="mono"
            />
          </label>
          <label className="check" htmlFor="allow-non-loopback" title="Acknowledges probing non-loopback hosts. Only enable for hosts you are authorized to test.">
            <input id="allow-non-loopback" type="checkbox" checked={allowNonLoopback} onChange={(e) => onAllowNonLoopback(e.target.checked)} aria-label="Acknowledge non-loopback probing" />
            allow non-loopback
          </label>
        </div>
      ) : null}
      <p className="cmdbar-note safe-strip">
        <IconLock size={13} />
        <span>
          Static discovery only{runtime ? " + bundled controlled probe (first-party fixture, timeout + isolation)" : " — target code is never executed"}
          {validate ? " + bounded active validation (explicit endpoints, loopback by default, observation only)" : ""}. Paths are
          jailed to the workspace; <code className="evidence">..</code> escapes and symlinks are rejected.
          {isGithub ? " Repository contents are treated as untrusted input and are statically analyzed without executing repository code." : ""}
        </span>
      </p>
      <div className="cta-row">
        <button className="btn btn-cta" type="submit" disabled={loading}>
          <IconScan size={15} />
          {loading ? "Scanning…" : isGithub ? "ANALYZE REPOSITORY" : "RUN SCAN"}
        </button>
      </div>
    </form>
  );
}

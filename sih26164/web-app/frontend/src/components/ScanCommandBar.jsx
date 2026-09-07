import React from "react";
import { IconLock, IconScan } from "./icons.jsx";

export default function ScanCommandBar({ target, onTarget, runtime, onRuntime, loading, onSubmit, targetRef, validate, onValidate, validationUrls, onValidationUrls, allowNonLoopback, onAllowNonLoopback, codeAnalysis, onCodeAnalysis }) {
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
      <div className="cmdbar-body">
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
        <button className="btn" type="submit" disabled={loading}>
          <IconScan size={15} />
          {loading ? "Scanning…" : "Run scan"}
        </button>
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
      <p className="cmdbar-note">
        <IconLock size={13} />
        <span>
          Static discovery only{runtime ? " + bundled controlled probe (first-party fixture, timeout + isolation)" : " — target code is never executed"}
          {validate ? " + bounded active validation (explicit endpoints, loopback by default, observation only)" : ""}. Paths are
          jailed to the workspace; <code className="evidence">..</code> escapes and symlinks are rejected.
        </span>
      </p>
    </form>
  );
}

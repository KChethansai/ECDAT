import React from "react";
import { IconLock, IconScan } from "./icons.jsx";

export default function ScanCommandBar({ target, onTarget, runtime, onRuntime, loading, onSubmit, targetRef }) {
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
        <button className="btn" type="submit" disabled={loading}>
          <IconScan size={15} />
          {loading ? "Scanning…" : "Run scan"}
        </button>
      </div>
      <p className="cmdbar-note">
        <IconLock size={13} />
        <span>
          Static discovery only{runtime ? " + bundled controlled probe (first-party fixture, timeout + isolation)" : " — target code is never executed"}. Paths are
          jailed to the workspace; <code className="evidence">..</code> escapes and symlinks are rejected.
        </span>
      </p>
    </form>
  );
}

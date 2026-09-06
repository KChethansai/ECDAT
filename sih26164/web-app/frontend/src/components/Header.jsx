import React from "react";
import { IconDownload, IconShield } from "./icons.jsx";

export default function Header({ health, scanId, onExport, canExport }) {
  const state = health?.state || "UNKNOWN";
  const detail =
    state === "OFFLINE"
      ? "API unreachable"
      : state === "CONNECTED"
        ? `API connected${health?.probe === "missing" ? " · probe missing" : ""}`
        : state === "DEGRADED"
          ? "API degraded · probe missing"
          : "Checking API…";
  return (
    <div className="topbar">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">
          <IconShield size={18} />
        </span>
        <span>
          <span className="brand-name">ECDAT</span>
          <div className="brand-sub">Enterprise Cryptographic Discovery &amp; Analysis</div>
        </span>
      </div>
      <div className="topbar-meta">
        {scanId ? (
          <span className="fact" title="Current report identifier">
            report <b className="mono">{scanId}</b>
          </span>
        ) : null}
        <span className="health" data-state={state} role="status" title={detail}>
          <span className="dot" aria-hidden="true" />
          {state}
        </span>
        <button type="button" className="btn-ghost btn" onClick={onExport} disabled={!canExport} title={canExport ? "Download the current report as CBOM-style JSON" : "Run a scan first"}>
          <IconDownload size={14} />
          Export
        </button>
      </div>
    </div>
  );
}

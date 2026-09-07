import React from "react";
import { arr, num, obj, str } from "../lib/report.js";

const QUANTUM_FAMILIES = new Set(["RSA", "DSA", "DH", "ECDSA", "ECDH", "ECC"]);

function baseOf(algorithm) {
  const n = String(algorithm || "").toUpperCase();
  if (n.startsWith("AES")) return "AES";
  if (n.startsWith("RSA")) return "RSA";
  return n;
}

export function triageScopeFor(report) {
  const source = obj(report?.source);
  if (source.type === "github") return `github:${str(source.owner)}/${str(source.repo)}`;
  const target = str(obj(report?.metadata).scanTarget).slice(0, 128);
  return target ? `local:${target}` : "";
}

export default function RepoPanel({ report, scanId, onSarif }) {
  const source = obj(report?.source);
  if (source.type !== "github") return null;
  const components = arr(report?.components);
  const code = arr(report?.codeAnalysis?.findings);
  const critical = components.filter((c) => c.severity === "critical");
  const quantum = components.filter((c) => QUANTUM_FAMILIES.has(baseOf(c.algorithm)));
  const migration = obj(report?.migration);
  const required = arr(migration.workItems).filter((w) => w.status === "MIGRATION_REQUIRED");
  const codeByCat = {};
  for (const f of code) codeByCat[f.category] = (codeByCat[f.category] || 0) + 1;
  const quickWins = code.filter((f) => f.priority === "QUICK_WIN").length;
  const withOptions = code.filter((f) => arr(f.remediation_options).length > 0).length;
  const vsum = obj(report?.validationSummary);
  const sha = str(source.sha);
  return (
    <div className="section" aria-label="Repository intelligence">
      <h2>Repository intelligence</h2>
      <p role="status" className="section-sub">
        <b className="mono">{str(source.owner)}/{str(source.repo)}</b>
        {" "}· ref <span className="mono">{str(source.ref_requested) || "(default)"}</span>
        {" "}· commit <span className="mono" title={sha}>{sha.slice(0, 12)}</span>
        {" "}· profile <b>{str(source.profile)}</b>
        {" "}· <a href={str(source.canonical_url)} target="_blank" rel="noreferrer">open on GitHub</a>
        {" "}· report <span className="mono" style={{ fontSize: 12 }}>{str(scanId)}</span>
      </p>
      <div className="hero-facts">
        <span className="fact">crypto <b>{components.length}</b> · critical <b>{critical.length}</b></span>
        <span className="fact">quantum-vulnerable <b>{quantum.length}</b></span>
        <span className="fact">migration required <b>{required.length}</b></span>
        <span className="fact">code findings <b>{code.length}</b> · quick wins <b>{quickWins}</b></span>
        <span className="fact">with options <b>{withOptions}</b></span>
        <span className="fact">
          validation <b>{vsum.total ? `${num(vsum.total)} check(s)` : "static only"}</b>
        </span>
        <span className="fact">
          acquired <b>{num(source.archive_bytes) > 1048576 ? `${(num(source.archive_bytes) / 1048576).toFixed(1)} MiB` : `${Math.round(num(source.archive_bytes) / 1024)} KiB`}</b>
          {" "}in <b>{num(source.duration_s)}s</b>
        </span>
      </div>
      <div className="export-actions" style={{ marginTop: 8 }}>
        <button type="button" className="btn btn-secondary" onClick={onSarif} title="Download SARIF 2.1.0 for this report">
          Download SARIF
        </button>
      </div>
      <p className="section-sub">
        Counts are transparent tallies, not scores. Findings below carry evidence;
        triage never alters evidence, risk, or CBOM.
      </p>
    </div>
  );
}

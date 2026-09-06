import React, { useEffect, useRef, useState } from "react";
import { arr, exportFacts, groupRecommendations, str } from "../lib/report.js";
import { PriorityBadge, SeverityBadge } from "./Badges.jsx";
import { IconBox, IconDownload, IconEye, IconX } from "./icons.jsx";

export function RelationshipsSection({ inventory, byId }) {
  const rows = arr(inventory).filter((r) => (r.findingCount || 0) > 1 || r.runtimeObserved);
  return (
    <section className="section" aria-label="Relationships">
      <div className="section-head">
        <div>
          <p className="eyebrow">EVIDENCE GRAPH</p>
          <h2 className="section-title">Relationships</h2>
          <p className="section-sub">Cross-scanner links by artifact, library, family and runtime support. Non-observation is never proof of absence.</p>
        </div>
      </div>
      <div className="card">
        {rows.length === 0 ? (
          <p style={{ color: "var(--muted)", fontSize: 13, margin: 0, lineHeight: 1.6 }}>
            No multi-finding families in this scan — every family stands alone. Absence of links is not proof of isolation.
          </p>
        ) : (
          rows.map((row) => (
            <div key={row.family} style={{ marginTop: 12 }}>
              <b className="mono" style={{ fontSize: 12.5 }}>
                {str(row.family)}
              </b>
              <ul style={{ margin: "4px 0", paddingLeft: 20, color: "var(--muted)", fontSize: 12.5, lineHeight: 1.7 }}>
                {arr(row.findingIds).map((id) => (
                  <li key={id}>
                    {byId[id] ? `${byId[id].scanner}: ${(byId[id].file_path || "").split("/").slice(-2).join("/")} — ${byId[id].usage}` : id}
                  </li>
                ))}
                <li>Runtime: {row.runtimeObserved ? "observed during this run" : "not observed in this run (not proof of absence)"}</li>
              </ul>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

export function AnalystSummary({ report, familyCount, runtimeCount, immediateCount, total }) {
  return (
    <section className="section" aria-label="Analyst summary">
      <div className="card">
        <p className="eyebrow">ANALYST SUMMARY (DETERMINISTIC)</p>
        <p className="section-sub" style={{ fontSize: 13.5, color: "var(--text2)" }}>
          {total} finding(s) across {familyCount} familie(s)
          {immediateCount > 0 ? `; start with the ${immediateCount} Immediate migration item(s)` : "; no immediate migration items"}
          {runtimeCount > 0
            ? `; ${runtimeCount} controlled runtime observation(s) corroborate static evidence`
            : "; nothing runtime-observed in this run (not proof of absence)"}
          . For open-ended questions, use the CLI analyst: <code className="evidence">agent explain &lt;target&gt; --ask "..."</code>.
        </p>
        <p className="disclaimer">{str(report?.riskSummary?.note, "Priorities are deterministic migration ordering, not QRQC prediction.")}</p>
      </div>
    </section>
  );
}

function JsonDialog({ report, filename, onClose }) {
  const closeRef = useRef(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }
  return (
    <>
      <div className="overlay" onClick={onClose} aria-hidden="true" />
      <div className="dialog" role="dialog" aria-modal="true" aria-label="CBOM-style JSON preview">
        <div className="dialog-head">
          <h2 className="mono" style={{ fontSize: 13 }}>
            {filename}
          </h2>
          <div style={{ display: "flex", gap: 8 }}>
            <button type="button" className="btn-ghost btn" style={{ padding: "7px 12px", fontSize: 12.5 }} onClick={copy}>
              {copied ? "Copied" : "Copy"}
            </button>
            <button ref={closeRef} type="button" className="icon-btn" onClick={onClose} aria-label="Close JSON preview">
              <IconX size={15} />
            </button>
          </div>
        </div>
        <div className="dialog-body">
          <pre>{JSON.stringify(report, null, 2)}</pre>
        </div>
      </div>
    </>
  );
}

export function RecommendationsList({ components }) {
  const groups = groupRecommendations(components);
  if (groups.length === 0) {
    return (
      <section className="section" aria-label="Recommendations">
        <div className="section-head">
          <div>
            <p className="eyebrow">ANALYST GUIDANCE</p>
            <h2 className="section-title">Recommendations</h2>
          </div>
        </div>
        <div className="card">
          <p style={{ color: "var(--muted)", fontSize: 13, margin: 0 }}>No recommendations in this report.</p>
        </div>
      </section>
    );
  }
  return (
    <section className="section" aria-label="Recommendations">
      <div className="section-head">
        <div>
          <p className="eyebrow">ANALYST GUIDANCE</p>
          <h2 className="section-title">Recommendations</h2>
          <p className="section-sub">Deterministic, rule-based migration guidance — grouped by direction with supporting evidence. Validate interoperability, policy and use case before any pilot.</p>
        </div>
      </div>
      <div className="rec-grid">
        {groups.map((g, n) => (
          <article key={g.direction} className="card rec-card hoverable" style={{ animationDelay: `${Math.min(n, 8) * 40}ms` }}>
            <div className="badge-row">
              <PriorityBadge value={g.worstPriority} />
              <SeverityBadge value={g.worstSeverity} />
              <span className="badge" data-tone="muted">
                {g.findings.length} finding(s)
              </span>
            </div>
            <h3>
              <span className="mono">{g.direction}</span>
            </h3>
            {g.notes ? (
              <p className="path">
                <b>Migration path</b>
                {g.notes}
              </p>
            ) : null}
            <p className="ev">
              <b>Evidence</b>
              <span className="mono">{g.algorithms.join(", ") || "—"}</span> across {g.findings.length} finding(s)
            </p>
            {g.guidance ? <p className="disclaimer" style={{ marginTop: 2 }}>{g.guidance}</p> : null}
          </article>
        ))}
      </div>
    </section>
  );
}

export function ExportPanel({ report, scanId, onDownload }) {
  const [viewOpen, setViewOpen] = useState(false);
  const facts = exportFacts(report, scanId);
  const filename = `ecdat-cbom-style-${scanId || "report"}.json`;
  const canExport = Boolean(report);
  return (
    <section className="section" aria-label="CBOM export">
      <div className="export">
        <div style={{ minWidth: 0 }}>
          <h3>
            <IconBox size={17} />
            Cryptographic Bill of Materials
          </h3>
          <p>Machine-readable inventory generated from this scan. CBOM-style / CBOM-oriented — not independently standards-verified.</p>
          <div className="export-meta">
            <span className="fact">
              scan <b className="mono">{facts.scanId}</b>
            </span>
            <span className="fact">
              <b>{facts.findings}</b>&nbsp;findings
            </span>
            <span className="fact">
              <b>{facts.families}</b>&nbsp;families
            </span>
            <span className="fact mono" style={{ fontSize: 11 }}>
              {facts.format}
            </span>
          </div>
        </div>
        <div className="export-actions">
          <button type="button" className="btn btn-secondary" onClick={() => setViewOpen(true)} disabled={!canExport} title={canExport ? "Preview the CBOM-style JSON" : "Run a scan first"}>
            <IconEye size={14} />
            View JSON
          </button>
          <button type="button" className="btn" onClick={onDownload} disabled={!canExport} title={canExport ? "Download the current report as CBOM-style JSON" : "Run a scan first"}>
            <IconDownload size={14} />
            Download CBOM
          </button>
        </div>
      </div>
      {viewOpen && canExport ? <JsonDialog report={report} filename={filename} onClose={() => setViewOpen(false)} /> : null}
    </section>
  );
}



import React from "react";
import { analystLine, arr, lineLabel, shortPath, str } from "../lib/report.js";
import { PriorityBadge, RealBadge, SeverityBadge, StatusBadge } from "./Badges.jsx";
import { IconSearch } from "./icons.jsx";
import { SectionEmpty } from "./States.jsx";

const SEV_ROW = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "" };

export default function FindingsExplorer({
  components,
  visible,
  total,
  filterPriority,
  onPriority,
  filterSeverity,
  onSeverity,
  filterScanner,
  onScanner,
  scannerSources,
  query,
  onQuery,
  onClear,
  activeFilters,
  onOpen,
}) {
  const all = arr(components);
  return (
    <section className="section" aria-label="Findings explorer">
      <div className="section-head">
        <div>
          <p className="eyebrow">SECURITY FINDINGS</p>
          <h2 className="section-title">Findings explorer</h2>
          <p className="section-sub">Severity → algorithm → location → evidence → recommendation. Select a row for the full analyst workspace.</p>
        </div>
      </div>
      <div className="card">
        <div className="filters" role="group" aria-label="Finding filters">
          <label className="field" htmlFor="f-priority">
            Priority
            <select id="f-priority" value={filterPriority} onChange={(e) => onPriority(e.target.value)} aria-label="Filter by priority">
              <option value="all">All priorities</option>
              <option value="P0">P0 — Immediate</option>
              <option value="P1">P1 — Near-term</option>
              <option value="P2">P2 — Planned</option>
              <option value="P3">P3 — Monitor</option>
            </select>
          </label>
          <label className="field" htmlFor="f-severity">
            Severity
            <select id="f-severity" value={filterSeverity} onChange={(e) => onSeverity(e.target.value)} aria-label="Filter by severity">
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
          <label className="field" htmlFor="f-scanner">
            Scanner
            <select id="f-scanner" value={filterScanner} onChange={(e) => onScanner(e.target.value)} aria-label="Filter by scanner">
              <option value="all">All scanners</option>
              {arr(scannerSources).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="field search" htmlFor="f-search">
            Search
            <span style={{ position: "relative", display: "block" }}>
              <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--faint)", display: "inline-flex" }}>
                <IconSearch size={14} />
              </span>
              <input
                id="f-search"
                value={query}
                onChange={(e) => onQuery(e.target.value)}
                aria-label="Search findings"
                placeholder="algorithm, path, evidence, library…"
                autoComplete="off"
                spellCheck="false"
                style={{ paddingLeft: 32 }}
              />
            </span>
          </label>
          <button type="button" className="btn btn-secondary" onClick={onClear} disabled={activeFilters.length === 0}>
            Clear
          </button>
        </div>
        <div className="active-filters result-count" aria-live="polite">
          <span>
            Showing <b>{visible.length}</b> of {total} findings.
          </span>
          {activeFilters.map((f) => (
            <span key={f} className="badge" data-tone="cyan">
              {f}
            </span>
          ))}
        </div>
        <div style={{ height: 12 }} />
        {all.length === 0 ? (
          <SectionEmpty>
            No cryptographic artifacts were detected across source, binary, container, dependency, certificate, HSM-config and cloud-config evidence. This is a
            completed scan, not a scanner error — and it is not a claim that the environment is secure.
          </SectionEmpty>
        ) : visible.length === 0 ? (
          <SectionEmpty>No findings match the current filters. Clear filters to see the full set.</SectionEmpty>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <caption>Deterministic findings ordered by priority score, then path</caption>
              <thead>
                <tr>
                  <th scope="col">Priority</th>
                  <th scope="col">Finding</th>
                  <th scope="col">Source</th>
                  <th scope="col">Evidence</th>
                  <th scope="col">Risk rationale</th>
                  <th scope="col">Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((f) => (
                  <tr key={f.id} className={SEV_ROW[f.severity] || ""}>
                    <td>
                      <div className="badge-row">
                        <PriorityBadge value={f.priority} />
                      </div>
                      <div className="cell-sub">
                        <SeverityBadge value={f.severity} /> <StatusBadge value={f.migrationStatus} />
                      </div>
                    </td>
                    <td>
                      <button type="button" className="row-button mono" onClick={() => onOpen(f)} aria-haspopup="dialog">
                        {str(f.algorithm, "?")}
                      </button>
                      <div className="cell-sub mono" style={{ fontSize: 11 }}>
                        {shortPath(f.file_path)}:{lineLabel(f.line)}
                      </div>
                      <div className="cell-sub">{str(f.usage, "—")}</div>
                      {f.key_size ? (
                        <div className="cell-sub">
                          {f.key_size} bits{str(f.curve) ? ` · ${f.curve}` : ""}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <RealBadge mock={f.is_mock} />
                      <div className="cell-sub mono" style={{ fontSize: 11 }}>
                        {str(f.scanner, "?")}
                      </div>
                    </td>
                    <td>
                      <code className="evidence">{str(f.evidence, "metadata only")}</code>
                    </td>
                    <td>
                      <div className="cell-sub" style={{ color: "var(--text2)" }}>
                        {str(f.rationale, "—")}
                      </div>
                      {arr(f.correlation?.supports).length > 0 ? (
                        <div className="cell-sub">↔ supported by {f.correlation.supports.length} static finding(s)</div>
                      ) : null}
                      <div className="cell-sub" style={{ color: "var(--cyan)" }}>
                        {analystLine(f)}
                      </div>
                    </td>
                    <td>
                      <div className="cell-sub" style={{ color: "var(--text2)" }}>
                        {str(f.recommendation?.recommend, "Review manually")}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

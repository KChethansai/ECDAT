import React from "react";
import { arr, str } from "../lib/report.js";
import { PriorityBadge, RuntimeBadge, SeverityBadge, StrengthBadge } from "./Badges.jsx";
import { SectionEmpty } from "./States.jsx";

export default function InventoryTable({ inventory }) {
  const rows = arr(inventory);
  const totalFindings = rows.reduce((n, r) => n + (r.findingCount || 0), 0);
  return (
    <section className="section" aria-label="Algorithm inventory">
      <div className="section-head">
        <div>
          <p className="eyebrow">CRYPTOGRAPHIC INTELLIGENCE</p>
          <h2 className="section-title">Algorithm inventory</h2>
          <p className="section-sub">One row per canonical family. Risk shows the worst member; strength shows the best-supported evidence type.</p>
        </div>
      </div>
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {rows.length === 0 ? (
          <div style={{ padding: 16 }}>
            <SectionEmpty>No inventory rows for this scan. An empty inventory means no cryptographic references were detected — not a scanner failure.</SectionEmpty>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 0, borderRadius: 0 }}>
            <table className="data">
              <caption>
                {rows.length} familie(s) across {totalFindings} findings
              </caption>
              <thead>
                <tr>
                  <th scope="col">Family</th>
                  <th scope="col">Findings</th>
                  <th scope="col">Scanners</th>
                  <th scope="col">Artifacts</th>
                  <th scope="col">Strength</th>
                  <th scope="col">Risk</th>
                  <th scope="col">Runtime</th>
                  <th scope="col">Migration direction</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, i) => (
                  <tr key={str(row.family, `row-${i}`)}>
                    <td>
                      <span className="cell-main mono">{str(row.family, "?")}</span>
                      <div className="cell-sub">{arr(row.algorithms).join(", ") || "—"}</div>
                    </td>
                    <td style={{ fontVariantNumeric: "tabular-nums", fontWeight: 700 }}>{row.findingCount ?? "—"}</td>
                    <td>
                      <div className="cell-sub mono" style={{ fontSize: 11 }}>
                        {arr(row.scanners).join(" · ") || "—"}
                      </div>
                    </td>
                    <td style={{ fontVariantNumeric: "tabular-nums" }}>{row.artifactCount ?? arr(row.artifacts).length ?? "—"}</td>
                    <td>
                      <StrengthBadge value={row.evidenceStrength} />
                    </td>
                    <td>
                      <div className="badge-row">
                        <PriorityBadge value={row.priority} />
                        <SeverityBadge value={row.severity} />
                      </div>
                    </td>
                    <td>{row.runtimeObserved ? <RuntimeBadge observed /> : <span style={{ color: "var(--text-muted)" }}>—</span>}</td>
                    <td>
                      <div className="cell-sub" style={{ color: "var(--text-muted)" }}>
                        {str(row.recommendation, "Review manually")}
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

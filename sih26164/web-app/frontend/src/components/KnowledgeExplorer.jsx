import React, { useState } from "react";
import { arr, knowledgeBase, obj, skillMatchCount, str } from "../lib/report.js";
import { Badge } from "./Badges.jsx";
import { IconCompass } from "./icons.jsx";

/* Subordinate explorer: which advisory skills matched this report, why, and
   where they came from. Never evidence — always labeled knowledge. */
export default function KnowledgeExplorer({ report, components }) {
  const [open, setOpen] = useState(null);
  const base = knowledgeBase(report);
  const ctx = obj(report?.knowledgeContext);
  if (base.length === 0) return null;
  const source = obj(ctx.source);
  return (
    <section className="section" aria-label="Security knowledge explorer">
      <div className="section-head">
        <div>
          <p className="eyebrow">SECURITY KNOWLEDGE (ADVISORY)</p>
          <h2 className="section-title">Knowledge explorer</h2>
          <p className="section-sub">
            {base.length} of {ctx.skillsTotal || "?"} registry skills matched this report's findings by deterministic
            rules. Select a skill for its guidance, verification checks, and provenance.
          </p>
        </div>
      </div>
      <div className="rec-grid">
        {base.map((s) => {
          const count = skillMatchCount(components, s.id);
          const expanded = open === s.id;
          return (
            <article key={s.id} className="card rec-card">
              <div className="badge-row">
                <Badge tone={s.tier === 1 ? "cyan" : "indigo"} label={s.tier === 1 ? "CORE" : "ADJACENT"} title={s.tier === 1 ? "Core cryptography knowledge" : "Adjacent-domain context"} />
                <Badge label={s.domain} title={`Domain ${s.domain}`} />
                <span className="badge" data-tone="muted">
                  {count} finding(s)
                </span>
              </div>
              <h3>{s.name}</h3>
              <p className="ev">{str(s.summary)}</p>
              <div>
                <button
                  type="button"
                  className="btn-ghost btn"
                  style={{ padding: "7px 12px", fontSize: 12.5 }}
                  aria-expanded={expanded}
                  aria-label={`${expanded ? "Hide" : "Show"} guidance for ${s.name}`}
                  onClick={() => setOpen(expanded ? null : s.id)}
                >
                  {expanded ? "Hide guidance" : "Show guidance"}
                </button>
              </div>
              {expanded ? (
                <div className="ev">
                  <b>Guidance</b>
                  <ul style={{ margin: "4px 0", paddingLeft: 17 }}>
                    {arr(s.guidance).map((g) => (
                      <li key={g}>{g}</li>
                    ))}
                  </ul>
                  <b>Verify</b>
                  <ul style={{ margin: "4px 0", paddingLeft: 17 }}>
                    {arr(s.verification).map((v) => (
                      <li key={v}>{v}</li>
                    ))}
                  </ul>
                  {(arr(s.frameworks?.nist_csf).length > 0 || arr(s.frameworks?.mitre_attack).length > 0) && (
                    <span className="cell-sub">
                      Related: {[...arr(s.frameworks?.nist_csf), ...arr(s.frameworks?.mitre_attack)].join(" · ")} (knowledge mapping, not a compliance claim)
                    </span>
                  )}
                  <p className="cell-sub" style={{ marginTop: 6 }}>
                    Source: {source.repository || "—"}@{String(source.commit || "").slice(0, 7)} · {source.license || ""} · {s.id}
                  </p>
                </div>
              ) : null}
            </article>
          );
        })}
      </div>
      <p className="disclaimer" style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
        <IconCompass size={13} />
        <span>
          {str(ctx.advisory, "Security knowledge is advisory context for observed evidence.")} Deterministic findings
          remain authoritative.
        </span>
      </p>
    </section>
  );
}

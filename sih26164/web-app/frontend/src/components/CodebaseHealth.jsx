import React, { useState } from "react";
import { arr, num, obj, str } from "../lib/report.js";

const CONSTRAINTS = ["preserve-public-apis", "minimize-files", "preserve-tests", "require-tests", "no-new-dependencies", "minimize-behavior-change"];

function FindingRow({ finding, analysisId }) {
  const [open, setOpen] = useState(false);
  const [option, setOption] = useState("");
  const [constraints, setConstraints] = useState([]);
  const [plan, setPlan] = useState(null);
  const [error, setError] = useState("");
  const f = obj(finding);
  const options = arr(f.remediation_options);

  async function generatePlan() {
    if (!option) return;
    setError("");
    try {
      const res = await fetch("/plans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysis_id: analysisId, finding_id: f.id, option_id: option, constraints }),
      });
      if (!res.ok) throw new Error(await res.text());
      const body = await res.json();
      setPlan(body.plan || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  function toggleConstraint(name) {
    setConstraints((prev) => (prev.includes(name) ? prev.filter((c) => c !== name) : [...prev, name]));
  }

  return (
    <div className="finding-row">
      <button type="button" className="finding-head" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="mono">{str(f.title, f.id).slice(0, 90)}</span>
        <span className="finding-meta">
          {str(f.category)} · {str(f.confidence)} · {str(f.verdict)} · {str(f.priority)}
        </span>
      </button>
      {open ? (
        <div className="finding-detail">
          <p><b>Evidence:</b> <code className="evidence">{str(f.evidence, "—")}</code></p>
          <p>{str(f.description)}</p>
          <p><b>Impact:</b> {str(f.impact)} · <b>Effort:</b> {str(f.effort)} · <b>Risk:</b> {str(f.risk)} · <b>Security risk:</b> {str(f.security_risk, "NONE")}</p>
          <p><b>Verification:</b> {str(f.verification)}</p>
          <p><b>Rationale:</b> {str(f.rationale)}</p>
          <div>
            <b>Remediation options (you choose):</b>
            {options.map((o) => (
              <label key={o.option_id} className="check" style={{ display: "block" }}>
                <input type="radio" name={`opt-${f.id}`} value={o.option_id} checked={option === o.option_id} onChange={(e) => setOption(e.target.value)} />
                <b>{str(o.title)}</b> — {str(o.description)}
                <span style={{ display: "block", fontSize: 12 }}>risk {str(o.risk)} · {str(o.complexity)} · {str(o.automation_suitability)}</span>
              </label>
            ))}
          </div>
          <div>
            <b>Constraints:</b>
            {CONSTRAINTS.map((c) => (
              <label key={c} className="check" style={{ display: "inline-block", marginRight: 12 }}>
                <input type="checkbox" checked={constraints.includes(c)} onChange={() => toggleConstraint(c)} />
                {c}
              </label>
            ))}
          </div>
          <button type="button" className="btn" disabled={!option} onClick={generatePlan}>Generate plan</button>
          {error ? <p className="alert">{error}</p> : null}
          {plan ? (
            <div>
              <p><b>Plan {str(plan.plan_id)} — {str(plan.selected_option?.title)}</b></p>
              <pre className="evidence" style={{ whiteSpace: "pre-wrap" }}>{str(plan.markdown)}</pre>
              <button type="button" className="btn" onClick={() => navigator.clipboard?.writeText(str(plan.agent_prompt))}>Copy AI agent prompt (optional)</button>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export default function CodebaseHealth({ analysis }) {
  const a = obj(analysis);
  const findings = arr(a.findings);
  const health = obj(a.health);
  const [filter, setFilter] = useState("all");
  if (!a.findings) return null;
  const visible = filter === "all" ? findings : findings.filter((f) => f.category === filter);
  const cats = Object.keys(obj(health.byCategory));
  return (
    <div className="section" aria-label="Codebase health">
      <h2>Codebase health</h2>
      <p role="status" className="section-sub">
        {num(health.total)} code finding(s) · {num(health.highConfidence)} high-confidence ·{" "}
        overall {num(health.overall?.value)}/100 <span title={str(health.overall?.formula)}>({str(health.overall?.meaning)})</span> ·{" "}
        deterministic analysis, no AI · engineering impact only (crypto severity untouched)
      </p>
      <div className="hero-facts">
        {cats.map((c) => (
          <button key={c} type="button" className={`fact${filter === c ? " warn" : ""}`} onClick={() => setFilter((prev) => (prev === c ? "all" : c))}>
            {c} <b>{num(health.byCategory[c])}</b>
          </button>
        ))}
      </div>
      <div>
        {visible.slice(0, 100).map((f) => (
          <FindingRow key={f.id} finding={f} analysisId={str(a.analysis_id)} />
        ))}
        {visible.length > 100 ? <p className="section-sub">Showing 100 of {visible.length} — refine the filter.</p> : null}
      </div>
    </div>
  );
}

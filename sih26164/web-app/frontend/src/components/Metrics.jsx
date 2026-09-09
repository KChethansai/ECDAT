import React from "react";
import { arr, num, obj, str, strengthCounts, unknownsCount } from "../lib/report.js";
import { PriorityBadge, SeverityBadge } from "./Badges.jsx";

function Metric({ label, value, meaning, tone, glow, small }) {
  return (
    <div className={`card metric${small ? " small" : ""}`} style={tone ? { "--bar": tone, "--bar-glow": glow } : undefined}>
      <span className="metric-value">{value}</span>
      <span className="metric-label">{label}</span>
      {meaning ? <span className="metric-meaning">{meaning}</span> : null}
    </div>
  );
}

export function ExecutiveMetrics({ report, criticallyHigh, runtimeCount, immediateCount, familyCount, candidateCount, unknownCount }) {
  const summary = obj(report?.summary);
  return (
    <section aria-label="Executive metrics">
      <div className="grid metrics-primary">
        <Metric label="Total findings" value={num(summary.total)} meaning="Normalized static + runtime evidence" tone="var(--accent)" glow="rgba(57,255,136,.12)" />
        <Metric
          label="Critical / high"
          value={criticallyHigh}
          meaning="Needs attention first"
          tone={criticallyHigh > 0 ? "var(--danger)" : "var(--accent)"}
          glow={criticallyHigh > 0 ? "rgba(255,77,77,.12)" : "rgba(57,255,136,.12)"}
        />
        <Metric
          label="Immediate migration"
          value={immediateCount}
          meaning="P0 / critical work items"
          tone={immediateCount > 0 ? "var(--warning)" : "var(--accent)"}
          glow="rgba(255,176,32,.12)"
        />
      </div>
      <div className="grid metrics-secondary">
        <Metric small label="Algorithm families" value={familyCount} meaning="Canonical inventory groups" tone="var(--text-muted)" glow="rgba(154,154,154,.12)" />
        <Metric small label="Migration candidates" value={candidateCount} meaning="Planned work items" tone="var(--text-muted)" glow="rgba(154,154,154,.12)" />
        <Metric small label="Open unknowns" value={unknownCount} meaning="Planner-recorded gaps" tone="var(--warning)" glow="rgba(255,176,32,.1)" />
        <Metric small label="Runtime observations" value={runtimeCount} meaning="Controlled probe only" tone="var(--accent)" glow="rgba(57,255,136,.1)" />
      </div>
    </section>
  );
}

const SEV_ORDER = ["critical", "high", "medium", "low"];
const SEV_BAR = { critical: "var(--danger)", high: "var(--warning)", medium: "var(--text-muted)", low: "var(--text-muted)" };
const PRI_ORDER = ["P0", "P1", "P2", "P3"];
const PRI_BAR = { P0: "var(--danger)", P1: "var(--warning)", P2: "var(--warning)", P3: "var(--accent)" };
const STR_ORDER = ["HIGH", "MEDIUM", "LOW"];
const STR_BAR = { HIGH: "var(--accent)", MEDIUM: "var(--warning)", LOW: "var(--text-muted)" };

function Dist({ title, sub, rows, max }) {
  return (
    <div className="card">
      <p className="eyebrow" style={{ fontSize: 10 }}>
        {title}
      </p>
      <p className="section-sub" style={{ fontSize: 12 }}>
        {sub}
      </p>
      <div className="dist" style={{ marginTop: 12 }}>
        {rows.map(([k, v]) => (
          <div className="dist-row" key={k}>
            <span className="k">{k}</span>
            <span className="dist-track" role="img" aria-label={`${k}: ${v} of ${max}`}>
              <span className="dist-fill" style={{ width: max > 0 ? `${Math.round((v / max) * 100)}%` : "0%", background: rows.color?.[k] || "var(--accent)" }} />
            </span>
            <span className="v">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function distRows(order, counts, colors) {
  const rows = order.map((k) => [k, num(counts[k])]);
  rows.color = colors;
  return rows;
}

export function RiskOverview({ report, components }) {
  const summary = obj(report?.summary);
  const risk = obj(report?.riskSummary);
  const total = Math.max(num(summary.total), 1);
  const strengths = strengthCounts(components);
  return (
    <section className="section" aria-label="Risk intelligence">
      <div className="section-head">
        <div>
          <p className="eyebrow">RISK INTELLIGENCE</p>
          <h2 className="section-title">Exposure at a glance</h2>
          <p className="section-sub">
            {num(risk.moscaExposed)} of {num(summary.total)} findings carry migration exposure under the Mosca heuristic — a sequencing aid, not a quantum-arrival
            prediction.
          </p>
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
        <Dist title="SEVERITY" sub="Deterministic severity tiers." rows={distRows(SEV_ORDER, obj(summary.bySeverity), SEV_BAR)} max={total} />
        <Dist title="PRIORITY" sub="P0 immediate → P3 monitor." rows={distRows(PRI_ORDER, obj(risk.priorities), PRI_BAR)} max={total} />
        <Dist title="EVIDENCE STRENGTH" sub="Evidence-type rank, not probability." rows={distRows(STR_ORDER, strengths, STR_BAR)} max={total} />
      </div>
    </section>
  );
}

export function FixFirstCard({ finding, runtimeAvailable }) {
  if (!finding) {
    return (
      <div className="card fixfirst calm">
        <p className="eyebrow">FIX FIRST</p>
        <h3>No critical or high findings</h3>
        <p>Review the complete inventory and exposure horizon. Absence of high-priority findings is not proof of cryptographic hygiene.</p>
      </div>
    );
  }
  const runtimeLine =
    finding.scanner === "runtime"
      ? "Observed under controlled execution."
      : (finding.correlation?.supports || []).length > 0
        ? "Supported by runtime observation in this scan."
        : runtimeAvailable
          ? "Not runtime-observed in this scan — not proof of absence."
          : "Static evidence only (runtime probe not run).";
  return (
    <div className="card fixfirst" aria-label="Fix first recommendation">
      <p className="eyebrow" style={{ color: "var(--danger)" }}>
        FIX FIRST — HIGHEST PRIORITY
      </p>
      <h3>
        <span className="algo">{str(finding.algorithm, "?")}</span>{" "}
        <span style={{ color: "var(--text-muted)", fontSize: 14, fontWeight: 600 }}>· top of deterministic order</span>
      </h3>
      <div className="badge-row">
        <PriorityBadge value={finding.priority} />
        <SeverityBadge value={finding.severity} />
      </div>
      <p>{str(finding.rationale, "Review rationale and evidence.")}</p>
      <dl className="kv">
        <div className="row">
          <dt>Location</dt>
          <dd className="mono" style={{ fontSize: 12 }}>
            {str(finding.file_path, "—")}:{typeof finding.line === "number" && finding.line > 0 ? finding.line : "—"}
          </dd>
        </div>
        <div className="row">
          <dt>Action</dt>
          <dd>
            <strong>{str(finding.recommendation?.recommend, "Review manually")}</strong>
          </dd>
        </div>
        <div className="row">
          <dt>Why</dt>
          <dd>{(finding.risk_factors || []).slice(0, 3).join("; ") || str(finding.severity)}</dd>
        </div>
        <div className="row">
          <dt>Runtime</dt>
          <dd>{runtimeLine}</dd>
        </div>
      </dl>
    </div>
  );
}

export function ExposurePanel({ report, components }) {
  const rows = arr(components);
  const strengths = strengthCounts(rows);
  let hsm = 0;
  let cloud = 0;
  for (const r of rows) {
    if (r.scanner === "hsm") hsm += 1;
    if (r.scanner === "cloud") cloud += 1;
  }
  const runtimeProv = obj(report?.metadata?.runtimeProvenance);
  const unknowns = unknownsCount(report?.migration);
  return (
    <div className="card" aria-label="Exposure and evidence overview">
      <p className="eyebrow">EXPOSURE / EVIDENCE</p>
      <h3 className="section-title" style={{ marginTop: 6 }}>
        What backs the decision
      </h3>
      <div className="dist" style={{ marginTop: 12 }}>
        {STR_ORDER.map((s) => (
          <div className="dist-row" key={s}>
            <span className="k">{s}</span>
            <span className="dist-track" role="img" aria-label={`${s} strength: ${strengths[s]} findings`}>
              <span className="dist-fill" style={{ width: rows.length > 0 ? `${Math.round((strengths[s] / rows.length) * 100)}%` : "0%", background: STR_BAR[s] }} />
            </span>
            <span className="v">{strengths[s]}</span>
          </div>
        ))}
      </div>
      <dl className="kv">
        <div className="row">
          <dt>HSM</dt>
          <dd>{hsm > 0 ? `${hsm} static/config reference(s) — no live HSM inspection` : "none in this scan"}</dd>
        </div>
        <div className="row">
          <dt>Cloud</dt>
          <dd>{cloud > 0 ? `${cloud} static/config reference(s) — no live account enumeration` : "none in this scan"}</dd>
        </div>
        <div className="row">
          <dt>Runtime</dt>
          <dd>{runtimeProv.available ? `${runtimeProv.events || 0} controlled observation(s)` : str(runtimeProv.reason, "probe not run in this scan")}</dd>
        </div>
        <div className="row">
          <dt>Unknowns</dt>
          <dd>{unknowns > 0 ? `${unknowns} planner-recorded gap(s) — see migration items` : "none recorded"}</dd>
        </div>
      </dl>
      <p className="disclaimer">Static discovery proves presence in artifacts, not runtime use. Runtime observation proves a controlled run, not full coverage.</p>
    </div>
  );
}

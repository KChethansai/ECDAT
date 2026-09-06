import React, { useMemo, useState } from "react";

const SEV = { critical: "#b42318", high: "#c2410c", medium: "#a16207", low: "#0f766e" };
const STAGES = ["SCAN", "FINDINGS", "RISK", "PRIORITY", "RECOMMENDATION", "INTEL", "MIGRATION", "CBOM"];
const STATUS_COLOR = { MIGRATION_REQUIRED: "#b42318", MIGRATION_PLANNED: "#a16207", MIGRATION_IN_PROGRESS: "#0F766E", MIGRATION_READY: "#0F766E" };
const shortStatus = (s) => (s || "").replace(/^MIGRATION_/, "");
const styles = {
  page: { fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif", maxWidth: 1120, margin: "0 auto", padding: "44px 20px 72px", color: "#102A43", background: "#F7FAFC", minHeight: "100vh" },
  header: { display: "grid", gridTemplateColumns: "1.3fr .7fr", gap: 32, alignItems: "end", marginBottom: 30 }, kicker: { color: "#0F766E", letterSpacing: ".11em", fontWeight: 800, fontSize: 11, margin: "0 0 8px" },
  title: { fontSize: "clamp(2rem, 5vw, 4rem)", lineHeight: .98, letterSpacing: "-.045em", margin: 0 }, lede: { color: "#486581", lineHeight: 1.6, margin: 0 },
  scanBox: { display: "flex", gap: 12, padding: 18, background: "#102A43", borderRadius: 8, marginBottom: 22 }, label: { color: "#fff", display: "grid", gap: 6, flex: 1, fontSize: 13, fontWeight: 700 }, input: { border: 0, borderRadius: 4, padding: "11px 12px", font: "inherit" },
  button: { background: "#14B8A6", border: 0, borderRadius: 4, color: "#042F2E", cursor: "pointer", fontWeight: 800, padding: "0 18px" }, flow: { display: "flex", flexWrap: "wrap", alignItems: "center", gap: 9, fontSize: 12, fontWeight: 800, letterSpacing: ".06em", margin: "24px 0" },
  metrics: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", borderTop: "2px solid #102A43", borderBottom: "1px solid #BCCCDC", marginBottom: 24 }, metric: { padding: "16px 12px", display: "grid", gap: 3, borderRight: "1px solid #D9E2EC" }, metricValue: { fontSize: 28 },
  twoColumn: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }, panel: { background: "#fff", border: "1px solid #D9E2EC", padding: 20, marginBottom: 16 }, h2: { fontSize: 20, margin: "0 0 8px", letterSpacing: "-.02em" }, muted: { color: "#627D98", margin: 0, lineHeight: 1.5, fontSize: 14 },
  sectionHead: { display: "flex", justifyContent: "space-between", alignItems: "start", gap: 16 }, secondary: { background: "#fff", color: "#0F766E", border: "1px solid #0F766E", borderRadius: 4, padding: "9px 12px", fontWeight: 700, cursor: "pointer" }, recommendations: { margin: "14px 0", paddingLeft: 20, lineHeight: 1.7 },
  table: { borderCollapse: "collapse", width: "100%", fontSize: 13, textAlign: "left" }, evidence: { whiteSpace: "normal", color: "#334E68", fontSize: 11 },
};

function Metric({ label, value, color = "#102A43" }) {
  return <div style={styles.metric}><b style={{ ...styles.metricValue, color }}>{value}</b><span>{label}</span></div>;
}

function analystLine(finding) {
  const bits = [`${finding.priority} because ${finding.severity} severity`];
  if (finding.evidenceStrength) bits.push(`${finding.evidenceStrength.toLowerCase()} evidence strength`);
  if (finding.mosca_exposed) bits.push("migration exposure under the Mosca heuristic");
  const related = (finding.related || []).length;
  bits.push(related > 0 ? `${related} linked finding(s)` : "no linked findings (not proof of isolation)");
  if (finding.scanner === "runtime") bits.push("observed under controlled execution");
  else if ((finding.correlation?.supports || []).length > 0) bits.push("supported by runtime observation");
  else bits.push("not runtime-observed in this run");
  return `Analyst (deterministic): ${finding.algorithm} is ${bits.join("; ")}.`;
}

export default function App() {
  const [target, setTarget] = useState("sample");
  const [runtime, setRuntime] = useState(false);
  const [report, setReport] = useState(null);
  const [scanId, setScanId] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [filterPriority, setFilterPriority] = useState("all");
  const [filterScanner, setFilterScanner] = useState("all");
  const [expanded, setExpanded] = useState(null);
  const topFindings = useMemo(() => report?.components.filter((f) => ["critical", "high"].includes(f.severity)) || [], [report]);
  const inventory = report?.intelligence?.inventory || [];
  const migration = report?.migration || null;
  const byId = useMemo(() => Object.fromEntries((report?.components || []).map((f) => [f.id, f])), [report]);
  const visible = useMemo(() => (report?.components || []).filter((f) =>
    (filterPriority === "all" || f.priority === filterPriority) &&
    (filterScanner === "all" || f.scanner === filterScanner) &&
    (query === "" || `${f.algorithm} ${f.file_path} ${f.evidence || ""} ${f.library || ""}`.toLowerCase().includes(query.toLowerCase()))), [report, filterPriority, filterScanner, query]);
  const runtimeCount = useMemo(() => (report?.components || []).filter((f) => f.scanner === "runtime").length, [report]);
  const requiredCount = migration?.roadmap?.Immediate?.length || 0;

  async function runScan(event) {
    event.preventDefault(); setLoading(true); setError(""); setScanId("");
    try {
      const response = await fetch("/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, scanners: ["source", "binary", "container", "dependency", "hsm", "cloud"], runtime }) });
      if (!response.ok) {
        let detail = await response.text();
        try { detail = JSON.parse(detail).detail || detail; } catch { /* keep raw body */ }
        throw new Error(`Scan failed (${response.status}): ${detail}`);
      }
      const body = await response.json(); setReport(body.report); setScanId(body.id);
    } catch (err) { setError(String(err.message || err)); } finally { setLoading(false); }
  }

  function downloadReport() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "ecdat-cbom-style-report.json"; link.click(); URL.revokeObjectURL(url);
  }

  const summary = report?.summary;
  return <main style={styles.page}>
    <header style={styles.header}><div><p style={styles.kicker}>ECDAT / CRYPTOGRAPHIC INTELLIGENCE</p><h1 style={styles.title}>Make the first migration decision obvious.</h1></div><p style={styles.lede}>Real source discovery, deterministic risk ordering, and CBOM-style evidence for a practical PQC migration conversation.</p></header>
    <form onSubmit={runScan} style={styles.scanBox}><label style={styles.label}>Scan target<input value={target} onChange={(e) => setTarget(e.target.value)} aria-label="scan target" style={styles.input} placeholder="sample or workspace-contained path" /></label><label style={{ ...styles.label, flex: 0, justifyContent: "end" }}><span><input type="checkbox" checked={runtime} onChange={(e) => setRuntime(e.target.checked)} aria-label="run controlled runtime probe" /> runtime probe</span></label><button disabled={loading} style={styles.button}>{loading ? "Scanning…" : "Run scan"}</button></form>
    {loading && <p role="status" style={styles.muted}>Scanning real source and configuration files. No code is executed.</p>}
    {error && <p role="alert" style={{ padding: 12, color: SEV.critical, background: "#fff1f0" }}>{error}</p>}
    <nav aria-label="ECDAT analysis flow" style={styles.flow}>{STAGES.map((stage, index) => <React.Fragment key={stage}><span style={{ color: "#486581" }}>{stage}</span>{index < STAGES.length - 1 && <span style={{ color: "#0F766E" }}>→</span>}</React.Fragment>)}</nav>
    {report?.mockWarning && <p style={{ padding: 12, color: "#854D0E", background: "#FEF3C7" }}>MOCK: {report.mockWarning}</p>}
    {summary && <>
      <p role="status" style={{ ...styles.muted, marginBottom: 16 }}>Scan complete: <b>{report.metadata.scanTarget}</b> · report {scanId} · {summary.real} real findings{runtime && (report.metadata.runtimeProvenance?.available ? ` · runtime: ${report.metadata.runtimeProvenance.events} observations (controlled probe)` : " · runtime: unavailable")}</p>
      <section aria-label="Scan summary" style={styles.metrics}><Metric label="Total findings" value={summary.total} /><Metric label="Critical / high" value={topFindings.length} /><Metric label="Quantum / migration exposure" value={report.riskSummary.moscaExposed} /><Metric label="Algorithm families" value={inventory.length} /><Metric label="Runtime observations" value={runtimeCount} /><Metric label="Migration required" value={requiredCount} color={requiredCount > 0 ? SEV.critical : undefined} />{Object.entries(summary.bySeverity).map(([severity, count]) => <Metric key={severity} label={severity} value={count} color={SEV[severity]} />)}</section>
      <section style={styles.twoColumn}><div style={styles.panel}><p style={styles.kicker}>ALGORITHM INVENTORY</p><h2 style={styles.h2}>{report.metadata.algorithmInventory.join(" · ") || "No crypto artifacts found"}</h2><p style={styles.muted}>Sources: {report.metadata.scannerSources.join(", ")} · {report.metadata.contextProvenance.available ? `CLI context: ${report.metadata.contextProvenance.chars} bounded chars` : "API scan"}</p></div><div style={styles.panel}><p style={styles.kicker}>FIX FIRST</p><h2 style={styles.h2}>{topFindings[0] ? `${topFindings[0].priority} — ${topFindings[0].algorithm}` : "No critical or high findings"}</h2><p style={styles.muted}>{topFindings[0]?.rationale || "Review the complete inventory and exposure horizon."}</p></div></section>
      <section style={styles.panel} aria-label="Finding filters"><div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "end" }}><label style={{ display: "grid", gap: 4, fontSize: 12, fontWeight: 700 }}>Priority<select value={filterPriority} onChange={(e) => setFilterPriority(e.target.value)} aria-label="filter by priority" style={styles.input}><option value="all">All priorities</option><option value="P0">P0</option><option value="P1">P1</option><option value="P2">P2</option><option value="P3">P3</option></select></label><label style={{ display: "grid", gap: 4, fontSize: 12, fontWeight: 700 }}>Scanner<select value={filterScanner} onChange={(e) => setFilterScanner(e.target.value)} aria-label="filter by scanner" style={styles.input}><option value="all">All scanners</option>{(report.metadata.scannerSources || []).map((s) => <option key={s} value={s}>{s}</option>)}</select></label><label style={{ display: "grid", gap: 4, fontSize: 12, fontWeight: 700, flex: 1 }}>Search<input value={query} onChange={(e) => setQuery(e.target.value)} aria-label="search findings" placeholder="algorithm, path, evidence…" style={styles.input} /></label></div><p style={{ ...styles.muted, marginTop: 10 }}>Showing {visible.length} of {report.components.length} findings.</p></section>
      <section style={styles.panel}><p style={styles.kicker}>UNIFIED INVENTORY</p>{inventory.length === 0 ? <p style={styles.muted}>No inventory rows for this scan.</p> : <div style={{ overflowX: "auto" }}><table style={styles.table}><thead><tr><th>Family</th><th>Findings</th><th>Scanners</th><th>Artifacts</th><th>Strength</th><th>Risk</th><th>Runtime</th><th>Recommendation</th></tr></thead><tbody>{inventory.map((row) => <tr key={row.family}><td><b>{row.family}</b><br/><small>{row.algorithms.join(", ")}</small></td><td>{row.findingCount}</td><td><small>{row.scanners.join(", ")}</small></td><td>{row.artifactCount}</td><td>{row.evidenceStrength}</td><td><b style={{ color: SEV[row.severity] }}>{row.priority}</b> <small>{row.severity}</small></td><td>{row.runtimeObserved ? "observed" : "—"}</td><td><small>{row.recommendation}</small></td></tr>)}</tbody></table></div>}</section>
      <section style={styles.panel}><p style={styles.kicker}>ANALYST SUMMARY (DETERMINISTIC)</p><p style={styles.muted}>{summary.total} findings across {inventory.length} families{(migration?.roadmap?.Immediate?.length || 0) > 0 ? `; start with the ${migration.roadmap.Immediate.length} Immediate migration item(s)` : "; no immediate migration items"}{runtimeCount > 0 ? `; ${runtimeCount} controlled runtime observation(s) corroborate static evidence` : "; nothing runtime-observed in this run (not proof of absence)"}. For open-ended questions, use the CLI analyst: <code style={styles.evidence}>agent explain &lt;target&gt; --ask "..."</code>.</p></section>
      <section style={styles.panel}><div style={styles.sectionHead}><div><p style={styles.kicker}>RECOMMENDATIONS</p><h2 style={styles.h2}>Conservative migration guidance</h2></div><button onClick={downloadReport} style={styles.secondary}>Download CBOM-style JSON</button></div><ul style={styles.recommendations}>{report.recommendations.map((item) => <li key={item}>{item}</li>)}</ul><p style={styles.muted}>{report.riskSummary.note}</p></section>
      <section style={styles.panel}><p style={styles.kicker}>FINDING DETAILS / EVIDENCE</p>{visible.length === 0 ? <p style={styles.muted}>{report.components.length === 0 ? "No cryptographic artifacts were detected in the selected text files. This is a completed scan, not a scanner error." : "No findings match the current filters."}</p> : <div style={{ overflowX: "auto" }}><table style={styles.table}><thead><tr><th>Priority</th><th>Finding</th><th>Source</th><th>Evidence</th><th>Risk rationale</th><th>Recommendation</th></tr></thead><tbody>{visible.map((finding) => <React.Fragment key={finding.id}><tr><td><b style={{ color: SEV[finding.severity] }}>{finding.priority}</b><br /><small>{finding.severity}</small><br /><small style={{ color: STATUS_COLOR[finding.migrationStatus] || "#627D98" }}>{shortStatus(finding.migrationStatus)}</small></td><td><button onClick={() => setExpanded(expanded === finding.id ? null : finding.id)} aria-expanded={expanded === finding.id} style={{ background: "none", border: 0, padding: 0, cursor: "pointer", textAlign: "left", font: "inherit", color: "#0F766E", fontWeight: 700 }}>{finding.algorithm}</button><br /><small>{finding.file_path.split("/").slice(-2).join("/")}:{finding.line || "—"} · {finding.usage}</small>{finding.key_size && <><br /><small>{finding.key_size} bits {finding.curve}</small></>}</td><td>{finding.is_mock ? <b style={{ color: "#854D0E" }}>MOCK</b> : "REAL"}<br /><small>{finding.scanner}</small></td><td><code style={styles.evidence}>{finding.evidence || "metadata only"}</code></td><td>{finding.rationale}{finding.correlation?.supports?.length > 0 && <><br /><small>↔ runtime observation supported by {finding.correlation.supports.length} static finding(s)</small></>}<br /><small style={{ color: "#0F766E" }}>{analystLine(finding)}</small></td><td>{finding.recommendation?.recommend}</td></tr>{expanded === finding.id && <tr><td colSpan={6} style={{ background: "#F7FAFC" }}><small><b>Evidence strength:</b> {finding.evidenceStrength || "—"} · <b>Confidence:</b> {finding.confidence} · <b>Status:</b> {finding.migrationStatus || "—"}{finding.signature_algorithm && <>{' '}· <b>Signed:</b> {finding.signature_algorithm}</>}{finding.expires_at && <>{' '}· <b>Expires:</b> {finding.expires_at}</>}</small>{(finding.related || []).length > 0 ? <><br /><small><b>Related evidence:</b></small><ul style={{ margin: "4px 0", paddingLeft: 18 }}>{finding.related.map((rel) => <li key={rel.id}><small>{byId[rel.id] ? `${byId[rel.id].algorithm} · ${byId[rel.id].scanner} · ${byId[rel.id].usage} (${rel.relation})` : `${rel.id} (${rel.relation})`}</small></li>)}</ul></> : <><br /><small>No linked findings in this scan (absence of links is not proof of isolation).</small></>}</td></tr>}</React.Fragment>)}</tbody></table></div>}</section>
      <section style={styles.panel}><p style={styles.kicker}>RELATIONSHIPS</p><p style={styles.muted}>Evidence chains across scanners. Non-observation is never proof of absence.</p>{inventory.filter((row) => row.findingCount > 1 || row.runtimeObserved).map((row) => <div key={row.family} style={{ marginTop: 12 }}><b>{row.family}</b><ul style={{ margin: "4px 0", paddingLeft: 20 }}>{row.findingIds.map((id) => <li key={id}><small>{byId[id] ? `${byId[id].scanner}: ${(byId[id].file_path || "").split("/").slice(-2).join("/")} — ${byId[id].usage}` : id}</small></li>)}<li><small>Runtime: {row.runtimeObserved ? "observed during this run" : "not observed in this run (not proof of absence)"}</small></li></ul></div>)}</section>
      {migration && <section style={styles.panel}><p style={styles.kicker}>MIGRATION WORKSPACE</p><h2 style={styles.h2}>What to migrate first, and why</h2>{["Immediate", "Near-term", "Planned", "Monitor"].map((bucket) => <div key={bucket} style={{ marginTop: 12 }}><b>{bucket} ({(migration.roadmap?.[bucket] || []).length})</b>{(migration.roadmap?.[bucket] || []).map((id) => { const item = (migration.workItems || []).find((w) => w.id === id); return item ? <div key={id} style={{ borderLeft: "3px solid #0F766E", paddingLeft: 12, marginTop: 8 }}><b>{item.priority} — {item.family}</b> <small style={{ color: STATUS_COLOR[item.status] || "#627D98" }}>{shortStatus(item.status)}</small><p style={styles.muted}>{item.reason}</p><p style={{ ...styles.muted, marginTop: 4 }}><b>Direction:</b> {item.direction} · <b>Artifacts:</b> {item.artifactCount}{item.hsmInvolved && " · involves HSM"}{item.cloudInvolved && " · involves cloud"}{item.runtimeObserved && " · runtime-observed"}</p><p style={{ ...styles.muted, marginTop: 4 }}><b>Unknowns:</b> {item.unknowns.join("; ")}</p></div> : null; })}</div>)}<p style={{ ...styles.muted, marginTop: 12 }}><b>Assumptions:</b> {(migration.assumptions || []).join(" · ")}</p></section>}
    </>}
  </main>;
}

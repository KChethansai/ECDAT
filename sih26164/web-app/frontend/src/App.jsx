import React, { useMemo, useState } from "react";

const SEV = { critical: "#b42318", high: "#c2410c", medium: "#a16207", low: "#0f766e" };
const STAGES = ["SCAN", "FINDINGS", "RISK", "PRIORITY", "RECOMMENDATION", "CBOM"];
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

export default function App() {
  const [target, setTarget] = useState("sample");
  const [report, setReport] = useState(null);
  const [scanId, setScanId] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const topFindings = useMemo(() => report?.components.filter((f) => ["critical", "high"].includes(f.severity)) || [], [report]);

  async function runScan(event) {
    event.preventDefault(); setLoading(true); setError(""); setScanId("");
    try {
      const response = await fetch("/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, scanners: ["source"] }) });
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
    <form onSubmit={runScan} style={styles.scanBox}><label style={styles.label}>Scan target<input value={target} onChange={(e) => setTarget(e.target.value)} aria-label="scan target" style={styles.input} placeholder="sample or workspace-contained path" /></label><button disabled={loading} style={styles.button}>{loading ? "Scanning…" : "Run source scan"}</button></form>
    {loading && <p role="status" style={styles.muted}>Scanning real source and configuration files. No code is executed.</p>}
    {error && <p role="alert" style={{ padding: 12, color: SEV.critical, background: "#fff1f0" }}>{error}</p>}
    <nav aria-label="ECDAT analysis flow" style={styles.flow}>{STAGES.map((stage, index) => <React.Fragment key={stage}><span style={{ color: "#486581" }}>{stage}</span>{index < STAGES.length - 1 && <span style={{ color: "#0F766E" }}>→</span>}</React.Fragment>)}</nav>
    {report?.mockWarning && <p style={{ padding: 12, color: "#854D0E", background: "#FEF3C7" }}>MOCK: {report.mockWarning}</p>}
    {summary && <>
      <p role="status" style={{ ...styles.muted, marginBottom: 16 }}>Scan complete: <b>{report.metadata.scanTarget}</b> · report {scanId} · {summary.real} real findings</p>
      <section aria-label="Scan summary" style={styles.metrics}><Metric label="Total findings" value={summary.total} /><Metric label="Critical / high" value={topFindings.length} /><Metric label="Quantum / migration exposure" value={report.riskSummary.moscaExposed} />{Object.entries(summary.bySeverity).map(([severity, count]) => <Metric key={severity} label={severity} value={count} color={SEV[severity]} />)}</section>
      <section style={styles.twoColumn}><div style={styles.panel}><p style={styles.kicker}>ALGORITHM INVENTORY</p><h2 style={styles.h2}>{report.metadata.algorithmInventory.join(" · ") || "No crypto artifacts found"}</h2><p style={styles.muted}>Sources: {report.metadata.scannerSources.join(", ")} · {report.metadata.contextProvenance.available ? `CLI context: ${report.metadata.contextProvenance.chars} bounded chars` : "API scan"}</p></div><div style={styles.panel}><p style={styles.kicker}>FIX FIRST</p><h2 style={styles.h2}>{topFindings[0] ? `${topFindings[0].priority} — ${topFindings[0].algorithm}` : "No critical or high findings"}</h2><p style={styles.muted}>{topFindings[0]?.rationale || "Review the complete inventory and exposure horizon."}</p></div></section>
      <section style={styles.panel}><div style={styles.sectionHead}><div><p style={styles.kicker}>RECOMMENDATIONS</p><h2 style={styles.h2}>Conservative migration guidance</h2></div><button onClick={downloadReport} style={styles.secondary}>Download CBOM-style JSON</button></div><ul style={styles.recommendations}>{report.recommendations.map((item) => <li key={item}>{item}</li>)}</ul><p style={styles.muted}>{report.riskSummary.note}</p></section>
      <section style={styles.panel}><p style={styles.kicker}>FINDING DETAILS / EVIDENCE</p>{report.components.length === 0 ? <p style={styles.muted}>No cryptographic artifacts were detected in the selected text files. This is a completed scan, not a scanner error.</p> : <div style={{ overflowX: "auto" }}><table style={styles.table}><thead><tr><th>Priority</th><th>Finding</th><th>Source</th><th>Evidence</th><th>Risk rationale</th><th>Recommendation</th></tr></thead><tbody>{report.components.map((finding) => <tr key={finding.id}><td><b style={{ color: SEV[finding.severity] }}>{finding.priority}</b><br/><small>{finding.severity}</small></td><td><b>{finding.algorithm}</b><br/><small>{finding.file_path.split("/").slice(-2).join("/")}:{finding.line || "—"} · {finding.usage}</small>{finding.key_size && <><br/><small>{finding.key_size} bits {finding.curve}</small></>}</td><td>{finding.is_mock ? <b style={{ color: "#854D0E" }}>MOCK</b> : "REAL"}</td><td><code style={styles.evidence}>{finding.evidence || "metadata only"}</code></td><td>{finding.rationale}</td><td>{finding.recommendation?.recommend}</td></tr>)}</tbody></table></div>}</section>
    </>}
  </main>;
}

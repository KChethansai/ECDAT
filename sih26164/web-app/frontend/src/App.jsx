import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Header from "./components/Header.jsx";
import ScanCommandBar from "./components/ScanCommandBar.jsx";
import { ExecutiveMetrics, ExposurePanel, FixFirstCard, RiskOverview } from "./components/Metrics.jsx";
import InventoryTable from "./components/InventoryTable.jsx";
import FindingsExplorer from "./components/FindingsExplorer.jsx";
import FindingDrawer from "./components/FindingDrawer.jsx";
import MigrationWorkspace from "./components/MigrationWorkspace.jsx";
import { AnalystSummary, ExportPanel, RecommendationsList, RelationshipsSection } from "./components/RecommendationsPanel.jsx";
import Pipeline from "./components/Pipeline.jsx";
import { EmptyState, ErrorState, LoadingStages, SCAN_STAGES } from "./components/States.jsx";
import { FALLBACK_SCANNERS, arr, downloadJson, formatNetworkError, formatScanError, num, obj, str, unknownsCount } from "./lib/report.js";

export default function App() {
  const [target, setTarget] = useState("sample");
  const [runtime, setRuntime] = useState(false);
  const [report, setReport] = useState(null);
  const [scanId, setScanId] = useState("");
  const [scannedTarget, setScannedTarget] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState(0);
  const [health, setHealth] = useState({ state: "UNKNOWN" });
  const [query, setQuery] = useState("");
  const [filterPriority, setFilterPriority] = useState("all");
  const [filterScanner, setFilterScanner] = useState("all");
  const [selected, setSelected] = useState(null);
  const targetRef = useRef(null);
  const stageTimer = useRef(null);

  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch("/health");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setHealth({
        state: body && body.ok ? "CONNECTED" : "DEGRADED",
        probe: body?.runtimeProbe,
        scanners: Array.isArray(body?.scanners) ? body.scanners : undefined,
      });
    } catch {
      setHealth((h) => ({ ...h, state: "OFFLINE" }));
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const t = setInterval(checkHealth, 30000);
    return () => clearInterval(t);
  }, [checkHealth]);

  useEffect(() => {
    if (!loading) return undefined;
    setStage(0);
    stageTimer.current = setInterval(() => {
      setStage((s) => (s < SCAN_STAGES.length - 1 ? s + 1 : s));
    }, 850);
    return () => clearInterval(stageTimer.current);
  }, [loading]);

  // Keep drawer selection in sync with the current report; drop stale ids.
  useEffect(() => {
    if (!report || !selected) return;
    const stillThere = arr(report.components).some((f) => f.id === selected.id);
    if (!stillThere) setSelected(null);
  }, [report, selected]);

  const components = useMemo(() => arr(report?.components), [report]);
  const inventory = useMemo(() => arr(report?.intelligence?.inventory), [report]);
  const migration = report?.migration || null;
  const byId = useMemo(() => Object.fromEntries(components.map((f) => [f.id, f])), [components]);
  const summary = obj(report?.summary);

  const criticallyHigh = useMemo(() => components.filter((f) => f.severity === "critical" || f.severity === "high").length, [components]);
  const runtimeCount = useMemo(() => components.filter((f) => f.scanner === "runtime").length, [components]);
  const immediateCount = useMemo(() => arr(obj(migration?.roadmap).Immediate).length, [migration]);
  const candidateCount = useMemo(() => arr(migration?.workItems).length, [migration]);
  const unknownTotal = useMemo(() => unknownsCount(migration), [migration]);
  const topFinding = useMemo(() => components.find((f) => f.severity === "critical" || f.severity === "high") || null, [components]);

  const scannerSources = useMemo(() => {
    const fromReport = arr(report?.metadata?.scannerSources);
    if (fromReport.length > 0) return fromReport;
    return [];
  }, [report]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return components.filter(
      (f) =>
        (filterPriority === "all" || f.priority === filterPriority) &&
        (filterScanner === "all" || f.scanner === filterScanner) &&
        (q === "" || `${str(f.algorithm)} ${str(f.file_path)} ${str(f.evidence)} ${str(f.library)} ${str(f.usage)}`.toLowerCase().includes(q)),
    );
  }, [components, filterPriority, filterScanner, query]);

  const activeFilters = useMemo(() => {
    const out = [];
    if (filterPriority !== "all") out.push(`priority ${filterPriority}`);
    if (filterScanner !== "all") out.push(`scanner ${filterScanner}`);
    if (query.trim() !== "") out.push(`“${query.trim()}”`);
    return out;
  }, [filterPriority, filterScanner, query]);

  const clearFilters = useCallback(() => {
    setFilterPriority("all");
    setFilterScanner("all");
    setQuery("");
  }, []);

  async function runScan(event) {
    event?.preventDefault();
    const cleanTarget = target.trim() || "sample";
    setLoading(true);
    setError("");
    try {
      const known = Array.isArray(health.scanners) && health.scanners.length > 0 ? health.scanners.filter((s) => s !== "runtime") : FALLBACK_SCANNERS;
      const response = await fetch("/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: cleanTarget, scanners: known, runtime }),
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(formatScanError(response.status, text));
      }
      const body = await response.json();
      setReport(body.report || null);
      setScanId(str(body.id, ""));
      setScannedTarget(str(body.report?.metadata?.scanTarget, cleanTarget));
      setSelected(null);
      checkHealth();
    } catch (err) {
      setError(err instanceof Error ? err.message : formatNetworkError(err));
    } finally {
      setLoading(false);
    }
  }

  function handleDownload() {
    if (!report) return;
    downloadJson(report, `ecdat-cbom-style-${scanId || "report"}.json`);
  }

  const runtimeProv = obj(report?.metadata?.runtimeProvenance);
  const hasReport = Boolean(report && summary);

  return (
    <>
      <a className="skip-link" href="#findings">
        Skip to findings
      </a>
      <div className="page">
        <header>
          <Header health={health} scanId={scanId} onExport={handleDownload} canExport={Boolean(report)} />
        </header>
        <main id="main">
          <div className="hero">
            <p className="eyebrow">CRYPTOGRAPHIC SECURITY INTELLIGENCE</p>
            <h1 className="h-display">
              Understand your <span className="accent">cryptographic exposure.</span>
            </h1>
            <p className="lede">Discover algorithms, assess quantum risk, prioritize migration, and generate machine-readable cryptographic inventory.</p>
            <div className="hero-facts" aria-label="Current scan context">
              <span className="fact">
                target <b className="mono">{hasReport ? scannedTarget : target.trim() || "sample"}</b>
              </span>
              {hasReport ? (
                <span className="fact">
                  <b>{num(summary.total)}</b>&nbsp;finding(s) · <b>{num(summary.real)}</b>&nbsp;real
                </span>
              ) : (
                <span className="fact">no report yet</span>
              )}
              <span className={`fact${runtime && hasReport && !runtimeProv.available ? " warn" : ""}`}>
                runtime:{" "}
                <b>
                  {hasReport
                    ? runtimeProv.available
                      ? `${runtimeProv.events || 0} controlled observation(s)`
                      : runtime
                        ? "requested, unavailable"
                        : "not run"
                    : runtime
                      ? "probe will run"
                      : "static only"}
                </b>
              </span>
            </div>
          </div>

          <ScanCommandBar target={target} onTarget={setTarget} runtime={runtime} onRuntime={setRuntime} loading={loading} onSubmit={runScan} targetRef={targetRef} />
          <Pipeline hasReport={hasReport} loading={loading} />

          {loading ? <LoadingStages active={stage} runtime={runtime} /> : null}
          <ErrorState message={error} onRetry={() => targetRef.current?.focus()} />
          {loading && hasReport ? (
            <p className="alert alert-stale" role="status">
              Scanning — showing the previous report below. It will be replaced when the new scan completes.
            </p>
          ) : null}
          {report?.mockWarning ? <p className="alert alert-mock">MOCK: {report.mockWarning}</p> : null}

          {!hasReport && !loading ? (
            <EmptyState
              title="READY TO SCAN"
              body={
                <>
                  Run a scan to populate risk intelligence, inventory, findings, relationships and migration planning. Try target <code>sample</code> for the
                  bundled vulnerable fixture, or tick the runtime probe for 6 controlled observations.
                </>
              }
              hint="Every number on this page is derived from the live report — nothing is hardcoded."
            />
          ) : null}

          {hasReport ? (
            <div className={loading ? "dimmed" : undefined} aria-busy={loading}>
              <p role="status" className="section-sub" style={{ marginTop: 16 }}>
                Scan complete: <b style={{ color: "var(--text)" }}>{str(report.metadata?.scanTarget, scannedTarget)}</b>
                {scanId ? (
                  <>
                    {" "}· report <span className="mono" style={{ fontSize: 12 }}>{scanId}</span>
                  </>
                ) : null}{" "}
                · {num(summary.real)} real finding(s)
                {runtimeProv.available ? ` · runtime: ${runtimeProv.events || 0} observation(s) (controlled probe)` : runtime ? " · runtime: unavailable" : ""} ·
                sources: {arr(report.metadata?.scannerSources).join(", ") || "—"}
              </p>

              <div className="section">
                <ExecutiveMetrics
                  report={report}
                  criticallyHigh={criticallyHigh}
                  runtimeCount={runtimeCount}
                  immediateCount={immediateCount}
                  familyCount={inventory.length}
                  candidateCount={candidateCount}
                  unknownCount={unknownTotal}
                />
              </div>

              <RiskOverview report={report} components={components} />

              <div className="section">
                <div className="grid two-col">
                  <FixFirstCard finding={topFinding} runtimeAvailable={Boolean(runtimeProv.available)} />
                  <ExposurePanel report={report} components={components} />
                </div>
              </div>

              <InventoryTable inventory={inventory} />
              <AnalystSummary report={report} familyCount={inventory.length} runtimeCount={runtimeCount} immediateCount={immediateCount} total={num(summary.total)} />

              <div id="findings">
                <FindingsExplorer
                  components={components}
                  visible={visible}
                  total={components.length}
                  filterPriority={filterPriority}
                  onPriority={setFilterPriority}
                  filterScanner={filterScanner}
                  onScanner={setFilterScanner}
                  scannerSources={scannerSources.length > 0 ? scannerSources : Array.from(new Set(components.map((f) => f.scanner)))}
                  query={query}
                  onQuery={setQuery}
                  onClear={clearFilters}
                  activeFilters={activeFilters}
                  onOpen={setSelected}
                />
              </div>

              <RelationshipsSection inventory={inventory} byId={byId} />
              <MigrationWorkspace migration={migration} />
              <RecommendationsList components={components} />
              <ExportPanel report={report} scanId={scanId} onDownload={handleDownload} />
            </div>
          ) : null}

          <footer className="foot">
            ECDAT deterministic engine: static presence ≠ runtime use · no runtime observation ≠ proof of absence · cloud/HSM are static-configuration evidence only
            · Mosca is a migration-readiness heuristic, not a quantum-arrival prediction · ML-KEM is not a drop-in for every HSM.
          </footer>
        </main>
      </div>
      <FindingDrawer finding={selected} byId={byId} onClose={() => setSelected(null)} />
    </>
  );
}

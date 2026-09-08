import React, { useState } from "react";
import { exportFacts } from "../lib/report.js";
import { scanTargetLabel } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import { ExportPanel } from "../components/RecommendationsPanel.jsx";
import { SectionEmpty } from "../components/States.jsx";
import { PageHead } from "./_shared.jsx";

export default function Reports() {
  const { report, scanId, scannedTarget, downloadReport, downloadSarif, loadReportById } = useStore();
  const [rid, setRid] = useState("");
  const [notice, setNotice] = useState("");

  async function openById(event) {
    event?.preventDefault();
    const id = rid.trim();
    if (!id) return;
    setNotice("");
    const result = await loadReportById(id);
    if (result.ok) {
      window.location.hash = "#/dashboard";
    } else {
      setNotice("Unknown report id — reports are in-memory and disappear on backend restart or eviction (last 50 kept).");
    }
  }

  async function sarif() {
    const result = await downloadSarif();
    if (!result.ok) setNotice("SARIF download failed — see the error above.");
  }

  return (
    <>
      <PageHead eyebrow="REPORTS & EXPORTS" title="Reports" sub="Every action below is wired to real data. Nothing is generated from placeholders." />
      {!report ? (
        <div className="card">
          <SectionEmpty>
            No current report. Run a scan, or open a known in-memory report by ID below.
          </SectionEmpty>
        </div>
      ) : (
        <>
          <div className="card" aria-label="Current report">
            <p className="eyebrow">CURRENT REPORT</p>
            <p>
              <b className="mono">{scanTargetLabel(report, scannedTarget)}</b>
              {" "}· report <b className="mono">{scanId}</b>
              {" "}· {exportFacts(report, scanId).findings} findings · {exportFacts(report, scanId).families} families
            </p>
            <div className="export-actions">
              <button type="button" className="btn btn-secondary" onClick={downloadReport}>Download CBOM JSON</button>
              <button type="button" className="btn btn-secondary" onClick={sarif}>Download SARIF 2.1.0</button>
            </div>
          </div>
          <ExportPanel report={report} scanId={scanId} onDownload={downloadReport} />
        </>
      )}
      <div className="card" aria-label="Open report by ID">
        <p className="eyebrow">OPEN BY REPORT ID</p>
        <form onSubmit={openById}>
          <div className="cmdbar-body" style={{ padding: 0 }}>
            <label className="field grow" htmlFor="report-id">
              In-memory report ID
              <input id="report-id" value={rid} onChange={(e) => setRid(e.target.value)} placeholder="e.g. 20a2ba00346a" autoComplete="off" spellCheck="false" className="mono" />
            </label>
            <button type="submit" className="btn btn-secondary">Open report</button>
          </div>
        </form>
        {notice ? <p role="alert" className="alert alert-error">{notice}</p> : null}
      </div>
    </>
  );
}

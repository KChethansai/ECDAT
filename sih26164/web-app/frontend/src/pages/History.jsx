import React, { useState } from "react";
import { useStore } from "../store.jsx";
import HistoryPanel from "../components/HistoryPanel.jsx";
import { PageHead } from "./_shared.jsx";

export default function History() {
  const { sessionScans, loadReportById, scanId } = useStore();
  const [notice, setNotice] = useState("");

  async function open(id) {
    setNotice("");
    const result = await loadReportById(id);
    if (result.ok) {
      window.location.hash = "#/dashboard";
    } else {
      setNotice("That report is no longer in backend memory (reports are in-memory: restart or eviction clears them). Re-run the scan to reproduce it deterministically.");
    }
  }

  return (
    <>
      <PageHead eyebrow="SCAN HISTORY" title="History" sub="Server history covers repository scans; this session lists every scan run from this browser." />
      {notice ? <p role="alert" className="alert alert-error">{notice}</p> : null}
      <div className="card" aria-label="This session">
        <p className="eyebrow">THIS SESSION (THIS BROWSER)</p>
        {sessionScans.length === 0 ? (
          <p className="cell-sub">No scans run yet in this session.</p>
        ) : (
          <ul>
            {sessionScans.map((s, i) => (
              <li key={`${s.at}-${i}`}>
                <span className="mono">{s.target}</span> · {s.ok ? (s.total ?? "done") + (typeof s.total === "number" ? " finding(s)" : "") : "failed"} ·{" "}
                <span className="cell-sub">{s.at ? new Date(s.at).toLocaleString() : ""}</span>
                {s.id ? (
                  <> · {s.id === scanId ? <b>current</b> : <button type="button" className="row-button" onClick={() => open(s.id)}>Open</button>}</>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>
      <HistoryPanel onOpen={open} />
      <p className="section-sub">
        History entries are compact counts held in backend memory (newest {100} kept; restart clears them).
        Deltas compare two in-memory reports by stable finding identity — never by array position.
      </p>
    </>
  );
}

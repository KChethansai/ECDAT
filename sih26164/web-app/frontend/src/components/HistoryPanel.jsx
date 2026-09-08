import React, { useCallback, useState } from "react";
import { arr, num, obj, str } from "../lib/report.js";

function fmtTime(ts) {
  try {
    return new Date(num(ts) * 1000).toLocaleString();
  } catch {
    return "—";
  }
}

export default function HistoryPanel({ onOpen }) {
  const [open, setOpen] = useState(false);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState([]);
  const [delta, setDelta] = useState(null);

  const load = useCallback(async () => {
    setError("");
    try {
      const res = await fetch("/scan-history");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setHistory(arr(body.history));
      setOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  function toggle(id) {
    setSelected((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev.slice(-1), id]));
  }

  async function compare() {
    if (selected.length !== 2) return;
    setError("");
    setDelta(null);
    try {
      const res = await fetch("/scan-delta", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ before: selected[0], after: selected[1] }),
      });
      if (!res.ok) throw new Error(await res.text());
      setDelta(await res.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="section" aria-label="Scan history">
      <div className="section-head">
        <h2>Scan history</h2>
        <div className="section-actions">
          <button type="button" className="btn btn-secondary" onClick={load}>
            {open ? "Refresh" : "View history"}
          </button>
          {open ? (
            <button type="button" className="btn btn-secondary" onClick={() => setOpen(false)}>
              Hide
            </button>
          ) : null}
        </div>
      </div>
      {error ? <p className="alert">{error}</p> : null}
      {open ? (
        history.length === 0 ? (
          <p className="section-sub">No repository scans recorded yet in this session.</p>
        ) : (
          <>
            <div>
              {history.map((h) => (
                <label key={h.scan_id} className="check" style={{ display: "block" }}>
                  <input type="checkbox" checked={selected.includes(h.scan_id)} onChange={() => toggle(h.scan_id)} />
                  <span className="mono">{str(h.repo)}@{(str(h.sha) || "").slice(0, 12)}</span>
                  {" "}· {str(h.profile)} · {fmtTime(h.timestamp)} · crypto {num(h.counts?.crypto)} / code {num(h.counts?.code)}
                  {onOpen ? (
                    <>
                      {" "}
                      <button type="button" className="row-button" onClick={() => onOpen(h.scan_id)} title="Load this report as the current report">
                        Open
                      </button>
                    </>
                  ) : null}
                </label>
              ))}
            </div>
            <button type="button" className="btn" disabled={selected.length !== 2} onClick={compare} title="Select two scans to compare">
              Compare selected
            </button>
            {delta ? (
              <div style={{ marginTop: 8 }}>
                <p><b>Delta:</b> {num(delta.summary?.new)} new · {num(delta.summary?.resolved)} resolved ·{" "}
                  {num(delta.summary?.unchanged)} unchanged · {num(delta.summary?.changed)} changed ·{" "}
                  {num(delta.summary?.regressions)} regression(s) ·{" "}
                  {num(delta.summary?.new_critical)} new critical · {num(delta.summary?.resolved_critical)} resolved critical</p>
                {["new", "resolved", "changed", "regressions"].map((key) => (
                  arr(delta[key]).length > 0 ? (
                    <div key={key}>
                      <p><b>{key}</b> ({arr(delta[key]).length})</p>
                      <ul>
                        {arr(delta[key]).slice(0, 30).map((e) => (
                          <li key={`${key}-${e.id}`}>
                            {key === "regressions" ? (
                              <><span className="mono">{str(e.id).slice(0, 24)}</span> · {str(e.kind)} · severity {str(e.before)} → <b>{str(e.after)}</b></>
                            ) : (
                              <><span className="mono">{str(e.title).slice(0, 80)}</span> · {str(e.kind)} ·{" "}
                              <code className="evidence">{str(e.file_path).slice(0, 100)}</code></>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null
                ))}
              </div>
            ) : null}
          </>
        )
      ) : null}
    </div>
  );
}

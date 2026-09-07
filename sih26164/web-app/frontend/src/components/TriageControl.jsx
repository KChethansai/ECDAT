import React, { useState } from "react";
import { obj, str } from "../lib/report.js";

const REASONS = ["false-positive", "intentional-architecture", "accepted-risk", "not-applicable", "duplicate", "deferred", "other"];

export default function TriageControl({ scope, fp, current, onSaved }) {
  const [status, setStatus] = useState(str(obj(current).status, "open"));
  const [reason, setReason] = useState(str(obj(current).reason));
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  if (!scope || !fp) return null;

  async function save() {
    setError("");
    setSaved(false);
    try {
      const res = await fetch("/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scope, fingerprint: fp, status, reason }),
      });
      if (!res.ok) throw new Error(await res.text());
      setSaved(true);
      if (onSaved) onSaved({ status, reason });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div>
      <b>Triage (workflow only — never changes evidence or risk):</b>{" "}
      <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Triage status">
        {["open", "reviewed", "suppressed", "resolved"].map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>{" "}
      {status === "suppressed" ? (
        <select value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Suppression reason (required)">
          <option value="">— reason required —</option>
          {REASONS.map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>
      ) : null}{" "}
      <button type="button" className="btn btn-secondary" onClick={save}>Save triage</button>
      {saved ? <span> saved.</span> : null}
      {error ? <p className="alert">{error}</p> : null}
    </div>
  );
}

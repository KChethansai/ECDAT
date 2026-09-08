import React from "react";
import { useStore } from "../store.jsx";
import { PageHead } from "./_shared.jsx";

export default function Settings() {
  const { prefs, setPrefs, health, checkHealth } = useStore();
  return (
    <>
      <PageHead eyebrow="PRODUCT SETTINGS" title="Settings" sub="Interface preferences only. Nothing here changes scanning, risk, or security behavior." />
      <div className="card" aria-label="Appearance">
        <p className="eyebrow">APPEARANCE</p>
        <label className="check" htmlFor="set-density" style={{ display: "flex", marginBottom: 8 }}>
          <input id="set-density" type="checkbox" checked={prefs.density === "compact"} onChange={(e) => setPrefs({ density: e.target.checked ? "compact" : "comfortable" })} />
          compact density (tighter spacing)
        </label>
        <label className="check" htmlFor="set-motion" style={{ display: "flex", marginBottom: 8 }}>
          <input id="set-motion" type="checkbox" checked={prefs.motion === "reduced"} onChange={(e) => setPrefs({ motion: e.target.checked ? "reduced" : "full" })} />
          reduced motion (disables non-essential animation)
        </label>
        <p className="cell-sub">Stored only in this browser (localStorage). Backend state is untouched.</p>
      </div>
      <div className="card" aria-label="Backend connection">
        <p className="eyebrow">BACKEND CONNECTION</p>
        <p>
          API status: <b>{health.state}</b>
          {health.probe ? <> · runtime probe {health.probe}</> : null}
          {health.scanners ? <> · {health.scanners.length} scanner(s) registered</> : null}
        </p>
        <button type="button" className="btn btn-secondary" onClick={checkHealth}>Re-check now</button>
        <p className="cell-sub">The UI talks to the API same-origin (Vite dev proxy or same-host deploy). Health re-checks automatically every 30 seconds.</p>
      </div>
    </>
  );
}

import React, { useEffect, useState } from "react";
import { href } from "../lib/router.js";
import { immediateCount, migration } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import { IconBox, IconClock, IconCompass, IconDoc, IconDownload, IconEvidence, IconGauge, IconGear, IconMenu, IconMigrate, IconPulse, IconScan, IconShield, IconX } from "./icons.jsx";

const NAV = [
  { name: "dashboard", label: "Dashboard", icon: IconGauge },
  { name: "scan", label: "Scan", icon: IconScan },
  { name: "findings", label: "Findings", icon: IconEvidence, needsReport: true, badge: (s) => (s.report ? String(s.report.summary?.total ?? s.report.components?.length ?? "") : "") },
  { name: "inventory", label: "Inventory", icon: IconBox, needsReport: true },
  { name: "risk", label: "Risk & Exposure", icon: IconPulse, needsReport: true },
  { name: "migration", label: "Migration", icon: IconMigrate, needsReport: true, badge: (s) => { const n = s.report ? immediateCount(migration(s.report)) : 0; return n > 0 ? String(n) : ""; } },
  { name: "code", label: "Code Intel", icon: IconCompass, needsReport: true },
  { name: "validation", label: "Validation", icon: IconShield, needsReport: true },
  { name: "history", label: "History", icon: IconClock, badge: (s) => (s.sessionScans.length > 0 ? String(s.sessionScans.length) : "") },
  { name: "knowledge", label: "Knowledge", icon: IconDoc, needsReport: true },
  { name: "reports", label: "Reports", icon: IconDownload, badge: (s) => (s.scanId ? "●" : "") },
  { name: "settings", label: "Settings", icon: IconGear },
];

function HealthPill({ health }) {
  const state = health?.state || "UNKNOWN";
  const detail =
    state === "OFFLINE" ? "API unreachable"
    : state === "CONNECTED" ? `API connected${health?.probe === "missing" ? " · probe missing" : ""}`
    : state === "DEGRADED" ? "API degraded · probe missing"
    : "Checking API…";
  return (
    <span className="health" data-state={state} role="status" title={detail}>
      <span className="dot" aria-hidden="true" />
      {state}
    </span>
  );
}

export default function Shell({ route, error, onExport, canExport, children }) {
  const store = useStore();
  const { prefs, setPrefs, health, scanId, scannedTarget, loading } = store;
  const collapsed = prefs.sidebar === "closed";
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") setMobileOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  function toggleNav() {
    const mobile = typeof window !== "undefined" && window.matchMedia("(max-width: 900px)").matches;
    if (mobile) setMobileOpen((v) => !v);
    else setPrefs({ sidebar: collapsed ? "open" : "closed" });
  }

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <div className={`shell${collapsed ? " sidebar-collapsed" : ""}${mobileOpen ? " drawer-open" : ""}`}>
        <aside className="sidebar" aria-label="Primary navigation" id="sidebar">
          <div className="sidebar-brand">
            <span className="brand-mark" aria-hidden="true">
              <IconShield size={18} />
            </span>
            <span className="sidebar-brand-text">
              <span className="brand-name">ECDAT</span>
              <span className="brand-sub">Crypto Security Intel</span>
            </span>
          </div>
          <nav aria-label="Sections" onClick={() => setMobileOpen(false)}>
            <ul className="nav-list">
              {NAV.map((item) => {
                const Icon = item.icon;
                const active = route.name === item.name;
                const badge = item.badge ? item.badge(store) : "";
                // Dimmed, never disabled: the link still works and lands on a
                // "run a scan first" prompt instead of a blank page.
                const awaitingReport = Boolean(item.needsReport) && !store.hasReport;
                return (
                  <li key={item.name}>
                    <a
                      href={href(item.name)}
                      className={`nav-item${active ? " active" : ""}${awaitingReport ? " needs-report" : ""}`}
                      aria-current={active ? "page" : undefined}
                      title={awaitingReport ? `${item.label} — run a scan first` : collapsed ? item.label : undefined}
                    >
                      <span className="nav-icon" aria-hidden="true">
                        <Icon size={16} />
                      </span>
                      <span className="nav-label">{item.label}</span>
                      {badge ? (
                        <span className="nav-badge" aria-label={`${item.label}: ${badge}`}>
                          {badge}
                        </span>
                      ) : null}
                    </a>
                  </li>
                );
              })}
            </ul>
          </nav>
          <div className="sidebar-foot">
            <HealthPill health={health} />
          </div>
        </aside>
        {mobileOpen ? (
          <div className="overlay nav-overlay" onClick={() => setMobileOpen(false)} aria-hidden="true" />
        ) : null}
        <div className="shell-main">
          <div className="topbar">
            <div className="topbar-left">
              <button
                type="button"
                className="icon-btn"
                aria-label="Toggle navigation"
                aria-expanded={mobileOpen || !collapsed}
                aria-controls="sidebar"
                onClick={toggleNav}
              >
                {collapsed ? <IconMenu size={16} /> : <IconX size={15} />}
              </button>
              <span className="topbar-context">
                {scannedTarget ? (
                  <>
                    target <b className="mono">{scannedTarget}</b>
                  </>
                ) : (
                  <span className="topbar-idle">No scan yet — start from Scan</span>
                )}
                {scanId ? (
                  <>
                    {" "}· report <b className="mono">{scanId}</b>
                  </>
                ) : null}
                {loading ? (
                  <>
                    {" "}· <span className="topbar-working" role="status">working…</span>
                  </>
                ) : null}
              </span>
            </div>
            <div className="topbar-meta">
              <HealthPill health={health} />
              <button type="button" className="btn-ghost btn" onClick={onExport} disabled={!canExport} title={canExport ? "Download the current report as CBOM-style JSON" : "Run a scan first"}>
                <IconDownload size={14} />
                Export
              </button>
            </div>
          </div>
          {error ? (
            <p role="alert" className="alert alert-error shell-alert">
              <b>Error. </b>
              {error}
            </p>
          ) : null}
          <main id="main" tabIndex={-1}>
            {children}
          </main>
          <footer className="foot">
            ECDAT deterministic engine: static presence ≠ runtime use · no runtime observation ≠ proof of absence · cloud/HSM are static-configuration evidence only
            · Mosca is a migration-readiness heuristic, not a quantum-arrival prediction · ML-KEM is not a drop-in for every HSM.
          </footer>
        </div>
      </div>
    </>
  );
}

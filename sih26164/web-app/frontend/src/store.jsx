/* Central application store: shell prefs, scan lifecycle, current report.
   Scan-form inputs live in the Scan page; page filters live in their pages
   (remounted per report via key={scanId}). No invented state: everything
   derives from health checks and real API responses. */

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "./lib/api.js";
import { FALLBACK_SCANNERS, downloadJson, str } from "./lib/report.js";

const StoreContext = createContext(null);

const PREFS_KEY = "ecdat-ui-prefs-v1";

function loadPrefs() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return { density: "comfortable", motion: "full", sidebar: "open" };
    const p = JSON.parse(raw);
    return {
      density: p.density === "compact" ? "compact" : "comfortable",
      motion: p.motion === "reduced" ? "reduced" : "full",
      sidebar: p.sidebar === "closed" ? "closed" : "open",
    };
  } catch {
    return { density: "comfortable", motion: "full", sidebar: "open" };
  }
}

export function AppProvider({ children }) {
  const [prefs, setPrefsState] = useState(loadPrefs);
  const [health, setHealth] = useState({ state: "UNKNOWN" });
  const [report, setReport] = useState(null);
  const [scanId, setScanId] = useState("");
  const [scannedTarget, setScannedTarget] = useState("");
  const [scanSource, setScanSource] = useState("local");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [sessionScans, setSessionScans] = useState([]);
  const abortRef = useRef(null);

  const setPrefs = useCallback((patch) => {
    setPrefsState((prev) => {
      const next = { ...prev, ...patch };
      try {
        localStorage.setItem(PREFS_KEY, JSON.stringify(next));
      } catch {
        /* private mode: prefs simply don't persist */
      }
      return next;
    });
  }, []);

  useEffect(() => {
    document.documentElement.dataset.density = prefs.density;
    document.documentElement.dataset.motion = prefs.motion;
  }, [prefs]);

  const checkHealth = useCallback(async () => {
    try {
      const body = await api.health();
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

  const applyResponse = useCallback((body, fallbackTarget) => {
    setReport(body.report || null);
    setScanId(str(body.id, ""));
    setScannedTarget(str(body.report?.metadata?.scanTarget, fallbackTarget));
  }, []);

  const runScan = useCallback(async (form) => {
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const startedAt = Date.now();
    setElapsed(0);
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - startedAt) / 1000)), 1000);
    setLoading(true);
    setError("");
    try {
      const response = await api.createScan(form.payload, controller.signal);
      applyResponse(response, form.fallbackTarget);
      setScanSource(form.isGithub ? "github" : "local");
      setSessionScans((prev) =>
        [{ id: str(response.id, ""), target: form.fallbackTarget, at: new Date().toISOString(),
           total: response.report?.summary?.total ?? null, ok: true },
        ...prev].slice(0, 20),
      );
      checkHealth();
      return { ok: true, id: str(response.id, "") };
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        setError("Scan cancelled in the browser. The server may still finish; no state was saved locally.");
      } else {
        setError(err instanceof ApiError || err instanceof Error ? err.message : String(err));
      }
      setSessionScans((prev) =>
        [{ id: "", target: form.fallbackTarget, at: new Date().toISOString(), total: null, ok: false },
        ...prev].slice(0, 20),
      );
      return { ok: false };
    } finally {
      clearInterval(timer);
      setLoading(false);
    }
  }, [applyResponse, checkHealth]);

  const cancelScan = useCallback(() => {
    if (abortRef.current) abortRef.current.abort();
  }, []);

  const refreshReport = useCallback(async () => {
    if (!scanId) return { ok: false };
    try {
      const body = await api.getReport(scanId);
      setReport(body || null);
      return { ok: true };
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : String(err));
      return { ok: false };
    }
  }, [scanId]);

  const loadReportById = useCallback(async (rid) => {
    setError("");
    try {
      const body = await api.getReport(rid);
      setReport(body || null);
      setScanId(rid);
      setScannedTarget(str(body?.metadata?.scanTarget, rid));
      setScanSource(body?.source?.type === "github" ? "github" : "local");
      return { ok: true };
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : String(err));
      return { ok: false };
    }
  }, []);

  const clearError = useCallback(() => setError(""), []);

  const downloadReport = useCallback(() => {
    if (!report) return false;
    return downloadJson(report, `ecdat-cbom-style-${scanId || "report"}.json`);
  }, [report, scanId]);

  const downloadSarif = useCallback(async () => {
    if (!report || !scanId) return { ok: false };
    setError("");
    try {
      const sarif = await api.getSarif(scanId);
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = `ecdat-${scanId}.sarif`;
        document.body.appendChild(link);
        link.click();
        link.remove();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      return { ok: true };
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : String(err));
      return { ok: false };
    }
  }, [report, scanId]);

  const value = useMemo(() => ({
    prefs, setPrefs, health, checkHealth, report, scanId, scannedTarget,
    scanSource, error, loading, elapsed, sessionScans,
    runScan, cancelScan, refreshReport, loadReportById, clearError,
    downloadReport, downloadSarif,
    hasReport: Boolean(report),
  }), [prefs, setPrefs, health, checkHealth, report, scanId, scannedTarget,
    scanSource, error, loading, elapsed, sessionScans,
    runScan, cancelScan, refreshReport, loadReportById, clearError,
    downloadReport, downloadSarif]);

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}

export function useStore() {
  const ctx = useContext(StoreContext);
  if (!ctx) throw new Error("useStore must be used inside AppProvider");
  return ctx;
}

export { FALLBACK_SCANNERS };

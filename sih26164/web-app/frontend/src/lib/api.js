/* Centralized API access for every frontend fetch (see API table in docs).
   All calls are same-origin (Vite dev proxy or same-host deploy). Errors are
   human-readable via formatScanError; aborts propagate as AbortError. */

import { formatNetworkError, formatScanError } from "./report.js";

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function apiFetch(path, { method = "GET", body, signal } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") throw err;
    throw new ApiError(0, formatNetworkError(err));
  }
  if (!res.ok) {
    let text = "";
    try {
      text = await res.text();
    } catch {
      text = "";
    }
    throw new ApiError(res.status, formatScanError(res.status, text));
  }
  try {
    return await res.json();
  } catch {
    throw new ApiError(res.status, "Backend returned a malformed response.");
  }
}

export const api = {
  health: (signal) => apiFetch("/health", { signal }),
  createScan: (payload, signal) => apiFetch("/scans", { method: "POST", body: payload, signal }),
  getReport: (rid, signal) => apiFetch(`/reports/${encodeURIComponent(rid)}`, { signal }),
  getSarif: (rid, signal) => apiFetch(`/reports/${encodeURIComponent(rid)}/sarif`, { signal }),
  scanHistory: (signal) => apiFetch("/scan-history", { signal }),
  scanDelta: (before, after, signal) =>
    apiFetch("/scan-delta", { method: "POST", body: { before, after }, signal }),
  saveTriage: (scope, fingerprint, status, reason, signal) =>
    apiFetch("/triage", { method: "POST", body: { scope, fingerprint, status, reason }, signal }),
  createValidation: (payload, signal) => apiFetch("/validations", { method: "POST", body: payload, signal }),
  getValidation: (vid, signal) => apiFetch(`/validations/${encodeURIComponent(vid)}`, { signal }),
  createPlan: (payload, signal) => apiFetch("/plans", { method: "POST", body: payload, signal }),
};

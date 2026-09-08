/* Pure report selectors: one UI-facing view model over raw report JSON.
   No fetching, no DOM, no invented data — every value derives from the
   report (safe fallbacks render as "unknown"/empty, never as zero-facts).
   Tested with node:test (frontend/tests/). */

import { arr, num, obj, str } from "./report.js";

export const SEVERITIES = ["critical", "high", "medium", "low"];
export const PRIORITIES = ["P0", "P1", "P2", "P3"];

export function getComponents(report) {
  return arr(report?.components);
}

export function getSummary(report) {
  return obj(report?.summary);
}

export function severityCounts(report) {
  const out = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of getComponents(report)) {
    if (out[f.severity] !== undefined) out[f.severity] += 1;
    // Unknown severities are ignored, never re-bucketed.
  }
  const bySev = obj(getSummary(report).bySeverity);
  // Prefer the authoritative backend tally when present.
  for (const s of SEVERITIES) {
    if (typeof bySev[s] === "number") out[s] = bySev[s];
  }
  return out;
}

export function criticalHighCount(report) {
  const c = severityCounts(report);
  return c.critical + c.high;
}

export function runtimeCount(report) {
  return getComponents(report).filter((f) => f.scanner === "runtime").length;
}

export function inventory(report) {
  return arr(report?.intelligence?.inventory);
}

export function familyCount(report) {
  return inventory(report).length;
}

export function migration(report) {
  return obj(report?.migration) || null;
}

export function roadmapBucket(mig, bucket) {
  return arr(obj(mig?.roadmap)[bucket]);
}

export function workItems(mig) {
  return arr(mig?.workItems);
}

export function immediateCount(mig) {
  return roadmapBucket(mig, "Immediate").length;
}

export function topFinding(report) {
  return (
    getComponents(report).find((f) => f.severity === "critical" || f.severity === "high") || null
  );
}

export function scannerSources(report) {
  const fromReport = arr(report?.metadata?.scannerSources);
  if (fromReport.length > 0) return fromReport;
  return [...new Set(getComponents(report).map((f) => str(f.scanner, "?")))].filter(Boolean);
}

export function runtimeProvenance(report) {
  return obj(report?.metadata?.runtimeProvenance);
}

export function validationSummary(report) {
  return obj(report?.validationSummary) || null;
}

export function repoIdentity(report) {
  const source = obj(report?.source);
  if (source.type !== "github") return null;
  return {
    owner: str(source.owner), repo: str(source.repo),
    refRequested: str(source.ref_requested), sha: str(source.sha),
    profile: str(source.profile), url: str(source.canonical_url),
    archiveBytes: num(source.archive_bytes), durationS: num(source.duration_s),
  };
}

export function scanTargetLabel(report, scannedTarget) {
  return str(report?.metadata?.scanTarget, str(scannedTarget));
}

export function codeAnalysis(report) {
  const a = obj(report?.codeAnalysis);
  return a.findings ? a : null;
}

export function codeStats(analysis) {
  const a = obj(analysis);
  const findings = arr(a.findings);
  const byCategory = {};
  for (const f of findings) {
    const c = str(f.category, "UNKNOWN");
    byCategory[c] = (byCategory[c] || 0) + 1;
  }
  return { total: findings.length, byCategory, health: obj(a.health), analysisId: str(a.analysis_id) };
}

export function algorithmFamilies(report) {
  const map = new Map();
  for (const f of getComponents(report)) {
    const fam = canonicalFamily(str(f.algorithm));
    if (!fam) continue;
    if (!map.has(fam)) map.set(fam, { family: fam, count: 0, criticalHigh: 0, libraries: new Set() });
    const g = map.get(fam);
    g.count += 1;
    if (f.severity === "critical" || f.severity === "high") g.criticalHigh += 1;
    if (f.library) g.libraries.add(f.library);
  }
  return [...map.values()]
    .map((g) => ({ ...g, libraries: [...g.libraries].sort() }))
    .sort((a, b) => b.criticalHigh - a.criticalHigh || b.count - a.count || (a.family < b.family ? -1 : 1));
}

export function canonicalFamily(algorithm) {
  const n = String(algorithm || "").toUpperCase();
  if (!n || n === "?") return "";
  if (n.startsWith("AES")) return "AES";
  if (n.startsWith("RSA")) return "RSA";
  if (n.startsWith("ECDSA")) return "ECDSA";
  if (n.startsWith("ECDH")) return "ECDH";
  if (n === "ECC" || n.startsWith("EC_")) return "ECC";
  if (n.startsWith("DH")) return "DH";
  if (n.startsWith("DSA")) return "DSA";
  if (n.startsWith("MD5")) return "MD5";
  if (n.startsWith("SHA")) return n.startsWith("SHA3") ? "SHA-3" : n.startsWith("SHA2") ? "SHA-2" : n.startsWith("SHA1") ? "SHA-1" : "SHA";
  if (n.startsWith("HMAC")) return "HMAC";
  if (n.startsWith("TLS") || n.startsWith("SSL")) return "TLS/SSL";
  return n;
}

const QUANTUM_VULNERABLE = new Set(["RSA", "DSA", "DH", "ECDSA", "ECDH", "ECC"]);

export function quantumExposure(report) {
  let total = 0;
  for (const f of getComponents(report)) {
    if (QUANTUM_VULNERABLE.has(canonicalFamily(str(f.algorithm)))) total += 1;
  }
  return total;
}

export function filterFindings(components, { priority = "all", severity = "all", scanner = "all", query = "" } = {}) {
  const q = String(query || "").trim().toLowerCase();
  return arr(components).filter(
    (f) =>
      (priority === "all" || f.priority === priority) &&
      (severity === "all" || f.severity === severity) &&
      (scanner === "all" || f.scanner === scanner) &&
      (q === "" ||
        `${str(f.algorithm)} ${str(f.file_path)} ${str(f.evidence)} ${str(f.library)} ${str(f.usage)}`.toLowerCase().includes(q)),
  );
}

export function activeFilterLabels({ priority = "all", severity = "all", scanner = "all", query = "" } = {}) {
  const out = [];
  if (priority !== "all") out.push(`priority ${priority}`);
  if (severity !== "all") out.push(`severity ${severity}`);
  if (scanner !== "all") out.push(`scanner ${scanner}`);
  if (String(query || "").trim() !== "") out.push(`“${String(query).trim()}”`);
  return out;
}

export function findingById(report, id) {
  return getComponents(report).find((f) => f.id === id) || null;
}

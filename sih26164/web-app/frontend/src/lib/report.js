/* Deterministic presentation helpers over the ECDAT CBOM-style report.
   Everything displayed must originate from the API report. No fabricated data. */

export const arr = (v) => (Array.isArray(v) ? v : []);
export const str = (v, fallback = "") => (typeof v === "string" ? v : fallback);
export const num = (v, fallback = 0) => (typeof v === "number" && Number.isFinite(v) ? v : fallback);
export const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});

export function shortPath(path, fallback = "—") {
  if (typeof path !== "string" || path === "") return fallback;
  const parts = path.split("/");
  return parts.slice(-2).join("/");
}

export function lineLabel(line) {
  return typeof line === "number" && line > 0 ? String(line) : "—";
}

/** Human-readable API error without leaking stack traces. Handles
 *  string bodies, {detail: string}, and FastAPI 422 {detail: [{loc,msg}]}. */
export function formatScanError(status, bodyText) {
  let detail = bodyText || "";
  try {
    const parsed = JSON.parse(bodyText);
    const d = parsed && parsed.detail !== undefined ? parsed.detail : parsed;
    if (typeof d === "string") detail = d;
    else if (Array.isArray(d)) {
      detail = d
        .map((e) => {
          if (typeof e === "string") return e;
          if (e && typeof e === "object") {
            const loc = Array.isArray(e.loc) ? e.loc.filter((x) => x !== "body").join(".") : "";
            return [loc, e.msg].filter(Boolean).join(": ") || "invalid request";
          }
          return "invalid request";
        })
        .join("; ");
    } else if (d && typeof d === "object") detail = JSON.stringify(d);
  } catch {
    /* keep raw body text */
  }
  const label =
    status === 400 ? "Invalid request" : status === 404 ? "Not found" : status === 422 ? "Validation error" : `Scan failed (${status})`;
  return detail ? `${label}: ${detail}` : label;
}

export function formatNetworkError(err) {
  if (err && (err.name === "TypeError" || /fetch|network|failed/i.test(String(err.message)))) {
    return "Backend unreachable: start the API (uvicorn app.main:app --port 8000) and retry. No data was changed.";
  }
  return String((err && err.message) || err || "Unknown error");
}

/** Safe CBOM-style JSON download: no navigation, object URL always released. */
export function downloadJson(report, filename) {
  if (!report) return false;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = url;
    link.download = filename || "ecdat-cbom-style-report.json";
    link.rel = "noopener";
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return true;
}

/** Deterministic analyst sentence — wording mirrors backend semantics exactly. */
export function analystLine(f) {
  const finding = obj(f);
  const bits = [`${str(finding.priority, "P?")} because ${str(finding.severity, "unknown")} severity`];
  if (finding.evidenceStrength) bits.push(`${String(finding.evidenceStrength).toLowerCase()} evidence strength`);
  if (finding.mosca_exposed) bits.push("migration exposure under the Mosca heuristic");
  const related = arr(finding.related).length;
  bits.push(related > 0 ? `${related} linked finding(s)` : "no linked findings (not proof of isolation)");
  if (finding.scanner === "runtime") bits.push("observed under controlled execution");
  else if (arr(obj(finding.correlation).supports).length > 0) bits.push("supported by runtime observation");
  else bits.push("not runtime-observed in this run");
  return `Analyst (deterministic): ${str(finding.algorithm, "unknown")} is ${bits.join("; ")}.`;
}

export const FALLBACK_SCANNERS = ["source", "binary", "container", "dependency", "hsm", "cloud"];

/* ---- security knowledge layer (advisory; deterministic engine authoritative) ---- */

export function knowledgeBase(report) {
  return arr(report?.knowledgeBase);
}

export function skillById(report, id) {
  return knowledgeBase(report).find((s) => s.id === id) || null;
}

/** Deterministic matches attached to a finding by the backend (may be absent on old reports). */
export function matchesFor(finding) {
  return arr(obj(finding).knowledge);
}

export function recContextFor(report, direction) {
  return arr(report?.recommendationContext).find((e) => e.direction === direction) || null;
}

/** How many components reference a skill (for the explorer). */
export function skillMatchCount(components, skillId) {
  return arr(components).filter((f) => matchesFor(f).some((m) => m.skill === skillId)).length;
}

export function knowledgeSource(report) {
  return obj(report?.knowledgeContext?.source);
}

/** Evidence-strength distribution over finding components (real data only). */
export function strengthCounts(components) {
  const out = { HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const r of arr(components)) {
    if (r && out[r.evidenceStrength] !== undefined) out[r.evidenceStrength] += 1;
    else out.UNKNOWN += 1;
  }
  return out;
}

/** Open unknowns: every unknown string the migration planner recorded (real data only). */
export function unknownsCount(migration) {
  return arr(obj(migration).workItems).reduce((n, w) => n + arr(w.unknowns).length, 0);
}

/** Group deterministic recommendations with their supporting evidence.
 *  Each card: direction + migration path (notes) + why (top rationale) +
 *  evidence (supporting finding count + algorithms). All derived, nothing invented. */
export function groupRecommendations(components) {
  const groups = new Map();
  for (const f of arr(components)) {
    const rec = obj(f.recommendation);
    const direction = str(rec.recommend, "").trim();
    if (!direction) continue;
    if (!groups.has(direction)) {
      groups.set(direction, {
        direction,
        notes: str(rec.notes),
        guidance: str(rec.guidance),
        findings: [],
        algorithms: new Set(),
        worstPriority: "P3",
        worstSeverity: "low",
      });
    }
    const g = groups.get(direction);
    g.findings.push(f);
    if (f.algorithm) g.algorithms.add(f.algorithm);
    const rank = { P0: 0, P1: 1, P2: 2, P3: 3 };
    if ((rank[f.priority] ?? 3) < (rank[g.worstPriority] ?? 3)) g.worstPriority = f.priority;
    const sev = { critical: 0, high: 1, medium: 2, low: 3 };
    if ((sev[f.severity] ?? 3) < (sev[g.worstSeverity] ?? 3)) g.worstSeverity = f.severity;
  }
  return [...groups.values()]
    .map((g) => ({ ...g, algorithms: [...g.algorithms].sort() }))
    .sort((a, b) => ({ P0: 0, P1: 1, P2: 2, P3: 3 }[a.worstPriority] ?? 3) - (({ P0: 0, P1: 1, P2: 2, P3: 3 }[b.worstPriority] ?? 3)));
}

/** Compact machine-readable summary of the report for the export panel. */
export function exportFacts(report, scanId) {
  const r = obj(report);
  return {
    scanId: str(scanId, "—"),
    findings: num(obj(r.summary).total),
    families: arr(r.intelligence?.inventory).length,
    scannedAt: str(r.scannedAt, "—"),
    format: `${str(r.bomFormat, "ECDAT-CBOM")} ${str(r.specVersion, "")}`.trim(),
  };
}

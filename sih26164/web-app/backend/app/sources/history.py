"""Scan history, deterministic delta, and triage. Presentation/workflow state only.

Triage and delta never alter scanner evidence, Mosca risk, CBOM, or analysis
results. Suppression requires a reason and never deletes the finding.
"""

from __future__ import annotations

import time

TRIAGE_STATES = ("open", "reviewed", "suppressed", "resolved")
SUPPRESS_REASONS = ("false-positive", "intentional-architecture", "accepted-risk",
                    "not-applicable", "duplicate", "deferred", "other")
# Severity rank for regression detection (higher = worse).
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def history_record(scan_id: str, source: dict, profile: str, report: dict,
                   duration_s: float) -> dict:
    """Compact history entry (counts only, never full findings)."""
    components = report.get("components", []) if isinstance(report, dict) else []
    analysis = report.get("codeAnalysis") or {}
    code = analysis.get("findings", []) if isinstance(analysis, dict) else []
    critical = sum(1 for c in components if isinstance(c, dict) and c.get("severity") == "critical")
    return {"scan_id": scan_id, "source_type": source.get("type", "local"),
            "repo": source.get("repo", ""), "owner": source.get("owner", ""),
            "sha": source.get("sha", ""), "ref_requested": source.get("ref_requested", ""),
            "profile": profile, "timestamp": time.time(), "duration_s": round(duration_s, 2),
            "counts": {"crypto": len(components), "critical": critical, "code": len(code)}}


def _index(rows: list) -> tuple[dict, dict]:
    by_id = {r.get("id"): r for r in rows if isinstance(r, dict) and r.get("id")}
    by_fp: dict[str, list] = {}
    for row in rows:
        if isinstance(row, dict) and row.get("fp"):
            by_fp.setdefault(row["fp"], []).append(row)
    return by_id, by_fp


def delta(before: dict, after: dict) -> dict:
    """Compare two reports by stable id; fingerprint fallback detects moves/changes.

    Statuses: NEW / RESOLVED / UNCHANGED / CHANGED (same fp, different id —
    e.g. line moved or severity-relevant field changed) / REGRESSION (severity
    worsened on an unchanged or moved finding).
    """
    result: dict = {"new": [], "resolved": [], "unchanged": [], "changed": [],
                    "regressions": [],
                    "severity_changed": [], "summary": {}}
    def _worse(before_sev: str, after_sev: str) -> bool:
        return SEV_RANK.get(after_sev, 0) > SEV_RANK.get(before_sev, 0)
    for kind in ("crypto", "code"):
        if kind == "crypto":
            b_rows = before.get("components", [])
            a_rows = after.get("components", [])
        else:
            b_rows = (before.get("codeAnalysis") or {}).get("findings", [])
            a_rows = (after.get("codeAnalysis") or {}).get("findings", [])
        b_id, b_fp = _index(b_rows)
        a_id, a_fp = _index(a_rows)
        consumed: set[str] = set()  # after-ids already paired as moves
        for fid in sorted(set(b_id) - set(a_id)):
            # Same fingerprint elsewhere = moved/changed (one entry per pair).
            fp = b_id[fid].get("fp", "")
            partner = next((r.get("id") for r in b_fp.get(fp, []) + a_fp.get(fp, [])
                            if r.get("id") in a_id and r.get("id") not in consumed), "")
            entry = {"id": fid, "kind": kind,
                     "title": b_id[fid].get("title") or b_id[fid].get("algorithm", ""),
                     "file_path": b_id[fid].get("file_path", "")}
            if fp and partner:
                consumed.add(partner)
                entry["after_id"] = partner
                entry["after_path"] = a_id[partner].get("file_path", "")
                result["changed"].append(entry)
                b_sev = b_id[fid].get("severity", "")
                a_sev = a_id[partner].get("severity", "")
                if _worse(b_sev, a_sev):
                    result["regressions"].append({"id": fid, "after_id": partner,
                                                 "kind": kind, "before": b_sev,
                                                 "after": a_sev})
            else:
                result["resolved"].append(entry)
        for fid in sorted(set(a_id) - set(b_id)):
            if fid in consumed:
                continue
            result["new"].append({"id": fid, "kind": kind,
                                  "title": a_id[fid].get("title") or a_id[fid].get("algorithm", ""),
                                  "file_path": a_id[fid].get("file_path", "")})
        for fid in sorted(set(b_id) & set(a_id)):
            result["unchanged"].append({"id": fid, "kind": kind})
            b_sev, a_sev = b_id[fid].get("severity"), a_id[fid].get("severity")
            if b_sev != a_sev:
                result["severity_changed"].append({
                    "id": fid, "kind": kind, "before": b_sev, "after": a_sev})
                if _worse(b_sev, a_sev):
                    result["regressions"].append({"id": fid, "kind": kind,
                                                 "before": b_sev, "after": a_sev})
    summary = {k: len(result[k]) for k in ("new", "resolved", "unchanged", "changed")}
    summary["regressions"] = len(result["regressions"])
    summary["new_critical"] = sum(
        1 for e in result["new"] if e["kind"] == "crypto" and _is_critical(after, e["id"]))
    summary["resolved_critical"] = sum(
        1 for e in result["resolved"] if e["kind"] == "crypto" and _is_critical(before, e["id"]))
    result["summary"] = summary
    return result


def _is_critical(report: dict, fid: str) -> bool:
    for row in report.get("components", []):
        if isinstance(row, dict) and row.get("id") == fid:
            return row.get("severity") == "critical"
    return False


def set_triage(store: dict, scope: str, fingerprint: str, status: str,
               reason: str = "") -> dict:
    """Record triage state. Suppression without a reason is rejected."""
    if status not in TRIAGE_STATES:
        raise ValueError(f"unknown triage status '{status}' (valid: {list(TRIAGE_STATES)})")
    if not fingerprint or len(fingerprint) > 64:
        raise ValueError("fingerprint is required")
    if status == "suppressed":
        if not reason or reason not in SUPPRESS_REASONS:
            raise ValueError(f"suppression requires a reason (valid: {list(SUPPRESS_REASONS)})")
    entry = {"scope": scope, "fingerprint": fingerprint, "status": status,
             "reason": reason if status == "suppressed" else "",
             "timestamp": time.time()}
    store[(scope, fingerprint)] = entry
    return entry


def apply_triage(rows: list, store: dict, scope: str) -> None:
    """Stamp presentation-only triage state onto finding dicts (in place)."""
    for row in rows:
        if not isinstance(row, dict):
            continue
        entry = store.get((scope, row.get("fp", "")))
        row["triage"] = {"status": entry["status"], "reason": entry["reason"]} \
            if entry else {"status": "open", "reason": ""}

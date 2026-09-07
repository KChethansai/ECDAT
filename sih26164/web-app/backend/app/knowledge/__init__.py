"""ECDAT security knowledge layer (advisory, local-first, deterministic).

Deterministic engine (scanners → risk → migration → CBOM) is authoritative and
untouched. This layer attaches traceable analyst context AFTER the report is
built: per-finding skill matches, per-direction recommendation context, and a
knowledge base limited to matched skills. Nothing here alters evidence,
severity, priority, counts, migration, or CBOM inventory.
"""

from __future__ import annotations

from .matcher import match_finding
from .provenance import (ADVISORY_NOTE, IMPORTED_AT, SCHEMA_VERSION,
                         SOURCE_COMMIT, SOURCE_LICENSE, SOURCE_REPOSITORY)
from .registry import BY_ID, SKILLS, validate

__all__ = ["annotate_report", "match_finding", "registry_info",
           "SKILLS", "BY_ID", "validate"]


def registry_info() -> dict:
    problems = validate()
    return {"ok": not problems, "problems": problems,
            "skillsTotal": len(SKILLS),
            "tiers": {1: sum(1 for s in SKILLS if s["tier"] == 1),
                      2: sum(1 for s in SKILLS if s["tier"] == 2)},
            "source": {"repository": SOURCE_REPOSITORY, "commit": SOURCE_COMMIT,
                       "license": SOURCE_LICENSE, "importedAt": IMPORTED_AT,
                       "schema": SCHEMA_VERSION}}


def _direction_of(component: dict) -> str:
    rec = component.get("recommendation") or {}
    return (rec.get("recommend") or "").strip()


def annotate_report(report: dict) -> dict:
    """Additive-only enrichment of a built CBOM-style report dict (in place)."""
    if not isinstance(report, dict):
        return report
    components = report.get("components") or []
    matched_ids: list[str] = []
    for component in components:
        matches = match_finding(component) if isinstance(component, dict) else []
        if isinstance(component, dict):
            component["knowledge"] = matches
            component["knowledgeBasis"] = "deterministic + knowledge"
        for match in matches:
            if match["skill"] not in matched_ids:
                matched_ids.append(match["skill"])
    base = {s["id"]: s for s in SKILLS}
    report["knowledgeBase"] = [
        {"id": sid, "name": base[sid]["name"], "domain": base[sid]["domain"],
         "tier": base[sid]["tier"], "summary": base[sid]["summary"],
         "guidance": base[sid]["guidance"], "verification": base[sid]["verification"],
         "considerations": base[sid]["considerations"],
         "frameworks": base[sid]["frameworks"],
         "provenance": base[sid]["provenance"]}
        for sid in matched_ids if sid in base
    ]
    # Per-direction analyst context for the recommendations UI.
    by_direction: dict[str, dict] = {}
    for component in components:
        direction = _direction_of(component) if isinstance(component, dict) else ""
        if not direction:
            continue
        entry = by_direction.setdefault(direction, {"direction": direction,
                                                    "skills": [], "considerations": []})
        for match in (component.get("knowledge") or []):
            skill = base.get(match["skill"])
            if not skill:
                continue
            if skill["id"] not in entry["skills"]:
                entry["skills"].append(skill["id"])
            for point in skill["considerations"][:2]:
                if point not in entry["considerations"] and len(entry["considerations"]) < 4:
                    entry["considerations"].append(point)
    report["recommendationContext"] = sorted(
        by_direction.values(), key=lambda e: e["direction"])
    report["knowledgeContext"] = {
        "enabled": True,
        "advisory": ADVISORY_NOTE,
        "source": {"repository": SOURCE_REPOSITORY, "commit": SOURCE_COMMIT,
                   "license": SOURCE_LICENSE, "importedAt": IMPORTED_AT,
                   "schema": SCHEMA_VERSION},
        "skillsTotal": len(SKILLS),
        "skillsMatched": len(matched_ids),
    }
    return report

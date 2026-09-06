"""Migration intelligence (Phase 13): status, work items, roadmap, report.

Deterministic planning derived from actual findings. Statuses MIGRATION_IN_PROGRESS
and MIGRATION_READY are never inferred — they require explicit caller overrides.
No dates, no costs, no ROI, no completion claims without evidence.
"""

from __future__ import annotations

from hashlib import sha1

from .intelligence import PRIORITY_RANK, SEVERITY_RANK
from .recommend import recommend
from .risk import canon

STATUSES = ("DISCOVERED", "ASSESSED", "MIGRATION_REQUIRED", "MIGRATION_PLANNED",
            "MIGRATION_IN_PROGRESS", "MIGRATION_READY")
BUCKETS = ("Immediate", "Near-term", "Planned", "Monitor")
# Work-item visibility: most urgent member status wins (never inferred completion).
URGENCY = {"MIGRATION_REQUIRED": 0, "MIGRATION_PLANNED": 1, "MIGRATION_IN_PROGRESS": 2,
           "MIGRATION_READY": 3, "DISCOVERED": 4, "ASSESSED": 5}


def status_for(row: dict, overrides: dict[str, str]) -> str:
    """Deterministic status. Overrides are caller-recorded truth, validated."""
    override = overrides.get(row["id"])
    if override is not None:
        if override not in STATUSES:
            raise ValueError(f"unknown migration status: {override!r}")
        return override
    severity, priority = row.get("severity", "low"), row.get("priority", "P3")
    if severity == "critical" or priority == "P0":
        return "MIGRATION_REQUIRED"
    if severity == "high" or priority == "P1":
        return "MIGRATION_REQUIRED"
    if severity == "medium" or priority == "P2":
        return "MIGRATION_PLANNED"
    return "DISCOVERED"


def bucket_for(row: dict) -> str:
    """Roadmap bucket from priority/severity only. No calendar dates, ever."""
    if row.get("priority") == "P0" or row.get("severity") == "critical":
        return "Immediate"
    if row.get("priority") == "P1" or row.get("severity") == "high":
        return "Near-term"
    if row.get("priority") == "P2" or row.get("severity") == "medium":
        return "Planned"
    return "Monitor"


def build_plan(enriched: list[dict], inventory: list[dict], lifetimes: dict,
               overrides: dict[str, str] | None = None) -> dict:
    """Annotate findings with migrationStatus and build the planning layer."""
    overrides = overrides or {}
    for row in enriched:
        row["migrationStatus"] = status_for(row, overrides)

    items: dict[str, dict] = {}
    for row in enriched:
        family = canon(row.get("algorithm", "UNKNOWN"))
        item = items.get(family)
        if item is None:
            digest = sha1(f"migrate:{family}".encode()).hexdigest()[:12]
            item = items[family] = {
                "id": digest, "family": family, "artifacts": set(),
                "libraries": set(), "findingIds": [], "rationales": {},
                "hsm": False, "cloud": False, "runtime": False,
            }
        item["artifacts"].add(row.get("file_path", ""))
        if row.get("library"):
            item["libraries"].add(str(row["library"]))
        item["findingIds"].append(row["id"])
        item["rationales"][row["id"]] = row.get("rationale", "")
        item["hsm"] = item["hsm"] or row.get("scanner") == "hsm"
        item["cloud"] = item["cloud"] or row.get("scanner") == "cloud"
        item["runtime"] = item["runtime"] or row.get("scanner") == "runtime"

    work_items = []
    for family in sorted(items):
        item = items[family]
        members = [r for r in enriched if r["id"] in item["findingIds"]]
        worst = min(members, key=lambda r: (PRIORITY_RANK.get(r.get("priority", "P3"), 3),
                                            SEVERITY_RANK.get(r.get("severity", "low"), 3)))
        rec = recommend(family)
        top_status = min((r["migrationStatus"] for r in members),
                         key=lambda s: URGENCY.get(s, 9))
        work_items.append({
            "id": item["id"], "family": family,
            "title": f"Migrate {family} ({len(members)} finding(s))",
            "priority": worst["priority"], "severity": worst["severity"],
            "status": top_status,
            "reason": worst.get("rationale", ""),
            "direction": rec["recommend"], "directionNotes": rec["notes"],
            "artifacts": sorted(item["artifacts"])[:20],
            "artifactCount": len(item["artifacts"]),
            "libraries": sorted(item["libraries"]),
            "findingIds": sorted(item["findingIds"]),
            "hsmInvolved": item["hsm"], "cloudInvolved": item["cloud"],
            "runtimeObserved": item["runtime"],
            "unknowns": [
                "migration complexity: unknown (not estimated)",
                f"data lifetime: assumes {lifetimes.get('data_years')}y unless provided",
                "business criticality: unknown",
            ],
            "validation": ("Verify provider support, pilot hybrid where applicable, "
                           "then re-scan to confirm removal."),
        })
    work_items.sort(key=lambda w: (PRIORITY_RANK.get(w["priority"], 3), w["family"]))

    roadmap = {bucket: [] for bucket in BUCKETS}
    for item in work_items:
        member_rows = [r for r in enriched if r["id"] in item["findingIds"]]
        bucket = min((bucket_for(r) for r in member_rows),
                     key=lambda b: BUCKETS.index(b))
        roadmap[bucket].append(item["id"])

    status_counts: dict[str, int] = {}
    for row in enriched:
        status_counts[row["migrationStatus"]] = status_counts.get(row["migrationStatus"], 0) + 1

    return {
        "statusCounts": status_counts,
        "workItems": work_items,
        "roadmap": roadmap,
        "assumptions": [
            f"data_lifetime_years={lifetimes.get('data_years')}",
            f"migration_years={lifetimes.get('migration_years')}",
            f"qrqc_years_left={lifetimes.get('qrqc_years_left')}",
            ("Mosca inequality is a migration-readiness heuristic, not a "
             "quantum-arrival prediction."),
            "Statuses IN_PROGRESS/READY appear only via explicit caller overrides.",
        ],
        "report": {
            "inventory": f"{len(inventory)} algorithm families across "
                         f"{sum(i['findingCount'] for i in inventory)} findings.",
            "highestPriority": (f"{work_items[0]['priority']} — {work_items[0]['family']}: "
                                f"{work_items[0]['reason']}" if work_items else "none"),
            "affectedArtifacts": sorted({a for i in work_items for a in i["artifacts"]})[:50],
            "infrastructure": [i["id"] for i in work_items
                               if i["hsmInvolved"] or i["cloudInvolved"]],
            "unknowns": ["migration complexity", "business criticality",
                         "caller-provided vs default lifetimes"],
        },
    }

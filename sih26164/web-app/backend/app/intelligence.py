"""Unified cryptographic intelligence (Phase 12): inventory, cross-scanner
correlation, evidence strength, usage graph.

Operates on enriched finding dicts (post assess/recommend). Pure functions,
deterministic throughout. Never mutates scores, never merges findings, never
drops provenance. Correlation explains relationships; it does not collapse them.
"""

from __future__ import annotations

from .recommend import recommend
from .risk import canon as _canon

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
MAX_RELATED = 8

_HIGH_USAGE = {"runtime observation", "certificate metadata",
               "binary symbol reference", "binary library reference"}


def strength(row: dict) -> str:
    """Qualitative evidence strength. No fake probabilities, deterministic."""
    usage = row.get("usage", "")
    try:
        confidence = float(row.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    if usage in _HIGH_USAGE:
        return "HIGH"
    if usage == "binary string reference" or confidence < 0.6:
        return "LOW"
    if usage == "direct" and confidence >= 0.8:
        return "HIGH"
    return "MEDIUM"


def relate(enriched: list[dict]) -> None:
    """Add `related: [{id, relation}]` links in place (capped, deterministic).

    Relations: same-artifact (same file), same-library, runtime-observed
    (static row referenced by a runtime observation), same-family (same canon,
    different scanner). Runtime rows keep their `correlation` links; static rows
    gain the reverse `runtime-observed` pointer. Non-observation is never
    recorded as absence — unlinked simply means unlinked.
    """
    runtime_supporters: dict[str, list[str]] = {}
    for row in enriched:
        if row.get("scanner") == "runtime":
            for sid in (row.get("correlation") or {}).get("supports", []):
                runtime_supporters.setdefault(sid, []).append(row["id"])
    for row in enriched:
        links: list[dict] = []
        seen: set[str] = set()

        def add(target: str, relation: str) -> None:
            if target != row["id"] and target not in seen and len(links) < MAX_RELATED:
                seen.add(target)
                links.append({"id": target, "relation": relation})

        for other in enriched:
            if other["id"] == row["id"]:
                continue
            if other.get("file_path") == row.get("file_path"):
                add(other["id"], "same-artifact")
        for other in enriched:
            if other["id"] == row["id"]:
                continue
            if row.get("library") and other.get("library") == row.get("library"):
                add(other["id"], "same-library")
        for supporter in runtime_supporters.get(row["id"], []):
            add(supporter, "runtime-observed")
        for other in enriched:
            if other["id"] == row["id"]:
                continue
            if (other.get("scanner") != row.get("scanner")
                    and _canon(other.get("algorithm", "")) == _canon(row.get("algorithm", ""))):
                add(other["id"], "same-family")
        row["related"] = links


def build_inventory(enriched: list[dict]) -> list[dict]:
    """One row per canonical family: scanners, artifacts, worst risk, guidance."""
    groups: dict[str, list[dict]] = {}
    for row in enriched:
        groups.setdefault(_canon(row.get("algorithm", "UNKNOWN")), []).append(row)
    inventory = []
    for family in sorted(groups):
        rows = groups[family]
        algorithms = sorted({r.get("algorithm", "") for r in rows})
        scanners = sorted({r.get("scanner", "") for r in rows})
        artifacts = sorted({r.get("file_path", "") for r in rows})
        finding_ids = sorted(r["id"] for r in rows)
        worst_sev = min((r.get("severity", "low") for r in rows),
                        key=lambda s: SEVERITY_RANK.get(s, 3))
        worst_pri = min((r.get("priority", "P3") for r in rows),
                        key=lambda p: PRIORITY_RANK.get(p, 3))
        strengths = {strength(r) for r in rows}
        evidence = "HIGH" if "HIGH" in strengths else ("MEDIUM" if "MEDIUM" in strengths else "LOW")
        inventory.append({
            "family": family,
            "algorithms": algorithms,
            "findingCount": len(rows),
            "findingIds": finding_ids,
            "scanners": scanners,
            "artifacts": artifacts[:50],
            "artifactCount": len(artifacts),
            "severity": worst_sev,
            "priority": worst_pri,
            "evidenceStrength": evidence,
            "runtimeObserved": any(r.get("scanner") == "runtime" for r in rows),
            "recommendation": recommend(family)["recommend"],
        })
    return inventory


def build_graph(enriched: list[dict]) -> dict:
    """Small JSON usage graph: artifacts, families, libraries, findings, edges."""
    nodes: dict[str, dict] = {}
    edges: list[list[str]] = []

    def node(node_id: str, kind: str, label: str) -> None:
        nodes.setdefault(node_id, {"id": node_id, "type": kind, "label": label[:120]})

    for row in sorted(enriched, key=lambda r: r["id"]):
        fid = f"finding:{row['id']}"
        node(fid, "finding", f"{row.get('algorithm', '?')} ({row.get('scanner', '?')})")
        artifact = row.get("file_path", "")
        node(f"artifact:{artifact}", "artifact", artifact.split("/")[-1][:80] or artifact[:80])
        edges.append([f"artifact:{artifact}", fid, "contains"])
        family = _canon(row.get("algorithm", ""))
        node(f"family:{family}", "algorithm", family)
        edges.append([fid, f"family:{family}", "instance-of"])
        if row.get("library"):
            node(f"library:{row['library']}", "library", str(row["library"])[:80])
            edges.append([fid, f"library:{row['library']}", "uses"])
        for link in row.get("related", []):
            edges.append([fid, f"finding:{link['id']}", link["relation"]])
    edges = sorted({(a, b, c) for a, b, c in edges})
    return {"nodes": [nodes[k] for k in sorted(nodes)],
            "edges": [{"from": a, "to": b, "relation": c} for a, b, c in edges]}

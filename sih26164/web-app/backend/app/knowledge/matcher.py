"""Deterministic skill-to-finding matching.

Explicit allowlist rules only: a skill matches when the finding's normalized
algorithm is listed AND every non-empty scanner/category/usage constraint is
satisfied. No fuzzy or semantic matching — the mapping is auditable by reading
registry.py. Match strength is rule depth, not a model score:
HIGH = algorithm-level match, MEDIUM = scanner/category/usage-level match.
"""

from __future__ import annotations

from ..risk import base_algorithm, canon
from .registry import SKILLS

# Display budget per finding: methodology + the most specific adjacent skills.
# The knowledge explorer and recommendation context carry full coverage.
MAX_MATCHES = 5


def _algo_keys(finding: dict) -> set[str]:
    keys = set()
    for raw in (finding.get("algorithm") or "",):
        upper = str(raw).upper()
        keys.add(upper)
        try:
            keys.add(base_algorithm(raw))
            keys.add(canon(raw))
        except Exception:
            pass
    return {k for k in keys if k}


def match_finding(finding: dict) -> list[dict]:
    """Ordered [{skill, strength, why}] for one enriched finding dict."""
    if not isinstance(finding, dict):
        return []
    keys = _algo_keys(finding)
    scanner = finding.get("scanner") or ""
    category = finding.get("category") or ""
    usage = finding.get("usage") or ""
    # Dependency-category rows (manifest references, lockfile integrity hashes)
    # are dependency findings whichever scanner emitted them.
    scanner_set = {scanner} | ({"dependency"} if category == "dependency" else set())
    hits: list[dict] = []
    for skill in SKILLS:
        applies = skill.get("applies", {})
        algos = set(applies.get("algorithms", []))
        algo_hit = bool(keys & algos)
        if algos and not algo_hit and skill["id"] != "crypto-audit":
            # Named algorithms are allowlists: without a hit the skill would
            # attach generically (code-signing on any dependency, PQC on any
            # library). Only the crypto-audit methodology skill keeps a broad
            # fallback; every other skill must match its named scope.
            continue
        scanners = applies.get("scanners", [])
        if scanners and scanner_set.isdisjoint(scanners):
            continue
        categories = applies.get("categories", [])
        if categories and category not in categories:
            continue
        usages = applies.get("usages", [])
        if usages and usage not in usages:
            continue
        if algo_hit:
            strength = "HIGH"
            why = f"{finding.get('algorithm', '?')} is in this skill's scope"
        elif scanners or categories or usages:
            strength = "MEDIUM"
            scope = scanner or category or usage or "report"
            why = f"{scope} context matches this skill's scope"
        else:
            continue  # unconstrained skill would match everything: never attach
        hits.append({"skill": skill["id"], "strength": strength, "why": why})
    order = [s["id"] for s in SKILLS]
    by_id = {s["id"]: s for s in SKILLS}

    def rank(hit: dict) -> tuple:
        skill = by_id[hit["skill"]]
        # HIGH matches keep stable registry order (authoritative relevance).
        # MEDIUM matches rank by methodology tier, then scanner specificity
        # (a container-only skill outranks a generic one on container rows).
        if hit["strength"] == "HIGH":
            return (0, 0, 0, order.index(hit["skill"]))
        return (1, skill.get("tier", 2),
                len(skill.get("applies", {}).get("scanners", []) or [None]),
                order.index(hit["skill"]))

    hits.sort(key=rank)
    return hits[:MAX_MATCHES]

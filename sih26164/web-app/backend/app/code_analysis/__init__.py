"""Codebase intelligence: deterministic static analysis + guided remediation.

Separate pipeline from crypto discovery. Findings are CodeFinding (engineering
impact), never CryptoFinding (security severity). No AI required; AI adapters
only render deterministic plans.
"""

import hashlib
import time

from . import complexity as _complexity
from . import dead_code as _dead_code
from . import dependencies as _dependencies
from . import duplication as _duplication
from . import efficiency as _efficiency
from . import structure as _structure
from .models import CATEGORIES, CodeFinding
from .planning import build_plan, finding_from_dict, to_agent_prompt, to_markdown
from .ranking import rank
from .remediation import attach_options
from .scope import iter_files
from .symbols import build_graph
from .verification import verify

ANALYZERS = ("dead_code", "duplication", "complexity", "efficiency",
             "dependencies", "structure")

__all__ = ["ANALYZERS", "CATEGORIES", "CodeFinding", "analyze", "build_plan",
           "finding_from_dict", "health_summary", "to_agent_prompt", "to_markdown",
           "verify"]


def analyze(root, categories: list[str] | None = None) -> dict:
    """Run selected analyzers over root. Returns a JSON-safe analysis record."""
    from pathlib import Path

    selected = [c for c in (categories or list(ANALYZERS)) if c in ANALYZERS]
    if not selected:
        raise ValueError(f"unknown categories: {categories}")
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"analysis target missing: {root}")
    started = time.time()
    files = iter_files(root)
    modules = build_graph(root, files)  # language filtering lives in build_graph
    # One shared AST parse per Python module; analyzers reuse it (no re-parsing).
    trees = {}
    if {"dead_code", "complexity", "efficiency"} & set(selected):
        from .symbols import parse_tree

        trees = {rel: parse_tree(mod) for rel, mod in modules.items()
                 if mod.language == "python"}
    findings: list[CodeFinding] = []
    if "dead_code" in selected:
        findings.extend(_dead_code.analyze(modules, trees))
    if "duplication" in selected:
        findings.extend(_duplication.analyze(root, files))
    if "complexity" in selected:
        findings.extend(_complexity.analyze(modules, trees))
    if "efficiency" in selected:
        findings.extend(_efficiency.analyze(modules, trees))
    if "dependencies" in selected:
        findings.extend(_dependencies.analyze(root, modules))
    if "structure" in selected:
        findings.extend(_structure.analyze(root, files, modules))
    attach_options(findings)
    ranked = rank(findings)
    rows = [f.to_dict() for f in ranked]
    return {"analysis_id": "ca" + hashlib.sha256(
                ("|".join(sorted(selected)) + "|" + str(root)).encode()
            ).hexdigest()[:11],
            "target": str(root), "categories": sorted(selected),
            "findings": rows, "health": health_summary(rows),
            "metrics": {"files": len(files), "modules": len(modules),
                        "symbols": sum(len(m.defs) for m in modules.values()),
                        "duration_s": round(time.time() - started, 3),
                        "truncated": len(files) >= 2000}}


def health_summary(findings: list[dict]) -> dict:
    """Per-dimension counts. No single collapsed score (shown only with formula)."""
    by_category: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    high_conf = 0
    for finding in findings:
        by_category[finding.get("category", "?")] = by_category.get(finding.get("category", "?"), 0) + 1
        by_priority[finding.get("priority", "?")] = by_priority.get(finding.get("priority", "?"), 0) + 1
        if finding.get("confidence") == "HIGH":
            high_conf += 1
    total = len(findings)
    # Transparent overall signal: share of HIGH-confidence findings, formula shown.
    score = round(100 * (1 - high_conf / max(total, 1)))
    return {"total": total, "byCategory": by_category, "byPriority": by_priority,
            "highConfidence": high_conf,
            "overall": {"value": score,
                        "formula": "100 * (1 - high_confidence_findings / total_findings)",
                        "meaning": "Higher = fewer high-confidence issues. Not a quality proof."}}

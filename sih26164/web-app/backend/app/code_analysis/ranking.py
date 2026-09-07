"""Deterministic prioritization: confidence × impact ÷ (effort × risk).

Labels only — QUICK_WIN … DO_NOT_AUTOMATE. No cost estimates, no fabricated hours.
"""

from __future__ import annotations

from .models import CodeFinding

CONFIDENCE_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
IMPACT_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
EFFORT_SCORE = {"SMALL": 1, "MEDIUM": 2, "LARGE": 3}
RISK_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def score(finding: CodeFinding) -> float:
    return (CONFIDENCE_SCORE.get(finding.confidence, 1)
            * IMPACT_SCORE.get(finding.impact, 1)
            / (EFFORT_SCORE.get(finding.effort, 2) * RISK_SCORE.get(finding.risk, 2)))


def label(finding: CodeFinding) -> str:
    if finding.risk == "HIGH":
        return "DO_NOT_AUTOMATE"
    if finding.confidence == "LOW":
        return "REQUIRES_REVIEW"
    value = score(finding)
    if value >= 3.0:
        return "QUICK_WIN"
    if value >= 1.5:
        return "HIGH_IMPACT" if finding.impact == "HIGH" else "LOW_RISK"
    if finding.effort == "LARGE":
        return "LARGE_REFACTOR"
    return "REQUIRES_REVIEW"


def rank(findings: list[CodeFinding]) -> list[CodeFinding]:
    for finding in findings:
        finding.priority = label(finding)
    return sorted(findings, key=lambda f: (-score(f), f.file_path, f.line, f.id))

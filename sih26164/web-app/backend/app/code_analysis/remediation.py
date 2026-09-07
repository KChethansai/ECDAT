"""Multiple remediation options per finding. Deterministic templates, no LLM.

Every option: option_id, title, description, advantages, disadvantages, risk,
complexity, affected files, prerequisites, verification, compatibility,
reversibility, automation suitability. The user chooses — never the engine.
"""

from __future__ import annotations

from .models import CodeFinding


def _option(option_id: str, title: str, description: str, finding: CodeFinding,
            risk: str, complexity: str, automation: str,
            advantages: list[str], disadvantages: list[str]) -> dict:
    return {
        "option_id": option_id, "title": title, "description": description,
        "advantages": advantages, "disadvantages": disadvantages, "risk": risk,
        "complexity": complexity,
        "affected_files": sorted({finding.file_path, *finding.related_files})[:8],
        "prerequisites": ["Confirm the finding's verification steps first."],
        "verification": [finding.verification or "Re-run analysis; finding must be gone."],
        "compatibility": "No public-API or behavior change expected when verification passes.",
        "reversibility": "Fully reversible via version control before merge.",
        "automation_suitability": automation,
    }


def options_for(finding: CodeFinding) -> list[dict]:
    """2–4 options depending on category. Pure function of the finding."""
    symbol = finding.symbol or "the flagged code"
    f = finding.file_path
    if finding.category == "DEAD_CODE":
        return [
            _option("delete", f"Delete {symbol}",
                    f"Remove {symbol} from {f}. Simplest; lowest maintenance.",
                    finding, "MEDIUM" if finding.confidence == "LOW" else "LOW",
                    "SMALL", "SAFE_WITH_TESTS",
                    ["Smallest diff", "No ongoing maintenance", "Removes code that need not exist"],
                    ["Breaks dynamic/config references if verification was skipped"]),
            _option("retain-document", f"Retain and document {symbol}",
                    f"Keep {symbol} as intentional API/surface; add an explicit export, "
                    f"reference, or docstring explaining why it exists.",
                    finding, "LOW", "SMALL", "MANUAL",
                    ["Zero breakage risk", "Converts unknown-unknown into documented surface"],
                    ["Keeps maintenance cost", "Does not reduce size"]),
            _option("quarantine", "Quarantine behind an explicit marker",
                    "Move the symbol to a clearly-marked compatibility module with a removal date.",
                    finding, "LOW", "MEDIUM", "MANUAL",
                    ["Unblocks cleanup without deletion", "Forces a revisit decision"],
                    ["Adds a module", "Only defers the choice"]),
        ]
    if finding.category == "DUPLICATION":
        return [
            _option("extract-helper", "Extract a shared helper",
                    "Move the repeated block into one helper; call it from each site.",
                    finding, "MEDIUM", "MEDIUM", "REQUIRES_REVIEW",
                    ["Single source of truth", "Fixes propagate once"],
                    ["Wrong abstraction merges distinct behaviors", "Needs careful parameter naming"]),
            _option("partial-share", "Share constants/config only",
                    "Keep logic separate; extract only the repeated data or configuration.",
                    finding, "LOW", "SMALL", "SAFE_WITH_TESTS",
                    ["Low risk", "Removes the most brittle drift"],
                    ["Logic duplication remains"]),
            _option("keep-as-is", "Keep as-is (documented)",
                    "Leave the duplication; note why (different owners, pending divergence).",
                    finding, "LOW", "TRIVIAL", "MANUAL",
                    ["No churn", "Honest about trade-offs"],
                    ["Drift risk remains"]),
        ]
    if finding.category == "EFFICIENCY":
        return [
            _option("hoist-cache", "Hoist / cache the repeated work",
                    "Move loop-invariant computation out of the loop or cache the parsed result.",
                    finding, "LOW", "SMALL", "SAFE_WITH_TESTS",
                    ["Removes repeated cost", "Usually a small diff"],
                    ["Caching adds state; hoisting changes evaluation timing"]),
            _option("restructure", "Restructure the data flow",
                    "Change shapes (sets/dicts, early exits, batching) instead of micro-fixes.",
                    finding, "MEDIUM", "MEDIUM", "REQUIRES_REVIEW",
                    ["Addresses the real complexity", "Often simplifies code too"],
                    ["Larger diff", "Needs profiling to justify"]),
            _option("keep-as-is", "Keep as-is (measured)",
                    "Profile first; if the path is cold, document and move on.",
                    finding, "LOW", "TRIVIAL", "MANUAL",
                    ["No risk", "Avoids premature optimization"],
                    ["Leaves the cost in place"]),
        ]
    if finding.category == "DEPENDENCY":
        return [
            _option("remove-dep", f"Remove dependency `{symbol}`",
                    f"Drop `{symbol}` from {f}, reinstall, run the full suite.",
                    finding, "MEDIUM", "SMALL", "SAFE_WITH_TESTS",
                    ["Smaller installs", "Less supply-chain surface"],
                    ["Breaks optional/dynamic usage missed by static scan"]),
            _option("mark-optional", "Mark as optional / lazy-load",
                    "Move to extras/optional and import lazily at the use site.",
                    finding, "LOW", "MEDIUM", "REQUIRES_REVIEW",
                    ["Keeps the capability", "Cheaper default install"],
                    ["More packaging complexity"]),
        ]
    # COMPLEXITY / STRUCTURE / CONFIGURATION / MAINTAINABILITY / default
    return [
        _option("simplify", f"Simplify `{symbol or f}`",
                f"Split, flatten, or reorganize per the finding evidence; keep behavior identical.",
                finding, "MEDIUM", "MEDIUM", "REQUIRES_REVIEW",
                ["Easier review and fewer defects", "Often removes hidden duplication"],
                ["Refactor churn", "Needs full test pass"]),
        _option("keep-as-is", "Keep as-is (documented)",
                "Complexity may be inherent; record the observation and revisit on next touch.",
                finding, "LOW", "TRIVIAL", "MANUAL",
                ["No risk", "No churn"],
                ["Cost stays"]),
    ]


def attach_options(findings: list[CodeFinding]) -> None:
    for finding in findings:
        finding.remediation_options = options_for(finding)

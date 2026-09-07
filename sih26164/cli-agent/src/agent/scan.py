"""CLI orchestration for the web application's real ECDAT domain pipeline."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from . import context
from .config import WORKSPACE_ROOT
from .memory import ObsidianVaultProvider

BACKEND_ROOT = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend"
CONTEXT_QUERY = "ECDAT scan cryptographic risk architecture requirements unresolved"


def validate_target(raw_target: str) -> Path:
    """Accept only existing non-symlink targets physically inside this workspace."""
    raw = Path(raw_target)
    if not raw_target.strip() or ".." in raw.parts:
        raise ValueError("unsafe scan target")
    candidate = raw if raw.is_absolute() else WORKSPACE_ROOT / raw
    if candidate.is_symlink():
        raise ValueError("unsafe scan target")
    try:
        target = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"scan target not found: {raw_target}") from exc
    workspace = WORKSPACE_ROOT.resolve()
    if target != workspace and workspace not in target.parents:
        raise ValueError("unsafe scan target")
    return target


def _run_pipeline(target: Path, data_years: float, migration_years: float,
                   qrqc_years_left: float, context_provenance: dict | None = None,
                   runtime: bool = False, validate: bool = False,
                   validation_targets: object = None,
                   validation_policy: object = None, code_analysis: bool = False,
                   code_categories: list[str] | None = None) -> dict:
    backend = str(BACKEND_ROOT)
    if backend not in sys.path:
        sys.path.insert(0, backend)
    from app.pipeline import REAL_SCANNERS, run_scan

    return run_scan(target, list(REAL_SCANNERS),
                     data_years, migration_years, qrqc_years_left, context_provenance,
                     runtime=runtime, validate=validate,
                     validation_targets=validation_targets,
                     validation_policy=validation_policy,
                     code_analysis=code_analysis,
                     code_categories=code_categories)


def _summary(target: Path, report: dict, context_notes: list[str],
             context_chars: int) -> str:
    significant = [row for row in report["components"]
                   if row.get("severity") in {"critical", "high"}]
    algorithms = sorted({row["algorithm"] for row in report["components"]})
    recommendations = []
    for row in significant:
        item = row["recommendation"]["recommend"]
        if item not in recommendations:
            recommendations.append(item)
    highest = next((level for level in ("critical", "high", "medium", "low")
                    if report["summary"]["bySeverity"].get(level)), "low")
    relative_target = target.relative_to(WORKSPACE_ROOT)
    return "\n".join([
        f"# ECDAT scan — {datetime.now(timezone.utc).date().isoformat()}",
        "",
        "## Durable summary",
        f"- Target: `{relative_target}`",
        f"- Scan timestamp: {report['scannedAt']}",
        f"- Findings: {report['summary']['real']} real, {report['summary']['mock']} mock",
        f"- Highest risk: {highest}",
        f"- Algorithms detected: {', '.join(algorithms) or 'none'}",
        f"- Significant findings: {len(significant)}",
        f"- Major recommendations: {'; '.join(recommendations[:5]) or 'none'}",
        f"- Context consulted: {', '.join(context_notes) or 'none'}",
        f"- Bounded orchestration context: {context_chars} chars",
        "",
        "No file evidence, cryptographic key material, or generated CBOM is retained here.",
    ]) + "\n"


def analyze_code(raw_target: str, categories: list[str] | None = None) -> dict:
    """Deterministic static codebase analysis (no vault write, no AI, no execution)."""
    backend = str(BACKEND_ROOT)
    if backend not in sys.path:
        sys.path.insert(0, backend)
    from app.code_analysis import analyze

    return analyze(validate_target(raw_target), categories)


def plan_finding(analysis: dict, finding_id: str, option_id: str,
                 constraints: list[str] | None = None) -> dict:
    """Deterministic remediation plan for a user-selected finding + option."""
    backend = str(BACKEND_ROOT)
    if backend not in sys.path:
        sys.path.insert(0, backend)
    from app.code_analysis import build_plan, finding_from_dict, to_agent_prompt, to_markdown

    raw = next((f for f in analysis.get("findings", []) if f.get("id") == finding_id), None)
    if raw is None:
        raise ValueError(f"unknown finding id: {finding_id}")
    plan = build_plan(finding_from_dict(raw), option_id, constraints)
    plan["markdown"] = to_markdown(plan)
    plan["agent_prompt"] = to_agent_prompt(plan)
    return plan


def verify_findings(before: list[dict], after: list[dict],
                    touched: list[str] | None = None) -> dict:
    backend = str(BACKEND_ROOT)
    if backend not in sys.path:
        sys.path.insert(0, backend)
    from app.code_analysis import verify

    return verify(before, after, touched)


def scan(mem: ObsidianVaultProvider, raw_target: str, data_years: float = 10.0,
         migration_years: float = 3.0, qrqc_years_left: float = 10.0,
         runtime: bool = False, persist: bool = True, validate: bool = False,
         validation_targets: object = None, validation_policy: object = None,
         code_analysis: bool = False, code_categories: list[str] | None = None) -> dict:
    """Load bounded vault context, run the real pipeline, and persist durable knowledge.

    `runtime` is explicit opt-in: it executes ONLY the bundled first-party probe
    under timeout/isolation. Static scans never execute anything.
    `validate` is explicit opt-in: bounded TLS/HTTP probes against explicit
    targets (loopback by default). `persist=False` skips the vault write.
    """
    if any(not 0 <= value <= 100 for value in (data_years, migration_years, qrqc_years_left)):
        raise ValueError("risk horizons must be between 0 and 100")
    target = validate_target(raw_target)
    mem.initialize()
    hits = mem.search(CONTEXT_QUERY, top_n=5)
    analysis_context = context.build_context(mem, CONTEXT_QUERY, max_chars=4000, top_n=5)
    context_notes = [rel for rel, _ in hits]
    report = _run_pipeline(target, data_years, migration_years, qrqc_years_left,
                           {"available": True, "notes": len(context_notes),
                            "chars": len(analysis_context), "maxChars": 4000},
                           runtime=runtime, validate=validate,
                           validation_targets=validation_targets,
                           validation_policy=validation_policy,
                           code_analysis=code_analysis,
                           code_categories=code_categories)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S%fZ")
    note = ""
    if persist:
        note = f"07-Sessions/Scans/{stamp}-scan.md"
        mem.write(note, _summary(target, report, context_notes, len(analysis_context)))
    return {"report": report, "contextNotes": context_notes,
            "contextChars": len(analysis_context), "memoryNote": note}

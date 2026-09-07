"""Shared ECDAT domain pipeline used by the API and the developer CLI."""

from __future__ import annotations

from pathlib import Path

from .cbom import build_cbom
from .intelligence import build_graph, build_inventory, relate, strength
from .knowledge import annotate_report
from .migration import build_plan
from .models import normalize_findings
from .recommend import recommend
from .risk import assess, canon as _canon
from .scanner import (BinaryScanner, CloudScanner, ContainerScanner, DependencyScanner,
                      HSMScanner, RuntimeScanner, SourceScanner)
from .scanner.runtime_scanner import RuntimeUnavailableError, TIMEOUT_SECS


SCANNERS = {"source": SourceScanner(), "binary": BinaryScanner(),
            "container": ContainerScanner(), "dependency": DependencyScanner(),
            "hsm": HSMScanner(), "cloud": CloudScanner(), "runtime": RuntimeScanner()}
REAL_SCANNERS = ["source", "binary", "container", "dependency", "hsm", "cloud"]


def correlate(enriched: list[dict]) -> None:
    """Link runtime observations to same-family static evidence (in place).

    Only stable family identifiers drive links, capped per finding.
    Correlation enriches context; it never changes scores or merges findings.
    """
    static_ids: dict[str, list[str]] = {}
    for row in enriched:
        if row.get("scanner") != "runtime" and not row.get("is_mock"):
            static_ids.setdefault(_canon(row["algorithm"]), []).append(row["id"])
    for row in enriched:
        if row.get("scanner") != "runtime":
            continue
        supports = static_ids.get(_canon(row["algorithm"]), [])[:5]
        row["correlation"] = {
            "supports": supports,
            "note": ("Runtime observation supported by matching static evidence."
                     if supports else "No matching static evidence in this scan."),
        }


def run_scan(target: str | Path, scanners: list[str] | None = None,
             data_years: float = 10.0, migration_years: float = 3.0,
             qrqc_years_left: float = 10.0, context_provenance: dict | None = None,
             runtime: bool = False, status_overrides: dict[str, str] | None = None,
             validate: bool = False, validation_targets: object = None,
             validation_policy: object = None, code_analysis: bool = False,
             code_categories: list[str] | None = None) -> dict:
    """Run discovery, risk, recommendations, and CBOM through one code path.

    `runtime` is explicit opt-in only: it executes the bundled first-party probe
    under timeout/isolation (see runtime_scanner). Static scans never execute.
    `status_overrides` records caller-asserted migration states (validated).
    `validate` is explicit opt-in only: it runs bounded TLS/HTTP probes against
    caller-supplied `validation_targets` (loopback by default; see validation).
    Validation adds metadata only; it never alters findings, scores, or counts.
    `code_analysis` is explicit opt-in: deterministic static codebase analysis
    (dead code, duplication, complexity, efficiency, dependencies, structure).
    Its findings are CodeFinding records under `report["codeAnalysis"]`, fully
    separate from crypto components, risk, migration, and CBOM.
    """
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan target missing: {target}")
    selected = scanners or list(REAL_SCANNERS)
    unknown = [name for name in selected if name not in SCANNERS]
    if unknown:
        raise ValueError(f"unknown scanners: {unknown}")
    findings = []
    for name in dict.fromkeys(selected):
        findings.extend(SCANNERS[name].scan(root))
    runtime_provenance: dict = {"available": False}
    if runtime:
        try:
            runtime_findings = RuntimeScanner().scan(root)
            findings.extend(runtime_findings)
            runtime_provenance = {"available": True, "probe": "crypto_probe",
                                  "events": len(runtime_findings),
                                  "timeoutSecs": TIMEOUT_SECS}
        except RuntimeUnavailableError as exc:
            runtime_provenance = {"available": False, "reason": str(exc)}
    enriched = assess(normalize_findings(findings), data_years, migration_years, qrqc_years_left)
    for finding in enriched:
        finding["recommendation"] = recommend(finding["algorithm"])
    correlate(enriched)
    relate(enriched)
    for finding in enriched:
        finding["evidenceStrength"] = strength(finding)
    inventory = build_inventory(enriched)
    plan = build_plan(enriched, inventory,
                      {"data_years": data_years, "migration_years": migration_years,
                       "qrqc_years_left": qrqc_years_left}, status_overrides)
    sources = list(dict.fromkeys(selected))
    if runtime and runtime_provenance.get("available") and "runtime" not in sources:
        sources.append("runtime")
    report = build_cbom(str(root), enriched, context_provenance, sources, runtime_provenance,
                        {"inventory": inventory, "graph": build_graph(enriched)}, plan)
    # Advisory knowledge context only: never alters evidence, severity,
    # priority, counts, migration, or CBOM inventory (see knowledge/__init__.py).
    report = annotate_report(report)
    _stamp_validation(report, validate=validate, validation_targets=validation_targets,
                      validation_policy=validation_policy)
    if code_analysis:
        from .code_analysis import analyze as analyze_codebase

        try:
            report["codeAnalysis"] = analyze_codebase(root, code_categories)
        except (ValueError, FileNotFoundError) as exc:
            report["codeAnalysis"] = {"error": str(exc), "findings": [], "health": {}}
    return report


def _stamp_validation(report: dict, validate: bool = False,
                      validation_targets: object = None,
                      validation_policy: object = None) -> None:
    """Attach validation metadata (in place, additive only)."""
    from .validation import ValidationPolicy, apply_correlation, run_validations

    components = report.get("components", [])
    if not validate:
        for row in components:
            row["validationStatus"] = ("NOT_APPLICABLE"
                                       if row.get("is_mock") else "STATIC_ONLY")
            row["correlatedValidations"] = []
        return
    try:
        policy = (validation_policy if isinstance(validation_policy, ValidationPolicy)
                  else ValidationPolicy.from_dict(validation_policy))
    except ValueError as exc:
        raise ValueError(f"invalid validation policy: {exc}") from exc
    run = run_validations(components, validation_targets, policy)
    apply_correlation(components, run["results"])
    report["validations"] = run
    report["validationSummary"] = {"run_id": run["run_id"],
                                   "byStatus": run["summary"]["byStatus"],
                                   "total": run["summary"]["total"],
                                   "blocked_targets": run["blocked_targets"],
                                   "dry_run": run["dry_run"]}

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
    from .sources import stamp_fps as _stamp_fps

    _stamp_fps(report)
    _stamp_validation(report, validate=validate, validation_targets=validation_targets,
                      validation_policy=validation_policy)
    if code_analysis:
        from .code_analysis import analyze as analyze_codebase

        try:
            report["codeAnalysis"] = analyze_codebase(root, code_categories)
        except (ValueError, FileNotFoundError) as exc:
            report["codeAnalysis"] = {"error": str(exc), "findings": [], "health": {}}
    return report


def run_github_scan(github_url: str, ref: str | None = None, profile: str = "full",
                    scanners: list[str] | None = None,
                    data_years: float = 10.0, migration_years: float = 3.0,
                    qrqc_years_left: float = 10.0,
                    runtime: bool = False, status_overrides: dict | None = None,
                    validate: bool = False, validation_targets: object = None,
                    validation_policy: object = None, code_analysis: bool = False,
                    code_categories: list[str] | None = None,
                    acquisition_policy: object = None) -> dict:
    """Acquire a public GitHub repo into an isolated workspace, then run_scan.

    The GitHub path is a source adapter only: acquisition, relativization, and
    source metadata wrap the EXISTING pipeline untouched. The temporary
    workspace is always cleaned up; tmp paths never leak into the report.
    """
    import time as _time
    from pathlib import Path as _Path

    from .sources import (AcquisitionError, AcquisitionPolicy, candidate_archives,
                          extract_archive, fetch_bytes, isolated_workspace,
                          parse_github_url, relativize_report, resolve_profile,
                          resolve_ref, topdir_sha)

    started = _time.time()
    parsed = parse_github_url(github_url)  # ValueError propagates (caller maps to 400)
    policy = (acquisition_policy if isinstance(acquisition_policy, AcquisitionPolicy)
              else AcquisitionPolicy(acquisition_policy))
    # Fail fast on unknown profiles before any network (resolve_profile raises).
    prof = resolve_profile(profile, scanners, code_analysis, validate)
    deadline = _time.monotonic() + policy.total_deadline_s
    wanted_ref = ref if ref is not None else parsed["ref"]
    wanted_kind = None if ref is not None else parsed["ref_kind"]
    if wanted_ref is not None and (not isinstance(wanted_ref, str) or not wanted_ref
                                   or len(wanted_ref) > 256):
        raise ValueError("invalid ref")
    owner, repo = parsed["owner"], parsed["repo"]
    try:
        resolved = resolve_ref(owner, repo, wanted_ref, wanted_kind, policy, deadline)
        candidates = candidate_archives(owner, repo, resolved)
        body, final_url, sha = b"", "", resolved.get("sha", "")
        last_error = "repository or ref not found (404)"
        for candidate in candidates:
            try:
                body, final_url = fetch_bytes(candidate, policy, deadline)
            except AcquisitionError as exc:
                if "404" in str(exc):
                    last_error = str(exc)
                    continue
                raise
            break
        else:
            raise AcquisitionError(last_error)
        with isolated_workspace() as workspace:
            topdir, skipped_links = extract_archive(body, workspace, policy)
            archive_sha = topdir_sha(topdir, repo)
            if archive_sha and sha and archive_sha != sha:
                raise AcquisitionError("archive identity does not match the resolved commit")
            if archive_sha:
                sha = archive_sha
            if not sha:
                raise AcquisitionError(
                    "could not resolve the ref to a commit SHA (GitHub API unreachable and "
                    "branch archives do not carry the SHA). Retry later or supply the full "
                    "40-character commit SHA as the ref.")
            resolved["sha"] = sha
            # Scan the archive topdir as root so it never leaks into finding paths.
            scan_root = _Path(workspace) / topdir
            # Never persist signed download URLs (time-limited SigV4 query).
            archive_ref = final_url.split("?", 1)[0].split("#", 1)[0][:512]
            if code_categories is not None:
                prof["code_categories"] = code_categories
                prof["code_analysis"] = True
            report = run_scan(scan_root, prof["scanners"], data_years, migration_years,
                              qrqc_years_left, runtime=runtime,
                              status_overrides=status_overrides, validate=prof["validate"],
                              validation_targets=validation_targets,
                              validation_policy=validation_policy,
                              code_analysis=prof["code_analysis"],
                              code_categories=prof["code_categories"])
            relativize_report(report, scan_root, owner, repo, sha)
            report["metadata"]["scanTarget"] = f"github:{owner}/{repo}@{sha[:12]}"
            report["source"] = {
                "type": "github", "host": "github.com", "owner": owner, "repo": repo,
                "canonical_url": parsed["canonical_url"],
                "ref_requested": resolved.get("requested_ref", ""),
                "ref_kind": resolved.get("ref_kind", ""),
                "sha": sha, "default_branch": resolved.get("default_branch", ""),
                "visibility": resolved.get("visibility", ""),
                "resolution": resolved.get("via", ""),
                "profile": prof["profile"], "archive_bytes": len(body),
                "archive_url": archive_ref,
                "skipped_symlinks": skipped_links,
                "acquisition": policy.summary(),
                "duration_s": round(_time.time() - started, 2),
            }
            return report
    except (AcquisitionError, ValueError):
        raise
    except OSError as exc:
        raise AcquisitionError(f"workspace failure: {type(exc).__name__}")


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

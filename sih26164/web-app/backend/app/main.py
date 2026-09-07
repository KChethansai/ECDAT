"""ECDAT FastAPI service: scan -> risk -> PQC recs -> CBOM. No database; reports are
rebuilt deterministically and held in process memory (restart clears them — re-POST).
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .pipeline import REAL_SCANNERS, SCANNERS, run_scan

app = FastAPI(title="ECDAT", version="0.1.0")
# Local demo dashboard only: same-origin in dev via Vite proxy; allow direct
# localhost access for `vite preview`/static serving. Never a wildcard.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:4173", "http://127.0.0.1:4173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    max_age=600,
)
REPORTS: dict[str, dict] = {}
MAX_REPORTS = 50  # in-memory only; oldest evicted, restart clears all
SOURCE_HISTORY: list[dict] = []
MAX_HISTORY = 100  # compact entries only (counts, never findings)
TRIAGE: dict[tuple[str, str], dict] = {}  # (scope, fingerprint) -> workflow state
BASE = Path(__file__).resolve().parent.parent
SAMPLES = BASE / "samples"
WORKSPACE_ROOT = BASE.parents[2]


class ScanRequest(BaseModel):
    target: str = Field(default="sample", description="'sample' or an existing workspace-contained path")
    scanners: list[str] = Field(default_factory=lambda: list(REAL_SCANNERS))
    data_years: float = Field(default=10.0, ge=0, le=100)
    migration_years: float = Field(default=3.0, ge=0, le=100)
    qrqc_years_left: float = Field(default=10.0, ge=0, le=100)
    runtime: bool = Field(default=False, description="explicit opt-in: run the controlled "
                          "runtime probe (bundled fixture only, bounded, isolated)")
    status_overrides: dict[str, str] | None = Field(default=None, description="caller-recorded "
                          "migration states by finding id (validated, never inferred)")
    validate: bool = Field(default=False, description="explicit opt-in: run bounded active "
                           "validation probes against validation_targets (loopback by default)")
    validation_targets: list[str] | None = Field(default=None, description="explicit probe URLs "
                           "(empty/missing = strategy mapping only, no network)")
    validation_policy: dict | None = Field(default=None, description="budgets/allowlist "
                           "(allow_non_loopback requires explicit acknowledgement)")
    code_analysis: bool = Field(default=False, description="explicit opt-in: deterministic "
                           "static codebase analysis (separate from crypto findings)")
    code_categories: list[str] | None = Field(default=None, description="analyzer subset "
                           "(default: all)")
    source: dict | None = Field(default=None, description="remote source adapter "
                           "{type: github, url, ref?} (exclusive with non-default target)")
    profile: str | None = Field(default=None, description="scan profile for remote sources "
                           "(quick|crypto|codebase|full|full-validation; default full)")
    acquisition: dict | None = Field(default=None, description="acquisition limits "
                           "(max_download_bytes, max_extracted_bytes, max_files, "
                           "total_deadline_s)")


@app.get("/health")
def health() -> dict:
    """Availability only: API liveness, registered scanners, optional probe presence."""
    from .scanner.runtime_scanner import PROBE

    return {"ok": True, "service": "ecdat", "version": "0.1.0",
            "scanners": sorted(SCANNERS),
            "runtimeProbe": "present" if PROBE.is_file() else "missing"}


MAX_LIST_ITEMS = 5000  # inbound list payload cap (runner/analyzer cap lower)


def _cap_list(name: str, values: list | None, limit: int = MAX_LIST_ITEMS) -> None:
    if values is not None and len(values) > limit:
        raise ValueError(f"{name} exceeds {limit} items")


def resolve_scan_target(raw_target: str) -> Path:
    """Resolve an API target without allowing the server filesystem to be probed."""
    if not isinstance(raw_target, str) or len(raw_target) > 1024:
        raise ValueError("unsafe scan target")
    if raw_target == "sample":
        return (SAMPLES / "vuln_sample").resolve()
    raw = Path(raw_target)
    if not raw_target.strip() or ".." in raw.parts:
        raise ValueError("unsafe scan target")
    candidate = raw if raw.is_absolute() else WORKSPACE_ROOT / raw
    if candidate.is_symlink():
        raise ValueError("unsafe scan target")
    try:
        target = candidate.resolve(strict=True)
    except OSError as exc:
        raise FileNotFoundError(raw_target) from exc
    workspace = WORKSPACE_ROOT.resolve()
    if target != workspace and workspace not in target.parents:
        raise ValueError("unsafe scan target")
    return target


@app.post("/scans")
def create_scan(req: ScanRequest) -> dict:
    if req.source is not None:
        return _create_remote_scan(req)
    try:
        target = resolve_scan_target(req.target)
    except FileNotFoundError:
        raise HTTPException(404, f"target not found: {req.target}")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    unknown = [s for s in req.scanners if s not in SCANNERS]
    if unknown:
        raise HTTPException(400, f"unknown scanners: {unknown}")
    try:
        _cap_list("validation_targets", req.validation_targets, 200)
        _cap_list("code_categories", req.code_categories, 20)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    try:
        report = run_scan(target, req.scanners, req.data_years, req.migration_years,
                          req.qrqc_years_left, runtime=req.runtime,
                          status_overrides=req.status_overrides, validate=req.validate,
                          validation_targets=req.validation_targets,
                          validation_policy=req.validation_policy,
                          code_analysis=req.code_analysis,
                          code_categories=req.code_categories)
    except FileNotFoundError:
        raise HTTPException(404, f"scan target not found: {req.target}")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rid = _store_report(report)
    return {"id": rid, "report": report}


def _store_report(report: dict) -> str:
    rid = uuid.uuid4().hex[:12]
    REPORTS[rid] = report
    while len(REPORTS) > MAX_REPORTS:
        REPORTS.pop(next(iter(REPORTS)))
    analysis = report.get("codeAnalysis") if isinstance(report, dict) else None
    if isinstance(analysis, dict) and analysis.get("analysis_id"):
        CODE_ANALYSES[analysis["analysis_id"]] = analysis
        while len(CODE_ANALYSES) > MAX_ANALYSES:
            CODE_ANALYSES.pop(next(iter(CODE_ANALYSES)))
    return rid


def _create_remote_scan(req: ScanRequest) -> dict:
    """GitHub source adapter: acquire, run the existing pipeline, record history."""
    import time as _time

    from .pipeline import run_github_scan
    from .sources import AcquisitionError
    from .sources.history import history_record

    if not isinstance(req.source, dict) or req.source.get("type") != "github":
        raise HTTPException(400, "unsupported source (valid: {type: github, url, ref?})")
    if req.target != "sample":
        raise HTTPException(400, "source and target are mutually exclusive")
    url = req.source.get("url", "")
    ref = req.source.get("ref")
    if ref is not None and not isinstance(ref, str):
        raise HTTPException(400, "source ref must be a string")
    try:
        _cap_list("validation_targets", req.validation_targets, 200)
        _cap_list("code_categories", req.code_categories, 20)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    started = _time.time()
    # Default scanner list defers to the profile; an explicit list overrides it.
    scanners = None if sorted(req.scanners) == sorted(REAL_SCANNERS) else req.scanners
    unknown = [s for s in (scanners or []) if s not in SCANNERS]
    if unknown:
        raise HTTPException(400, f"unknown scanners: {unknown}")
    try:
        report = run_github_scan(
            url, ref, req.profile or "full", scanners,
            req.data_years, req.migration_years, req.qrqc_years_left,
            runtime=req.runtime, status_overrides=req.status_overrides,
            validate=req.validate, validation_targets=req.validation_targets,
            validation_policy=req.validation_policy,
            code_analysis=req.code_analysis, code_categories=req.code_categories,
            acquisition_policy=req.acquisition)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except AcquisitionError as exc:
        raise HTTPException(502, f"repository acquisition failed: {exc}")
    rid = _store_report(report)
    SOURCE_HISTORY.append(history_record(rid, report.get("source", {}),
                                         report["source"].get("profile", "full"),
                                         report, _time.time() - started))
    while len(SOURCE_HISTORY) > MAX_HISTORY:
        SOURCE_HISTORY.pop(0)
    return {"id": rid, "report": report}


@app.get("/reports/{rid}")
def get_report(rid: str) -> dict:
    if rid not in REPORTS:
        raise HTTPException(404, "unknown report (reports are in-memory; re-POST /scans)")
    _apply_report_triage(REPORTS[rid])
    return REPORTS[rid]


def _triage_scope(report: dict) -> str:
    source = report.get("source") or {}
    if source.get("type") == "github":
        return f"github:{source.get('owner')}/{source.get('repo')}"
    return f"local:{(report.get('metadata') or {}).get('scanTarget', '')[:128]}"


def _apply_report_triage(report: dict) -> None:
    from .sources.history import apply_triage

    scope = _triage_scope(report)
    apply_triage(report.get("components", []), TRIAGE, scope)
    apply_triage((report.get("codeAnalysis") or {}).get("findings", []), TRIAGE, scope)


@app.get("/scan-history")
def scan_history() -> dict:
    return {"history": list(reversed(SOURCE_HISTORY))}


class DeltaRequest(BaseModel):
    before: str = Field(description="report id of the earlier scan")
    after: str = Field(description="report id of the later scan")


@app.post("/scan-delta")
def scan_delta(req: DeltaRequest) -> dict:
    from .sources.history import delta

    if req.before not in REPORTS or req.after not in REPORTS:
        raise HTTPException(404, "unknown report id (reports are in-memory; re-POST /scans)")
    return delta(REPORTS[req.before], REPORTS[req.after])


class TriageRequest(BaseModel):
    scope: str = Field(description="triage scope, e.g. github:owner/repo")
    fingerprint: str = Field(description="stable finding fingerprint (fp)")
    status: str = Field(description="open|reviewed|suppressed")
    reason: str = Field(default="", description="required for suppressed")


@app.post("/triage")
def set_finding_triage(req: TriageRequest) -> dict:
    from .sources.history import set_triage

    if not req.scope or len(req.scope) > 256:
        raise HTTPException(400, "invalid triage scope")
    try:
        return set_triage(TRIAGE, req.scope, req.fingerprint, req.status, req.reason)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/triage")
def list_triage(scope: str = "") -> dict:
    if len(scope) > 256:
        raise HTTPException(400, "invalid triage scope")
    entries = [e for (s, _), e in TRIAGE.items() if not scope or s == scope]
    return {"triage": sorted(entries, key=lambda e: e["timestamp"], reverse=True)[:500]}


VALIDATIONS: dict[str, dict] = {}
MAX_VALIDATIONS = 50  # in-memory only; oldest evicted, restart clears all


class ValidationRequest(BaseModel):
    report_id: str = Field(description="in-memory report id from POST /scans")
    finding_ids: list[str] | None = Field(default=None, description="subset to validate "
                           "(default: all validatable findings)")
    targets: list[dict] | None = Field(default=None, description="explicit probe targets "
                           "[{url, finding_ids?}] (empty/missing = runtime correlation only)")
    policy: dict | None = Field(default=None, description="budgets/allowlist/dry_run")


@app.post("/validations")
def create_validation(req: ValidationRequest) -> dict:
    """Re-validate without rescanning: new immutable run, history preserved."""
    from .validation import ValidationPolicy, apply_correlation, run_validations

    if req.report_id not in REPORTS:
        raise HTTPException(404, "unknown report (reports are in-memory; re-POST /scans)")
    try:
        policy = ValidationPolicy.from_dict(req.policy)
        _cap_list("finding_ids", req.finding_ids)
        _cap_list("targets", req.targets, 200)
    except ValueError as exc:
        raise HTTPException(400, f"invalid validation policy: {exc}")
    report = REPORTS[req.report_id]
    components = report.get("components", [])
    subset = [c for c in components
              if req.finding_ids is None or c.get("id") in set(req.finding_ids or [])]
    try:
        run = run_validations(subset, req.targets, policy)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    apply_correlation(components, run["results"])
    vid = run["run_id"]
    VALIDATIONS[vid] = run
    while len(VALIDATIONS) > MAX_VALIDATIONS:
        VALIDATIONS.pop(next(iter(VALIDATIONS)))
    return {"id": vid, "run": run}


@app.get("/validations/{vid}")
def get_validation(vid: str) -> dict:
    if vid not in VALIDATIONS:
        raise HTTPException(404, "unknown validation run (in-memory; re-POST /validations)")
    return VALIDATIONS[vid]


@app.get("/reports/{rid}/sarif")
def get_sarif(rid: str) -> dict:
    from .validation.sarif import to_sarif

    if rid not in REPORTS:
        raise HTTPException(404, "unknown report (reports are in-memory; re-POST /scans)")
    report = REPORTS[rid]
    validations = report.get("validations", {}).get("results", []) if isinstance(report, dict) else []
    return to_sarif(report, validations)


CODE_ANALYSES: dict[str, dict] = {}
MAX_ANALYSES = 20  # in-memory only; oldest evicted, restart clears all
PLANS: dict[str, dict] = {}
MAX_PLANS = 50


class CodeAnalysisRequest(BaseModel):
    target: str = Field(default="sample", description="'sample' or an existing workspace-contained path")
    categories: list[str] | None = Field(default=None, description="analyzer subset (default: all)")


@app.post("/code-analysis")
def create_code_analysis(req: CodeAnalysisRequest) -> dict:
    from .code_analysis import ANALYZERS, analyze

    try:
        target = resolve_scan_target(req.target)
    except FileNotFoundError:
        raise HTTPException(404, f"target not found: {req.target}")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    unknown = [c for c in (req.categories or []) if c not in ANALYZERS]
    if unknown:
        raise HTTPException(400, f"unknown categories: {unknown}")
    try:
        _cap_list("categories", req.categories, 20)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    try:
        analysis = analyze(target, req.categories)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    aid = analysis["analysis_id"]
    CODE_ANALYSES[aid] = analysis
    while len(CODE_ANALYSES) > MAX_ANALYSES:
        CODE_ANALYSES.pop(next(iter(CODE_ANALYSES)))
    return {"id": aid, "analysis": analysis}


@app.get("/code-analysis/{aid}")
def get_code_analysis(aid: str) -> dict:
    if aid not in CODE_ANALYSES:
        raise HTTPException(404, "unknown analysis (in-memory; re-POST /code-analysis)")
    return CODE_ANALYSES[aid]


class PlanRequest(BaseModel):
    analysis_id: str = Field(description="in-memory analysis id from POST /code-analysis")
    finding_id: str = Field(description="CodeFinding id to remediate")
    option_id: str = Field(description="user-selected remediation option id")
    constraints: list[str] | None = Field(default=None, description="user-selected constraints")


@app.post("/plans")
def create_plan(req: PlanRequest) -> dict:
    from .code_analysis import build_plan, finding_from_dict, to_agent_prompt, to_markdown

    if req.analysis_id not in CODE_ANALYSES:
        raise HTTPException(404, "unknown analysis (in-memory; re-POST /code-analysis)")
    try:
        _cap_list("constraints", req.constraints, 20)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    raw = next((f for f in CODE_ANALYSES[req.analysis_id].get("findings", [])
                if f.get("id") == req.finding_id), None)
    if raw is None:
        raise HTTPException(404, "unknown finding id in this analysis")
    try:
        plan = build_plan(finding_from_dict(raw), req.option_id, req.constraints)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    plan["markdown"] = to_markdown(plan)
    plan["agent_prompt"] = to_agent_prompt(plan)
    PLANS[plan["plan_id"]] = plan
    while len(PLANS) > MAX_PLANS:
        PLANS.pop(next(iter(PLANS)))
    return {"id": plan["plan_id"], "plan": plan}


@app.get("/plans/{pid}")
def get_plan(pid: str) -> dict:
    if pid not in PLANS:
        raise HTTPException(404, "unknown plan (in-memory; re-POST /plans)")
    return PLANS[pid]


class VerifyRequest(BaseModel):
    before: list[dict] = Field(default_factory=list, description="finding dicts from the pre-change analysis")
    after: list[dict] = Field(default_factory=list, description="finding dicts from the post-change analysis")
    touched_files: list[str] | None = Field(default=None)


@app.post("/plans/verify")
def verify_plan(req: VerifyRequest) -> dict:
    from .code_analysis import verify

    try:
        _cap_list("before", req.before)
        _cap_list("after", req.after)
        _cap_list("touched_files", req.touched_files, 200)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return verify(req.before, req.after, req.touched_files)

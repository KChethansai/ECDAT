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


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "ecdat", "version": "0.1.0"}


def resolve_scan_target(raw_target: str) -> Path:
    """Resolve an API target without allowing the server filesystem to be probed."""
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
        report = run_scan(target, req.scanners, req.data_years, req.migration_years,
                          req.qrqc_years_left, runtime=req.runtime,
                          status_overrides=req.status_overrides)
    except FileNotFoundError:
        raise HTTPException(404, f"scan target not found: {req.target}")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rid = uuid.uuid4().hex[:12]
    REPORTS[rid] = report
    while len(REPORTS) > MAX_REPORTS:
        REPORTS.pop(next(iter(REPORTS)))
    return {"id": rid, "report": report}


@app.get("/reports/{rid}")
def get_report(rid: str) -> dict:
    if rid not in REPORTS:
        raise HTTPException(404, "unknown report (reports are in-memory; re-POST /scans)")
    return REPORTS[rid]

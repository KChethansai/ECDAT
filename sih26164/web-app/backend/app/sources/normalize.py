"""Workspace relativization: tmp-dir paths become stable repo-scoped identities.

Rewrites file_path to `<owner>/<repo>@<shortsha>/<relpath>` and recomputes
finding ids through the REAL dataclasses (no formula duplication), then stamps
a line-independent fingerprint `fp` used for delta + triage carry-forward.
Non-workspace paths (e.g. runtime fixture rows) are left untouched.
"""

from __future__ import annotations

from hashlib import sha1
from pathlib import Path


def logical_prefix(owner: str, repo: str, sha: str) -> str:
    # NOTE: sha is intentionally excluded: finding ids must stay stable across
    # commits of the same repo (delta UNCHANGED depends on it). The scanned
    # commit lives at report.source.sha and in history records.
    del sha
    return f"{owner}/{repo}"


def _crypto_fp(row: dict, path: str) -> str:
    seed = (f"{row.get('scanner')}|{path}|{row.get('algorithm')}|{row.get('category')}|"
            f"{row.get('key_size')}|{row.get('curve')}|{row.get('usage')}").encode()
    return "f" + sha1(seed).hexdigest()[:11]


def _code_fp(row: dict, path: str) -> str:
    seed = (f"{row.get('analyzer')}|{row.get('category')}|{path}|"
            f"{row.get('symbol')}|{row.get('title')}").encode()
    return "f" + sha1(seed).hexdigest()[:11]


def stamp_fps(report: dict) -> None:
    """Stamp line-independent fingerprints on every finding (additive, in place).

    Called for all reports so triage and delta work for local scans too.
    Relativization recomputes them on the logical path afterwards.
    """
    for row in report.get("components", []):
        if isinstance(row, dict) and row.get("id") and not row.get("fp"):
            row["fp"] = _crypto_fp(row, str(row.get("file_path", "")))
    for row in (report.get("codeAnalysis") or {}).get("findings", []):
        if isinstance(row, dict) and row.get("id") and not row.get("fp"):
            row["fp"] = _code_fp(row, str(row.get("file_path", "")))


def rekey_crypto(row: dict, new_path: str) -> None:
    """Recompute a crypto finding id for a new path via CryptoFinding itself."""
    from ..models import CryptoFinding

    known = ("scanner", "file_path", "line", "algorithm", "category", "evidence",
             "key_size", "mode", "protocol_version", "library", "curve",
             "signature_algorithm", "expires_at", "usage", "rationale",
             "confidence", "is_mock")
    data = {k: row.get(k) for k in known if k in row}
    data["file_path"] = new_path
    data.pop("id", None)
    fresh = CryptoFinding(**data)
    row["file_path"] = new_path
    row["id"] = fresh.id


def rekey_code(row: dict, new_path: str) -> None:
    """Recompute a code finding id for a new path via CodeFinding itself."""
    from ..code_analysis.models import CodeFinding

    data = {k: v for k, v in row.items()
            if k in CodeFinding.__dataclass_fields__ and k != "id"}
    data["file_path"] = new_path
    fresh = CodeFinding(**data)
    row["file_path"] = new_path
    row["id"] = fresh.id


def relativize_report(report: dict, workspace: Path, owner: str, repo: str, sha: str) -> str:
    """Rewrite workspace paths in place. Returns the logical prefix used."""
    prefix = logical_prefix(owner, repo, sha)
    try:
        root = workspace.resolve()
    except OSError:
        return prefix
    def _rel_of(raw_path: str) -> str | None:
        """Workspace-relative path, whether stored absolute or already relative."""
        candidate = Path(str(raw_path or ""))
        if not candidate.is_absolute():
            return str(raw_path)  # code findings are already repo-relative
        try:
            return str(candidate.resolve().relative_to(root))
        except (OSError, ValueError):
            return None  # outside the workspace: runtime rows, probes — untouched

    remap: dict[str, str] = {}
    for row in report.get("components", []):
        if not isinstance(row, dict):
            continue
        old_id = row.get("id", "")
        rel = _rel_of(row.get("file_path", ""))
        if rel is None:
            continue
        new_path = f"{prefix}/{rel}"
        try:
            rekey_crypto(row, new_path)
        except TypeError:
            row["file_path"] = new_path  # malformed row: rewrite path, keep id
        if old_id and row.get("id") != old_id:
            remap[old_id] = row["id"]
        row["fp"] = _crypto_fp(row, new_path)
    analysis = report.get("codeAnalysis") or {}
    for row in analysis.get("findings", []):
        if not isinstance(row, dict):
            continue
        old_id = row.get("id", "")
        rel = _rel_of(row.get("file_path", ""))
        if rel is None:
            continue
        new_path = f"{prefix}/{rel}"
        try:
            rekey_code(row, new_path)
        except (TypeError, ValueError):
            row["file_path"] = new_path
        if old_id and row.get("id") != old_id:
            remap[old_id] = row["id"]
        row["fp"] = _code_fp(row, new_path)
    if remap:
        for row in report.get("components", []):
            if isinstance(row, dict) and row.get("correlatedValidations"):
                row["correlatedValidations"] = [remap.get(v, v)
                                                for v in row["correlatedValidations"]]
        for res in (report.get("validations") or {}).get("results", []):
            if isinstance(res, dict) and res.get("finding_id") in remap:
                res["finding_id"] = remap[res["finding_id"]]
    return prefix

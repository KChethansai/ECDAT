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
    pathmap: dict[str, str] = {}
    for row in report.get("components", []):
        if not isinstance(row, dict):
            continue
        old_id = row.get("id", "")
        old_path = str(row.get("file_path", ""))
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
        if old_path and old_path != new_path:
            pathmap[old_path] = new_path
        row["fp"] = _crypto_fp(row, new_path)
    analysis = report.get("codeAnalysis") or {}
    for row in analysis.get("findings", []):
        if not isinstance(row, dict):
            continue
        old_id = row.get("id", "")
        old_path = str(row.get("file_path", ""))
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
        if old_path and old_path != new_path:
            pathmap[old_path] = new_path
        row["fp"] = _code_fp(row, new_path)
    if remap or pathmap:
        def _remap_ids(values: list) -> list:
            return [remap.get(v, v) for v in values]

        def _remap_paths(values: list) -> list:
            return [pathmap.get(v, v) for v in values]

        for row in report.get("components", []):
            if not isinstance(row, dict):
                continue
            if row.get("correlatedValidations"):
                row["correlatedValidations"] = _remap_ids(row["correlatedValidations"])
            corr = row.get("correlation")
            if isinstance(corr, dict) and corr.get("supports"):
                corr["supports"] = _remap_ids(corr["supports"])
            for link in row.get("related") or []:
                if isinstance(link, dict) and link.get("id") in remap:
                    link["id"] = remap[link["id"]]
        for res in (report.get("validations") or {}).get("results", []):
            if isinstance(res, dict) and res.get("finding_id") in remap:
                res["finding_id"] = remap[res["finding_id"]]
        intel = report.get("intelligence") or {}
        for fam in intel.get("inventory", []):
            if isinstance(fam, dict) and fam.get("findingIds"):
                fam["findingIds"] = _remap_ids(fam["findingIds"])
            if isinstance(fam, dict) and fam.get("artifacts"):
                fam["artifacts"] = _remap_paths(fam["artifacts"])
        for item in (report.get("migration") or {}).get("workItems", []):
            if isinstance(item, dict) and item.get("findingIds"):
                item["findingIds"] = _remap_ids(item["findingIds"])
            if isinstance(item, dict) and item.get("artifacts"):
                item["artifacts"] = _remap_paths(item["artifacts"])
        mig_report = (report.get("migration") or {}).get("report") or {}
        if isinstance(mig_report, dict) and mig_report.get("affectedArtifacts"):
            mig_report["affectedArtifacts"] = _remap_paths(mig_report["affectedArtifacts"])
        for row in analysis.get("findings", []):
            if isinstance(row, dict) and row.get("related_files"):
                fixed = []
                for v in row["related_files"]:
                    if v in pathmap:
                        fixed.append(pathmap[v])
                    elif (isinstance(v, str) and v and not v.startswith("/")
                            and not v.startswith(prefix + "/")):
                        fixed.append(f"{prefix}/{v}")  # topdir-relative → logical
                    else:
                        fixed.append(v)
                row["related_files"] = fixed
        # The usage graph embeds finding ids + artifact paths: rebuild it from
        # the already-relativized components rather than patching strings.
        if isinstance(intel, dict) and "graph" in intel:
            from ..intelligence import build_graph  # deferred: avoids import cycle

            intel["graph"] = build_graph(
                [r for r in report.get("components", []) if isinstance(r, dict)])
    return prefix

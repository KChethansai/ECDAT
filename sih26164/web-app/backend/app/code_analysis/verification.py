"""Before/after verification: re-analyze, diff by stable finding id, report status.

RESOLVED (gone) / REMAINS (still there) / REGRESSION (new in touched files) /
INCONCLUSIVE (analysis incomparable). Historical snapshots are never mutated.
"""

from __future__ import annotations

VERDICTS = ("RESOLVED", "REMAINS", "REGRESSION", "INCONCLUSIVE")


def verify(before: list[dict], after: list[dict],
           touched_files: list[str] | None = None) -> dict:
    """Diff two finding lists (dicts with stable `id`). Pure function."""
    if not isinstance(before, list) or not isinstance(after, list):
        raise ValueError("before/after must be finding lists")
    before_ids = {f.get("id") for f in before if isinstance(f, dict) and f.get("id")}
    after_ids = {f.get("id") for f in after if isinstance(f, dict) and f.get("id")}
    if not before and not after:
        return {"status": "INCONCLUSIVE", "resolved": [], "remains": [],
                "regressions": [], "note": "Both analyses are empty; nothing to compare."}
    resolved = sorted(before_ids - after_ids)
    remains = sorted(before_ids & after_ids)
    new_ids = sorted(after_ids - before_ids)
    touched = set(touched_files or [])
    regressions = [i for i in new_ids
                   if not touched or any(isinstance(f, dict) and f.get("file_path") in touched
                                         for f in after if isinstance(f, dict) and f.get("id") == i)]
    unrelated_new = [i for i in new_ids if i not in regressions]
    if remains:
        status = "REMAINS"
    elif regressions:
        status = "REGRESSION"
    elif resolved:
        status = "RESOLVED"
    else:
        status = "INCONCLUSIVE"
    return {"status": status, "resolved": resolved, "remains": remains,
            "regressions": regressions, "unrelated_new": unrelated_new,
            "note": (f"{len(resolved)} resolved, {len(remains)} remain, "
                     f"{len(regressions)} regression(s) in touched files.")}

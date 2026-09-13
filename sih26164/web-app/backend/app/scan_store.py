"""Durable file-based scan store (stdlib only, offline, human-inspectable).

Layout under ``backend/.data/`` (gitignored, overridable via the
``ECDAT_DATA_DIR`` environment variable): ``scans/index.json`` plus one
``<scan-id>.json`` per scan, and ``triage.json`` for the workflow overlay.
Writes are atomic (temp file in the same directory, fsync, os.replace);
a corrupt scan file is quarantined aside so it can never destroy history.
Retention: the listing index keeps the newest MAX_INDEX entries and their
files; older files are deleted on save so disk cannot grow without bound.
Single-process assumption: the dev server runs one uvicorn worker; tmp names
carry pid+thread+timestamp so even concurrent writers never share a path
(last-writer-wins on the index itself is accepted for the prototype).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
MAX_INDEX = 500  # retention: newest 500 entries+files; older files deleted on save


def _data_dir() -> Path:
    override = os.environ.get("ECDAT_DATA_DIR", "")
    return Path(override) if override else BASE / ".data"


def _scans_dir() -> Path:
    return _data_dir() / "scans"


def _index_file() -> Path:
    return _scans_dir() / "index.json"


def triage_file() -> Path:
    return _data_dir() / "triage.json"


def _atomic_write(path: Path, obj: object) -> None:
    """Write JSON atomically: temp file in the same dir, fsync, os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass  # either replaced (gone) or never created


def _read_json(path: Path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def valid_id(sid: object) -> bool:
    return isinstance(sid, str) and ID_RE.fullmatch(sid) is not None


def counts_for(report: dict) -> dict:
    components = report.get("components", []) if isinstance(report, dict) else []
    analysis = report.get("codeAnalysis") or {}
    code = analysis.get("findings", []) if isinstance(analysis, dict) else []
    critical = high = 0
    for c in components:
        if not isinstance(c, dict):
            continue
        if c.get("severity") == "critical":
            critical += 1
        elif c.get("severity") == "high":
            high += 1
    n_crypto = sum(1 for c in components if isinstance(c, dict))
    n_code = sum(1 for c in code if isinstance(c, dict))
    return {"crypto": n_crypto, "critical": critical, "high": high,
            "code": n_code, "total": n_crypto + n_code}


def scan_record(sid: str, report: dict, target: str = "",
                profile: str = "local", duration_s: float = 0.0) -> dict:
    """Build the persisted record. The report is stored verbatim (already
    redacted upstream — this layer invents no second secret system)."""
    source = report.get("source") if isinstance(report, dict) else None
    source = source if isinstance(source, dict) else {}
    if not target and isinstance(report, dict):
        target = str((report.get("metadata") or {}).get("scanTarget", ""))
    migration = report.get("migration") if isinstance(report, dict) else None
    return {
        "id": sid,
        "timestamp": time.time(),
        "target": str(target or "")[:512],
        "source": {k: source.get(k) for k in (
            "type", "owner", "repo", "sha", "ref_requested", "profile",
            "canonical_url") if source.get(k) is not None},
        "profile": str(profile or "local")[:64],
        "status": "complete",
        "counts": counts_for(report),
        "migration_summary": migration if isinstance(migration, dict) else {},
        "report": report,
        "duration_s": round(float(duration_s or 0.0), 2),
    }


def _index_entry(record: dict) -> dict:
    """Compact history shape (counts only, never findings)."""
    source = record.get("source") or {}
    return {
        "scan_id": record.get("id", ""),
        "target": record.get("target", ""),
        "source_type": source.get("type", "local"),
        "owner": source.get("owner", ""),
        "repo": source.get("repo", ""),
        "sha": source.get("sha", ""),
        "ref_requested": source.get("ref_requested", ""),
        "profile": record.get("profile", ""),
        "timestamp": record.get("timestamp", 0.0),
        "duration_s": record.get("duration_s", 0.0),
        "status": record.get("status", "complete"),
        "counts": record.get("counts", {}),
    }


def save_scan(record: dict) -> dict:
    sid = record.get("id", "")
    if not valid_id(sid):
        raise ValueError("invalid scan id")
    _atomic_write(_scans_dir() / f"{sid}.json", record)
    raw = _read_json(_index_file())
    # A corrupt index must not wipe existing pointers: rebuild from files first.
    entries = [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else _rebuild_index()
    entries = [e for e in entries if e.get("scan_id") != sid]
    entries.append(_index_entry(record))
    entries.sort(key=lambda e: e.get("timestamp", 0.0))
    kept = entries[-MAX_INDEX:]
    for stale in entries[:len(entries) - len(kept)]:
        eid = stale.get("scan_id", "")
        if valid_id(eid) and eid != sid:
            try:
                (_scans_dir() / f"{eid}.json").unlink()
            except OSError:
                pass  # retention is best-effort; the index stays authoritative
    _atomic_write(_index_file(), kept)
    return record


def get_scan(sid: str):
    """Return the full record, or None. Unparseable files are quarantined
    aside (renamed, never deleted) so one bad record cannot break history.
    Unreadable files (permissions) are left alone — not corruption."""
    if not valid_id(sid):
        return None
    path = _scans_dir() / f"{sid}.json"
    try:
        with open(path, encoding="utf-8") as fh:
            record = json.load(fh)
    except FileNotFoundError:
        return None
    except PermissionError:
        return None
    except (ValueError, OSError):
        record = None
    if isinstance(record, dict) and isinstance(record.get("report"), dict):
        return record
    if path.is_file():
        try:
            path.rename(path.parent / f"{sid}.corrupt-{time.time_ns()}.json")
        except OSError:
            pass
    return None


def _rebuild_index() -> list:
    entries = []
    try:
        files = sorted(_scans_dir().glob("*.json"))
    except OSError:
        return []
    for path in files:
        if path.name == "index.json" or ".corrupt-" in path.name:
            continue
        record = _read_json(path)
        if isinstance(record, dict) and isinstance(record.get("report"), dict):
            entries.append(_index_entry(record))
    entries.sort(key=lambda e: e.get("timestamp", 0.0))
    return entries[-MAX_INDEX:]


def list_scans() -> list:
    """Newest first. A corrupt/missing index is rebuilt from scan files;
    entries whose file is gone or corrupt are dropped (index rewritten)."""
    raw = _read_json(_index_file())
    if not isinstance(raw, list):
        raw = []
    live = [e for e in raw if isinstance(e, dict) and get_scan(str(e.get("scan_id", ""))) is not None]
    if len(live) != len([e for e in raw if isinstance(e, dict)]):
        try:
            _atomic_write(_index_file(), sorted(
                live, key=lambda e: e.get("timestamp", 0.0)))
        except OSError:
            pass
    if not raw:
        live = [e for e in _rebuild_index()
                if get_scan(str(e.get("scan_id", ""))) is not None]
    live.sort(key=lambda e: e.get("timestamp", 0.0), reverse=True)
    return live


def get_latest():
    scans = list_scans()
    return scans[0] if scans else None


def get_previous():
    scans = list_scans()
    return scans[1] if len(scans) > 1 else None


def delete_scan(sid: str) -> bool:
    if not valid_id(sid):
        return False
    removed = False
    try:
        path = _scans_dir() / f"{sid}.json"
        if path.is_file():
            path.unlink()
            removed = True
    except OSError:
        return False
    try:
        raw = _read_json(_index_file()) or []
        kept = [e for e in raw if not (isinstance(e, dict) and e.get("scan_id") == sid)]
        if len(kept) != len(raw):
            _atomic_write(_index_file(), kept)
            removed = True
    except OSError:
        pass
    return removed


def load_triage() -> dict:
    """Rebuild the (scope, fingerprint) -> entry dict.

    Legacy statuses migrate via history.migrate_status (single authority).
    Overlay only — never touches finding evidence.
    """
    from .sources.history import migrate_status  # deferred: avoids import cycle

    raw = _read_json(triage_file())
    store: dict = {}
    if isinstance(raw, list):
        for e in raw:
            if (isinstance(e, dict) and isinstance(e.get("scope"), str)
                    and isinstance(e.get("fingerprint"), str)
                    and isinstance(e.get("status"), str)):
                e = dict(e)
                e["status"] = migrate_status(e["status"])
                store[(e["scope"], e["fingerprint"])] = e
    return store


def save_triage(store: dict) -> None:
    _atomic_write(triage_file(), sorted(
        (dict(v) for v in store.values() if isinstance(v, dict)),
        key=lambda e: str(e.get("timestamp", ""))))

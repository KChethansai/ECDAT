"""Agent registry: configured agents + live availability probes. Never mark missing as ready."""

from __future__ import annotations

import shutil
from pathlib import Path

from .config import load_registry


def _which(cmd: str, alternates: list[str] | None = None) -> str | None:
    for c in [cmd, *(alternates or [])]:
        if found := shutil.which(c):
            return found
    return None


def status(registry_path: Path | None = None) -> list[dict]:
    agents = load_registry(registry_path)
    out = []
    for a in agents:
        exe = _which(a["command"], a.get("alternates"))
        out.append({**a, "available": exe is not None, "resolved": exe})
    return out


def get(name: str, registry_path: Path | None = None) -> dict:
    for a in status(registry_path):
        if a["name"] == name:
            return a
    raise KeyError(f"unknown agent: {name}")

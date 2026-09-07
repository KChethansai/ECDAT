"""Configuration: vault path resolution + registry loading. No hard-coded machine paths."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
CLI_ROOT = PACKAGE_DIR.parent.parent  # sih26164/cli-agent/
WORKSPACE_ROOT = CLI_ROOT.parent.parent  # <WORKSPACE_ROOT>/
BACKEND_ROOT = WORKSPACE_ROOT / "sih26164" / "web-app" / "backend"
REGISTRY_FILE = CLI_ROOT / "config" / "agents.json"


def resolve_vault_path(explicit: str | None = None) -> Path:
    """Single mechanism lives in backend app.project_memory (stdlib-only).

    Priority: explicit --vault > deployment config > OBSIDIAN_VAULT_PATH >
    user-local ~/Documents/Vaults/SIH. The developer path is never a default.
    """
    if str(BACKEND_ROOT) not in sys.path:
        sys.path.insert(0, str(BACKEND_ROOT))
    from app.project_memory import resolve_vault_path as shared

    return shared(explicit).resolve()


def load_registry(path: Path | None = None) -> list[dict]:
    fp = path or REGISTRY_FILE
    with open(fp, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["agents"]

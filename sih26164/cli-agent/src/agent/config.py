"""Configuration: vault path resolution + registry loading. No hard-coded machine paths."""

from __future__ import annotations

import json
import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
CLI_ROOT = PACKAGE_DIR.parent.parent  # sih26164/cli-agent/
WORKSPACE_ROOT = CLI_ROOT.parent.parent  # <WORKSPACE_ROOT>/
# Authoritative ECDAT vault (Phase 9 migration). Overridable via OBSIDIAN_VAULT_PATH.
DEFAULT_VAULT = Path("/home/chethan/Documents/Vaults/SIH")
LEGACY_VAULT = WORKSPACE_ROOT / "obsidian-vault"  # frozen reference; no new writes
REGISTRY_FILE = CLI_ROOT / "config" / "agents.json"


def resolve_vault_path(explicit: str | None = None) -> Path:
    """Explicit --vault wins; then OBSIDIAN_VAULT_PATH; then workspace default."""
    if explicit:
        return Path(explicit).expanduser().resolve()
    if env := os.environ.get("OBSIDIAN_VAULT_PATH"):
        return Path(env).expanduser().resolve()
    return DEFAULT_VAULT.resolve()


def load_registry(path: Path | None = None) -> list[dict]:
    fp = path or REGISTRY_FILE
    with open(fp, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["agents"]

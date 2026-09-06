"""Acceptance: two GENUINELY FRESH processes share knowledge only via Vault Markdown.

Session 1 (process A): set key -> exit. Session 2 (process B): get key -> must print value.
Fails if the value comes from process memory, hardcode, cache, or a database: both
processes are spawned fresh with only OBSIDIAN_VAULT_PATH in common, and the test asserts
the value exists as literal text inside a .md file under the vault.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

CLI_ROOT = Path(__file__).resolve().parent.parent
SRC = CLI_ROOT / "src"
SHIM = CLI_ROOT / "scripts" / "agent"


def _run(vault: Path, *args: str) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", ""),
           "OBSIDIAN_VAULT_PATH": str(vault), "PYTHONPATH": str(SRC)}
    return subprocess.run([sys.executable, str(SHIM), "--vault", str(vault), *args],
                          capture_output=True, text=True, env=env, timeout=60)


def test_two_process_memory_persistence(tmp_path):
    vault = tmp_path / "vault"
    assert _run(vault, "init").returncode == 0
    key = f"acceptance.{uuid.uuid4().hex[:8]}"
    assert _run(vault, "memory", "set", key, "qrqc-2035").returncode == 0
    # process A is dead here; process B starts fresh:
    got = _run(vault, "memory", "get", key)
    assert got.returncode == 0 and "qrqc-2035" in got.stdout
    # and the bytes really live in a Markdown file (no DB, no hardcode):
    md_files = list(vault.rglob("*.md"))
    assert md_files and any("qrqc-2035" in p.read_text() for p in md_files)


def test_two_process_scan_summary_persistence(tmp_path):
    vault = tmp_path / "vault"
    sample = CLI_ROOT.parent / "web-app" / "backend" / "samples" / "vuln_sample"
    assert _run(vault, "scan", str(sample)).returncode == 0
    # A separate process retrieves knowledge from the Markdown vault, not process state.
    got = _run(vault, "memory", "search", "RSA critical")
    assert got.returncode == 0 and "07-Sessions/Scans/" in got.stdout
    summaries = list((vault / "07-Sessions" / "Scans").glob("*.md"))
    assert len(summaries) == 1 and "ML-KEM" in summaries[0].read_text()

"""Minimal orchestration: plan (GSD-lite) + verify. Heavy lifting stays in providers."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from .context import build_context
from .memory import ObsidianVaultProvider


def plan(mem: ObsidianVaultProvider, goal: str) -> str:
    """Write a small plan note under 05-Tasks/ and return its vault path."""
    ctx = build_context(mem, goal)
    slug = "".join(c if c.isalnum() else "-" for c in goal.lower())[:40].strip("-") or "task"
    rel = f"05-Tasks/{time.strftime('%Y-%m-%d')}-{slug}.md"
    n = 1
    while (mem.vault / rel).exists():  # never silently overwrite an existing plan
        n += 1
        rel = f"05-Tasks/{time.strftime('%Y-%m-%d')}-{slug}-{n}.md"
    mem.write(rel, f"# Plan: {goal}\n\n## Goal\n{goal}\n\n## Context sources\n{ctx[:2000]}\n\n"
                   "## Steps\n1. Implement smallest change\n2. Run tests\n3. Verify + persist learning\n")
    return rel


def verify(cli_root: Path) -> dict:
    """Run the CLI test suite; return a small result dict."""
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q"], capture_output=True,
                          text=True, cwd=str(cli_root),
                          timeout=300)  # noqa: S603 (same-interpreter pytest)
    return {"ok": proc.returncode == 0, "returncode": proc.returncode,
            "tail": (proc.stdout + proc.stderr)[-2000:]}

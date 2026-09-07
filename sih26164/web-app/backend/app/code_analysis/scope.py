"""Bounded, jailed file scope for static analysis. Never executes target code."""

from __future__ import annotations

from pathlib import Path

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 2000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".idea", "vendor", "target", "out", "coverage", ".next", ".nuxt", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", ".planning", "graphify-out"}

PYTHON_EXTS = {".py"}
JS_EXTS = {".js", ".jsx", ".ts", ".tsx"}
CONFIG_NAMES = {"requirements.txt", "package.json", "pyproject.toml", "Cargo.toml",
                "go.mod", "pom.xml", "build.gradle", "setup.cfg", "Pipfile",
                ".env.example", "docker-compose.yml", "docker-compose.yaml"}


def language_of(path: Path) -> str:
    name, suffix = path.name, path.suffix.lower()
    if suffix in PYTHON_EXTS:
        return "python"
    if suffix in JS_EXTS:
        return "javascript"
    if name in CONFIG_NAMES or suffix in (".json", ".toml", ".yaml", ".yml", ".cfg",
                                          ".ini", ".txt", ".gradle", ".xml"):
        return "config"
    return "other"


def iter_files(root: Path, languages: set[str] | None = None) -> list[Path]:
    """Sorted, capped, symlink-free file list under root. Deterministic order."""
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if languages and language_of(path) not in languages:
            continue
        out.append(path)
        if len(out) >= MAX_FILES:
            break
    return out


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError, ValueError):
        return None


def redact(text: str, limit: int = 160) -> str:
    """Truncate evidence; never leak long lines that may hold secrets."""
    one_line = " ".join(text.split())
    return one_line[:limit]

"""Declared-vs-imported dependency analysis. Conservative by design.

A dependency is flagged unused only when no module imports its normalized name
AND no dynamic-loading marker mentions it. Framework entry points stay silent.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import CodeFinding
from .scope import read_text, redact
from .symbols import ModuleInfo

PY_STDLIB = {"os", "sys", "re", "json", "pathlib", "ast", "hashlib", "subprocess",
             "threading", "time", "datetime", "typing", "dataclasses", "socket", "ssl",
             "http", "urllib", "collections", "itertools", "functools", "io", "shutil",
             "tempfile", "unittest", "pytest", "math", "random", "string", "enum",
             "abc", "copy", "logging", "argparse", "csv", "sqlite3", "email", "base64"}


def _normalize_dep(name: str) -> str:
    return re.split(r"[<>=!~\s\[]", name.strip().lower().replace("-", "_"))[0].strip()


# Distribution name -> import name for common mismatches. Absence here degrades
# to a LOW-confidence POTENTIAL finding, never a wrong confirmation.
DIST_TO_IMPORT = {"pillow": "pil", "beautifulsoup4": "bs4", "scikit_learn": "sklearn",
                  "scikit_image": "skimage", "pyyaml": "yaml", "python_dateutil": "dateutil",
                  "opencv_python": "cv2", "protobuf": "google"}


def _import_names_for(dep: str) -> set[str]:
    return {dep, DIST_TO_IMPORT.get(dep, dep)}


def _declared(root: Path) -> dict[str, dict]:
    """dep-name -> {file, line, dev}."""
    declared: dict[str, dict] = {}
    req = root / "requirements.txt"
    if req.is_file() and not req.is_symlink():
        text = read_text(req) or ""
        for lineno, line in enumerate(text.splitlines(), 1):
            clean = line.strip()
            if not clean or clean.startswith(("#", "-")):
                continue
            declared[_normalize_dep(clean)] = {"file": "requirements.txt",
                                               "line": lineno, "dev": False}
    pkg = root / "package.json"
    if pkg.is_file() and not pkg.is_symlink():
        try:
            data = json.loads(read_text(pkg) or "")
            for section, dev in (("dependencies", False), ("devDependencies", True)):
                section_data = data.get(section) or {}
                if isinstance(section_data, dict):
                    for name in section_data:
                        declared[_normalize_dep(str(name))] = {
                            "file": "package.json", "line": 0, "dev": dev}
        except (ValueError, AttributeError):
            pass
    return declared


def _imported_names(modules: dict[str, ModuleInfo]) -> set[str]:
    names: set[str] = set()
    for mod in modules.values():
        for info in mod.imports.values():
            source = str(info.get("source") or "")
            top = source.lstrip(".").split("/")[0].split(".")[0].lower().replace("-", "_")
            if top and not top.startswith("__import"):
                names.add(top)
        for text in mod.strings:
            lowered = text.lower()
            if "require(" in lowered or "import " in lowered:
                for token in re.findall(r"[a-z0-9_@/-]+", lowered):
                    names.add(token.replace("-", "_").split("/")[-1])
    return names


def analyze(root: Path, modules: dict[str, ModuleInfo]) -> list[CodeFinding]:
    declared = _declared(root)
    if not declared:
        return []
    imported = _imported_names(modules)
    dynamic_blob = " ".join(
        s.lower() for mod in modules.values() for s in mod.strings[:50])
    findings: list[CodeFinding] = []
    for name, info in sorted(declared.items()):
        if not name or name in PY_STDLIB:
            continue
        if _import_names_for(name) & imported:
            continue
        if name in dynamic_blob or mod_dynamic(name, modules):
            continue  # dynamically referenced — silence, not certainty
        findings.append(CodeFinding(
            analyzer="dependencies", category="DEPENDENCY",
            file_path=info["file"], line=info["line"], symbol=name,
            title=f"Possibly unused dependency `{name}`",
            description=(f"`{name}` is declared in `{info['file']}` but no static import "
                         f"was found in the analyzed scope."),
            evidence=redact(f"declared {name} in {info['file']}, no imports"),
            confidence="LOW", verdict="POTENTIAL_DEAD_CODE", impact="LOW",
            effort="SMALL", risk="MEDIUM",
            rationale="Unused dependencies slow installs and widen supply-chain surface; "
                      "dynamic loading is the false-positive risk.",
            verification="Confirm with the package manager / bundler, remove, reinstall, run tests.",
            deterministic=True))
    return findings


def mod_dynamic(name: str, modules: dict[str, ModuleInfo]) -> bool:
    return any(name in mod.names_used for mod in modules.values())

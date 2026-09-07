"""Project-structure observations: orphans, duplicate configs, stale artifacts."""

from __future__ import annotations

from pathlib import Path

from .models import CodeFinding
from .scope import CONFIG_NAMES, redact
from .symbols import ModuleInfo, cross_references

ENTRY_FILES = {"__init__.py", "__main__.py", "main.py", "app.py", "cli.py", "manage.py",
               "setup.py", "conftest.py", "index.js", "index.ts", "main.js", "main.ts",
               "App.jsx", "App.tsx", "vite.config.js", "vite.config.ts"}
CONFIG_GROUPS = ({"requirements.txt", "pyproject.toml", "setup.cfg", "Pipfile"},
                 {".env.example", ".env"})


def analyze(root: Path, files: list[Path],
            modules: dict[str, ModuleInfo]) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    refs = cross_references(modules)
    imported_files: set[str] = set()
    for mod in modules.values():
        for info in mod.imports.values():
            imported_files.add(str(info.get("source") or ""))

    for rel, mod in sorted(modules.items()):
        if mod.path.name in ENTRY_FILES or "__init__" in mod.path.name:
            continue
        name = mod.path.stem
        linked = (name in refs or any(name in src for src in imported_files))
        if not linked and mod.language == "python":
            findings.append(CodeFinding(
                analyzer="structure", category="STRUCTURE", file_path=rel, line=0,
                symbol=name,
                title=f"Possibly orphaned module `{rel}`",
                description=(f"No static import of `{rel}` was found — possibly abandoned, "
                             f"possibly an undocumented entry point."),
                evidence=redact(f"module {rel} with no inbound references"),
                confidence="LOW", verdict="OBSERVATION", impact="LOW",
                effort="SMALL", risk="MEDIUM",
                rationale="Orphans may be dead weight or undocumented entry points.",
                verification="Check docs/routes/registries for references before removing.",
                deterministic=True))

    present_configs = sorted({p.name for p in files if p.name in CONFIG_NAMES})
    for group in CONFIG_GROUPS:
        hit = sorted(set(present_configs) & group)
        if len(hit) > 1:
            findings.append(CodeFinding(
                analyzer="structure", category="CONFIGURATION", file_path=hit[0], line=0,
                title=f"Overlapping configuration: {', '.join(hit)}",
                description=(f"Multiple files cover the same configuration concern "
                             f"({', '.join(hit)}). Confirm they agree or consolidate."),
                evidence=redact(f"config overlap: {', '.join(hit)}"),
                confidence="MEDIUM", verdict="OBSERVATION", impact="LOW",
                effort="SMALL", risk="LOW",
                rationale="Split configuration drifts out of sync silently.",
                verification="Diff effective settings from each source; consolidate if redundant.",
                related_files=hit,
                deterministic=True))

    return findings

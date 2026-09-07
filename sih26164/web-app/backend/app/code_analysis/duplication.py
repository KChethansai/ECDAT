"""Duplicate-block detection via normalized hashing. Only reports useful sizes."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .models import CodeFinding
from .scope import language_of, read_text, redact

MIN_LINES = 6        # smaller repeats are noise, not findings
MIN_OCCURRENCES = 2
MAX_BUCKETS = 20000  # global cap: analysis stays bounded on huge repos


def _normalize(lines: list[str], near: bool) -> str:
    out = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        if near:
            stripped = re.sub(r"\b0x[0-9a-fA-F]+\b|\b\d+(\.\d+)?\b", "<NUM>", stripped)
            stripped = re.sub(r"'[^']*'|\"[^\"]*\"", "<STR>", stripped)
        out.append(stripped)
    return "\n".join(out)


def analyze(root: Path, files: list[Path]) -> list[CodeFinding]:
    buckets: dict[str, list[dict]] = {}
    for path in files:
        if len(buckets) >= MAX_BUCKETS:
            break  # bounded: earliest (sorted) files win; noted in metrics via counts
        if language_of(path) not in ("python", "javascript"):
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            continue
        text = read_text(path)
        if text is None:
            continue
        lines = text.splitlines()
        if len(lines) > 2000:
            continue  # ponytail: huge files skipped for dup scan; AST analyzers still cover them
        for width in (12, 8, MIN_LINES):
            for start in range(0, max(len(lines) - width + 1, 0)):
                for near in (False, True):
                    key = _normalize(lines[start:start + width], near)
                    if key.count("\n") + 1 < MIN_LINES:
                        continue
                    digest = hashlib.sha1(key.encode()).hexdigest()[:16]  # noqa: S324
                    buckets.setdefault(("near" if near else "exact") + digest, []).append(
                        {"rel": rel, "start": start + 1, "width": width})
    candidates = []
    for key, occurrences in buckets.items():
        unique_files = sorted({o["rel"] for o in occurrences})
        if len(occurrences) < MIN_OCCURRENCES:
            continue
        cross = len(unique_files) > 1
        near = key.startswith("near")
        if not cross and near:
            continue  # same-file near-dups are usually intentional variants
        candidates.append((occurrences[0]["width"], key, occurrences, unique_files))
    # Widest windows first; accept only spans not already covered in the same file.
    candidates.sort(key=lambda c: (-c[0], c[1]))
    covered: dict[str, list[tuple[int, int]]] = {}
    findings: list[CodeFinding] = []
    for width, key, occurrences, unique_files in candidates:
        if len(unique_files) == 1 and width < 12:
            continue  # small same-file repeats are idioms, not findings
        first = occurrences[0]
        spans = covered.setdefault(first["rel"], [])
        if any(s <= first["start"] <= e for s, e in spans):
            continue
        spans.append((first["start"], first["start"] + width))
        cross = len(unique_files) > 1
        near = key.startswith("near")
        locations = ", ".join(f"{o['rel']}:{o['start']}" for o in occurrences[:5])
        findings.append(CodeFinding(
            analyzer="duplication", category="DUPLICATION", file_path=first["rel"],
            line=first["start"], end_line=first["start"] + first["width"],
            title=f"{'Near-duplicate' if near else 'Duplicate'} block ({len(occurrences)}×, ~{first['width']} lines)",
            description=(f"{'Similar' if near else 'Identical'} code appears {len(occurrences)} times "
                         f"across {len(unique_files)} file(s): {locations}."
                         f"{'' if cross else ' Same-file repeat — consolidation optional.'}"),
            evidence=redact(f"repeated block at {locations}"),
            confidence="MEDIUM" if cross and not near else "LOW",
            verdict="OBSERVATION", impact="MEDIUM" if cross else "LOW",
            effort="MEDIUM", risk="MEDIUM",
            rationale="Consolidation reduces drift; merging distinct behaviors by mistake is the risk.",
            related_files=unique_files[:8],
            verification="Extract shared helper, re-run tests, confirm no behavior change.",
            deterministic=True))
        if len(findings) >= 100:
            break
    return sorted(findings, key=lambda f: (f.file_path, f.line))

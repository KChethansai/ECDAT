"""Shared ECDAT domain pipeline used by the API and the developer CLI."""

from __future__ import annotations

from pathlib import Path

from .cbom import build_cbom
from .models import normalize_findings
from .recommend import recommend
from .risk import assess
from .scanner import (BinaryScanner, CloudCryptoScanner, ContainerScanner, HSMScanner,
                      LibraryScanner, SourceScanner)


SCANNERS = {"source": SourceScanner(), "binary": BinaryScanner(),
            "container": ContainerScanner(), "library": LibraryScanner(),
            "hsm": HSMScanner(), "cloud": CloudCryptoScanner()}


def run_scan(target: str | Path, scanners: list[str] | None = None,
             data_years: float = 10.0, migration_years: float = 3.0,
             qrqc_years_left: float = 10.0, context_provenance: dict | None = None) -> dict:
    """Run discovery, risk, recommendations, and CBOM through one code path."""
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan target missing: {target}")
    selected = scanners or ["source"]
    unknown = [name for name in selected if name not in SCANNERS]
    if unknown:
        raise ValueError(f"unknown scanners: {unknown}")
    findings = []
    for name in dict.fromkeys(selected):
        findings.extend(SCANNERS[name].scan(root))
    enriched = assess(normalize_findings(findings), data_years, migration_years, qrqc_years_left)
    for finding in enriched:
        finding["recommendation"] = recommend(finding["algorithm"])
    return build_cbom(str(root), enriched, context_provenance, list(dict.fromkeys(selected)))

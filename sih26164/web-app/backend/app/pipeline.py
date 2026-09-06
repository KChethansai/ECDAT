"""Shared ECDAT domain pipeline used by the API and the developer CLI."""

from __future__ import annotations

import re
from pathlib import Path

from .cbom import build_cbom
from .models import normalize_findings
from .recommend import recommend
from .risk import assess, base_algorithm
from .scanner import (BinaryScanner, CloudScanner, ContainerScanner, DependencyScanner,
                      HSMScanner, RuntimeScanner, SourceScanner)
from .scanner.runtime_scanner import RuntimeUnavailableError, TIMEOUT_SECS


SCANNERS = {"source": SourceScanner(), "binary": BinaryScanner(),
            "container": ContainerScanner(), "dependency": DependencyScanner(),
            "hsm": HSMScanner(), "cloud": CloudScanner(), "runtime": RuntimeScanner()}
REAL_SCANNERS = ["source", "binary", "container", "dependency", "hsm", "cloud"]


def _canon(algorithm: str) -> str:
    """Correlation key: family-level match so SHA-256 links SHA-2 evidence, etc.

    Used ONLY for static/runtime linking. Risk and recommendations keep using
    base_algorithm unchanged.
    """
    base = base_algorithm(algorithm)
    if re.fullmatch(r"SHA[-_ ]?(224|256|384|512)", base):
        return "SHA-2"
    if base.startswith("HMAC"):
        return "HMAC"
    if base in ("PBKDF2", "KDF"):
        return "KDF"
    if base.startswith("TLS"):
        return "TLS"
    return base


def correlate(enriched: list[dict]) -> None:
    """Link runtime observations to same-family static evidence (in place).

    Only stable family identifiers drive links, capped per finding.
    Correlation enriches context; it never changes scores or merges findings.
    """
    static_ids: dict[str, list[str]] = {}
    for row in enriched:
        if row.get("scanner") != "runtime" and not row.get("is_mock"):
            static_ids.setdefault(_canon(row["algorithm"]), []).append(row["id"])
    for row in enriched:
        if row.get("scanner") != "runtime":
            continue
        supports = static_ids.get(_canon(row["algorithm"]), [])[:5]
        row["correlation"] = {
            "supports": supports,
            "note": ("Runtime observation supported by matching static evidence."
                     if supports else "No matching static evidence in this scan."),
        }


def run_scan(target: str | Path, scanners: list[str] | None = None,
             data_years: float = 10.0, migration_years: float = 3.0,
             qrqc_years_left: float = 10.0, context_provenance: dict | None = None,
             runtime: bool = False) -> dict:
    """Run discovery, risk, recommendations, and CBOM through one code path.

    `runtime` is explicit opt-in only: it executes the bundled first-party probe
    under timeout/isolation (see runtime_scanner). Static scans never execute.
    """
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan target missing: {target}")
    selected = scanners or list(REAL_SCANNERS)
    unknown = [name for name in selected if name not in SCANNERS]
    if unknown:
        raise ValueError(f"unknown scanners: {unknown}")
    findings = []
    for name in dict.fromkeys(selected):
        findings.extend(SCANNERS[name].scan(root))
    runtime_provenance: dict = {"available": False}
    if runtime:
        try:
            runtime_findings = RuntimeScanner().scan(root)
            findings.extend(runtime_findings)
            runtime_provenance = {"available": True, "probe": "crypto_probe",
                                  "events": len(runtime_findings),
                                  "timeoutSecs": TIMEOUT_SECS}
        except RuntimeUnavailableError as exc:
            runtime_provenance = {"available": False, "reason": str(exc)}
    enriched = assess(normalize_findings(findings), data_years, migration_years, qrqc_years_left)
    for finding in enriched:
        finding["recommendation"] = recommend(finding["algorithm"])
    correlate(enriched)
    sources = list(dict.fromkeys(selected))
    if runtime and runtime_provenance.get("available") and "runtime" not in sources:
        sources.append("runtime")
    return build_cbom(str(root), enriched, context_provenance, sources, runtime_provenance)

"""Deterministic validation-strategy selector.

Maps a static finding to the validator that can observe it — or to no
validator, with an honest reason. No LLM, no heuristics beyond this table:
algorithm family + category + usage decide. Unknown findings never get
automatic active validation.
"""

from __future__ import annotations

from ..risk import base_algorithm

# (validator, reason-template)
TLS_ALGOS = {"RSA", "ECDSA", "ECC", "DSA", "DH", "ECDH", "TLS", "SSL",
             "TLS10", "TLS11", "TLS12", "TLS13", "PEM", "KEYFILE"}
TLS_CATEGORIES = {"certificate", "protocol", "key"}
RUNTIME_CATEGORIES = {"library", "symmetric", "asymmetric", "hash"}


def strategy_for(finding: dict) -> tuple[str | None, str]:
    """Return (validator_type, reason). validator_type is None when no
    automatic active validation applies."""
    if not isinstance(finding, dict):
        return None, "finding is not a mapping"
    if finding.get("is_mock"):
        return None, "mock findings are never actively validated"
    base = base_algorithm(str(finding.get("algorithm") or ""))
    category = finding.get("category") or ""
    usage = finding.get("usage") or ""
    if usage == "dependency integrity metadata":
        return None, "lockfile integrity metadata is not runtime-probed"
    if category in ("certificate", "protocol") or (
            base in TLS_ALGOS and category in TLS_CATEGORIES):
        return "tls", f"{base} {category} evidence maps to TLS/certificate observation"
    if category in RUNTIME_CATEGORIES and base not in ("UNKNOWN", ""):
        return "runtime", f"{base} {category} evidence maps to runtime crypto observation"
    if category == "dependency":
        return "runtime", "dependency reference maps to runtime library-usage observation"
    return None, f"no automatic validator for {base or 'unknown'} {category or 'unclassified'} evidence"

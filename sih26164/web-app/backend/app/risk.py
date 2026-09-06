"""Quantum-risk engine: Mosca's inequality + severity tiers (stdlib only)."""

from __future__ import annotations

import re

QUANTUM_VULNERABLE = {"RSA", "DSA", "DH", "ECDSA", "ECDH", "ECC"}
WEAK_CLASSICAL = {"DES", "3DES", "RC4", "MD5", "SHA-1", "SSL", "TLS1.0", "TLS1.1", "Blowfish"}
SHORT_RSA_BITS = 2048  # < 2048 is classically weak regardless of quantum
# Heuristic assumption: symmetric/hash/library artefacts at sane strengths are not
# harvest-now-decrypt-later targets (Grover only halves effective strength), so Mosca
# exposure is tracked for asymmetric + weak-classical findings. Revisit with policy input.
MOSCA_EXEMPT = {"AES", "SHA-2", "SHA-3", "KDF", "STDLIB", "PyCA", "JCA", "WebCrypto",
                "NaCl/PGP", "OpenSSL", "HMAC"}


def canon(algorithm: str) -> str:
    """Family-level canonical key so SHA-256 links SHA-2 evidence, etc.

    Used ONLY for correlation/inventory grouping. Risk and recommendations keep
    using base_algorithm unchanged.
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


def base_algorithm(name: str) -> str:
    n = name.upper()
    if n.startswith("AES"): return "AES"
    if n.startswith("RSA"): return "RSA"
    if n.startswith("TLS"): return n.replace(".", "")
    if n.startswith("SHA-2"): return "SHA-2"
    if n.startswith("PEM-"): return "PEM"
    return n


def mosca_exposed(data_years: float, migration_years: float, qrqc_years_left: float) -> bool:
    """Mosca: data_lifetime + migration_time > time until QRQC => harvest-now-decrypt-later risk."""
    return (data_years + migration_years) > qrqc_years_left


def severity(finding_algo: str, key_size: int | None, exposed: bool) -> str:
    base = base_algorithm(finding_algo)
    if base in QUANTUM_VULNERABLE:
        if key_size is not None and base == "RSA" and key_size < SHORT_RSA_BITS:
            return "critical"  # weak now AND quantum-broken later
        return "critical" if exposed else "high"
    if base in WEAK_CLASSICAL:
        return "high" if exposed else "medium"
    return "medium" if exposed else "low"


def priority(finding: dict, exposed: bool) -> tuple[int, list[str]]:
    """Explainable deterministic ordering; it is not a QRQC prediction."""
    base = base_algorithm(finding["algorithm"])
    score, factors = 0, []
    if base in WEAK_CLASSICAL:
        score += 70
        factors.append("obsolete or classically weak algorithm")
    if base in QUANTUM_VULNERABLE:
        score += 45
        factors.append("quantum-vulnerable public-key cryptography")
    if base == "RSA" and finding.get("key_size") and finding["key_size"] < SHORT_RSA_BITS:
        score += 35
        factors.append(f"RSA key below {SHORT_RSA_BITS} bits")
    if base in {"SSL", "TLS10", "TLS11"}:
        score += 20
        factors.append("legacy protocol version")
    if exposed and base not in MOSCA_EXEMPT:
        score += 25
        factors.append("data lifetime plus migration effort exceeds supplied QRQC horizon")
    if not factors:
        factors.append("inventory and review")
    return min(score, 100), factors


def assess(findings: list, data_years: float = 10.0, migration_years: float = 3.0,
           qrqc_years_left: float = 10.0) -> list[dict]:
    exposed = mosca_exposed(data_years, migration_years, qrqc_years_left)
    out = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        d["mosca_exposed"] = exposed and base_algorithm(d["algorithm"]) not in MOSCA_EXEMPT
        d["severity"] = severity(d["algorithm"], d.get("key_size"), d["mosca_exposed"])
        d["priority_score"], d["risk_factors"] = priority(d, d["mosca_exposed"])
        d["priority"] = ("P0" if d["priority_score"] >= 90 else "P1"
                         if d["priority_score"] >= 65 else "P2"
                         if d["priority_score"] >= 30 else "P3")
        d["rationale"] = d.get("rationale") or "; ".join(d["risk_factors"])
        out.append(d)
    return sorted(out, key=lambda row: (-row["priority_score"], row["file_path"], row["line"],
                                        row["algorithm"]))

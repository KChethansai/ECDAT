"""PQC/hybrid recommendation table keyed by base algorithm (stdlib only)."""

from __future__ import annotations

from .risk import base_algorithm

TABLE: dict[str, dict] = {
    "RSA": {"recommend": "ML-KEM-768 hybrid + ML-DSA-65",
            "notes": "KEX first (Shor breaks RSA); hybrid X25519+ML-KEM for latency-sensitive paths."},
    "ECDSA": {"recommend": "ML-DSA-65 (or SLH-DSA-SHA2-128s for conservative roots)",
              "notes": "Larger sigs (~3KB); batch-verify; watch handshake bloat."},
    "ECC": {"recommend": "ML-KEM-768 / ML-DSA-65", "notes": "Same Shor exposure as RSA."},
    "ECDH": {"recommend": "X25519+ML-KEM-768 hybrid", "notes": "Standard hybrid KEX; minimal latency delta."},
    "DH": {"recommend": "ML-KEM-768", "notes": "Replace finite-field DH outright."},
    "DSA": {"recommend": "ML-DSA-65", "notes": "Legacy; migrate signatures."},
    "DES": {"recommend": "AES-256-GCM", "notes": "Broken classically; urgent."},
    "3DES": {"recommend": "AES-256-GCM", "notes": "Sweet32; migrate."},
    "RC4": {"recommend": "AES-256-GCM / ChaCha20-Poly1305", "notes": "Broken; urgent."},
    "MD5": {"recommend": "SHA-256 / SHA-3-256", "notes": "Collision-broken; not for signatures."},
    "SHA-1": {"recommend": "SHA-256 / SHA-3-256", "notes": "Shattered; migrate certs/code-signing."},
    "SSL": {"recommend": "TLS 1.3", "notes": "All SSL versions insecure."},
    "TLS10": {"recommend": "TLS 1.3 (min 1.2)", "notes": "POODLE/BEAST-era; disable."},
    "TLS11": {"recommend": "TLS 1.3 (min 1.2)", "notes": "Deprecate."},
    "TLS12": {"recommend": "TLS 1.3 + hybrid KEX pilot", "notes": "Plan PQC cipher-suite negotiation."},
    "TLS13": {"recommend": "TLS 1.3 + hybrid KEX pilot", "notes": "Add ML-KEM hybrids where peers allow."},
    "AES": {"recommend": "AES-256-GCM (double key length posture)", "notes": "Grover halves effective strength; 256-bit stays safe."},
    "SHA-2": {"recommend": "SHA-384/SHA-512 or SHA-3", "notes": "Grover margin; prefer 384+ outputs for longevity."},
    "PEM": {"recommend": "Re-issue with PQC/hybrid certs (pilot CA)", "notes": "Inventory first; rotate short-lived."},
    "PKCS11": {"recommend": "Inventory HSM-backed keys; confirm PQC/hybrid support with the HSM vendor",
               "notes": "Hardware protects key material but not the algorithm: RSA/ECC behind PKCS#11 still needs a migration plan. Pilot vendor-supported hybrids; ML-KEM does not drop into every HSM."},
    "HSM": {"recommend": "Inventory HSM integrations; plan PQC migration retaining hardware-backed protection",
            "notes": "Evaluate vendor PQC roadmap first; verify interoperability before any migration pilot."},
    "KMS": {"recommend": "Inventory managed keys; verify provider PQC roadmap and pilot hybrid where supported",
            "notes": "Cloud KMS does not automatically mean quantum-safe: check which algorithms back each key and whether the provider supports hybrid key establishment."},
    "KEYVAULT": {"recommend": "Inventory vault keys/certs; verify provider PQC roadmap and pilot hybrid where supported",
                 "notes": "Same posture as KMS: managed service still needs per-key algorithm inventory."},
    "CLOUDHSM": {"recommend": "Inventory CloudHSM-backed keys; plan PQC migration retaining hardware-backed protection",
                 "notes": "Evaluate provider PQC support; verify before piloting."},
    "TLS": {"recommend": "TLS 1.3 posture + hybrid-KEX pilot",
            "notes": "Confirm version and cipher suites; negotiate hybrid key exchange where peers allow."},
    "ENV-SECRET": {"recommend": "Remove baked-in secret reference; use a secret manager with rotation",
                   "notes": "Hygiene finding, not a primitive: no crypto migration applies."},
}

DEFAULT = {"recommend": "Review manually", "notes": "No canned mapping; assess exposure individually."}


def recommend(algorithm: str) -> dict:
    entry = TABLE.get(base_algorithm(algorithm), DEFAULT)
    return {"algorithm": algorithm, **entry,
            "guidance": "Migration guidance only; validate interoperability, policy, and use case."}

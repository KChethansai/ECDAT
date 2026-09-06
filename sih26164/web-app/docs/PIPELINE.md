# Scanner pipeline

```text
target → SourceScanner (REAL) + BinaryScanner (REAL, static analysis) + ContainerScanner (REAL, static archives) + DependencyScanner (REAL, manifests) + HSMScanner (REAL, config evidence) + CloudScanner (REAL, config evidence) [+ RuntimeScanner (REAL, explicit opt-in probe)]
→ list[CryptoFinding] → risk.assess (Mosca) → recommend (PQC table) → correlate/relate → intelligence (inventory, strength, graph) → migration (status, work items, roadmap) → cbom.build_cbom → GUI/report
```

## Real coverage (SourceScanner)

Algorithms (AES-128/192/256, DES/3DES, ChaCha20, RC4, Blowfish, RSA+key-size,
ECDSA/curves, Ed25519, ECDH, DH, DSA, MD5, SHA-1/2/3, HMAC, bcrypt/scrypt/Argon2/PBKDF2),
protocols (SSLv2/v3, TLS 1.0–1.3), PEM blocks + key-file refs, library imports
(OpenSSL, PyCA, hashlib/node:crypto, JCA, WebCrypto, openpgp/libsodium).
Skips `.git/node_modules/.venv/__pycache__/dist/build/vendor/target/out/coverage`,
framework build dirs (`.next/.nuxt`), and caches (`.tox/.mypy_cache/.pytest_cache/.ruff_cache`),
files >512KB, binary files, and symlinks. Bare `.key` fires only for path-like or
filename-position references, so code attribute access (`args.key`) stays silent.
`key_size`/`key_length` fire only in declaration context (`key_size=2048`,
`key_size: 4096`, `RSA(key_size=1024)`); bare reads (`f.key_size`) stay silent.
Dependency-lockfile integrity hashes (`"integrity": "sha512-…"` in
`package-lock.json`/`yarn.lock`/etc.) are classified as `dependency integrity
metadata` (LOW strength), never as application crypto usage. HSM vendor names are
matched token-aware (`nShield` matches "Thales nShield", not `IconShield`).

## Risk

`mosca_exposed = (data_years + migration_years) > qrqc_years_left`.
Severity: quantum-vulnerable (RSA/ECDSA/ECDH/DH/DSA/ECC) + exposed → critical;
weak classical (DES/RC4/MD5/SHA-1/SSL/TLS≤1.1) → high/medium; else low/medium.
Heuristic, not scientific certainty: symmetric/hash/library artefacts at sane strengths
are exempt from Mosca exposure (Grover-margin assumption, see `MOSCA_EXEMPT` in `risk.py`).

## Handoff to operators

CLI/API → invoke this pipeline (`run_scan()` in `app/pipeline.py`: scanners +
`assess` + `recommend` + correlate/relate + intelligence + migration +
`build_cbom`) → persist durable knowledge to vault (CLI) → surface report in GUI.

## Recommendations (first-pass, verify against NIST PQC + peer constraints before migration)

RSA→ML-KEM-768 hybrid+ML-DSA; ECDH→X25519+ML-KEM hybrid; signatures→ML-DSA/SLH-DSA;
DES/RC4→AES-256-GCM; MD5/SHA-1→SHA-256/3; TLS→1.3+hybrid-KEX pilot; AES→256-bit posture.

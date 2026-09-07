"""Tier-1 cryptography knowledge entries (ECAT-authored normalized summaries).

Source: mukul975/Anthropic-Cybersecurity-Skills @ 54a7988 (Apache-2.0).
Skill automation scripts were never imported or executed; only the published
guidance was distilled. Each entry states what it is, when it applies to an
ECDAT finding, and what an analyst should verify — never new evidence.
"""

# applies: algorithms (base names from risk.base_algorithm + canon families),
#   scanners, categories, usages. matcher.py resolves these deterministically.
CRYPTO_SKILLS = [
    {
        "id": "crypto-audit",
        "source_skill": "performing-cryptographic-audit-of-application",
        "name": "Cryptographic audit methodology",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Systematic review of primitives, protocols, and key management: "
                    "weak algorithms, insecure modes, hardcoded keys, weak KDF parameters, "
                    "protocol misconfigurations."),
        "guidance": [
            "Review application code and configuration files together; crypto often lives in config, not code.",
            "Check third-party dependencies for known crypto vulnerabilities, not just first-party code.",
            "Verify certificates and TLS configurations on deployed servers, not just in the repo.",
            "Flag MD5/SHA-1 for security purposes, ECB mode, hardcoded keys/passwords, and weak KDF parameters.",
            "Load secrets from environment or a vault; never accept them baked into source or images.",
        ],
        "verification": [
            "Re-scan after each fix and confirm the finding (same file/line) is gone.",
            "Confirm severity, location, and remediation are recorded per finding.",
        ],
        "considerations": [
            "Audit on a cadence; crypto drifts as dependencies update.",
            "Track false positives per rule so precision work compounds.",
        ],
        "applies": {
            "algorithms": ["RSA", "DSA", "DH", "ECDSA", "ECDH", "ECC", "AES", "DES", "3DES",
                           "RC4", "BLOWFISH", "MD5", "SHA-1", "SHA-2", "SHA-3", "HMAC", "KDF",
                           "SSL", "TLS", "TLS10", "TLS11", "TLS12", "TLS13", "PEM", "KEYFILE",
                           "KEYSIZE", "OPENSSL", "PYCA", "JCA", "WEBCRYPTO", "NACL", "STDLIB"],
            "scanners": ["source", "binary", "container", "dependency", "hsm", "cloud", "runtime"],
            "categories": ["symmetric", "asymmetric", "hash", "protocol", "library",
                           "certificate", "key", "dependency"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553"]},
    },
    {
        "id": "pqc-migrate",
        "source_skill": "migrating-to-post-quantum-cryptography",
        "name": "Post-quantum migration engineering",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Shor breaks RSA/DH/ECDH/ECDSA; Grover only weakens AES/SHA. Migrate by "
                    "HNDL exposure (Mosca), pilot ML-KEM hybrids, and build crypto-agility."),
        "guidance": [
            "Prioritize by harvest-now-decrypt-later exposure: data lifetime plus migration time vs QRQC horizon.",
            "Pilot hybrid X25519MLKEM768 key exchange with classical fallback before cutover.",
            "Use ML-KEM-768 for key establishment and ML-DSA-65 for signatures (SLH-DSA for conservative roots).",
            "AES needs 256-bit posture, not replacement; SHA needs 384+ outputs, not emergency migration.",
            "Centralize algorithm selection in configuration and schedule inventory re-runs to track residual use.",
        ],
        "verification": [
            "Confirm hybrid group negotiates on a test endpoint before production rollout.",
            "Confirm ML-DSA sign/verify round-trips and certificate chains validate.",
        ],
        "considerations": [
            "OpenSSL 3.5+ exposes ML-KEM/ML-DSA natively; older stacks need oqs-provider.",
            "Larger PQC keys/signatures affect handshake size, storage, and HSM capacity planning.",
            "Verify HSM/KMS PQC support with the vendor — ML-KEM does not drop into every HSM.",
        ],
        "applies": {
            "algorithms": ["RSA", "DSA", "DH", "ECDSA", "ECDH", "ECC", "AES", "SHA-2", "SHA-3",
                           "TLS", "TLS10", "TLS11", "TLS12", "TLS13"],
            "scanners": ["source", "binary", "container", "dependency", "hsm", "cloud", "runtime"],
            "categories": ["symmetric", "asymmetric", "hash", "protocol", "library",
                           "certificate", "key"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-02"],
                       "mitre_attack": ["T1573", "T1573.002", "T1573.001"]},
    },
    {
        "id": "pqc-perform",
        "source_skill": "performing-post-quantum-cryptography-migration",
        "name": "PQC migration planning checklist",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("NIST PQC standards (FIPS 203/204/205, Aug 2024) applied as a migration "
                    "program: roadmap by data sensitivity, capacity planning, HSM/KMS checks."),
        "guidance": [
            "Roadmap migration by data sensitivity and compliance timeline, not by algorithm alphabet.",
            "Account for PQC key/signature size growth in network and storage capacity planning.",
            "Benchmark PQC performance under production load before committing cutover dates.",
            "Confirm CA readiness before planning PQC certificate issuance.",
        ],
        "verification": [
            "HSM/KMS PQC compatibility verified with each vendor in the inventory.",
            "HNDL risk assessed per sensitive-data channel.",
        ],
        "considerations": [
            "Keep SLH-DSA evaluated as a backup signature path for long-lived trust anchors.",
            "Re-run discovery after each migration wave to confirm removal.",
        ],
        "applies": {
            "algorithms": ["RSA", "DSA", "DH", "ECDSA", "ECDH", "ECC"],
            "scanners": ["source", "binary", "container", "hsm", "cloud", "runtime"],
            "categories": ["asymmetric", "certificate", "key"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553"]},
    },
    {
        "id": "rsa-mgmt",
        "source_skill": "implementing-rsa-key-pair-management",
        "name": "RSA key management (NIST SP 800-57)",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("RSA key strength, formats (PEM/DER/PKCS#8), passphrase protection, "
                    "RSA-PSS/OAEP modern padding, restrictive storage, annual rotation."),
        "guidance": [
            "Minimum 3072-bit keys for new deployments; below 2048 bits is classically weak now.",
            "Use RSA-PSS for signatures and RSA-OAEP for encryption — never PKCS#1 v1.5 for new use.",
            "Protect private keys with passphrase encryption and 0600 file permissions.",
            "Rotate keys at least annually while retaining old public keys for verification.",
        ],
        "verification": [
            "Extract the public key and fingerprint from each private key found.",
            "Confirm padding mode (PSS/OAEP vs v1.5) before accepting any RSA use.",
        ],
        "considerations": [
            "Even healthy RSA needs a PQC plan: Shor breaks all RSA regardless of key size.",
            "Short keys (<2048) are an immediate hygiene fix independent of quantum timelines.",
        ],
        "applies": {
            "algorithms": ["RSA", "KEYSIZE", "KEYFILE", "PEM"],
            "scanners": ["source", "binary", "container", "hsm", "cloud", "runtime"],
            "categories": ["asymmetric", "key", "certificate"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553"]},
    },
    {
        "id": "aes-rest",
        "source_skill": "implementing-aes-encryption-for-data-at-rest",
        "name": "AES data-at-rest construction",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("AES-256-GCM with proper KDF (PBKDF2 600k+ / Argon2id / scrypt), "
                    "unique nonces, authenticated encryption, XTS for disk."),
        "guidance": [
            "Always use authenticated encryption (GCM/CCM); unauthenticated CBC/CTR invites tampering.",
            "Never reuse a nonce with the same key — catastrophic in GCM.",
            "Derive keys with PBKDF2 (600k+ iterations), Argon2id, or scrypt — never raw passwords.",
            "Prefer AES-256 for long-lived data; use XTS for disk-level encryption.",
        ],
        "verification": [
            "Confirm cipher mode on every AES finding (GCM vs CBC/ECB).",
            "Confirm KDF parameters wherever a password becomes a key.",
        ],
        "considerations": [
            "Migrating DES/RC4/3DES → AES-256-GCM also resolves Grover-margin posture.",
            "Wipe keys from memory after use where the platform allows it.",
        ],
        "applies": {
            "algorithms": ["AES", "DES", "3DES", "RC4", "CHACHA20", "BLOWFISH", "KDF"],
            "scanners": ["source", "binary", "container", "runtime"],
            "categories": ["symmetric", "hash"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553"]},
    },
    {
        "id": "ed25519-sig",
        "source_skill": "implementing-digital-signatures-with-ed25519",
        "name": "Ed25519 signature practice",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Deterministic, side-channel-resistant 128-bit signatures; validate keys, "
                    "verify full messages, store private keys encrypted."),
        "guidance": [
            "Validate public keys before use (low-order point checks).",
            "Verify the full message — Ed25519 hashes internally; pre-hashing changes the scheme.",
            "Store private keys encrypted at rest; they cannot be recovered from signatures.",
        ],
        "verification": [
            "Confirm tampered-message and wrong-key verification both fail.",
        ],
        "considerations": [
            "Ed25519 is a near-term modern alternative, but it is still Shor-vulnerable — plan ML-DSA after.",
        ],
        "applies": {
            "algorithms": ["ECC", "ECDSA"],
            "scanners": ["source", "binary", "container", "dependency", "runtime"],
            "categories": ["asymmetric", "library"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573"]},
    },
    {
        "id": "jwt-sign",
        "source_skill": "implementing-jwt-signing-and-verification",
        "name": "JWT signing hardening (RFC 7519)",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("HMAC/RSA/ECDSA JWT validation: algorithm allowlists, no alg=none, "
                    "expiry, claims checks, no keys in source."),
        "guidance": [
            "Validate the alg header against an allowlist; reject alg=none and prevent algorithm confusion.",
            "Prefer asymmetric (RS256/ES256) tokens for distributed verifiers.",
            "Enforce short expiries with refresh, full claims validation, and JWK rotation.",
        ],
        "verification": [
            "Test tampered-token, expired-token, and alg-confusion rejection.",
        ],
        "considerations": [
            "JWT library presence alone does not prove tokens are validated — trace the verify path.",
        ],
        "applies": {
            "algorithms": ["HMAC", "RSA", "ECDSA"],
            "scanners": ["source", "container", "dependency"],
            "categories": ["hash", "asymmetric"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573"]},
    },
    {
        "id": "mtls",
        "source_skill": "implementing-mtls-for-zero-trust-services",
        "name": "Mutual TLS service authentication",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("CA-issued service certificates with mutual verification for "
                    "service-to-service authentication."),
        "guidance": [
            "Verify peer certificates on both sides; server-only TLS is not mTLS.",
            "Pin issuance to an internal CA with short-lived service certificates.",
            "Rotate service identities automatically; monitor for verification failures.",
        ],
        "verification": [
            "Confirm client-cert verification is enforced, not merely configured.",
        ],
        "considerations": [
            "mTLS client certificates join the certificate inventory and rotation plan.",
        ],
        "applies": {
            "algorithms": ["TLS", "TLS12", "TLS13", "PEM", "KEYFILE"],
            "scanners": ["source", "container", "cloud"],
            "categories": ["protocol", "certificate", "key"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["DE.CM-01", "RS.MA-01", "GV.OV-01", "DE.AE-02"],
                       "mitre_attack": ["T1078", "T1190", "T1059", "T1553"]},
    },
    {
        "id": "e2ee-msg",
        "source_skill": "implementing-end-to-end-encryption-for-messaging",
        "name": "Key-exchange hygiene (forward secrecy)",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("X25519 exchange + HKDF + AES-256-GCM per-message keys; delete used keys "
                    "so compromise does not reveal past traffic."),
        "guidance": [
            "Prefer ephemeral (X25519/ECDHE) exchange so past traffic survives key compromise.",
            "Derive per-message keys (HKDF) and delete them after use.",
            "Authenticate every message (AES-GCM) with replay protection.",
        ],
        "verification": [
            "Confirm the exchange is ephemeral, not static-key ECDH.",
        ],
        "considerations": [
            "Static ECDH findings deserve priority review for forward-secrecy gaps.",
        ],
        "applies": {
            "algorithms": ["ECDH"],
            "scanners": ["source", "binary", "container", "runtime"],
            "categories": ["asymmetric"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553"]},
    },
    {
        "id": "tls13-config",
        "source_skill": "configuring-tls-1-3-for-secure-communications",
        "name": "TLS 1.3 configuration baseline",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("TLS 1.3 (RFC 8446): 1-RTT, restricted cipher suites, mandatory forward "
                    "secrecy; harden with HSTS, OCSP stapling, modern certificates."),
        "guidance": [
            "Disable TLS 1.0/1.1 everywhere; keep 1.2 fallback only where legacy clients require it.",
            "Offer only approved cipher suites and enforce forward secrecy.",
            "Enable OCSP stapling, HSTS with long max-age + includeSubDomains, and CT monitoring.",
            "Treat 0-RTT as replayable: limit it to idempotent requests.",
        ],
        "verification": [
            "Confirm negotiated versions/ciphers on live endpoints (testssl.sh or equivalent).",
            "Confirm the certificate chain is complete and stapling works.",
        ],
        "considerations": [
            "Negotiate hybrid ML-KEM key exchange where peers allow it.",
        ],
        "applies": {
            "algorithms": ["TLS", "TLS10", "TLS11", "TLS12", "TLS13", "SSL"],
            "scanners": ["source", "binary", "container", "cloud"],
            "categories": ["protocol"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1557", "T1040", "T1573.002", "T1539"]},
    },
    {
        "id": "tls-assess",
        "source_skill": "performing-ssl-tls-security-assessment",
        "name": "TLS endpoint assessment method",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Assess live TLS posture: versions, cipher strength, chain validity, HSTS, "
                    "OCSP, and known flaws (Heartbleed, ROBOT, renegotiation)."),
        "guidance": [
            "Inventory supported versions and accepted suites per endpoint before changing config.",
            "Check chain validity, HSTS, OCSP, and known-vulnerability probes as one pass.",
            "Re-assess after every TLS change; config drift reintroduces old versions.",
        ],
        "verification": [
            "Record offered versions/ciphers per host and diff against policy.",
        ],
        "considerations": [
            "Static discovery of a TLS version string is a lead for assessment, not proof of negotiation.",
        ],
        "applies": {
            "algorithms": ["TLS", "TLS10", "TLS11", "TLS12", "TLS13", "SSL"],
            "scanners": ["source", "container", "cloud"],
            "categories": ["protocol"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.IR-01", "DE.CM-01", "ID.AM-03", "PR.DS-02"],
                       "mitre_attack": ["T1046", "T1040", "T1557", "T1071"]},
    },
    {
        "id": "cert-lifecycle",
        "source_skill": "performing-ssl-certificate-lifecycle-management",
        "name": "Certificate lifecycle management",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Request → issue → deploy → monitor → renew → revoke, automated via ACME; "
                    "inventory every certificate and plan for CA compromise."),
        "guidance": [
            "Maintain an inventory of all certificates, locations, and expiries — ECDAT output is the starting point.",
            "Automate renewal (ACME) and monitor expiries; outages from expired certs are common.",
            "Validate chains and revocation (OCSP/CRL); prefer ECDSA P-256 for performance.",
            "Plan for CA compromise: backup CAs and rotation runbooks.",
        ],
        "verification": [
            "Parse every inventoried certificate and confirm chain, expiry, and signature algorithm.",
        ],
        "considerations": [
            "Short-lived certificates reduce revocation burden; pilot PQC/hybrid issuance early.",
        ],
        "applies": {
            "algorithms": ["PEM", "KEYFILE", "RSA", "ECDSA", "TLS", "TLS12", "TLS13"],
            "scanners": ["source", "binary", "container", "cloud"],
            "categories": ["certificate", "key", "protocol"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553"]},
    },
    {
        "id": "ca-openssl",
        "source_skill": "configuring-certificate-authority-with-openssl",
        "name": "PKI CA hierarchy practice",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Two-tier CA (offline root + online intermediate) with path-length "
                    "constraints, CRL/OCSP, policies, and issuance auditing."),
        "guidance": [
            "Keep the root CA offline (ideally in an HSM); operate via intermediates.",
            "Use ≥4096-bit RSA or P-384 ECDSA CA keys with path-length constraints.",
            "Publish CRL/OCSP, embed certificate policies, and audit every issuance.",
        ],
        "verification": [
            "Verify issued certificates chain intermediate → root with constraints enforced.",
        ],
        "considerations": [
            "CA keys are the longest-lived trust anchors — prioritize them in PQC planning.",
        ],
        "applies": {
            "algorithms": ["PEM", "RSA", "ECDSA"],
            "scanners": ["source", "container", "cloud"],
            "categories": ["certificate", "key"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1649", "T1553.004", "T1557"]},
    },
    {
        "id": "hsm-config",
        "source_skill": "configuring-hsm-for-key-storage",
        "name": "HSM key-storage practice (PKCS#11)",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Tamper-resistant key storage with keys that never leave the device; "
                    "partitions, ceremonies, audit logging, non-exportable keys (SoftHSM2 for dev)."),
        "guidance": [
            "Keep private keys non-exportable (CKA_EXTRACTABLE=False); operate on them inside the HSM.",
            "Separate slots/partitions per application; require multi-person ceremonies for CA roots.",
            "Enable audit logging plus backup/disaster recovery; use strong SO/user PINs.",
        ],
        "verification": [
            "Confirm listed objects match expected keys and none are exportable.",
        ],
        "considerations": [
            "Hardware protects key material, not the algorithm — RSA/ECC behind PKCS#11 still migrates.",
        ],
        "applies": {
            "algorithms": ["PKCS11", "HSM", "RSA", "ECDSA", "AES", "KEYFILE"],
            "scanners": ["hsm", "source", "container", "cloud"],
            "categories": ["key", "library", "asymmetric", "symmetric"],
            "usages": ["hsm integration reference"],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1552.004", "T1555"]},
    },
    {
        "id": "hsm-integrate",
        "source_skill": "performing-hardware-security-module-integration",
        "name": "HSM integration via PKCS#11",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Application integration over PKCS#11 (python-pkcs11): generate, sign, "
                    "encrypt, and verify inside the token; validate slots and FIPS mode."),
        "guidance": [
            "Generate and use keys inside the token; query slots/tokens rather than assuming them.",
            "Validate the HSM configuration against FIPS 140-2/3 requirements where claimed.",
            "Prefer provider-supported hybrid flows when piloting PQC with HSMs.",
        ],
        "verification": [
            "Exercise generate → sign → verify inside the token before trusting the integration.",
        ],
        "considerations": [
            "Static integration references prove configuration presence, not live HSM contents.",
        ],
        "applies": {
            "algorithms": ["PKCS11", "HSM", "CLOUDHSM"],
            "scanners": ["hsm", "source", "container", "cloud"],
            "categories": ["key", "library"],
            "usages": ["hsm integration reference"],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553", "T1078.004"]},
    },
    {
        "id": "envelope-kms",
        "source_skill": "implementing-envelope-encryption-with-aws-kms",
        "name": "Envelope encryption with managed KMS",
        "domain": "cryptography",
        "tier": 1,
        "summary": ("Data encrypted locally with a DEK (AES-256-GCM); the DEK is wrapped by a "
                    "KMS master key. Plaintext DEKs are never stored."),
        "guidance": [
            "Generate data keys via the KMS API; encrypt locally with AES-256-GCM.",
            "Store only the encrypted DEK beside ciphertext; wipe plaintext DEKs from memory.",
            "Restrict GenerateDataKey/Decrypt with key policies; log all KMS calls; use encryption context.",
            "Rotate master keys on schedule (automatic annual rotation where offered).",
        ],
        "verification": [
            "Confirm decrypt round-trips through KMS and that no plaintext DEK persists.",
        ],
        "considerations": [
            "Managed KMS is not automatically quantum-safe — inventory the backing algorithms per key.",
        ],
        "applies": {
            "algorithms": ["KMS", "CLOUDHSM", "AES", "KEYVAULT"],
            "scanners": ["cloud", "source", "container"],
            "categories": ["key", "symmetric", "library"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
                       "mitre_attack": ["T1600", "T1573", "T1553", "T1078.004"]},
    },
]

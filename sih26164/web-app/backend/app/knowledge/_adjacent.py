"""Tier-2 adjacent-domain knowledge entries (ECDAT-authored normalized summaries).

Same source/provenance rules as _crypto.py. These contextualize ECDAT
dependency, container, secret, and signing-related findings; they never
expand ECDAT into a general scanner for those domains.
"""

ADJACENT_SKILLS = [
    {
        "id": "sbom-gen",
        "source_skill": "generating-and-analyzing-sboms",
        "name": "SBOM generation and use (CycloneDX/SPDX)",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Machine-readable component inventory (CycloneDX/SPDX): generate, sign, "
                    "gate CI on severity, re-scan on database updates. ECDAT CBOM is the "
                    "cryptographic counterpart."),
        "guidance": [
            "Treat the crypto inventory as one lens and the SBOM as the other; correlate crypto libraries across both.",
            "Gate builds on agreed severity and re-scan stored inventories when vulnerability data updates.",
            "Sign inventory artifacts (cosign attestations) so downstream consumers can verify them.",
        ],
        "verification": [
            "Confirm every crypto-relevant dependency in ECDAT output also appears in the SBOM.",
        ],
        "considerations": [
            "SBOMs are sensitive inventory data — handle them with the same care as scan reports.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["dependency", "container"],
            "categories": ["dependency", "library"],
            "usages": ["dependency reference", "dependency integrity metadata",
                       "container file reference", "container config reference",
                       "container binary reference"],
        },
        "frameworks": {"nist_csf": ["ID.AM-08"], "mitre_attack": []},
    },
    {
        "id": "slsa-sigstore",
        "source_skill": "verifying-build-provenance-with-slsa-sigstore",
        "name": "Build provenance verification (SLSA/Sigstore)",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Verify artifacts were built from the expected source by a trusted builder: "
                    "cosign verification, SLSA provenance, keyless OIDC identities."),
        "guidance": [
            "Verify signatures and SLSA provenance before trusting a dependency or image.",
            "Pin the OIDC issuer and certificate identity — never accept any-issuer verification in production.",
            "Assign each consumed artifact a SLSA build level and gate admission on it.",
        ],
        "verification": [
            "Inspect the provenance predicate: source repo, commit, and builder must match expectations.",
        ],
        "considerations": [
            "Provenance answers 'was this built correctly', not 'is this version vulnerability-free'.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["dependency", "container"],
            "categories": ["dependency", "library"],
            "usages": ["dependency reference", "container file reference",
                       "container binary reference"],
        },
        "frameworks": {"nist_csf": ["PR.DS-01"], "mitre_attack": ["T1195"]},
    },
    {
        "id": "sigstore-sign",
        "source_skill": "implementing-sigstore-for-software-signing",
        "name": "Software signing with Sigstore",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Keyless signing via Fulcio short-lived certificates bound to OIDC identity, "
                    "logged in Rekor; know the air-gap/offline limits."),
        "guidance": [
            "Prefer keyless OIDC-bound certificates over long-lived keys where the infrastructure allows it.",
            "Sign by digest, pin issuer and identity, and verify the full chain (signature + cert + Rekor).",
            "Keep PGP/GPG flows where regulation mandates specific key management.",
        ],
        "verification": [
            "Confirm Rekor inclusion and identity binding on every verified artifact.",
        ],
        "considerations": [
            "Signing proves integrity and origin — it says nothing about code quality or crypto hygiene.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["dependency", "container"],
            "categories": ["dependency", "library"],
            "usages": ["dependency reference", "container file reference"],
        },
        "frameworks": {"nist_csf": ["GV.SC-01", "GV.SC-03", "GV.SC-06", "GV.SC-07"],
                       "mitre_attack": ["T1078", "T1190", "T1059", "T1610", "T1611"]},
    },
    {
        "id": "code-sign",
        "source_skill": "implementing-code-signing-for-artifacts",
        "name": "Artifact code signing",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Sign release artifacts for publisher identity and integrity (detached "
                    "signatures, provenance, transparency); signing is not encryption."),
        "guidance": [
            "Sign release artifacts and publish provenance so consumers can verify origin.",
            "Reject unsigned artifacts in zero-trust deployment pipelines.",
            "Use container-image signing (cosign), not generic artifact signing, for images.",
        ],
        "verification": [
            "Verify publisher identity and artifact integrity independently before deployment.",
        ],
        "considerations": [
            "A valid signature does not imply the signed code uses safe cryptography.",
        ],
        "applies": {
            "algorithms": ["RSA", "ECDSA", "ECC", "PEM"],
            "scanners": ["dependency", "container"],
            "categories": ["asymmetric", "certificate", "dependency"],
            "usages": ["dependency reference", "container file reference"],
        },
        "frameworks": {"nist_csf": ["PR.PS-01", "GV.SC-07", "ID.IM-04", "PR.PS-04"],
                       "mitre_attack": ["T1195", "T1554", "T1059.004", "T1610"]},
    },
    {
        "id": "cosign-image",
        "source_skill": "implementing-image-provenance-verification-with-cosign",
        "name": "Container image signing (cosign)",
        "domain": "container",
        "tier": 2,
        "summary": ("Sign/verify OCI images and attach SBOM/SLSA attestations; enforce at "
                    "admission (policy-controller/Kyverno); sign by digest."),
        "guidance": [
            "Sign images by digest with keyless CI signing; attach SBOM attestations alongside.",
            "Enforce signature verification at admission; verify chain, identity, and Rekor inclusion.",
            "Store key-based signing keys in KMS/Vault, never in the repo or image.",
        ],
        "verification": [
            "Confirm admission rejects unsigned or wrong-identity images.",
        ],
        "considerations": [
            "Image signatures cover supply integrity; crypto inside the image still needs ECDAT review.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["container"],
            "categories": ["dependency", "library", "certificate", "key"],
            "usages": ["container file reference", "container config reference",
                       "container binary reference"],
        },
        "frameworks": {"nist_csf": ["PR.PS-01", "PR.IR-01", "ID.AM-08", "DE.CM-01"],
                       "mitre_attack": ["T1610", "T1611", "T1609", "T1525"]},
    },
    {
        "id": "in-toto",
        "source_skill": "implementing-supply-chain-security-with-in-toto",
        "name": "Supply-chain layout attestation (in-toto/SLSA)",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Signed link metadata per SDLC step proving what ran, who ran it, and "
                    "what was produced; verify deployed images followed the approved layout."),
        "guidance": [
            "Require signed step attestations from build to deployment for crypto-bearing artifacts.",
            "Verify images against the approved layout before they reach clusters.",
        ],
        "verification": [
            "Check that every deployed image maps to a complete, valid attestation chain.",
        ],
        "considerations": [
            "Layout verification complements, not replaces, vulnerability and crypto review.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["container", "dependency"],
            "categories": ["dependency"],
            "usages": ["container file reference", "dependency reference"],
        },
        "frameworks": {"nist_csf": ["PR.PS-01", "PR.IR-01", "ID.AM-08", "DE.CM-01"],
                       "mitre_attack": ["T1610", "T1611", "T1609", "T1525"]},
    },
    {
        "id": "dep-confusion",
        "source_skill": "detecting-dependency-confusion",
        "name": "Dependency-confusion defenses",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Private-vs-public registry resolution risk: pin internal scopes, review "
                    "extra indexes, reserve un-isolatable names, gate CI on every push."),
        "guidance": [
            "Pin internal scopes to the private registry (.npmrc / pip config / Maven mirror).",
            "Review extra-index-url and merged feeds for highest-version-pull risk.",
            "Enforce confusion checks in CI on every push/PR with owners recorded.",
        ],
        "verification": [
            "Enumerate manifests and confirm each private name resolves only privately.",
        ],
        "considerations": [
            "A confused crypto dependency poisons every downstream crypto finding — verify provenance first.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["dependency"],
            "categories": ["dependency"],
            "usages": ["dependency reference", "dependency integrity metadata"],
        },
        "frameworks": {"nist_csf": ["ID.RA-09"], "mitre_attack": []},
    },
    {
        "id": "typosquat",
        "source_skill": "detecting-typosquatting-packages-in-npm-pypi",
        "name": "Typosquat detection (npm/PyPI)",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Name-similarity (Levenshtein/keyboard distance, PEP 503 normalization) "
                    "plus metadata signals — similarity alone never proves malice."),
        "guidance": [
            "Normalize names (PEP 503) before comparing; respect npm scope rules.",
            "Combine similarity with metadata signals; review flagged packages manually.",
            "Monitor the crypto libraries you depend on for lookalike registrations.",
        ],
        "verification": [
            "Manually review any flagged lookalike of a crypto dependency before action.",
        ],
        "considerations": [
            "Typosquatted crypto libraries are high-value targets — prioritize their review.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["dependency"],
            "categories": ["dependency"],
            "usages": ["dependency reference"],
        },
        "frameworks": {"nist_csf": ["GV.SC-01", "GV.SC-03", "GV.SC-06", "GV.SC-07"],
                       "mitre_attack": ["T1195.001", "T1195.002", "T1608.001"]},
    },
    {
        "id": "sbom-vuln",
        "source_skill": "analyzing-sbom-for-supply-chain-vulnerabilities",
        "name": "SBOM vulnerability correlation",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("Correlate inventory components (CycloneDX/SPDX, PURL/CPE) with NVD CVEs; "
                    "watch transitives, shaded JARs, and parser skew."),
        "guidance": [
            "Correlate each inventoried crypto library with NVD via PURL/CPE, including transitives.",
            "Distrust completeness claims — shaded/bundled artifacts hide components.",
            "Track KEV-listed crypto issues ahead of generic CVSS ordering.",
        ],
        "verification": [
            "Confirm crypto components resolve to exact NVD entries, not fuzzy neighbors.",
        ],
        "considerations": [
            "Vulnerability status and crypto-migration priority are different orderings — keep both.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["dependency", "container"],
            "categories": ["dependency", "library"],
            "usages": ["dependency reference", "dependency integrity metadata",
                       "container file reference"],
        },
        "frameworks": {"nist_csf": ["GV.SC-01", "GV.SC-03", "GV.SC-06", "GV.SC-07"],
                       "mitre_attack": ["T1195.001", "T1195.002", "T1554"]},
    },
    {
        "id": "sca-snyk",
        "source_skill": "performing-sca-dependency-scanning-with-snyk",
        "name": "SCA dependency scanning practice",
        "domain": "supply-chain",
        "tier": 2,
        "summary": ("SCA over direct and transitive dependencies with reachability and license "
                    "policy; monitor continuously, fix via upgrades."),
        "guidance": [
            "Prioritize reachable vulnerabilities in crypto code paths over merely-present ones.",
            "Monitor continuously — new disclosures affect already-deployed inventories.",
            "Enforce license policy on crypto dependencies alongside vulnerability gates.",
        ],
        "verification": [
            "Confirm reachable crypto findings map to code paths ECDAT also flags.",
        ],
        "considerations": [
            "SCA finds known-bad versions; ECDAT finds crypto usage — use both orderings.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["dependency"],
            "categories": ["dependency"],
            "usages": ["dependency reference"],
        },
        "frameworks": {"nist_csf": ["PR.PS-01", "GV.SC-07", "ID.IM-04", "PR.PS-04"],
                       "mitre_attack": ["T1195", "T1554"]},
    },
    {
        "id": "gcp-binauthz",
        "source_skill": "implementing-gcp-binary-authorization",
        "name": "Deploy-time attestation gates (Binary Authorization)",
        "domain": "cloud",
        "tier": 2,
        "summary": ("Admit only images with attestations (vuln scan, review, provenance) via "
                    "policy; continuous validation watches running pods."),
        "guidance": [
            "Require attestations (scan + provenance) before images deploy.",
            "Monitor running pods with continuous validation and keep break-glass audited.",
        ],
        "verification": [
            "Attempt a non-compliant deploy and confirm the gate blocks it.",
        ],
        "considerations": [
            "Admission gates enforce provenance; they do not assess the crypto inside admitted images.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["container"],
            "categories": ["dependency"],
            "usages": ["container file reference", "container config reference"],
        },
        "frameworks": {"nist_csf": ["PR.IR-01", "ID.AM-08", "GV.SC-06", "DE.CM-01"],
                       "mitre_attack": ["T1078.004", "T1530", "T1537", "T1580"]},
    },
    {
        "id": "vault-secrets",
        "source_skill": "implementing-secrets-management-with-vault",
        "name": "Secrets management with Vault",
        "domain": "cloud",
        "tier": 2,
        "summary": ("Dynamic secrets, engines (KV/database/AWS/PKI/Transit), leases with TTL, "
                    "AppRole for machines, response wrapping for delivery."),
        "guidance": [
            "Replace baked-in secret references with leased, auto-expiring credentials.",
            "Use Transit for encryption-as-a-service so apps never hold keys.",
            "Deliver secrets via response wrapping; authenticate machines with AppRole.",
        ],
        "verification": [
            "Confirm no static credential survives where a leased one was adopted.",
        ],
        "considerations": [
            "Rotation only helps if every consumer (including CI) reads from the manager.",
        ],
        "applies": {
            "algorithms": ["ENV-SECRET", "KEYFILE", "KMS", "KEYVAULT"],
            "scanners": ["source", "container", "cloud"],
            "categories": ["key", "dependency"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.IR-01", "ID.AM-08", "GV.SC-06", "DE.CM-01"],
                       "mitre_attack": ["T1078.004", "T1530", "T1537", "T1580"]},
    },
    {
        "id": "registry-images",
        "source_skill": "securing-container-registry-images",
        "name": "Container registry hygiene",
        "domain": "container",
        "tier": 2,
        "summary": ("Scan and sign registry images, require SBOMs, enforce tag immutability, "
                    "attach scan/SBOM attestations for pre-deployment verification."),
        "guidance": [
            "Scan every registry image and require SBOMs for deployed ones.",
            "Enforce tag immutability so a verified digest cannot be swapped under its tag.",
            "Attach attestations (scan results, SBOM, provenance) for admission checks.",
        ],
        "verification": [
            "Audit the registry for unscanned or unsigned images on a schedule.",
        ],
        "considerations": [
            "Registry hygiene gates what deploys; ECDAT still reviews the crypto within.",
        ],
        "applies": {
            "algorithms": [],
            "scanners": ["container"],
            "categories": ["dependency", "library", "certificate", "key"],
            "usages": ["container file reference", "container config reference",
                       "container binary reference"],
        },
        "frameworks": {"nist_csf": ["PR.IR-01", "ID.AM-08", "GV.SC-06", "DE.CM-01"],
                       "mitre_attack": ["T1078.004", "T1530", "T1537", "T1580"]},
    },
    {
        "id": "gitleaks",
        "source_skill": "implementing-secret-scanning-with-gitleaks",
        "name": "Secret scanning with Gitleaks",
        "domain": "devsecops",
        "tier": 2,
        "summary": ("Regex + entropy secret detection with pre-commit hooks, baselines, "
                    "allowlists, SARIF output, and history rewriting for remediation."),
        "guidance": [
            "Block commits with pre-commit hooks; baseline existing findings to catch only new secrets.",
            "Tune allowlists per path/commit; purge leaked secrets from history with git-filter-repo.",
            "Export SARIF so secret findings join the same dashboard as crypto findings.",
        ],
        "verification": [
            "Confirm the baseline distinguishes new leaks from grandfathered ones.",
        ],
        "considerations": [
            "Detection is step one — rotation and history purge complete the remediation.",
        ],
        "applies": {
            "algorithms": ["ENV-SECRET", "KEYFILE", "PEM"],
            "scanners": ["source", "container"],
            "categories": ["key", "certificate"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.PS-01", "GV.SC-07", "ID.IM-04", "PR.PS-04"],
                       "mitre_attack": ["T1195", "T1554", "T1059.004", "T1003"]},
    },
    {
        "id": "secrets-cicd",
        "source_skill": "implementing-secrets-scanning-in-ci-cd",
        "name": "Secrets scanning in CI/CD",
        "domain": "devsecops",
        "tier": 2,
        "summary": ("Gitleaks/TruffleHog gates that block deployments containing high-severity "
                    "secret findings, including history scans with verification."),
        "guidance": [
            "Gate deployments on high-severity secret findings, including git history.",
            "Verify suspected live secrets through the provider before/while rotating.",
            "Keep the gate fast enough that teams do not bypass it.",
        ],
        "verification": [
            "Confirm a seeded test secret blocks the pipeline end-to-end.",
        ],
        "considerations": [
            "A red gate must route to rotation runbooks, not just to dismissed alerts.",
        ],
        "applies": {
            "algorithms": ["ENV-SECRET", "KEYFILE"],
            "scanners": ["source", "container"],
            "categories": ["key"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.PS-01", "GV.SC-07", "ID.IM-04", "PR.PS-04"],
                       "mitre_attack": ["T1195", "T1554"]},
    },
    {
        "id": "vault-dynamic",
        "source_skill": "implementing-hashicorp-vault-dynamic-secrets",
        "name": "Dynamic secrets lifecycle (Vault)",
        "domain": "devsecops",
        "tier": 2,
        "summary": ("Short-lived per-request credentials with leases, renewal, revocation, and "
                    "root rotation; watch pool/TTL/HA pitfalls."),
        "guidance": [
            "Issue short-lived per-consumer credentials with leases instead of shared static ones.",
            "Handle renewal/revocation in connection pools; set TTLs the workload can sustain.",
            "Rotate root credentials into Vault custody and run Vault highly available.",
        ],
        "verification": [
            "Revoke a lease and confirm dependent access actually stops.",
        ],
        "considerations": [
            "Dynamic secrets only help consumers that read from Vault at request time.",
        ],
        "applies": {
            "algorithms": ["ENV-SECRET", "KEYFILE"],
            "scanners": ["source", "container", "cloud"],
            "categories": ["key"],
            "usages": [],
        },
        "frameworks": {"nist_csf": ["PR.AA-01", "PR.AA-02", "PR.AA-05", "PR.AA-06"],
                       "mitre_attack": ["T1078", "T1110", "T1556", "T1098", "T1003"]},
    },
]

# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool
## Comprehensive Technical Architecture, Algorithms, Intelligence & Security Report

- **Version:** frozen `phase-17-freeze` + finalization pass (commit `3fcb01a` + uncommitted finalization diff at time of writing)
- **Date:** 2026-09-06
- **Scope note:** every claim below was cross-checked against the code in `sih26164/`. Uncertain items are marked. Nothing here describes an imagined ML system.

---

## Table of contents

1. Executive technical overview · 2. System architecture · 3. Technologies & dependencies
2. Cryptographic algorithms & primitives · 5. "Used by" vs "detected by" vs "recommended"
3. ML/AI analysis · 7. Loss functions · 8. Mathematical & scoring methods · 9. Mosca heuristic
4. Scanners (source, binary, container, dependency, certs, HSM, cloud, runtime)
5. Normalization, canonicalization, correlation, evidence strength
6. Risk, prioritization, recommendations, migration intelligence
7. CBOM-style output · 20. AI analyst · 21. Obsidian memory · 22. Security engineering
8. Resource bounds · 24. Error handling · 25. Determinism · 26. Performance (observed)
9. Testing strategy · 28. REAL vs FUTURE · 29. What ECDAT does NOT do · 30. Limitations
10. Glossary · 32. Evaluator Q&A

---

## 1. Executive technical overview

**Problem (SIH26164, NTRO):** organizations cannot migrate to post-quantum cryptography without first knowing where cryptography lives — algorithms, keys, certificates, protocols, libraries, HSM/cloud integrations — across source, binaries, containers, and configs.

**System objective:** statically discover cryptographic evidence, normalize it into one finding model, assess quantum-migration risk deterministically, prioritize remediation, recommend NIST-aligned migration directions, plan the migration, and report everything as CBOM-style JSON through a CLI, an API, and a dashboard, with bounded Markdown project memory.

**Intended users:** security engineers and migration planners preparing PQC transition inventories.

**Pipeline (actual stage names in `pipeline.py` + extensions):**

```text
DISCOVER (7 scanners) → NORMALIZE (CryptoFinding + dedupe) → CORRELATE (runtime links,
related links) → ASSESS (Mosca exposure, severity) → PRIORITIZE (score → P0–P3)
→ RECOMMEND (family table) → PLAN (intelligence inventory/graph + migration
status/work-items/roadmap) → REPORT (CBOM-style JSON) → OPERATE (CLI/API/dashboard,
optional runtime probe, optional analyst Q&A) → REMEMBER (bounded Obsidian notes)
```

---

## 2. System architecture

```text
                    ┌────────────── React 18 + Vite 6 dashboard ──────────────┐
                    │ metrics · inventory · findings+filters · relationships  │
                    │ migration workspace · analyst summary · JSON download   │
                    └───────────────────────┬─────────────────────────────────┘
                                            │  POST /scans  GET /reports/{id}  GET /health
┌────────────── CLI (Python stdlib only) ────┼────────────────── FastAPI backend ──────────────┐
│ agent scan/target ──► run_scan() ──► SCANNERS dict ──► normalize → assess → correlate/relate │
│ agent explain ──► analyst.py (deterministic) ──► optional SubprocessAdapter ─► provider CLI  │
│ agent memory ──► MemoryProvider ──► ObsidianVaultProvider ──► ~/Documents/Vaults/SIH (*.md)  │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Frontend** (`web-app/frontend/src/App.jsx`, single-file app): scan form (+ runtime opt-in checkbox), metrics row, inventory table, findings table with priority/scanner/text filters and expandable detail rows, relationships section, migration workspace, recommendations, JSON download. No router, no state library, no test framework. All rendering is React-escaped (no `dangerouslySetInnerHTML` anywhere — verified).
- **Backend** (`web-app/backend/app/`): FastAPI with 3 routes; `pipeline.run_scan()` is the single orchestration used by API *and* CLI (CLI imports it via `sys.path`, verified byte-identical reports). No database, no background jobs, in-memory report store (FIFO-capped at 50, restart clears).
- **CLI** (`cli-agent/src/agent/`, 10 subcommands): `init status agents context memory plan run scan explain verify`. `scan` runs the shared pipeline; `explain` renders deterministic answers and optionally shells to a provider CLI; `run` shells to provider CLIs with caller-supplied args.
- **Scanner layer**: `Scanner.scan(target) -> list[CryptoFinding]` implementations registered in `SCANNERS`; `REAL_SCANNERS` lists the six static defaults (runtime is opt-in, never default).
- **Intelligence layer** (`intelligence.py`, `migration.py`): pure functions over enriched dicts — inventory, `related[]` links, HIGH/MEDIUM/LOW strength, JSON graph, migration statuses/work-items/roadmap. No model changes, no score mutation.
- **Memory layer**: `MemoryProvider → ObsidianVaultProvider → Markdown` under `OBSIDIAN_VAULT_PATH` (default `/home/chethan/Documents/Vaults/SIH`). Dotted-key convenience backed by one Markdown note; traversal-jailed paths.
- **AI layer**: deterministic renderers first (`analyst.py`), existing subprocess adapters second, provider CLIs third. Backend has no AI endpoints.

---

## 3. Technologies and dependencies

| Technology | Purpose | Where used | Why used |
|---|---|---|---|
| Python 3.14 (stdlib only for CLI/scanners) | everything except API transport | `cli-agent/src`, `backend/app` scanners/pipeline/intel | zero-install judges, no CVE surface, deterministic |
| FastAPI + uvicorn + httpx | HTTP API + server + test client | `backend/app/main.py`, tests | minimal API layer; httpx only via Starlette TestClient in tests |
| pydantic (via FastAPI) | request validation (`ge=0, le=100`, `runtime: bool`) | `main.py` ScanRequest | safe API inputs |
| React 18 + Vite 6 | dashboard UI + build | `frontend/src/App.jsx` | existing team stack; no UI framework beyond React |
| `tomllib` (stdlib 3.11+) | Cargo/pyproject parsing | `dependency_scanner.py` | exact parsing, no dependency |
| `xml.etree` (stdlib) | pom.xml parsing | `dependency_scanner.py` | exact parsing, no dependency |
| `tarfile`/`gzip`/`json`/`re`/`hashlib` (stdlib) | archives, manifests, patterns, finding IDs | scanners, models | no binary deps |
| `subprocess` (stdlib, arg-list, no shell) | provider CLIs, pytest self-check, controlled probe | adapters, orchestration, runtime scanner | only three justified sites |
| Markdown + Obsidian | persistent project memory | vault (default `~/Documents/Vaults/SIH`) | human-readable, zero-dependency, auditable |
| pytest 8 | test runner | both suites | standard |

**Not used:** TypeScript (JSX only), test frameworks for frontend (build-only validation), Docker/K8s, any database, any ML library, any network client in product code (grep-verified: no `socket`/`requests`/`urllib`/`httpx` outside tests), any crypto implementation library (ECDAT *detects references* to OpenSSL etc.; it does not link them).

---

## 4. Cryptographic algorithms and primitives (detected / referenced / recommended)

ECDAT **detects references to** these primitives; it **does not implement** any of them (HEURISTIC + RULES, not implementations):

| Family | Names seen in code | Detection | Quantum relevance (as coded) | Migration guidance (table) |
|---|---|---|---|---|
| RSA (1024/2048/3072/4096) | source regex, binary strings, cert parser (modulus bit-length) | `QUANTUM_VULNERABLE` (+35 if <2048 bits) | ML-KEM-768 hybrid + ML-DSA-65 |
| ECDSA, ECC (P-256/384/521, Ed25519, X25519/ECDH), DSA, DH | source/binary/cert/curve regexes | `QUANTUM_VULNERABLE` | ML-DSA / X25519+ML-KEM hybrid |
| ML-KEM, ML-DSA (+SLH-DSA named in notes) | binary strings, recommendation text | guidance targets, not findings | evaluate/pilot/verify-provider |
| AES-128/192/256, 3DES, DES, ChaCha20, RC4, Blowfish | source/binary | DES/3DES/RC4 in `WEAK_CLASSICAL` | AES-256-GCM (Grover-margin note) |
| MD5, SHA-1, SHA-2 (224–512), SHA-3, HMAC, bcrypt/scrypt/Argon2/PBKDF2, HKDF, BLAKE3 | source/binary/dependency names | MD5/SHA-1 in `WEAK_CLASSICAL` | SHA-256/SHA-3-256 |
| TLS/SSL (SSLv2/v3, TLS 1.0–1.3, cipher-suite tokens) | source/binary/container/TLS-policy | SSL/TLS≤1.1 weak; +20 legacy-protocol score | TLS 1.3 + hybrid-KEX pilot |
| X.509 certs, PEM blocks, key files, PKCS#11, KMS/KeyVault/CloudHSM, ENV-SECRET | cert parser, HSM/cloud scanners | integration inventory, not breakage claims | re-issue/rotate/inventory guidance |

---

## 5. "Used by" vs "detected by" vs "recommended"

- **Used internally by ECDAT (DETERMINISTIC techniques, no ML):** regex matching, magic-byte identification, bounded ASCII-string extraction, DER/ASN.1 walking (minimal), TOML/JSON/XML parsing, tar streaming, SHA-1-based ID canonicalization (`sha1(scanner|file|line|algorithm|…)` truncated — IDs only, not security), deterministic multi-key sorting, exact-key deduplication, additive integer scoring with thresholds, qualitative strength mapping, keyword routing (analyst `route()`), family canonicalization.
- **Detected in targets:** the table in §4 (references/evidence, never implementations).
- **Recommended for migration:** ML-KEM-768 hybrids, ML-DSA-65, SLH-DSA (named option), AES-256-GCM, SHA-256/SHA-3, TLS 1.3+hybrid-KEX, secret-manager hygiene — always worded evaluate/pilot/verify, never drop-in claims.

---

## 6. ML/AI analysis — explicit verdict

**ECDAT does not currently train or run a machine-learning model.** Verified by repository-wide grep: no sklearn/torch/tensorflow/transformers/numpy/pandas, no embeddings, no vector database, no training loop, no inference endpoint, no dataset, no benchmark.

What exists instead:
1. **Deterministic analysis** (the entire product): rules, scoring, sorting, grouping.
2. **Deterministic analyst renderers** (`analyst.py`): template/section assembly from report fields — no probabilities, no generation.
3. **Optional external provider calls**: the CLI can pipe a bounded evidence brief to an already-installed coding-agent CLI (`codex`/`claude`/`cursor-agent`/`agy`) and print its stdout labeled PROVIDER INTERPRETATION. No model names are assumed; no LLM runs unless the operator explicitly passes `--agent` plus provider args; offline behavior is complete without it.

This design is safer than LLM-generated findings because facts are computed before any model is involved, the model can only append labeled interpretation, failures degrade to the deterministic answer, and tests assert the report object is never mutated.

---

## 7. Loss functions — explicit verdict

**No loss function exists.** No model is trained, so there is no training loss, no cross-entropy/MSE, no gradient descent, no backpropagation. What ECDAT uses instead: additive integer scores with thresholds (§8), qualitative strength tiers, and the Mosca inequality comparison (§9). If an evaluator asks for "the loss function," the correct answer is that the concept does not apply; the closest mathematical objective is the priority score (documented below).

---

## 8. Mathematical and scoring methods (exact, from `risk.py`)

```text
exposed = (data_years + migration_years) > qrqc_years_left      # Mosca boolean
score   = 70·[WEAK_CLASSICAL] + 45·[QUANTUM_VULNERABLE]
        + 35·[RSA ∧ key_size<2048] + 20·[SSL∨TLS1.0∨TLS1.1]
        + 25·[exposed ∧ ¬MOSCA_EXEMPT]                            # capped at 100
P0 ⇔ score≥90 · P1 ⇔ ≥65 · P2 ⇔ ≥30 · P3 otherwise
severity: critical ⇔ (quantum-vuln ∧ exposed) ∨ (RSA ∧ short key);
          high ⇔ quantum-vuln ∨ (weak-classical ∧ exposed);
          medium ⇔ weak-classical ∨ exposed; low otherwise
strength: HIGH ⇔ usage ∈ {runtime-observation, certificate-metadata,
          binary-symbol/library-ref} ∨ (direct ∧ conf≥0.8);
          LOW ⇔ binary-string-ref ∨ conf<0.6; else MEDIUM
```

- Variables: `data_years`, `migration_years`, `qrqc_years_left` (floats, API-validated 0–100, defaults 10/3/10).
- `MOSCA_EXEMPT` = {AES, SHA-2, SHA-3, KDF, STDLIB, PyCA, JCA, WebCrypto, NaCl/PGP, OpenSSL, HMAC} (Grover-margin assumption, documented in code).
- Deduplication: exact match on `(scanner, is_mock, file, line, algorithm, category, key_size, curve, mode, proto, library, usage)`; first occurrence wins; ordering deterministic (`-score, file, line, algorithm`).
- IDs: `sha1(...)[:12]` over identity fields — stable across runs.
- No probabilities, no learned weights, no normalization formula beyond capping at 100.

---

## 9. Mosca heuristic (HEURISTIC, not prediction)

Implemented exactly as `mosca_exposed()` above. It exists to answer migration sequencing ("must data outlive our migration window past the assumed horizon?"), using caller-supplied or default horizons. ECDAT states in code, CBOM (`riskSummary.note`), GUI copy, and migration assumptions that it is **not** a prediction of QRQC arrival, break dates, or compromise certainty. Unknown horizons are reported as assumptions, never filled with fake precision.

---

## 10. Scanner algorithms (one section each)

**Source** (`source_scanner.py`, REAL): 30+ compiled case-insensitive regexes over text files (extension allowlist + null-byte sniff fallback); skips 18 generated dirs, symlinks, files >512 KB, caps at 2000 files; per-line matching with size/curve/mode/protocol extraction; KEYFILE rule restricted to path-like/quoted `.key` refs (attribute-access FP fix); evidence truncated to 160 chars with secret-value redaction (`password|secret|token|api_key|private_key = …` → `[REDACTED]`).

**Binary** (`binary_scanner.py`, REAL): magic-gated ELF/PE/Mach-O; bounded ASCII-string extraction (≥4 chars, 20k cap); library/symbol/algorithm-identifier tables; one finding per distinct matching string (≤100/file); line=0 convention; **never executed** (pure `open().read()`).

**Container** (`container_scanner.py`, REAL): docker-save tarballs (manifest-aware), extracted/OCI layouts (hex-validated digests), single layer tars, Dockerfiles. **Never extracts** (Zip-Slip has no target; symlinks/devices skipped by member type); 512 MB outer cap, 10 layers, 2000 members, 64 KB peeks, 64 MB decompression budget + gzip tell-guard; embedded binaries delegated to binary tables; image-config Env yields names-only findings.

**Dependency** (`dependency_scanner.py`, REAL): requirements (+same-dir `-r` includes, depth ≤3, cycle-guarded), package.json/lock (real JSON), pyproject/Cargo (tomllib), pom.xml (ElementTree), Gradle/Go.mod (regex); exact normalized-name map of 54 crypto packages across Python/Node/Java/Rust/Go; `authlib`-style substrings correctly ignored; versions recorded as inventory — **not CVE scanning** (no vulnerability data anywhere).

**Certificates** (`cert_metadata.py`, REAL): minimal DER walker (no crypto library): RSA modulus bit-length, EC curve OIDs, signature-algorithm OID names, expiry; first-cert-only; malformed input → `None`; bodies never emitted.

**HSM** (`hsm_scanner.py`, REAL static/config): PKCS#11 URIs (only token/manufacturer/model kept), module paths, SunPKCS11/provider config, vendor refs; one finding per line max. No connection/auth/enumeration — impossible by construction (no socket/HSM code exists).

**Cloud** (`cloud_scanner.py`, REAL static/config): AWS KMS/CloudHSM ARNs (12-digit account IDs masked), Azure vault/MHSM URIs, GCP KMS resource IDs, Terraform resource types, TLS policy tokens, KEY_ID/ARN/URL refs. No cloud APIs — impossible by construction.

**Runtime** (`runtime_scanner.py`, REAL opt-in): bundled first-party probe (6 deterministic stdlib ops emitting `ECDAT-TELEMETRY k=v` lines) via Popen + 30 s timeout + kill/wait, fresh tmp cwd, scrubbed env (PATH + seeds only), 64 KB output cap, 50-event cap; telemetry-only parsing; decoys ignored; secrets redacted. **Static scans never execute; arbitrary programs can never run** (probe path is first-party or test-constructed).

---

## 11. Normalization · 12. Canonicalization · 13. Correlation · 14. Strength

- **Normalization** (`models.py`): single `CryptoFinding` dataclass (scanner, file_path, line, algorithm, category, key_size, mode, protocol_version, library, curve, signature_algorithm, expires_at, usage, rationale, confidence, is_mock, id) + `normalize_findings()` exact-key dedupe. Necessary because 7 scanners emit incompatible raw evidence.
- **Canonicalization** (`canon()` in `risk.py`): `SHA-256→SHA-2`, `HMAC-*→HMAC`, `PBKDF2→KDF`, `TLS*→TLS`, else `base_algorithm`. Used ONLY for grouping/linking; risk/recommendations use `base_algorithm` unchanged.
- **Correlation**: runtime→static `supports` links (family match, cap 5) + `related[]` links (`same-artifact` → `same-library` → `runtime-observed` → `same-family`, cap 8, no self-links, non-observation never recorded). Graph = sorted artifact/family/library/finding nodes + typed edges, plain JSON.
- **Strength**: HIGH/MEDIUM/LOW per §8 mapping. **Strength ≠ probability** — it is an evidence-type ranking, stated as such.

---

## 15. Risk · 16. Prioritization · 17. Recommendations · 18. Migration

- **Risk**: §8 formulas; every score ships its `risk_factors` list and human `rationale`, so any P-level is auditable to its causes.
- **Priorities**: P0 (≥90) → Immediate investigation; P1 (≥65) → Near-term; P2 (≥30) → Planned; P3 → Monitor. Two findings differ in priority iff their observable factors differ (algorithm class, key size, protocol age, exposure).
- **Recommendations**: 26-entry family table (verified keys: RSA/ECDSA/ECC/ECDH/DH/DSA/DES/3DES/RC4/MD5/SHA-1/SSL/TLS10–13/TLS/AES/SHA-2/PEM/PKCS11/HSM/KMS/KEYVAULT/CLOUDHSM/ENV-SECRET + DEFAULT "Review manually"). Conservative wording throughout ("evaluate/pilot/verify provider support"); ML-KEM explicitly not a KMS/HSM drop-in.
- **Migration** (`migration.py`): statuses REQUIRED/PLANNED/DISCOVERED derived from severity/priority; IN_PROGRESS/READY only via validated caller overrides (bad values → 400/CLI exit 2). Work items per family (reason, direction, artifacts ≤20 shown, HSM/cloud/runtime flags, unknowns, validation note, deterministic 12-hex id). Roadmap buckets contain work-item ids, never dates.

---

## 19. CBOM-style output

`build_cbom()` emits: `bomFormat`/`specVersion`/`reportType` (**"CBOM-style / CBOM-oriented (not independently standards-verified)"** — compliance explicitly disclaimed), tool/version, target, `scannedAt`, summary (total/mock/real/bySeverity), metadata (target, count, scannerSources, algorithmInventory, context/runtime provenance), riskSummary, recommendations list, mockWarning, components, intelligence (inventory+graph), migration (statuses/items/roadmap/assumptions/report). All JSON-serializable; deterministic except timestamps.

---

## 20. AI analyst internals

`analyst.py`: `build_brief` (≤6000 chars, metadata-only, no raw evidence), `summarize`/`explain_finding`/`explain_migration`/`explain_relationships`/`executive` (each FACT/INTERPRETATION/UNKNOWN), keyword `route()`. Provider path reuses `SubprocessAdapter` with the brief marked authoritative-facts and vault context marked untrusted; failures print the deterministic answer plus a one-line reason. Tests prove: bounds, section presence, unknown-id KeyError, input-immutability (deepcopy), instruction-text-quoted-not-obeyed, routing. **AI cannot mutate findings** — renderers receive the report by value-semantics (read-only use, tested) and return strings.

---

## 21. Obsidian memory

`MemoryProvider.initialize/search/read/write/update/list/link` → `ObsidianVaultProvider` over `.md` files (plus dotted-key convenience in one KV note). Default `/home/chethan/Documents/Vaults/SIH` (env/flag overridable). Guards: traversal rejection on all paths (tested incl. `list /etc`), 1 MB note cap, non-UTF8 fallback, idempotent link. Retrieval: keyword search → top-5 → 4000-char cap (scan path) / 2000-char (analyst path). Two-process test proves disk-backed persistence. Notes are data: never executed, never alter scan math (analyst facts exclude vault text by construction).

---

## 22. Security engineering

Redaction (values, URI attrs, account IDs, PEM bodies, key material — key bodies are never even read, only BEGIN-line metadata); traversal protection (vault paths, scan jail under workspace root, archive member names, OCI digests, Zip-Slip impossible — zero `extract`/`extractall` calls); bounds (§8 constants); runtime isolation (timeout/kill/tmp-cwd/scrubbed-env/caps); CORS localhost-only (5173/4173, GET+POST, Content-Type); Pydantic validation with clean 400/404/422; CLI exit codes 0/1/2 without tracebacks; React-escaped output; provider subprocesses allowlisted, arg-list, no shell. Threat model: analyst's own machine, malicious repo/archive content, malicious vault text — all treated as data. Residual: dashboard needs one human visual pass; status overrides trust the caller.

---

## 23. Resource bounds (actual numbers from code)

512 KB source files · 2000 files/scan · 200 manifests · 20k binary strings · 100 findings/binary file · 512 MB outer archives · 10 layers · 2000 members · 64 KB peeks · 64 MB decompression budget · 30 s probe timeout · 64 KB probe output · 50 runtime events · 8 related links · 5 correlation supports · 50 CBOM reports in memory · 4000/2000-char AI/vault context caps · 1 MB vault notes.

---

## 24. Error handling

API: 400 unknown scanners/bad values, 404 missing target/report, 422 schema violations; FastAPI default safe error bodies. CLI: 0 ok, 1 not-found/operational, 2 invalid input. Scanner failures isolated per-file/per-member (skip + continue); malformed archives return partial results; runtime unavailability degrades to a reason string with static results intact; provider failures degrade to the deterministic answer. No raw tracebacks reach users on any tested path.

---

## 25. Determinism

Sorted traversal, sorted assess output, sorted inventory/graph/roadmap, stable sha1 ids, first-occurrence dedupe, fixed table data, capped iteration. Verified byte-identical repeat scans modulo `scannedAt` (runtime `observed_at` likewise excluded by design).

---

## 26. Performance (observed during local validation — not a benchmark)

≈1.6 MB reference tree → 25 findings in 0.72 s; fixture corpus → 78 findings in <0.1 s; graph for 78 findings = 149 nodes / 631 edges (bounded, no client-side explosion). Single measurement on developer hardware — not a universal claim.

---

## 27. Testing strategy

Backend: one module (`tests/test_pipeline.py`, **56 tests**) — scanner units with in-test-built fixtures (tars, ELF/PE/Mach-O byte blobs, manifests, IaC), risk/rec units, CBOM/API integration via Starlette TestClient, security tests (traversal, redaction, bombs, timeouts with process-liveness asserts), determinism tests. CLI: 6 modules (**35 tests**) incl. real two-process vault persistence proof. Mocked providers (no external AI in tests). Frontend: production build only (no test framework — stated gap, mitigated by contract tests on report shape and null-guarded rendering).

---

## 28. REAL vs FUTURE

| Capability | Status | Explanation |
|---|---|---|
| Source discovery | REAL | 30+ regex rules, redaction, FP controls |
| Binary discovery | REAL | ELF/PE/Mach-O magic + strings, never executes |
| Container discovery | REAL | docker-save/OCI/layers/Dockerfiles, streamed, never runs |
| Dependency discovery | REAL | 6 ecosystems, exact-name map, versions as inventory |
| Cert/key metadata | REAL | minimal DER parser, redaction-first |
| HSM discovery | REAL — static/config evidence | URIs/modules/vendors; no connection possible |
| Cloud discovery | REAL — static/config evidence | KMS/vault IDs, masked; no cloud APIs |
| Runtime discovery | REAL — controlled opt-in probe | bundled fixture, timeout+isolation |
| Correlation/intelligence/migration/CBOM/CLI/API/dashboard/Obsidian/AI analyst | REAL | as documented above |
| Live HSM/cloud enumeration, unrestricted runtime monitoring | FUTURE | explicitly out of scope |

---

## 29. What ECDAT does NOT do (mandatory honesty list)

No ML training/inference; no loss functions/gradients; no neural networks/embeddings/vector DB; no arbitrary process monitoring, kernel instrumentation, TLS MITM, private-key extraction, credential harvesting, malware analysis, or exploit execution; no CVE database or vulnerability verdicts; no live cloud/HSM enumeration; no universal runtime coverage (non-observation ≠ absence); no compliance certification; no exact quantum timelines; no universal PQC compatibility guarantee; no remediation execution; no production deployment claims.

---

## 30. Limitations (genuine)

Static presence ≠ runtime use; string evidence is heuristic; `.key` bare filenames and exotic formats have documented blind spots; dependency map covers 54 known packages (unknown crypto deps are missed — stated); container coverage is static-only; runtime covers only the bundled probe; dashboard untested in a real browser; status overrides are per-report; CBOM is style-compatible, not standards-certified; clean-machine proof covered backend venv, not a second `npm ci`.

---

## 31. Glossary

**Cryptographic inventory** — the enumerated set of crypto artifacts in a target. **CBOM** — Cryptography Bill of Materials; ECDAT emits CBOM-*style* JSON, not certified CBOM. **PQC** — post-quantum cryptography. **KEM** — key-encapsulation mechanism. **ML-KEM** — NIST FIPS 203 lattice KEM (migration target). **ML-DSA** — FIPS 204 lattice signatures. **SLH-DSA** — FIPS 205 hash-based signatures (conservative option). **HSM** — hardware security module; ECDAT sees config evidence only. **PKCS#11** — cryptoki API standard for tokens/HSMs; ECDAT parses URIs/configs. **TLS** — transport security; versions/cipher tokens detected. **Certificate** — X.509 public metadata (never private keys). **Cryptographic agility** — ability to migrate algorithms (what the roadmap plans). **Discovery** — finding references (static) vs **runtime analysis** — observing the probe. **Evidence strength** — HIGH/MEDIUM/LOW evidence-type rank, not probability. **Correlation** — typed links between findings. **Migration readiness** — Mosca-heuristic sequencing. **Mosca heuristic** — lifetime+migration > horizon ⇒ exposure. **AI analyst** — deterministic renderers + optional provider interpretation.

---

## 32. Evaluator Q&A (answers grounded in implementation)

**Does ECDAT use machine learning?** No — grep-verified absence of every ML library/technique; it uses rules, scoring, sorting, grouping.
**What model is trained? / loss function?** None — no training exists, so no model, loss, gradients, or datasets exist either.
**Why no ML?** Deterministic output is auditable, reproducible, dependency-free, and testable — required properties for a migration-inventory tool; probabilities would be dishonest without labeled data.
**How is risk calculated?** §8 formulas: additive 70/45/35/20/25 score → P0–P3 thresholds, Mosca boolean, each score shipping its factor list.
**How are algorithms detected?** Compiled regexes (source), magic-gated string tables (binary), streamed tar member inspection (containers), manifest parsers + exact-name map (dependencies), DER walking (certs), config patterns (HSM/cloud), telemetry lines (runtime).
**Binaries without executing?** Magic bytes select supported formats; only `read()` + regex run — execution is structurally impossible (no exec/spawn of targets).
**False positives?** Confidence tiers, attribute-access suppression for `.key`, exact-name dependency matching, path/quoted requirements, bounded evidence; residual FPs documented.
**Containers safely?** Never extracted (Zip-Slip impossible), streamed with member/layer/decompression caps, digest-validated.
**HSM usage?** Config references (URIs redacted, modules, vendors). **Direct HSM connection?** No — no socket/HSM code exists. **AWS KMS queries?** No — ARN/config patterns only, account IDs masked.
**Runtime scope/proof of absence?** Bundled probe under timeout+isolation; observations are per-run facts; non-observation explicitly never means absence (stated in code, GUI, and correlation notes).
**Correlation/strength?** Family-canonical links capped at 8 + runtime supports capped at 5; HIGH/MEDIUM/LOW from usage+confidence, not probabilities.
**PQC guidance? Why ML-KEM/ML-DSA?** 26-entry table mapping detected families to NIST FIPS 203/204 directions with evaluate/pilot wording; chosen because they are the standardized primitives — ECDAT does not implement them.
**Mosca? Quantum-break prediction?** Lifetime+migration > horizon ⇒ exposure boolean for sequencing only; explicitly not a prediction (stated in code, CBOM, GUI, migration assumptions).
**CBOM? Vulnerability scanner?** CBOM-style JSON (compliance disclaimed); discovery + inventory, never CVE verdicts.
**AI vs deterministic findings?** Analyst renders report facts; providers append labeled interpretation; failures fall back; mutation tested impossible.
**Prompt injection?** Vault/report text is data: facts exclude vault text, evidence is quoted-not-obeyed (tested), nothing executes notes.
**Why Obsidian, no vector DB?** Bounded keyword retrieval over human-readable Markdown is sufficient, auditable, and dependency-free; embeddings would add opacity without need.
**Provider/scanner unavailable?** Degrades to deterministic answer / reason string / partial results; static scans never depend on runtime or providers.
**Biggest limitations?** §30: static≠runtime, map coverage, no browser test yet, per-report overrides, style-not-standard CBOM.

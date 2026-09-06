# Requirements (SIH26164, distilled — not invented)

## Inputs

Source repositories, binaries, libraries, container images; scan scope + data-lifetime /
migration-time estimates + QRQC-horizon assumption.

## Outputs

- CBOM inventory: algorithms, keys, certs, protocols (+versions/modes), libraries, HSM refs, cloud KMS refs.
- Quantum-risk classification per artefact (Mosca-exposed or not, severity).
- PQC/hybrid recommendations with latency/cost notes.
- Standardized machine-readable report (CBOM JSON) + interactive GUI.

## Functional

1. Scan source/config text for crypto artefacts (REAL in MVP).
2. Normalize every hit to `CryptoFinding` (scanner, location, algorithm, category, key size,
   mode/version, evidence, confidence, `is_mock` flag).
3. Score risk via Mosca: `data_lifetime + migration_time > qrqc_years_left → exposed`.
4. Recommend alternatives per risk profile.
5. Emit CBOM JSON with mock results explicitly labeled; render in GUI with MOCK badges.

## Non-functional

Offline-capable MVP; no secrets in reports (redact key material, keep metadata);
scan of a small repo < 30s; deterministic mock output for tests.

## MVP / Future / Unnecessary

- MVP: SourceScanner + risk + recs + CBOM + GUI + `POST /scans` flow.
- Future: real binary/container/library/HSM/cloud connectors, policy engine, trend DB.
- Unnecessary now: microservices, K8s, cloud deploy, vector DB, app DB for memory.

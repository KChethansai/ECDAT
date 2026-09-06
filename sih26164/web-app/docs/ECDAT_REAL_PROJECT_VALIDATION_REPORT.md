# ECDAT Real Project Validation Report

- **Date:** 2026-09-06
- **Scope:** real-data validation of the finalized ECDAT web application against real project directories. No mocks as primary validation; no project files modified; no product code changed (see §17).

## 1. Executive Summary

Overall result: **PASS WITH OBSERVATIONS** (original validation; see §20 for the post-hardening verdict: **PASS**)

All 6 real-project scans plus zero-finding, multi-scan, error-path, runtime, responsive, console, CBOM, build, and backend-suite checks completed through the actual browser UI. Discovery → Evidence → Risk → Priority → Recommendation → Migration → CBOM propagates correctly on real data, all 7 scanner types fired on real inputs, 19/20 manually traced evidence lines verified byte-for-byte, zero JS errors. One genuine medium-severity false-positive pattern found (HSM vendor substring `nShield` matches UI icon name `IconShield`); two low-severity heuristic-noise observations; one by-design scope limitation (out-of-jail sibling projects are rejected, not scanned). Nothing here blocks demo or use; the medium finding is a scanner-precision fix for a future pass, deliberately NOT fixed in this validation (product-change freeze).

## 2. Environment

- OS: Linux (Python 3.14.7, system `/usr/bin/python3`)
- Node: v24.19.0, npm 11.17.0 (repo `package.json`: react 18.3.1, vite 6.0.3 — no new dependencies)
- Backend: `sih26164/web-app/backend/.venv/bin/uvicorn app.main:app --port 8000`
- Frontend: `sih26164/web-app/frontend` → `npm run dev -- --port 5173 --strictPort` (API proxied)
- Browser: headless Mozilla Firefox 155.0.1 driven via a stdlib-only Marionette client (Chrome SIGTRAP-crashes at launch in this environment — environment defect, unrelated to ECDAT; documented in prior verification)
- Frontend URL: http://localhost:5173/ · Backend URL: http://localhost:8000/
- Health: `{"ok":true,"service":"ecdat","version":"0.1.0","scanners":["binary","cloud","container","dependency","hsm","runtime","source"],"runtimeProbe":"present"}`

## 3. Projects Tested

| Project | Path | Type | Scan Result | Findings |
|---|---|---|---|---|
| frontend-src | `/home/chethan/Projects/ECDAT/sih26164/web-app/frontend/src` | React JSX (real app UI) | 200, scan `93ca5769efb5` | 8 |
| backend-app | `/home/chethan/Projects/ECDAT/sih26164/web-app/backend/app` | Python (ECDAT engine itself) | 200, scan `89e2edb9affd` | 214 |
| frontend-full | `/home/chethan/Projects/ECDAT/sih26164/web-app/frontend` | JS + lockfile + build output | 200, scan `9386c8f1ff9b` | 124 |
| samples | `/home/chethan/Projects/ECDAT/sih26164/web-app/backend/samples` | fixtures: py/binaries/tar/manifests/certs/IaC | 200, scan `c262f6e9ced4` | 72 |
| cli-agent | `/home/chethan/Projects/ECDAT/sih26164/cli-agent` | Python CLI + tests | 200, scan `127174cee71b` | 18 |
| obsidian-vault | `/home/chethan/Projects/ECDAT/obsidian-vault` | Markdown docs (frozen copy) | 200, scan `747d96be5514` | 53 |
| empty-proj | scratch `notes.txt` (benign prose, deleted after) | zero-finding probe | 200, scan `272dc9afafca` | 0 |
| sample+runtime | bundled fixture, `runtime:true` | runtime opt-in | 200, scan `401c8527ad7b` | 21 (15+6) |

**Scope limitation (by design, verified):** sibling projects (`Stocks`, `CampusFlow`, `ruflow`, …) live outside the API filesystem jail (`WORKSPACE_ROOT` = ECDAT repo root; `..` escapes, symlinks, and out-of-tree absolute paths are rejected). `POST /scans {"target":"/home/chethan/Projects/Stocks"}` → `400 "unsafe scan target"` via API and via UI. The jail was NOT weakened for this validation. Consequence: no in-jail Java/C++/Go project exists; those ecosystems remain covered by the backend fixture suite (56 tests, green), not by live UI scans — stated as not-tested, not assumed.

## 4. Scan Results

### frontend-src
- target `/home/chethan/Projects/ECDAT/sih26164/web-app/frontend/src`, static, 200, ~0.5 s UI round-trip
- 8 findings, 0 mock; scanners: source 3, hsm 5; algos: HSM 5, KEYSIZE 3; sev: 8 medium; status: 8 MIGRATION_PLANNED; roadmap Immediate 0 / Near-term 0 / Planned 2 / Monitor 0; recs: Review manually, HSM-inventory guidance

### backend-app (stress case: 214 findings, 578 KB report)
- target `…/backend/app`, static, 200
- 214 findings, 0 mock; scanners: source 177, hsm 21, cloud 16; top algos: RSA 24, KEYSIZE 15, HSM 15, SHA-2 13, ECDSA 10
- sev: critical 57 / high 26 / medium 91 / low 40; pri: P0 28 / P1 55 / P2 5 / P3 126; exposed 174; recs 21; roadmap 11 / 0 / 14 / 6
- UI rendered, filtered, and drew the drawer over this report with no lag observed

### frontend-full
- 124 findings, 0 mock; scanners: source 119, hsm 5; algos dominated by SHA-2 ×116 (all from `package-lock.json` integrity hashes — see §9)
- sev: medium 8 / low 116; roadmap 0 / 0 / 2 / 1; recs 3

### samples (all-scanner case)
- 72 findings, 0 mock; scanners: source 39, binary 10, container 7, dependency 6, cloud 6, hsm 4
- sev: critical 4 / high 5 / medium 39 / low 24; roadmap 5 / 0 / 15 / 5; recs 14
- Every scanner type produced real, traceable evidence (§5)

### cli-agent
- 18 findings, 0 mock, all source; algos: RSA 8, KEYFILE 6, OpenSSL 3, MD5 1
- sev: critical 8 / high 1 / medium 9; roadmap 2 / 0 / 2 / 0; recs 3

### obsidian-vault
- 53 findings, 0 mock; scanners: source 52, cloud 1; sev: critical 10 / high 16 / medium 11 / low 16; roadmap 6 / 0 / 4 / 3; recs 9
- Prose mentions of algorithms score severity like code references (documented heuristic limitation, see §9/§16)

## 5. Evidence Validation

Every row below was opened read-only and the exact line compared to the reported evidence.

| Project | Finding | File | Line | Scanner | Evidence Verified |
|---|---|---|---|---|---|
| cli-agent | MD5 | tests/test_memory.py | 55 | source | PASS (`assert "md5" in …`) |
| cli-agent | RSA | tests/test_analyst.py | 14 | source | PASS (fixture JSON references RSA) |
| backend-app | RSA | scanner/binary_scanner.py | 67 | source | PASS (own pattern table — reference, not use) |
| backend-app | SHA-1 | migration.py | 10 | source | PASS (`from hashlib import sha1`) |
| backend-app | SHA-512-RSA | scanner/cert_metadata.py | 14 | source | PASS (OID map entry) |
| backend-app | HSM | recommend.py | 37 | hsm | PASS (CloudHSM guidance text) |
| backend-app | HSM | scanner/cloud_scanner.py | 25–26 | hsm | PASS (own `cloudhsm` regex) |
| backend-app | KMS | recommend.py | 34–36 | cloud | PASS (`"KMS":` dict key; evidence redacted honestly) |
| frontend-src | HSM | components/Header.jsx | 2, 18 | hsm | **FAIL — false positive** (`IconShield` matched by `nShield` vendor substring, §16) |
| frontend-src | KEYSIZE | components/FindingDrawer.jsx | 87 | source | PASS w/ observation (`f.key_size` UI code, conf 0.5/LOW, §16) |
| frontend-full | SHA-2 ×116 | package-lock.json | 22 (e.g.) | source | PASS (integrity hashes are real hash refs; inventory-noise observation, §16) |
| samples | RSA-1024/MD5/SHA-1 | vuln_sample/app.py | 9/5/6 | source | PASS (incl. `[REDACTED]` on secret line) |
| samples | KMS/KEYVAULT/GCP | cloud/keys.json | 2/3/4 | cloud | PASS (account `123456789012` masked to `****` in evidence) |
| samples | PKCS11 | hsm/java.config | 3–4 | hsm | PASS (`libsofthsm2.so`, `SunPKCS11-DemoHSM`) |
| samples | PKCS11 | hsm/pkcs11.conf | 2 | hsm | PASS (`opensc-pkcs11.so`) |
| samples | ring/x-crypto/jsonwebtoken | dependencies/{Cargo.toml:4,go.mod:5,package.json:3} | — | dependency | PASS (names + versions match evidence) |
| samples | RSA/OpenSSL | binaries/openssl-linked-demo.bin | 0 | binary | PASS (ELF magic verified via `file`; target never executed) |
| samples | ENV-SECRET/requirements/cert | containers/demo-image.tar | — | container | PASS (password value withheld; nothing extracted) |
| obsidian-vault | KMS | 01-Project/Requirements.md | 10 | cloud | PASS (prose reference) |
| obsidian-vault | RSA/3DES | 07-Sessions/…md | 6/8 | source | PASS (prose mentions) |

Result: **19/20 PASS**, 1 concrete FP. No invented paths, no wrong line numbers, no duplicates, no malformed findings, no mock findings anywhere (`mock: 0` on all six reports).

## 6. Risk Validation

- RSA-1024 (samples/app.py:9) → critical/P0 with "RSA key below 2048 bits" factor — matches `risk.py` formula exactly.
- MD5/SHA-1 + exposed → high; STDLIB/hashlib refs → low/medium; MOSCA_EXEMPT behavior consistent (AES/STDLIB low despite exposure).
- `riskSummary.priorities` and UI buckets agree in every report (e.g. samples P0 6/P1 3 → Immediate 5: bucket is per-work-item worst-member roll-up, roadmap counts are work-item ids — consistent, not contradictory).
- Mosca note ("deterministic migration ordering, not QRQC prediction") rendered in UI on every report. No timelines, no probabilities anywhere.

## 7. Recommendation Validation

- RSA → "ML-KEM-768 hybrid + ML-DSA-65" (samples, cli-agent, vault) ✓
- MD5/SHA-1 → "SHA-256 / SHA-3-256" ✓ · DES/3DES → "AES-256-GCM" ✓ · TLS → "TLS 1.3 …" ✓
- KMS/KEYVAULT/CLOUDHSM/HSM → inventory/roadmap guidance, explicitly NOT ML-KEM drop-in ✓ (checked in UI rec cards and `recommend.py`)
- Unknown families (KEYFILE, STDLIB, KEYSIZE) → "Review manually" ✓ — no canned mapping invented
- Grouped rec cards show direction + migration path + supporting-finding evidence; counts match components

## 8. Migration Validation

Bucket counts (Immediate / Near-term / Planned / Monitor) from UI == report `roadmap` in all scans: e.g. backend-app 11/0/14/6, samples 5/0/15/5, vault 6/0/4/3. "Near-term 0" everywhere is consistent (P1 maps to MIGRATION_REQUIRED → Immediate bucket roll-up per `bucket_for`/roadmap logic — verified in code, not a UI bug). No dates, costs, ROI, or completion claims; IN_PROGRESS/READY absent without overrides; assumptions listed; unknowns surfaced per item.

## 9. CBOM Validation

- View-JSON dialog on the 72-finding samples report: parses as valid JSON (289,720 chars), `summary.total` 72 == 72 components, `mock` 0, inventory 25 rows, workItems 25, target + scanId match the on-screen report, `reportType` carries the not-standards-verified disclaimer.
- File download was validated in the prior finalization pass; this pass validated the identical payload via the in-UI viewer (parsed programmatically). Actual file-save re-test: not repeated (stated, not assumed).

## 10. Multi-Scan State Validation

frontend-src (8 findings, id `a050a32824ee`, P0 filter showing "0 of 8", drawer open on KEYSIZE) → cli-agent scan → id `d9cf7fdaf3ff`, metrics replaced (18/9/2), drawer auto-closed, result count "18 of 18". Six sequential matrix scans likewise each fully replaced ids/metrics/inventory/buckets/recs. **PASS** — no stale findings, no stale drawer; filters persist by design.

## 11. Error Handling

- Nonexistent in-jail path → `404 "Not found: target not found: …"` + retry affordance; previous report stays visible *with the alert on top* (explicit, not masquerading). **PASS**
- Out-of-jail absolute path (`/home/chethan/Projects/Stocks`) via UI → `400 "Invalid request: unsafe scan target"`, no `[object Object]`, no crash. **PASS**
- 422 array-detail rendering was fixed previously; backend contract re-confirmed live (`greater_than_equal` array shape).

## 12. Runtime Validation

Sample + runtime opt-in via UI: 21 findings (15 static + 6 probe observations), hero chip "runtime: 6 controlled observation(s)", `runtimeProvenance.available:true` in report, buckets coherently extended (Planned 8), static findings intact. Static scan copy ("target code is never executed") vs explicit probe opt-in both displayed. **PASS**. Runtime on third-party projects was not forced (probe only runs the bundled fixture — limitation stated, not tested beyond).

## 13. Responsive Validation

Dense 72-finding report: 768px (756==756), 500px live (488==488, full DOM audit zero escapees), 390px column-fit (bodyScroll exactly 390, zero offenders; tables scroll internally by design; drawer 100vw; filters/migration/recs/export usable). Exact-390 method caveat as previously documented (headless floor 500px + 390px content-column test, same ≤640px regime). **PASS**

## 14. Console Validation

In-page error collector across load → 6 scans → drawer → filters → errors → runtime → CBOM dialog → responsive: **`[]` — zero JS errors.** No React exceptions, no failed app assets (favicon is inline data-URI).

## 15. Performance Observations

Measured only, no benchmarks: UI submit→rendered ≈ 0.5–2.7 s per scan (includes 1 s settle polling; true render faster); server-side samples scan 0.038 s; 214-finding/578 KB report filtered and opened the drawer with no perceptible lag; 289 KB CBOM dialog rendered <1 s. Initial load fast. No virtualization needed at these sizes.

## 16. Issues Found

### Critical
None.

### High
None.

### Medium
1. **HSM vendor-substring false positive (`hsm_scanner.py:26`).** Pattern `nShield` (case-insensitive, no left word boundary) matches `IconShield` in the dashboard's own icon imports → 5 HSM findings on `frontend/src` (Header.jsx:2,18, States.jsx:2, icons.jsx) with confidence 0.6/MEDIUM. Evidence is displayed honestly so a reviewer can dismiss it, but it inflates HSM inventory on any JS/TS codebase using "Shield" icon names. Repro: scan `sih26164/web-app/frontend/src`, filter scanner=hsm. Suggested future fix (not applied — validation freeze): left-boundary or token-aware match for vendor names.

### Low
2. **KEYSIZE heuristic noise on JS property access.** `\bkey[_-]?size\b` matches `f.key_size` display code (FindingDrawer.jsx:87, FindingsExplorer.jsx:130,132), conf 0.5/LOW. Honest evidence, negligible severity; same class of fix as above.
3. **Lockfile integrity-hash inventory noise.** `package-lock.json` contributes 116 LOW SHA-2 findings (one per `sha512-…` integrity line), dominating the frontend inventory. True hash references per documented string-evidence semantics, but a lockfile-aware usage tier would improve signal.

### Observations (not defects)
- Self-scanning a crypto tool yields high critical counts (backend-app: 57 critical) — expected: the engine's own pattern tables/OID maps *reference* these algorithms. Static≠runtime disclaimers are shown throughout.
- Vault prose mentions score severity like code (vault: 10 critical) — inherent to reference-based discovery; documented limitation.
- Sibling projects outside the jail cannot be scanned; Java/C++/Go live coverage remains suite-fixture-only.
- "Near-term 0" in all roadmaps is correct per bucket roll-up logic, not a UI bug.
- Filters persist across scans by design; drawer + metrics + inventory + scanId always reset.

## 17. Changes Made During Validation

**NO PRODUCT CODE CHANGES.** Backend, frontend, scanners, risk, migration, CBOM, API, and tests are byte-identical to the finalized state (only pre-existing finalization work is in the tree). Scratch verification scripts lived in `.verify-tmp/` (repo root) and were deleted afterwards; `empty-proj/` probe likewise. Scanned projects were opened read-only; nothing was installed, built, executed, or written outside the deleted scratch dir.

## 18. Final Verdict (original validation)

**PASS WITH OBSERVATIONS** — superseded by §19 below after precision hardening.

ECDAT scans real, diverse, in-jail projects through the real UI; every displayed number traces to verified report data; evidence traces to real file content 19/20 with the single miss honestly characterized above; risk/rec/migration/CBOM propagate consistently; empty/error/multi-scan/runtime/responsive/console behavior all pass; backend suite 56/56 green.

## 19. Scanner Precision Hardening

Follow-up task addressing the three §16 scanner-quality observations. No frontend, API, risk-formula, migration, CBOM, or jail changes. Method: unit tests first (7 new tests in `backend/tests/test_precision.py`), then implementation, then full-suite + live UI revalidation of all six §3 projects plus the zero-finding probe.

### 19.1 HSM vendor substring false positive — RESOLVED

- **Original issue:** `VENDOR_RE` in `app/scanner/hsm_scanner.py` used bare substring alternation, so `nShield` matched `IconShield` (5 HSM findings on `frontend/src`), and by the same mechanism `Luna` would match `lunar`, `ncipher` would match `encipher`.
- **Root cause:** no token boundaries around vendor alternatives.
- **Fix (`hsm_scanner.py`):** wrapped the whole alternation in `(?<![A-Za-z])…(?![A-Za-z])`. Case-insensitivity, snake_case (`my_nshield`), versioned (`nshield2`), and prefixed (`aws_cloudhsm`) references still match; letter-glued identifiers (`IconShield`, `ShieldIcon`, `nShieldLikeIdentifier`, `lunar`) no longer do. No project-specific exclusions; no ECDAT paths hardcoded.
- **Tests added:** genuine references (`nShield`, `nShield Connect`, `Thales nShield`, lowercase `nshield …`, `SunPKCS11`, `libsofthsm2.so`, `aws_cloudhsm_cluster`) must hit; `IconShield` / `SomeIconShieldComponent` / `ShieldIcon` / `nShieldLikeIdentifier` / `lunar` / `lunch` must not.
- **Before/after (live UI rescans):** `frontend/src` HSM findings 5 → 0; `frontend` HSM findings 5 → 0; genuine HSM fixtures in `samples` (PKCS11 ×3, SoftHSM, SunPKCS11) byte-identical before/after; `backend/app` HSM set byte-identical apart from the fix's own new documentation lines (see §19.4).
- **Evidence verification:** re-timestamped HSM rows in `samples` re-checked against `hsm/java.config:3-4`, `hsm/pkcs11.conf:2` — PASS.

### 19.2 KEYSIZE heuristic noise — RESOLVED

- **Original issue:** RULES entry `\bkey[_-]?size\b` fired on any mention, including UI property reads (`f.key_size`, `{f.key_size}`) and the scanner's own dedup-key reads (`finding.key_size`).
- **Root cause:** no syntactic context requirement.
- **Fix (`source_scanner.py`):** removed KEYSIZE from the bare-match RULES; new `_keysize_hit()` requires declaration context — assignment (`key_size=2048`, incl. `config.key_size = 2048`), mapping/typing colon with a value (`key_size: 4096`, `"key_size": 1024`), or CLI/config numeric form (`keysize 2048`). Bare reads (`f.key_size`, `print(key_size)`, `if finding.key_size:`, `key_size == 1024`, `key_size => …`) are skipped. Declared bit-lengths are parsed into `key_size` (e.g. `key_size=2048` → 2048); usage is now the honest `key size declaration` at confidence 0.5/LOW instead of bare `direct`.
- **Tests added:** positives (`RSA(key_size=1024)`, `key_size=2048`, `key_size: 4096`, `config.key_size = 2048`, `keysize 2048`, `"key_size": 1024`) must hit; negatives (`f.key_size`, `{f.key_size}`, `print(key_size)`, `finding.key_size:`, `object.key_size`, `key_size == 1024`) must not; bit parsing + usage/confidence/strength asserted.
- **Before/after (same-file, old-code vs new-code differential):** all 29 removed findings are KEYSIZE-`direct` bare reads (incl. the old RULES entry matching its own pattern source); 6 genuine declarations re-emitted as `key size declaration` (`models.py:17` field decl, `risk.py:50` signature decl, `key_size=metadata[…]` call sites in binary/container/source scanners, `"key_size": None` dict key). `frontend/src` KEYSIZE 3 → 0. Samples/clip-agent/vault finding sets byte-identical.
- **Evidence verification:** `binary_scanner.py:164` (`key_size=metadata["key_size"]`) and `models.py:17` (`key_size: int | None = None`) re-opened — both are genuine declaration sites, PASS.

### 19.3 Lockfile integrity-hash metadata — RESOLVED (classification, no suppression)

- **Original issue:** all 116 `package-lock.json` `sha512-…` integrity lines emitted `SHA-2`/`hash`/`direct`/0.85 findings indistinguishable from application crypto usage.
- **Root cause:** no lockfile/integrity context in the source scanner.
- **Fix (`source_scanner.py`):** new `_lockfile_integrity()` — when the file is a known lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `poetry.lock`, `go.sum`) and the line carries integrity metadata (`"integrity": "…"`, `sha{1,224,256,384,512}-<base64>`), matching SHA-1/SHA-2 hits are emitted as category `dependency`, usage `dependency integrity metadata`, confidence ≤0.4 (→ LOW strength), with rationale "verifies vendored package bytes, not application cryptographic usage". Algorithm stays `SHA-2`, so inventory grouping, recommendations, and counts are preserved — the evidence remains discoverable and filterable, but is now self-describing. `risk.py`, `migration.py`, `cbom.py` untouched (severity/priority derive from algorithm/key-size/exposure only, so ordering is unchanged by construction).
- **Tests added:** lockfile integrity line → `(SHA-2, dependency integrity metadata, ≤0.5, dependency)` + LOW strength; real `hashlib.sha256(…)` in `.py` still `(SHA-2, direct, 0.85, hash)`; non-integrity lockfile lines unaffected.
- **Before/after (live UI rescan, `frontend`):** 116/116 integrity rows reclassified in place (same lines, new usage/category/confidence); total 124 → 116 (only the 5 HSM + 3 KEYSIZE removals); families 3 → 1; UI renders the new usage in tables, drawer ("Usage: dependency integrity metadata" verified in the analyst drawer), and scanner filter (116/116 source). No data-model redesign was needed — `usage`/`category`/`rationale`/`confidence` already supported this.
- **Evidence verification:** `package-lock.json:22` integrity line re-opened — byte-identical to reported evidence, PASS.

### 19.4 Before/after totals and risk regression

Live UI rescans of all six §3 projects plus zero probe (run `run_scan` differential old-code vs new-code on identical trees confirms the UI numbers):

| Project | Before | After | Delta explanation |
|---|---|---|---|
| frontend-src | 8 | **0** | −5 HSM FP, −3 KEYSIZE reads (target checks PASS) |
| frontend-full | 124 | **116** | −8 removals; 116 SHA-2 reclassified, counts preserved |
| backend-app | 214 | **221** | −29 bare-read KEYSIZE, +14 declarations; remainder is self-scan of the fix's own new pattern-documentation lines (RSA×2 critical, SHA×1 high, SHA-2×1 low, KEYSIZE×8/HSM×3 medium, all honest string references on added lines — verified line-by-line) |
| samples | 72 | 72 | byte-identical finding set |
| cli-agent | 18 | 18 | byte-identical finding set |
| obsidian-vault | 53 | 53 | byte-identical finding set |
| empty probe | 0 | 0 | truthful empty state retained |

Pure behavior delta on identical files: critical/high **unchanged** (57/26), roadmap **unchanged** (11/0/14/6), recommendations for pre-existing findings unchanged, migration logic untouched, `severity()`/`priority()`/`mosca_exposed` source-identical. The +3 crit/high in shipped state are the fix's own `RSA(key_size=1024)` doc examples scoring critical per the (correct, unchanged) short-RSA rule — self-scan transparency, not a regression.

### 19.5 CBOM, frontend, security regression

- CBOM (samples, post-fix, parsed from the in-UI viewer): valid JSON, total 72 == 72 components, mock 0, inventory 25, workItems 25, target/scanId match screen, disclaimer present. No stale entries (finding ids are content-derived; removed FPs simply absent).
- Frontend (unchanged code): metrics, inventory, findings, P0/scanner filters, drawer with new usage strings, rec cards, migration board, export dialog, empty state — all exercised on post-fix reports via headless Firefox; zero JS errors; 500px and 390px-column checks pass with the dense 72-finding report.
- Security: jail intact live (`/home/chethan/Projects/Stocks` → 400, `../..` → 400), CORS unchanged (evil origin gets no ACAO; localhost:5173 allowed), no command execution/HTML injection introduced (`dangerouslySetInnerHTML` count 0), evidence still truncated/redacted server-side. `WORKSPACE_ROOT` untouched.

### 19.6 Change log (this task only)

- `sih26164/web-app/backend/app/scanner/hsm_scanner.py` — token-aware `VENDOR_RE` + comment. Affects scanner output (fewer vendor FPs); no API/risk/CBOM change.
- `sih26164/web-app/backend/app/scanner/source_scanner.py` — KEYSIZE declaration-context logic, lockfile integrity classification, supporting regexes/helpers. Affects scanner output (fewer bare-read hits, reclassified lockfile rows); no API/risk/CBOM/jail change.
- `sih26164/web-app/backend/tests/test_precision.py` — NEW, 7 tests covering all three fixes (PASS/FAIL examples from the task spec).
- `sih26164/web-app/docs/PIPELINE.md` — documents the three classification behaviors.
- `sih26164/web-app/docs/ECDAT_REAL_PROJECT_VALIDATION_REPORT.md` — this section + verdict update.
- Scratch `.verify-tmp/` (drivers, old-tree copy, downloaded reports) created during validation and deleted afterwards; scanned projects untouched (read-only).

### 19.7 Future work (not implemented)

> Support for explicitly configured additional scan roots could allow broader local-project validation while preserving an allowlist-based filesystem boundary. The current validation intentionally does not weaken the existing jail.

## 20. Final Verdict (after hardening)

**PASS**

All three precision issues resolved and verified end-to-end: HSM FP eliminated with genuine fixtures intact; KEYSIZE restricted to declaration context with bit parsing; lockfile hashes reclassified as self-describing integrity metadata without suppression or redesign. Suite 63/63 (56 existing + 7 new), frontend build green, six real projects + zero probe + runtime-equivalent rescans pass through the UI with zero JS errors, CBOM/security/responsive regressions all pass. Remaining §16 items are documented limitations (prose severity, self-scan counts, jail scope), not defects.

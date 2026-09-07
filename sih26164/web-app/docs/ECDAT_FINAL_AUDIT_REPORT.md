# ECDAT final pre-push audit report

- Audit date: 2026-09-07
- Repo: `KChethansai/ECDAT`, branch `main`
- Commit before audit: `55b69ff` (plus uncommitted session work: validation,
  knowledge, code-intelligence — all included in this audit)
- Scope: full engineering / security / architecture / test / docs / hygiene / git audit

## Architecture verified

Vite React → FastAPI → scanners → normalization → risk (Mosca) → recommendations →
correlation → migration → CBOM; additive code-analysis (`CodeFinding`, engineering
impact only) and opt-in active validation; AI absent by design (prompt renderer only).
No redesign performed; all changes are local defect fixes.

## Issues found and fixed

P0 (security/release blockers): none found. Secrets scan clean (only venv
third-party docstrings); no tracked venv/build artifacts; PEMs are truncated
test fixtures; CORS stays localhost-only; jail/symlink/redaction intact.

P1 (correctness):
- `http_probe`: connection-constructor failure masked by `NameError` in `finally`
  → guarded close.
- `safety.check_host_port`: IPv6 literals unbracketed → always rejected → bracket
  + integer port coercion.
- CLI: non-object JSON (`[1,2,3]`) crashed `remediate`/`verify-fix` with traceback
  → `_load_json_file` shape validation; SARIF/`--out` writes moved into `try`
  (bad paths → exit 1, not traceback).
- `verification.verify`: non-list/non-dict inputs crashed → `ValueError` + item guards.

P2 (quality, safely fixable):
- Repeated AST re-parsing (3–5× per file across analyzers) → single shared parse
  via `symbols.parse_tree` (backend-app analysis 4.2 s → 1.5 s).
- Duration budget unenforced on TLS handshakes → checked per target in runner.
- Unbounded inbound lists → `MAX_LIST_ITEMS` caps + 1024-char target cap (400s).
- `verify()` confidence cast crash on non-numeric → `_confidence_of` fallback.
- `build_plan` accepted string constraints (set-of-chars) → type guard.
- Stale/misleading wording: dead-code rationale ("one occurrence"), structure
  orphan description (claimed unchecked property), dead `elif` branch, missing
  parens in `or`/`and` chains.
- `DO_NOT_AUTOMATE` priority was unreachable → HIGH remediation risk now maps to it.
- Duplication bucket cap `break` only exited the inner loop → file-level bound.
- Dependency false positives on dist-vs-import names → `DIST_TO_IMPORT` alias map.
- Dogfood dead imports removed (4 in new code: `Path`, `asdict`, `field`,
  `urlsplit`+`apply_correlation`; pre-existing `json` in `cloud_scanner.py`,
  `Path` in `cli.py`).
- Docs drift: test counts (→103/39), ranking labels, root-manifest limitation.
- Hygiene: LibreOffice lock file deleted.

P3 (observations, left as-is): `run_validations` cyclomatic 40 is intentional
sequential-pipeline shape; `sni` param is a future extension point; `iter_files`
`languages` filter unused by current callers; `/tmp` at 80% (environment, not repo);
no-browser environment → browser validation NOT TESTED (compensated with live-API
smoke: scan/code-analysis/plans/verify/SARIF/400s/404/CORS-deny all PASS).

## Test results (actual)

- Backend: **103 passed** (82 baseline + 16 code-intelligence + 5 release-audit)
- CLI: **39 passed** (37 + 1 flow + 1 hardening)
- Frontend: `npm run build` succeeds
- New tests: IPv6/port validation, payload caps, malformed-JSON CLI paths,
  `verify()` hardening, dep aliases, `DO_NOT_AUTOMATE` mapping

## Real-project validation (actual)

frontend-src 18, backend-app 248, frontend-full 19, samples 3, cli-agent 44,
obsidian-vault 0, empty 0 — all deterministic across runs, processes, and
`PYTHONHASHSEED` values. Count deltas vs pre-audit (259→248 on backend-app)
investigated: audit fixes removed 13 false positives (dead imports, `ast.*`
self-hits), new code added ~2 duplicate windows — net improvement, explained.
Crypto regression byte-identical (components/summary/migration).

## Security status

PASS: no secrets, no SSRF bypass (loopback-default, per-hop redirect checks,
credential rejection, budgets), no XSS vectors (`innerHTML` absent, React-escaped),
error paths return 400/404 without tracebacks, error strings avoid paths/secrets,
stdlib-only product code, no subprocess in product paths, `httpx` retained with
cause (Starlette TestClient transport).

## Documentation status

Synchronized: counts, ranking labels, limitations (root manifests, JS heuristics,
caps), matrix/architecture/report docs accurate. License attributions intact
(knowledge: Apache-2.0 pinned commit; Ponytail/GSD/Strix: concepts only, no code).

## Final status

PASS WITH OBSERVATIONS (P3 items above; browser validation not tested).
No architecture regression. No AI dependency. CodeFinding/CryptoFinding separation
intact (grep-verified, zero crypto-file diffs). Mosca/CBOM untouched.

# ECDAT repository minimization report

Date: 2026-09-07. Branch: `main`. No commit/push (review only).

## Scope

Full-tree audit for vendored upstream repositories, unused skills/configs/deps,
dead code, stale references, and license/provenance gaps across ECDAT
(`sih26164/` product + workspace root). Prior audit fixes (GitHub hardening) and
Stitch visual refinement were already in the working tree and are out of scope
except where minimization touched them.

## External material identified

| Material | Location | Size | Disposition |
|---|---|---|---|
| `affaan-m/ECC` (MIT) @ `e04ea0b` | `tools/everything-claude-code/` | 3518 files | **Removed** (`git rm -r`; retained in git history) |
| `open-gsd/gsd-core` (MIT) @ `c3e2da1` | `tools/get-shit-done/` | 3393 files | **Removed** (same) |
| `DietrichGebert/ponytail` (MIT) @ `974d940` | `tools/ponytail/` | 159 files | **Removed** (same) |
| `jaredrhod/fullstack-agent` (**AGPL-3.0**) | `tools/fullstack-agent/` | 12 files | **Removed** (same; also removes accidental AGPL-reuse risk) |
| `TOOLS.md` env-verification note | root | 1 file | **Removed** (content below) |
| `mukul975/Anthropic-Cybersecurity-Skills` (Apache-2.0) @ `54a7988` | knowledge source only, never vendored | 0 files | **Retained as provenance record** |

Removed-tree licenses (`LICENSE` in each tree) were deleted together with the
trees they govern — legally appropriate since no upstream code remains in the
working tree. Full trees + licenses remain recoverable in git history
(commit `f33b5d2` and parents).

`TOOLS.md` pins preserved here: Ponytail 4.9.0, GSD Core 1.13.0, ECC 2.2.1,
Full-Stack Agent @ `5bb159f`, provider CLIs `codex`/`claude`/`cursor-agent`/`agy`
probed live 2026-09-06. No Docker on this machine.

## Functionality actually required (all ECDAT-native, verified by reachability)

- Crypto pipeline: scanners → `CryptoFinding` → Mosca risk → PQC recs → migration → CBOM → API/GUI. (Mosca = Mosca's inequality, public scientific concept, independently implemented in `app/risk.py`.)
- Codebase intelligence: 14 analyzers → `CodeFinding` → ranking → remediation → planner → verification. No GSD framework code; two docstrings crediting "GSD-lite/inspired" renamed to native terminology (inspiration remains documented in `PONYTAIL_GSD_INTEGRATION_MATRIX.md`).
- Active Validation: TLS/HTTP observation, loopback-first policy, budgets, dry-run, correlation, SARIF. Narrow and safety-controlled; no pentest-framework residue found.
- GitHub source adapter: URL parsing, acquisition, ref resolution, isolation. No git binary, no vendored repos at scan time.
- CLI orchestration (stdlib only): all 9 modules reachable and called from `cli.py`.
- Knowledge layer: 32 ECDAT-authored normalized summaries (not verbatim copies, scripts never imported/executed), attributed in `app/knowledge/provenance.py` + `docs/knowledge/skill-inventory.json` + `docs/knowledge/README.md`. Retained in full.
- `obsidian-vault/` (24 files): frozen pre-migration reference copy, secret-scan clean, referenced by historical reports. Retained.

## Material removed (working tree)

- `tools/` — 7082 files, 4 whole upstream repos. Zero imports from product code (verified by grep); only doc references were the read-only policy itself and 3 historical reports (left untouched as history; stale `tools/` pointers there now resolve via git history).
- `TOOLS.md` — env note superseded by this report's pins table.
- `app/scanner/mocks.py` — `_MockBase` placeholder with zero importers/subclasses/tests ("for future scanners"). The `is_mock` mechanism lives in `models.py` and is asserted via real scanners; unaffected.
- `import os` (`sources/acquire.py`), unused `key` unpack (`sources/history.py`) — genuine dead code found by dogfooding ECDAT on itself (fixed; the analyzer's remaining self-findings are style/complexity observations, not defects; method-call "unused function" hits verified as false positives via `self.` call sites).

## Reference updates (no behavior change)

- `README.md`: layout tree + docs bullet. `AGENTS.md`: dropped `tools/` bullets.
- `backend/requirements.txt`: `httpx` annotated test-only (required by starlette `TestClient`; zero app imports — verified).

## Dependencies

Python: fastapi, uvicorn (runtime), httpx + pytest (test-only). CLI: zero deps (stdlib). Node: react, react-dom, vite, @vitejs/plugin-react — all used; `package-lock.json` intact, no changes needed. No removals beyond annotation; nothing unused found.

## Size before/after

- Tracked files: **7262 → 178** (150 `sih26164` + 24 `obsidian-vault` + 4 root).
- Working tree on disk: 312 MB → ~12 MB product + unchanged gitignored dev artifacts (`.venv` 49 MB, `node_modules` 45 MB) + `.git` 50 MB (history preserves removed trees — provenance not erased).

## Test results (observed, not historical)

- Backend: **128 passed**. CLI: **40 passed**. Frontend `vite build`: green.
- Dogfood: ECDAT code analysis on own backend — genuine dead-code hits fixed above; no legitimate architecture removed.
- Crypto regression: `test_precision.py` + determinism tests green; `risk/migration/models/cbom/recommend` untouched by this pass.
- API smoke: local sample scan + 400-shapes for bad URL/profile/creds/triage, no tracebacks or path leaks.
- Live GitHub equivalence/determinism re-verified in the prior pass (pyjwt 384-finding digest MATCH).

## Security results

- Secret scan: clean (only fake key-material fixtures in tests).
- SSRF/archive/isolation controls untouched by removals (files removed had no security role; `mocks.py` was unreachable code).
- BROWSER VALIDATION NOT AVAILABLE (no browser in this environment).

## Remaining third-party notices / provenance

- `app/knowledge/provenance.py` (+ inventory + README): Apache-2.0 source repo/commit recorded; entries are summaries, not copies — no license text redistribution required.
- `PONYTAIL_GSD_INTEGRATION_MATRIX.md`, `STRIX_ECDAT_INTEGRATION_MATRIX.md`, `STRIX_ECDAT_INTEGRATION_REPORT.md`: conceptual-provenance docs. Retained.
- No copied upstream runtime code found anywhere in product (no "ported/copied/vendored from" admissions; `ponytail:`-style markers in product are methodology notes, e.g. `duplication.py:46`).

## Known observations

- `.stitch/` (untracked, local loop scaffolding) and `frontend/dist/` (gitignored build output) left as-is.
- `cli-agent/AGENTS.md` "no network" line vs `scan --github` (bounded HTTPS): pre-existing tension, flagged previously, unchanged here.
- DNS-rebinding TOCTOU and in-memory history limits: documented limitations, unchanged.

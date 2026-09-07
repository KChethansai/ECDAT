# ECDAT Codebase Intelligence — final report

## 1. Implementation summary

New `backend/app/code_analysis/` package (13 modules): `CodeFinding` model,
six analyzers (dead code, duplication, complexity, efficiency, dependencies,
structure), symbol/reference graph, deterministic ranking, multi-option
remediation, deterministic planner + `plan.md` + AI prompt renderer, pure
before/after verification. Wired additively into pipeline (`code_analysis`
opt-in), API (5 endpoints), CLI (`analyze`, `remediate`, `verify-fix`,
`scan --code-analysis`), and UI (`code analysis` checkbox + `CodebaseHealth`
section with option-select → plan generation). No new dependencies; no AI path.

## 2–3. Ponytail / GSD concepts adopted

See `PONYTAIL_GSD_INTEGRATION_MATRIX.md`. Adopted: YAGNI/stdlib-first discipline,
delete-oriented findings, certainty ladder, structured plans with must_haves,
verify-by-diff. Rejected: auto-fix, agent execution, command frameworks, metrics.

## 4. Capabilities implemented

Dead-code (imports HIGH-exact, defs POTENTIAL, unreachable HIGH, locals MEDIUM),
reachability graph (Python AST + JS heuristics), duplication (exact+near, windowed),
complexity observations, efficiency POTENTIALs (receiver-aware), dependency
declared-vs-imported, structure orphans + config overlap, ranking labels,
2–4 remediation options per finding, user constraints (12 validated),
deterministic plans (Confirm/Implement/Verify), plan.json + plan.md + agent prompt,
verification statuses, snapshots as user-held files, health summary with shown formula.

## 5. Capabilities rejected

§50 freeze honored: no auto-modification, no AI provider/network, no wave
orchestration, no Java/Go/Rust analyzers, no lines-saved metric, no strictness modes.

## 6–11. Architecture / analysis / AI-optional / options / planning / verification

See `ECDAT_CODEBASE_INTELLIGENCE_ARCHITECTURE.md` and
`ECDAT_GUIDED_REMEDIATION_ARCHITECTURE.md`. Deterministic engine is complete
without AI; the AI adapter is a renderer (no LLM, no network); user choice is
mandatory (`build_plan` requires `option_id`); AI cannot alter findings/severity/
scope; source is untrusted data with fenced evidence.

## 12. Security

Static parse only (never imported/executed); scanner-grade jail (symlinks, `..`,
size/file caps, workspace containment) tested; evidence truncated to 160 chars;
injection comments treated as text; prompt adapter fences evidence with
UNTRUSTED-DATA instructions; existing CORS/jail/redaction/validation-safety untouched.

## 13. Testing

Backend `103 passed` (82 baseline + 16 code-intelligence + 5 release-audit
in `tests/test_code_analysis.py` / `tests/test_validation.py`):
per-analyzer true/false positives, public-API/dynamic/test/hook downgrades,
JS LOW-heuristic behavior, options/plan round-trip, invalid option/constraint
rejection, all four verification statuses, determinism (minus wall-clock),
jail/symlink/injection tests, API round-trips + error paths, payload caps,
IPv6/port validation, crypto regression
(byte-identical components/risk/migration). CLI `38 passed` (37 + analyze→
remediate→verify-fix flow). Frontend `npm run build` succeeds.

## 14. Real-project validation

| Target | Findings | Files | Time | Deterministic |
|---|---|---|---|---|
| frontend-src | 18 | 18 | 0.24 s | yes |
| backend-app | 243 | 49 | 4.2 s | yes |
| frontend-full | 19 | 23 | 0.34 s | yes |
| samples | 3 | 16 | 0.01 s | yes |
| cli-agent | 45 | 11 | 0.62 s | yes |
| obsidian-vault | 0 | 24 | 0.00 s | yes |
| empty project | 0 | 0 | 0.00 s | yes |

Spot-checks: no exported React symbols flagged, no keyword false positives,
`dict.get` excluded, `ast.*` introspection excluded, analyzer dogfooded (4 real
dead imports in new code removed). Crypto regression on samples: UNCHANGED.

## 15. Performance

Bounded: 2000 files / 512 KiB per file, duplication capped at 100 findings,
windows short-circuit past 20000 buckets, no subprocesses, no network.
Worst measured: 4.2 s / 49 files (backend-app, all analyzers).

## 16. Limitations

Python is AST-grade; JS/TS is heuristic (`LOW`, `deterministic: false`); other
languages detected but not analyzed; duplication windowed; whole-run byte budget
n/a (no network); runtime-timestamp rationale in crypto runtime probe is a
pre-existing nondeterminism (static scanners fully deterministic).

## 17. Dependencies

None added (stdlib `ast/re/json/hashlib` + existing conventions only).

## 18. Final verdict

All acceptance criteria met: crypto baseline intact (82→103 backend, 37→39 CLI,
build green), analysis/options/user-choice/constraints/planner/verification/
CLI/API/UI/plan-export present, AI fully optional (no AI code path exists),
verification + regression detection work, docs complete, diff additive and
explainable, nothing committed, nothing pushed. **FROZEN.**

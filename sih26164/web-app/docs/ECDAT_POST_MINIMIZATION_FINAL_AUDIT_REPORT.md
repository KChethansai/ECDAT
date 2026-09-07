# ECDAT post-minimization final audit report

Date: 2026-09-07. Branch: `main`. Mode: audit + verify only. NOT COMMITTED. NOT PUSHED.

## 1. Executive summary — PASS WITH OBSERVATIONS

The minimized repository (178 tracked files, down from 7262) is complete,
coherent, functional, secure, deterministic, and release-ready. All suites
green (backend 128, CLI 40, frontend build). No runtime dependency on removed
trees. Crypto behavior unchanged by minimization. Three non-blocking
observations recorded (§24). No fixes were needed during this audit; no code
was changed (this report is the only artifact).

## 2. Repository state

- `git status`: minimization + prior hardening diffs present, uncommitted.
  Staged deletions: `tools/` (7082 files), `TOOLS.md`, `mocks.py`.
  Modified: 2 root docs, 2 docstrings, 5 backend files, 1 test file, 2 arch docs,
  6 frontend files. Untracked: `.stitch/` (local loop scaffolding),
  `ECDAT_REPOSITORY_MINIMIZATION_REPORT.md` (intended), this report (required).
- Tracked: **178 files** (150 `sih26164`, 24 `obsidian-vault`, 4 root).
  No tracked caches/venvs/node_modules/dist/binaries/secrets/tool outputs.
- Working tree ≈12 MB product + gitignored dev artifacts (`.venv` 49 MB,
  `node_modules` 45 MB) + `.git` 50 MB (removed trees preserved in history).

## 3. Minimization verification

`tools/` (ECC/GSD/ponytail/fullstack-agent clones) fully absent from worktree;
`TOOLS.md` pins preserved in the minimization report; `mocks.py` gone;
`import os` + unused `key` unpack gone. Nothing else deleted. No accidental
generated files, binaries, caches, or archives.

## 4. Retained functionality

Backend pipeline, 14 code analyzers, 9 CLI modules, validation, sources,
knowledge layer (32 entries), all API routes, all frontend components —
reachability-verified (import/call-graph grep + green suites). No orphan
product files found.

## 5. Removed functionality/trees

Only: 4 upstream reference clones, `TOOLS.md` (superseded), `_MockBase`
scaffolding (zero importers; `is_mock` mechanism in `models.py` unaffected),
2 dead code fragments. Zero product capability removed.

## 6. Reachability results — PASS

Every retained module classified USED (entrypoint/import/call evidence) or
intentionally retained (frozen vault copy, historical reports, provenance
docs/matrices, test fixtures). Details in minimization report §"Functionality
actually required".

## 7. Provenance/licensing audit — PASS

- Knowledge entries: ECDAT-authored summaries, attributed
  (`provenance.py` + per-file headers + inventory + README, Apache-2.0
  repo/commit recorded). No verbatim copies; scripts never imported.
- Matrices document studied references and per-row adopt/reject verdicts;
  `tools/` path mentions therein are historical (where study happened).
- Removed-tree LICENSEs deleted with their trees (nothing remains to govern).
- Mosca = public scientific concept, independently implemented.
- Nothing requiring human/legal review found. No speculative legal claims made.

## 8. Backend test results — PASS: 128 passed (~4 s)

## 9. CLI test results — PASS: 40 passed

## 10. Frontend build result — PASS (`vite build` green)

## 11. Self-scan results — PASS

ECDAT on own backend: 256 code findings (categories EFFICIENCY/DEAD_CODE/
COMPLEXITY/DUPLICATION/STRUCTURE). Two genuine dead-code hits from the prior
pass already fixed; remaining method-level "unused" hits verified false
positives (`self.` call sites). Stylistic observations not chased.

## 12. Crypto regression results — PASS WITH OBSERVATION

- vuln_sample: 15 findings, 0 mock, identical digest across runs and across
  PYTHONHASHSEED=1/99. 5/5 separate processes byte-identical canonical JSON
  (modulo `scannedAt`).
- Observation: one earlier pair differed at a single `codeAnalysis.metrics.
  duration_s` timing value — a measurement, not analysis output; finding IDs,
  counts, severities, recommendations unaffected. Expected, not a defect.

## 13. Code intelligence regression — PASS

Plan generation (phases/tasks/rollback/definition_of_done/testing),
constraint handling, verification statuses, and Crypto/CodeFinding separation
verified live on self-scan findings. No crypto/CBOM contamination.

## 14. Active Validation regression — PASS

Non-loopback without ack → blocked with actionable message, 0 requests.
Dry-run → 0 requests. Policy/target validation, budgets, correlation, SARIF
covered by suite (24 validation tests green). No subprocess/proxy/browser/
telemetry/LLM paths in validation code.

## 15. GitHub scanning regression — PASS

24 source tests green (URL parsing, SSRF, archive hostility, equivalence,
delta/triage, API). Live negative paths re-verified (400s, no leaks).
Prior-pass live proof stands: pyjwt local-vs-acquired digest MATCH,
deterministic repeat scans. GitHub remains a source adapter over the single
`run_scan` pipeline.

## 16. Security audit — PASS

Secrets: clean (only fake key fixtures in tests). No `pickle`/`yaml.load`/
`eval`/shell execution in product (one `eval(` hit is a string literal in the
analyzer's dynamic-marker list). No `dangerouslySetInnerHTML`. SSRF/archive/
isolation gates intact. API errors: no tracebacks, no path leaks.

## 17. Determinism audit — PASS

Same-target repeats, separate processes, varied hash seeds, local-vs-acquired
equivalence all stable. Only legitimate variance: wall-clock durations.

## 18. Dependency audit — PASS

Backend: fastapi+uvicorn (runtime), httpx+pytest (test-only, annotated).
CLI: zero. Frontend: react/react-dom/vite/plugin-react, lockfile intact.
No unused, no missing, no additions. All standard permissive licenses
(no license-scanner run — noted, low risk).

## 19. Documentation audit — PASS WITH OBSERVATION

Current-state docs consistent (profiles, triage states, delta categories,
caps, test counts verified against code). Historical reports intentionally
untouched. Observation: integration matrices reference removed `tools/`
paths as study locations — accurate history, resolvable via git; left as-is.

## 20. API audit — PASS

`/health`, `/scans` (local+github), reports, code-analysis, plans, verify,
validations, SARIF, history, delta, triage: status codes, schemas, caps,
and error shapes verified live. Contracts unchanged.

## 21. CLI audit — PASS

`status` (provider probing), local scan, `--github/--ref/--profile`,
`analyze`, `explain`, invalid-input handling (`unsafe scan target`, exit
codes asserted in suite). Malformed input fails cleanly.

## 22. Repository size

Tracked 178 files / ~1.5 MB product source (app 1.1 MB, frontend src 196 KB,
CLI src 220 KB, docs 164 KB, vault 140 KB). Nothing suspiciously large.

## 23. Real-project validation — PASS WITH OBSERVATION

 crypto findings — frontend-src 6, backend-app 352, frontend-full 122,
 samples 72, cli-agent 20, empty 0. All paths execute end-to-end.
 Observation: counts differ from the §18 historical numbers (18/248/19/3/44)
 because those predate the intentional dependency-manifest extension
 (+2/−1 lines, GitHub commit) and used undocumented invocation scope;
 minimization-era diff touches no scan logic (verified: only scanner diff
 since baseline is that manifest extension + unreachable `mocks.py`).

## 24. Remaining observations

1. `cli-agent/AGENTS.md` "no network" line vs `scan --github` (bounded HTTPS) — pre-existing, flagged, needs owner decision.
2. No license-scanner tooling run; dependency set is small and standard-permissive.
3. BROWSER VALIDATION NOT AVAILABLE in this environment (recorded, not claimed).

## 25. Release recommendation — READY

No blockers. No audit-time code changes were required.

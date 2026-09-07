# ECDAT Codebase Intelligence architecture

Deterministic static analysis + guided remediation, fully separate from the
cryptographic pipeline. No AI required; no AI dependency; no new runtime
dependencies (stdlib + existing `ast`/`re`/`json` only).

## Package (`backend/app/code_analysis/`)

| Module | Role |
|---|---|
| `models.py` | `CodeFinding`: engineering impact, never security severity (`security_risk` defaults `"NONE"`) |
| `scope.py` | Jailed, capped file scope (symlinks skipped, 512 KiB/file, 2000 files, generated dirs skipped) |
| `symbols.py` | Symbol/reference graph: Python via `ast` (HIGH determinism); JS/TS via import/export + textual refs (heuristic) |
| `dead_code.py` | Unused imports (exact Name-counting, `__future__`/`__all__`-aware), unreachable statements, unused locals, unreferenced defs |
| `duplication.py` | Normalized block hashing (exact + near), widest-window wins, same-file needs ≥12 lines |
| `complexity.py` | Cyclomatic + nesting + length + params; reported as `COMPLEXITY_OBSERVATION` |
| `efficiency.py` | Loop-invariant I/O-parse-compile patterns, receiver-aware (dict.get excluded); all `POTENTIAL_PERFORMANCE_ISSUE` |
| `dependencies.py` | Declared (requirements.txt / package.json) vs imported; dynamic mentions silence, never confirm |
| `structure.py` | Orphaned Python modules, overlapping configuration |
| `ranking.py` | confidence × impact ÷ (effort × risk) → `QUICK_WIN / LOW_RISK / HIGH_IMPACT / LARGE_REFACTOR / REQUIRES_REVIEW / DO_NOT_AUTOMATE` (HIGH remediation risk → `DO_NOT_AUTOMATE`). No hour estimates |
| `remediation.py` | 2–4 deterministic options per finding (delete/retain, extract/partial/keep, hoist/restructure/measure…) |
| `planning.py` | Deterministic plan builder + `plan.md` renderer + optional AI prompt adapter (template, no LLM) |
| `verification.py` | Before/after diff by stable id → `RESOLVED / REMAINS / REGRESSION / INCONCLUSIVE` |

## Deterministic model

- Finding ids are `sha1` of analyzer+category+path+line+symbol+title: stable across runs.
- Certainty ladder: `DEAD_CODE` (proven: unused import, unreachable statement) →
  `POTENTIAL_DEAD_CODE` (unreferenced symbol, public/dynamic context) →
  `POTENTIAL_PERFORMANCE_ISSUE` (static shape, needs measurement) →
  `COMPLEXITY_OBSERVATION` / `OBSERVATION`.
- Confidence `HIGH/MEDIUM/LOW`; JS findings are always `LOW` + `deterministic: false`.
- Dynamic/framework hazards (decorators, `__all__`, `importlib`, registries, routes,
  tests, entry files) downgrade to `LOW`, never ignored.

## Dead-code detection rules

- Unused import: zero `Name` occurrences (import bindings are alias nodes, not uses);
  `__future__` excluded; `__all__` string entries count as uses.
- Unreferenced def: no same-module load and no cross-module reference. Public names,
  decorated defs, test files, dynamic modules, entry names → `POTENTIAL_DEAD_CODE/LOW`.
- Unreachable: statement after return/raise/break/continue in the same block (`HIGH`).
- Unused locals: assigned-never-loaded, excluding `_`-prefixed and parameters
  (`MEDIUM/POTENTIAL`, closures may capture).
- JS: word-count ≤1 and non-exported and len ≥3 → `POTENTIAL_DEAD_CODE/LOW`; keywords excluded.

## Efficiency analysis limits

Static analysis shows repeated work, never wall-clock cost. `dict.get`, `list`
accessors, and `ast.*` introspection are excluded by receiver. Findings always
carry "profile before/after" verification. No performance numbers are claimed.

## Dependencies & structure limits

- Only `requirements.txt` + `package.json` declarations are read; stdlib names excluded.
- A dep named in any string literal or dynamic context is silenced (not confirmed).
- Orphans: Python modules only; entry files (`main.py`, `index.*`, `App.*`, …) excluded.

## Safety

Static parsing only — target code is never imported or executed. The same
filesystem jail as scanners (no `..` escapes, no symlinks, workspace-contained).
Source content is untrusted data: evidence truncated to 160 chars; the AI prompt
adapter fences evidence under an explicit UNTRUSTED DATA banner and instructs the
agent to ignore embedded instructions. Verification runs no project code
(it diffs finding lists); test execution, if the user wants it, happens in their
own environment per the plan's verification steps.

## Health summary

Per-dimension counts (`byCategory`, `byPriority`) plus one transparent overall
signal with its formula shown (`100 * (1 - high_confidence/total)`). No black-box score.

## Limitations (documented, not hidden)

- Dependency manifests are read at the analysis root only (`requirements.txt`,
  `package.json`); nested manifests in monorepos are not merged.
- JS/TS analysis is textual heuristics; Python is AST-grade.
- Only Python + JS/TS/JSX/TSX symbols are analyzed; other languages are detected, not claimed.
- Cross-file duplication caps at 100 findings; file scope caps at 2000 files / 512 KiB per file.
- Whole-run byte budget is per-response in validation; analysis has no network at all.

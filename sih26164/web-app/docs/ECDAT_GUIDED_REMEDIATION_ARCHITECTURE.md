# ECDAT Guided Remediation architecture

GSD-inspired, ECDAT-native: finding → options → **user choice** → constraints →
plan → optional AI execution → verification. No GSD code imported; only the
planning concepts (structured phases, per-task WHAT/WHY/WHERE/VERIFY,
must_haves truths, rollback, definition of done).

## Workflow

```
CodeFinding (+ remediation_options)
        ↓
USER SELECTS option_id          (mandatory; engine never chooses)
        ↓
USER SETS constraints           (optional; validated against allowlist)
        ↓
build_plan()                    (deterministic; unknown option/constraint → ValueError)
        ↓
plan.json + plan.md             (machine + human readable)
        ↓
to_agent_prompt()               (optional AI adapter; template only, no LLM)
        ↓
USER/AGENT IMPLEMENTS           (ECDAT never modifies source itself)
        ↓
verify(before, after, touched)  (RESOLVED / REMAINS / REGRESSION / INCONCLUSIVE)
```

## Plan structure

`plan_id`, `finding_id` + embedded finding, `selected_option`, `rejected_options`,
`why_this_approach`, `constraints`, `affected_files`, `dependencies` (single-finding
scope noted), `phases` (Confirm → Implement → Verify), `tasks` (each: task_id, title,
what, why, where, constraints, expected, verify[]), `testing_plan`,
`regression_risks`, `rollback` (version-control revert), `must_haves`
(truths/artifacts/key_links, GSD-style), `definition_of_done`.

Constraint tasks (`require-tests`, `preserve-tests`, `no-new-dependencies`,
`preserve-public-apis`) are injected as explicit tasks when selected.
Valid constraints: `preserve-public-apis, minimize-files, minimize-behavior-change,
prioritize-performance, prioritize-readability, prioritize-maintainability,
preserve-backward-compat, no-new-dependencies, no-arch-changes, preserve-tests,
require-tests, minimize-runtime-risk`.

## AI boundary

- AI is optional (`AIProvider = None` by default — there is no provider abstraction
  to configure because there is no AI path in the product; the adapter is a renderer).
- `to_agent_prompt()` renders plan content only, with system instructions that
  forbid scope expansion and mark project evidence as UNTRUSTED DATA.
- AI (external, user-invoked) can never alter deterministic findings, severity,
  scope, or the user's selected option — it only receives the finished plan.
- No network call occurs when AI is disabled (there is no AI code path at all).

## Verification & snapshots

`verify()` is a pure diff over stable finding ids; snapshots (before/after
analysis JSON) are user-held files, never mutated by ECDAT. API `POST
/plans/verify` wraps the same function. CLI `verify-fix --before --after
--touched` exits 0 on `RESOLVED`/`INCONCLUSIVE`, 1 otherwise (CI-usable).

## Active Validation interplay

Plans whose verification steps touch runtime behavior (e.g., TLS config changes)
can cite existing Active Validation runs as evidence; the validation safety model
(loopback-first, bounded, dry-run) is unchanged and never invoked implicitly.

## API / CLI / UI map

- API: `POST /code-analysis`, `GET /code-analysis/{id}`, `POST /plans`,
  `GET /plans/{id}`, `POST /plans/verify`; scan-embedded via `POST /scans`
  (`code_analysis: true`), which also registers the analysis for `/plans`.
- CLI: `agent analyze TARGET [--dead-code --efficiency --duplicates --complexity
  --dependencies --structure] [--summary] [--out]`; `agent remediate --analysis
  --finding --option [--constraint] [--out] [--markdown] [--agent-prompt]`;
  `agent verify-fix --before --after [--touched]`; `agent scan --code-analysis`.
- UI: scan-console `code analysis` checkbox; `CodebaseHealth` section (category
  filters, expandable findings, option radio-select, constraint checkboxes,
  Generate-plan → plan.md + copyable AI prompt). Crypto UI untouched.

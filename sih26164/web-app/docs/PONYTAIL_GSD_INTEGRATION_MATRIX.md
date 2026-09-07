# Ponytail / GSD → ECDAT integration matrix

References studied read-only (`tools/ponytail`, `tools/get-shit-done`); **nothing
copied, imported, or embedded**. ECDAT-native equivalents below.

| Reference | Capability | Relevant | Implemented | ECDAT equivalent | Reason |
|---|---|---|---|---|---|
| Ponytail ladder (YAGNI → reuse → stdlib → native → installed → one line → minimal) | Build discipline | Yes (process) | Yes | Fewest-files package, `ast`/`re` stdlib, reuse of scanner jail conventions + `cert_metadata` DER pattern | Ladder is a habit, not a feature |
| Ponytail `delete:` review tag | Dead-code findings | Yes | Yes | `dead_code.py`: unused imports (`HIGH`), unreferenced defs (`POTENTIAL`), unreachable code | Core product feature |
| Ponytail `stdlib:`/`native:` tags | Remediation direction | Partly | Adapted | Options prefer deletion + stdlib (e.g., hoist, list+join); no auto-fix application | ECDAT proposes, user disposes |
| Ponytail `net: -N lines` metric | Progress signal | Partly | Rejected | No lines-saved metric; verification statuses instead | Line counts reward churn, not correctness |
| Ponytail `ponytail:` ceiling comments | Documented simplifications | Yes (process) | Yes | Documented limits (JS heuristics, caps, no whole-run byte budget) in arch docs | Same honesty, doc form |
| Ponytail one-line-per-finding format | Finding density | Yes | Adapted | One-line titles + evidence + options; titles carry location + verdict | UI-friendly variant |
| Ponytail intensity levels | Strictness modes | No | Deferred | Single calibrated strictness (LOW-confidence POTENTIAL labels) | Modes add UX complexity; revisit on demand |
| Ponytail benchmarks/claims | Marketing metrics | No | Rejected | — | Not a product capability |
| GSD phase loop (discuss→plan→execute→verify→ship) | Remediation workflow | Yes | Adapted | Confirm→Implement→Verify plan phases; user replaces discuss/execute/ship | No agents/subagents in ECDAT |
| GSD PLAN.md (frontmatter, waves, files_modified) | Plan structure | Yes | Adapted | `planning.build_plan`: tasks, files, must_haves truths, rollback, definition of done; no waves (single-finding scope) | Multi-plan waves deferred |
| GSD must_haves (truths/artifacts/key_links) | Verifiable plans | Yes | Yes | `plan["must_haves"]` with truths + artifacts | Direct concept adoption |
| GSD requirements traceability | Roadmap linkage | Partly | Deferred | `rejected_options` + constraints recorded; no ROADMAP.md IDs | No roadmap artifact in ECDAT |
| GSD fresh-context executors | Agent execution | No | Rejected | ECDAT never executes; external agents consume plan.md/prompt | Out of scope by design |
| GSD verify agent | Post-execution check | Yes | Adapted | `verification.verify`: RESOLVED/REMAINS/REGRESSION/INCONCLUSIVE diff | Deterministic, no agent |
| GSD /gsd-* command framework | CLI surface | No | Rejected | Native `analyze/remediate/verify-fix` commands | No framework import |
| Strix (prior phase) | Active validation | Yes | Reused | Plans may cite validation runs as verification evidence | Unchanged safety model |

## What was deliberately NOT built

Automatic code modification, AI provider abstraction with network paths, multi-plan
wave orchestration, strictness modes, lines-saved metrics, roadmap traceability —
each deferred or rejected with reasons above. No Ponytail/GSD/Strix code exists in
`app/code_analysis/` (independently implemented; only general concepts adopted).

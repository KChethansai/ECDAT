# Session 2026-09-06 — Audit hardening pass

## Findings fixed (all verified, both repos recommitted)

Critical: `memory list()` vault escape → jailed; scanner symlink following +
single-file size bypass → both guarded; `/scans` unvalidated/unbounded →
dedupe + `ge/le` validation + 404/400 mapping + REPORTS cap (50).
High: `--vault` precedence (explicit > env > default); `verify` uses
`sys.executable`; prompt temp files unlinked on success; 8 new tests
(CLI 14→17, backend 5→10) incl. traversal, error-path, symlink/size guards.
Medium: `MOSCA_EXEMPT` constant + Grover assumption doc; mock wording/label
consistency; context budget clamp; plan-collision guard; PIPELINE handoff note.

Live probe: dedupe confirmed (14 real, not 28), mockWarning + 404/400 paths OK.
Verdict after fixes: READY FOR CODEX (Phase 5).

# ADR-0002 — Python stdlib CLI, no LLM inside

Date: 2026-09-06 · Status: accepted.

CLI is orchestration, not a model host. Stdlib-only keeps install zero-friction for judges
and avoids dependency CVEs. Provider access happens by shelling to installed agent CLIs.

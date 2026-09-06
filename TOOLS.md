# Tooling verification (2026-09-06, Arch Linux, Node 24.19, Python 3.14)

Reference clones under `tools/` are READ-ONLY. Nothing is copied into ECDAT code.

| Tool | Repository (verified remote) | Commit | Install mechanism used | Status |
|---|---|---|---|---|
| Ponytail 4.9.0 | `DietrichGebert/ponytail` | `974d940` | Reference clone; rules adopted via repo `AGENTS.md` + OpenCode plugin already global | verified (clone + version) |
| GSD (GSD Core 1.13.0) | `open-gsd/gsd-core` (note: `glittercowboy/get-shit-done` is ARCHIVED, redirects here) | `c3e2da1` | `npx @opengsd/gsd-core` pattern reference; `tools/get-shit-done` holds the renamed repo | verified (clone + version) |
| ECC 2.2.1 | `affaan-m/ECC` (renamed from `everything-claude-code`) | `e04ea0b` | `npx ecc-universal setup` selective-pattern reference; NOT bulk-installed into repo | verified (clone + version) |
| Full-Stack Agent | `jaredrhod/fullstack-agent` (**AGPL-3.0**) | `5bb159f` | Cloned; installer is interactive Claude wizard (`claude "set me up"`) | cloned; wizard = MANUAL step (below) |

Provider CLIs probed live by `agent status`: `codex` 0.153.4 ready, `claude` 2.1.263 ready,
`cursor-agent` ready (no IDE), `agy` 1.1.25 ready. Obsidian desktop 1.13.7 present.
No Docker on this machine (no container work in foundation).

## Manual action remaining

1. Full-Stack Agent wizard: `cd tools/fullstack-agent && claude "set me up"` — interactive
   (identity questions, vault-path confirmation, voice/face/hands opt-ins needing mic/webcam/Chrome).
   Its optionals stay independent of ECDAT core by design.
2. API keys (none required for foundation; add only via local `.env`, never commit).

# ECDAT — SIH26164 Master Workspace

**Problem:** SIH26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT), NTRO.
A CBOM analytics tool: scan source repos / binaries / libraries / container images →
quantum-risk assessment (Mosca) → classification → PQC/hybrid recommendations →
standardized reports + interactive GUI.

## Layout

```text
tools/                     # external references only (never imported by ECDAT code)
├── ponytail/              # DietrichGebert/ponytail (workflow reference)
├── get-shit-done/         # open-gsd/gsd-core (planning reference; upstream renamed)
├── everything-claude-code/# affaan-m/ECC (patterns reference)
└── fullstack-agent/       # jaredrhod/fullstack-agent, AGPL — independent optional tooling
obsidian-vault/            # frozen Phase 1–8 reference copy (authoritative vault now lives at ~/Documents/Vaults/SIH)
sih26164/
├── cli-agent/             # provider-neutral orchestration CLI (Python stdlib, zero runtime deps)
└── web-app/               # SIH product (React/Vite + FastAPI)
```

> The Obsidian Vault is the authoritative persistent AI/project memory.

## Memory rule

- Vault at `~/Documents/Vaults/SIH` → persistent AI/project knowledge (Markdown).
- `git` → source + history.
- App DB → runtime/domain data only (no DB in MVP; none exists).
- Never store agent/project memory in a database, vector DB, or hidden JSON store.

## Quick start

```bash
# CLI agent (Python 3.10+, no runtime dependencies)
cd sih26164/cli-agent
python scripts/agent status
python scripts/agent scan ../web-app/backend/samples --summary
python scripts/agent explain ../web-app/backend/samples/vuln_sample --ask "what should we migrate first"

# Web app backend (FastAPI)
cd ../web-app/backend
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload  # :8000 — GET /health, POST /scans, GET /reports/{id}

# Web app frontend
cd ../frontend
npm install && npm run dev  # :5173, API proxied to :8000
```

Runtime analysis and provider Q&A are explicit opt-ins:
`agent scan <target> --runtime`, `agent explain <target> --agent <name> -- <provider args>`.

Public GitHub repositories can be scanned statically (never executed):
`agent scan ignored --github https://github.com/owner/repo --ref main --profile full --summary`,
or via the web UI source picker, or `POST /scans` with
`{"source": {"type": "github", "url": "...", "ref": "main"}, "profile": "full"}`.
See `sih26164/web-app/docs/ECDAT_GITHUB_SCAN_ARCHITECTURE.md`.
Details per app in their READMEs; end-to-end demo path in `sih26164/web-app/docs/DEMO.md`.

## Docs

- `sih26164/cli-agent/README.md` + `AGENTS.md` — CLI usage, adapters, memory.
- `sih26164/web-app/README.md` + `docs/` — product, scanner pipeline, API.
- `~/Documents/Vaults/SIH` — durable knowledge (human-readable, Obsidian-compatible).
- `docs/DEMO.md` (in cli-agent) — two-session persistent-memory demo.
- `TOOLS.md` — external tooling verification report.

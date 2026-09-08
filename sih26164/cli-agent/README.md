# cli-agent

Provider-neutral orchestration CLI for ECDAT (Python stdlib only — no runtime deps).

## Run (zero install)

```bash
python scripts/agent init
python scripts/agent status
python scripts/agent agents --verbose
python scripts/agent context "assess TLS findings"
python scripts/agent scan sih26164/web-app/backend/samples/vuln_sample --summary
python scripts/agent scan sih26164/web-app/backend/samples --runtime --summary  # explicit opt-in probe
python scripts/agent explain sih26164/web-app/backend/samples/vuln_sample --ask "what should we migrate first"
python scripts/agent explain sih26164/web-app/backend/samples/vuln_sample --finding <id> --agent codex -- exec -
python scripts/agent memory set <dotted.key> <value>   # Markdown-backed
python scripts/agent memory get <dotted.key>
python scripts/agent memory search <terms> | read <Note> | write <Note> <text> | list [dir]
python scripts/agent plan "add container scanner"
python scripts/agent run --agent codex --task "..." -- <provider's own args>
python scripts/agent verify
```

Vault: `OBSIDIAN_VAULT_PATH` env, `--vault` flag, deployment config, or user-local default `~/Documents/Vaults/SIH`.
`src/agent/` mirrors the spec (`cli`, `configuration→config`, `memory`, `context`,
`registry`, `adapters`, `orchestration`). Full layout rationale + demo: `docs/DEMO.md`.

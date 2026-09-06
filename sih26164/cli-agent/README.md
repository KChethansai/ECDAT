# cli-agent

Provider-neutral orchestration CLI for ECDAT (Python stdlib only — no runtime deps).

## Run (zero install)

```bash
python scripts/agent init
python scripts/agent status
python scripts/agent agents --verbose
python scripts/agent context "assess TLS findings"
python scripts/agent scan sih26164/web-app/backend/samples/vuln_sample
python scripts/agent memory set <dotted.key> <value>   # Markdown-backed
python scripts/agent memory get <dotted.key>
python scripts/agent memory search <terms> | read <Note> | write <Note> <text> | list [dir]
python scripts/agent plan "add container scanner"
python scripts/agent run --agent codex --task "..." -- <provider's own args>
python scripts/agent verify
```

Vault: `OBSIDIAN_VAULT_PATH` env, or `--vault`, or default `/home/chethan/Documents/Vaults/SIH`.
`src/agent/` mirrors the spec (`cli`, `configuration→config`, `memory`, `context`,
`registry`, `adapters`, `orchestration`). Full layout rationale + demo: `docs/DEMO.md`.

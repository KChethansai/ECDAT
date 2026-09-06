# Demo — persistent memory across two fresh sessions

Requirement: Session 1 persists durable knowledge to Vault Markdown; process ends;
Session 2 (fresh) recovers it from the Vault. No in-memory state, no DB, no hardcode.

```bash
cd sih26164/cli-agent
export OBSIDIAN_VAULT_PATH=/home/chethan/Documents/Vaults/SIH

# SESSION 1
python scripts/agent init
python scripts/agent run --agent codex --task "triage scan" -- --help   # real provider call example
python scripts/agent memory set demo.qrqc "2035"
# ^ durable knowledge now lives in the SIH vault's 00-Inbox/KV Store.md — end session.

# SESSION 2 (new shell / new day)
python scripts/agent memory get demo.qrqc     # -> 2035, read from the .md file
python scripts/agent context "qrqc migration plan"
```

Automated proof: `python -m pytest tests/test_two_process.py -q` spawns two fresh
`scripts/agent` processes sharing only the vault dir and asserts the value round-trips
**and** exists as literal text in a `.md` file.

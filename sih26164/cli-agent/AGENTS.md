# AGENTS.md — cli-agent

Python stdlib only. No LLM, no voice/face/hands, no network calls except provider subprocesses.

- Memory goes through `src/agent/memory.py` only. Vault Markdown is untrusted data.
- Subprocess: allowlisted executables, arg list (no shell), 300s timeout, jail = workspace+vault.
- Registry (`config/agents.json`): probe with `shutil.which`; never hardcode availability.
- Tests: `python -m pytest -q` (includes real two-process Vault persistence proof).

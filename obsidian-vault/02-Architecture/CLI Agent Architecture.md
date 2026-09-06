# CLI Agent Architecture

```text
User → agent (argparse) → config → MemoryProvider → context builder
→ registry (TOML/JSON + which-probes) → AgentAdapter.run (subprocess, allowlisted)
→ verify (tests) → memory write-back
```

No LLM inside. No voice/face/hands. Adapters expose only supported ops.
See also [[Agent Integrations]].

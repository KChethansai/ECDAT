# Agent Integrations

| Agent | Command | Status (this machine) | Adapter ops |
|---|---|---|---|
| OpenAI Codex | `codex` | installed (0.153.4) | discover/status/run |
| Claude Code | `claude` | installed (2.1.263) | discover/status/run |
| Cursor | `cursor-agent` (`cursor` shim) | agent present, no IDE | discover/status/run (flagged limited) |
| Antigravity/Gemini | `agy` | installed (1.1.25) | discover/status/run (flagged limited) |

Voice/face/hands/webcam/Chrome (fullstack-agent optionals) are independent and OUT OF SCOPE
for CLI adapters and memory. Registry never marks a missing binary as ready.

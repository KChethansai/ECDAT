# Strix → ECDAT capability integration matrix

Upstream audited: `usestrix/strix` @ `main` (`ff5c8cc`, 2026-09-06), Apache-2.0.
Audit was read-only (shallow clone outside the repo); **no upstream code was copied**.
Every row below is an ECDAT-native re-implementation or a deliberate rejection.

| # | Strix capability (upstream location) | ECDAT equivalent | Verdict | Rationale |
|---|--------------------------------------|------------------|---------|-----------|
| 1 | Sandbox session lifecycle, Docker backends, bind mounts (`strix/runtime/`) | Opt-in `validation_policy` (loopback by default, budgets, sequential probes) + existing isolated runtime probe | **Adapted** | No Docker in ECDAT; safety comes from target policy + bounds, not containers |
| 2 | Scan budgets / max turns / timeouts (`strix/core/execution.py`) | `ValidationPolicy`: `timeout_s`, `max_requests`, `max_redirects`, `max_bytes`, `max_duration_s` | **Adopted** | Same philosophy, stdlib enforcement |
| 3 | URL safety gate (`strix/interface/url_safety.py`) | `validation/safety.py`: `check_url`, `check_host_port`, `is_loopback_host` | **Adopted, stricter default** | Loopback-only default; non-loopback needs explicit acknowledgement |
| 4 | SARIF 2.1.0 sidecar (`strix/report/sarif.py`) | `validation/sarif.py::to_sarif` + `GET /reports/{id}/sarif` + CLI `--sarif-out` | **Adopted** | Native writer; validation status rides in `properties.ecdat` |
| 5 | Run records / report state (`strix/report/state.py`, `writer.py`) | Immutable in-memory validation runs (`POST /validations`, `GET /validations/{id}`) | **Adapted** | In-memory fits ECDAT's stateless reports; re-validation = new run, history kept |
| 6 | Finding dedupe (`strix/report/dedupe.py`) | Existing `normalize_findings` (unchanged) | **Reused, not duplicated** | No second dedupe path |
| 7 | Fix-verification workflow (`skills/analysis/fix_verification.md`) | Re-validation runs + `NOT_CONFIRMED` semantics (absence ≠ safety) | **Adapted** | No auto-fix suggestions; verification only |
| 8 | Severity calibration (`skills/analysis/severity_calibration.md`) | Risk engine untouched; validation never changes severity/priority | **Rejected (by design)** | Validation adds context, never scores |
| 9 | Counter-evidence discipline (`skills/analysis/counterevidence.md`) | `NOT_CONFIRMED` / `INCONCLUSIVE` statuses, conservative `_match_tls` wording | **Adopted** | Precise words: observed vs confirmed |
| 10 | Strategy dispatch per finding class | `validation/strategies.py::strategy_for` (deterministic table) | **Adopted** | No LLM routing; unknown findings get no automatic validation |
| 11 | HTTP intercept proxy (`strix/tools/proxy/`) | — | **Rejected** | Traffic interception is out of ECDAT's static-inventory scope |
| 12 | Agent browser (`strix/tools/agent_browser/`) | — | **Rejected** | No browser automation; observation via stdlib `http.client` only |
| 13 | LLM agents / prompts (`strix/agents/`, `strix/llm/`) | — | **Rejected** | No LLM anywhere in the validation path; fully deterministic |
| 14 | Markdown skills library (`strix/skills/`, `skills/`) | Advisory knowledge layer (pre-existing, unchanged) | **Noted, out of scope** | Separate concern from active validation |
| 15 | Telemetry (`strix/telemetry/`) | — | **Rejected** | No telemetry in ECDAT |
| 16 | Coverage reporting (`strix/report/coverage.py`) | Validation summary counts (`byStatus`, requests, bytes) | **Adapted** | Run completeness without a coverage model |

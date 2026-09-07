# Strix → ECDAT Active Validation Engine — integration report

## What was built

An ECDAT-native Active Validation Engine inspired by a read-only audit of
`usestrix/strix` (Apache-2.0; no upstream code copied): deterministic finding→strategy
mapping, bounded stdlib TLS/HTTP validators, correlation roll-ups, immutable run
management, re-validation without rescanning, SARIF 2.1.0 + CI gates, and UI integration
(opt-in console, per-finding drawer section, metrics). See
`STRIX_ECDAT_INTEGRATION_MATRIX.md` (adopt/adapt/reject per capability) and
`ECDAT_ACTIVE_VALIDATION_ARCHITECTURE.md` (design, safety model, invariants).

## Verification evidence

- Backend: `82 passed` (`python -m pytest -q` from `backend/`), including live
  loopback TLS (throwaway `openssl` cert) + HTTP probes, redirect/HSTS handling,
  header redaction, safety-policy unit tests, determinism (repeat runs agree),
  API validation/re-validation/SARIF round-trips and error paths.
- CLI: `37 passed` (`python -m pytest -q` from `cli-agent/`), including
  `scan --validate --dry-run` summary output, `validate --sarif-out` SARIF shape,
  and `--fail-on confirmed|critical` gates.
- Frontend: `npm run build` succeeds.
- Real-project proof: self-scan of the backend (572 components) — static findings
  byte-identical with validation on/off; dry-run maps 508 checks, zero requests,
  JSON-safe report.
- Security self-review: stdlib-only product code (no subprocess/network deps beyond
  `socket`/`ssl`/`http.client`), every probe + redirect hop policy-checked,
  credentials rejected, sensitive headers redacted, errors use exception type names
  (no path/secret leakage), no key material handled, targets capped at 50/run,
  runs capped in memory (50).

## Deliberate rejections (with reason)

Proxy interception, browser automation, LLM routing/scoring, telemetry, and a second
dedupe path were all rejected: outside ECDAT's static-inventory scope, non-deterministic,
or already covered by existing components.

## Residual risks / follow-ups

- Hostname policy is string-based (no DNS resolution): non-loopback probing stays an
  explicit acknowledged act; DNS-rebinding against allowlisted names is a known,
  documented limitation.
- Byte budget is per-response (`max_bytes`) plus request/duration caps; there is no
  separate whole-run byte cap — acceptable at 1 MiB × 20 requests max, revisit if
  limits are ever raised.
- Runtime `rationale` embeds a probe timestamp (pre-existing), so two `runtime=True`
  runs differ in that one field; static scanners are fully deterministic.

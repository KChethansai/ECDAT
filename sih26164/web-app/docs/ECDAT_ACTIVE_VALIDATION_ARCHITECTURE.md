# ECDAT Active Validation architecture

Opt-in, bounded, deterministic, stdlib-only. Static discovery stays the source of
truth; validation adds **additive metadata only** (`validationStatus`,
`correlatedValidations`, `validations`, `validationSummary`).

## Components (`backend/app/validation/`)

- `models.py` — `ValidationResult` (structured, redacted evidence), `VALIDATION_STATUSES`
  (`CONFIRMED / OBSERVED / PARTIALLY_CONFIRMED / NOT_CONFIRMED / NOT_APPLICABLE /
  INCONCLUSIVE / BLOCKED / ERROR`), `CORRELATION_STATUSES`, `VALIDATOR_VERSION="1"`.
- `safety.py` — `ValidationPolicy` (loopback-only default, allowlist, explicit
  `allow_non_loopback` acknowledgement, bounded `timeout_s / max_requests /
  max_redirects / max_bytes / max_duration_s`, `dry_run`). `check_url` rejects
  non-http(s) schemes, credentials, control characters, bad ports; every redirect
  hop is re-checked.
- `strategies.py` — `strategy_for(finding)`: deterministic table over algorithm
  family + category + usage. Mock findings and lockfile-integrity metadata are never
  auto-validated; unknown evidence maps to `NOT_APPLICABLE` with a reason.
- `tls_probe.py` — stdlib `ssl` handshake observation: version, cipher, presented-cert
  metadata (subject/issuer/validity/SAN via stdlib parsing, signature + public-key
  algorithm via the existing `cert_metadata` DER helpers). `CERT_NONE`: we record what
  is presented, never a trust decision. RSA key size only (EC reports curve, not bits).
- `http_probe.py` — stdlib `http.client` GET with manual policy-checked redirects,
  sensitive headers redacted (`Authorization`, `Cookie`, … → `[REDACTED]`),
  body capped at `max_bytes`.
- `runner.py` — `run_validations(components, targets, policy)`: sequential, budgeted,
  immutable run record. TLS findings fan out per explicit target; runtime findings
  consume **existing** probe rows (same-family link → `CONFIRMED`, else `NOT_CONFIRMED`);
  nothing new is executed. Conservative `_match_tls` wording throughout.
- `correlate.py` — `apply_correlation`: stamps `validationStatus` per finding
  (`STATIC_ONLY / RUNTIME_OBSERVED / RUNTIME_CORRELATED / RUNTIME_CONFIRMED /
  UNRELATED_RUNTIME_OBSERVATION / NOT_APPLICABLE`). Presentation only.
- `sarif.py` — minimal SARIF 2.1.0 writer; validation context in `properties.ecdat`.

## Wiring

- Pipeline: `run_scan(..., validate=False, validation_targets=None, validation_policy=None)`.
  Default stamps `STATIC_ONLY`/`NOT_APPLICABLE` (no network). Opt-in runs probes and
  attaches `validations` + `validationSummary`.
- API: `POST /scans` (`validate`, `validation_targets`, `validation_policy`);
  `POST /validations` (re-validate without rescanning; new immutable run);
  `GET /validations/{id}`; `GET /reports/{id}/sarif`.
- CLI: `agent scan --validate --validation-url … --dry-run`; `agent validate TARGET
  --validation-url … --sarif-out … --fail-on confirmed|observed|critical` (CI gate).
- UI: scan-console opt-in checkbox + explicit endpoints field + non-loopback
  acknowledgement; per-finding ACTIVE VALIDATION drawer section; validated/confirmed
  counts in header and report summary.

## Safety model

1. Default-deny targets (loopback or explicit allowlist/acknowledgement).
2. Bounded everything (requests, bytes, redirects, duration, 50 targets/run).
3. Observation only: no exploits, no auth, no trust decisions, no key material.
4. Dry-run mode maps strategies with zero requests (CI-safe preview).
5. Known limitation: hostname policy is string-based (no DNS resolution), so
   non-loopback probing is always an explicit, acknowledged act.

## Invariants (tested)

- Same static input → same static findings with validation on or off
  (only additive metadata differs; verified on 572-component self-scan).
- Validation never changes severity, priority, Mosca, recommendations, counts.
- Probes are deterministic: two runs against the same endpoint agree status-for-status.

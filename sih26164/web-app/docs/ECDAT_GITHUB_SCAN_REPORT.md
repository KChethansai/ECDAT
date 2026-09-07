# ECDAT GitHub repository scanning — implementation report

## Implementation summary

New `backend/app/sources/` boundary (stdlib urllib+tarfile only): strict GitHub
URL parsing, API best-effort ref resolution with explicit-SHA offline path,
bounded codeload download, hostile-tar extraction, isolated workspaces, path
relativization with dataclass-driven id recomputation, five scan profiles,
in-memory history, id+fingerprint delta, reason-gated triage. `run_github_scan`
feeds the unchanged crypto + code-analysis pipelines. API (`source`/`profile` on
`POST /scans`, `/scan-history`, `/scan-delta`, `/triage`), CLI
(`scan --github/--ref/--profile`), and UI (source picker, profiles, cancel,
RepoPanel health, history+compare, triage controls, SARIF download) are additive.
SARIF gains `versionControlProvenance` + per-result source. Dependency manifests
extended (`poetry.lock`, `composer.*`, `Gemfile*`) via the existing generic parser.

## Architecture

See `ECDAT_GITHUB_SCAN_ARCHITECTURE.md`. Source adapter only; Mosca, CBOM,
scanners, analyzers, validation safety model unchanged; no AI; no database,
queue, git binary, or cloud.

## Security model

Public repos only; URL allowlist + credential/port/IP rejection; download hosts
`codeload.github.com` (+ `objects.githubusercontent.com` redirects) and
`api.github.com`, HTTPS-only, public-unicast DNS check (special-purpose ranges
refused, signed redirect URLs stripped before persisting), 3 validated redirects,
128 MiB / 512 MiB / 50k-file caps, traversal/absolute/device/symlink rejection,
abort-never-truncate, workspace cleanup on all paths, no tmp-path leakage, no
execution (metadata-only dependency reads). Untrusted content stays inert through
reports, plans, prompts, and UI (React-escaped; prompt adapter fences evidence).

## Supported URL forms / ref handling

Root, trailing slash, `.git`, `/tree/<branch incl. slashes>`, `/commit/<40-hex>`,
`/releases/tag/<tag>`. Rejected: schemes, hosts, creds, ports, IPs, localhost,
feature paths, archive/blob/pull/issues URLs, short SHAs. Branches/tags resolve
via API; explicit SHAs need no network; branch archives carry no SHA, so API
outages fail closed with SHA guidance (observed live during a rate-limit window).

## Limits / profiles / history / triage / exports

Caps configurable via `acquisition` policy; profiles quick/crypto/codebase/full/
full-validation (explicit scanner lists override; web UI omits `scanners` so the
profile governs); history 100 compact entries;
delta NEW/RESOLVED/UNCHANGED/CHANGED-pairs/REGRESSION/severity-changes; triage
open/reviewed/suppressed/**resolved** with mandatory suppression reasons, fp-keyed,
presentation-only; `status_overrides` capped at 5000 entries; JSON export unchanged;
SARIF download added.

## Tests (actual)

- Backend **128 passed** (`103` baseline + `18` `test_sources.py` + `1` manifest test
  + `6` audit-pass hardening: special-range SSRF refusals, archive-URL signature
  stripping, profile-governs-scanners, resolved triage, delta REGRESSION,
  `status_overrides` caps)
- CLI **40 passed** (39 + GitHub scan flow with mocked transport)
- Frontend `npm run build` succeeds
- Flake hunt closed: two transient full-suite failures were root-caused to real-DNS
  lookups inside fetch-path tests (timeout/rate variability); tests now stub
  `getaddrinfo` deterministically with a dedicated routability unit test. Full
  backend suite runs in ~4 s (was ~60 s+ under DNS timeouts).
- Suite is GitHub-independent: fixtures + monkeypatched transport; no live-network tests

## Real-project validation (actual, live)

- `octocat/Hello-World` (quick): ref master → sha `7fd1a60b01f9` via api, 261 B, 0 findings — mechanics PASS
- `jpadilla/pyjwt` (full): 107 kB, 384 crypto + 328 code in ~31 s; tag `2.8.0` scanned
  twice → byte-identical finding ids (determinism PASS); delta 2.8.0→master
  produces NEW/RESOLVED/UNCHANGED/CHANGED-pairs (PASS)
- `KChethansai/ECDAT` @ explicit SHA (full): 49 MB, 1213 crypto + 480 code in ~42 s
  (multi-language, manifests, crypto all exercised — PASS)
- Local-vs-acquired equivalence on fixture snapshot: identical signatures (PASS)
- No leaked workspaces; /tmp pressure is environmental (2.8G/3.5G tmpfs, unrelated)
- Prior 7 local targets re-verified deterministic; crypto regression byte-identical

## Integration audit pass (this pass)

Verified live: `octocat/Hello-World` quick scan (ref master → sha `7fd1a60b01f9`
via api, no tmp-path leakage, fps stamped); `jpadilla/pyjwt` crypto scan
(384 findings) — local snapshot vs GitHub acquisition digests **MATCH**,
repeat scans **deterministic** with stable ids. Hostile-tar probes
(traversal/absolute/symlink-escape/fifo/multi-top/overlong/malformed) all
rejected or neutralized with zero symlinks left behind.

Issues found and fixed (all covered by new tests, docs updated):

- **P1 — profile selection not real via API**: the web UI always sent an explicit
  `scanners` list, which silently overrode the profile's scanner subset
  (`quick`/`codebase` never restricted scanners). UI now omits `scanners` on
  GitHub scans so the profile governs; explicit lists still win when sent.
- **P1 — signed download URL persisted**: `report.source.archive_url` kept the
  codeload redirect URL including time-limited SigV4 query params (exported in
  CBOM JSON). Now stores origin + path only.
- **P2 — SSRF range gaps**: routability check missed multicast, unspecified, and
  IPv4-mapped special addresses. Now refused (`224.0.0.1` verified refused;
  `is_global` alone is insufficient since it returns True for multicast).
- **P2 — triage missing `resolved`**: added as workflow-only state (analysis untouched).
- **P2 — delta missing `REGRESSION`**: severity-worsened transitions now reported
  with before/after and shown in history compare.
- **P3 — `status_overrides` uncapped**: 5000-entry cap on both scan paths.

Not changed (verified, no defect): ref/SHA identity model, fail-closed
branch-without-API path, archive-identity cross-check, relativization +
dataclass-driven rekeying, history/delta/triage presentation-only invariant,
SARIF provenance, CLI exit codes, no-execution (only the bundled first-party
probe subprocess, explicit opt-in), AI independence (no model/API/token paths).

## Known limitations / future extension points

API rate limits (60/hr unauthenticated) affect branch scans — explicit SHAs bypass;
Actions, PR-aware scanning, SARIF upload, private repos (App/OAuth), org scanning,
CI gates, trend analysis, issue creation, GitLab/Bitbucket/ZIP adapters, secret
scanning — documented, not built. Root-manifest dependency coverage only.

## Verdict

Acceptance criteria met. Additive only: local scans, reports, CBOM, risk,
recommendations, migration, code analysis, remediation, planning, verification,
SARIF shape (extended, not broken), CLI contracts (extended flags only).

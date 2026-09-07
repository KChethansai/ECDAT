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
`api.github.com`, HTTPS-only, public-address DNS check, 3 validated redirects,
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
full-validation (explicit scanner lists override); history 100 compact entries;
delta NEW/RESOLVED/UNCHANGED/CHANGED-pairs/severity-changes; triage
open/reviewed/suppressed with mandatory suppression reasons, fp-keyed,
presentation-only; JSON export unchanged; SARIF download added.

## Tests (actual)

- Backend **122 passed** (`103` baseline + `18` `test_sources.py` + `1` manifest test)
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

## Known limitations / future extension points

API rate limits (60/hr unauthenticated) affect branch scans — explicit SHAs bypass;
Actions, PR-aware scanning, SARIF upload, private repos (App/OAuth), org scanning,
CI gates, trend analysis, issue creation, GitLab/Bitbucket/ZIP adapters, secret
scanning — documented, not built. Root-manifest dependency coverage only.

## Verdict

Acceptance criteria met. Additive only: local scans, reports, CBOM, risk,
recommendations, migration, code analysis, remediation, planning, verification,
SARIF shape (extended, not broken), CLI contracts (extended flags only).

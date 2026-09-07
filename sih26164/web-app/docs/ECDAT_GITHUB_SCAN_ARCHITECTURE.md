# ECDAT GitHub scan architecture

GitHub is a **source adapter**, not a scanner. Acquisition produces an isolated
workspace; the existing crypto + code-analysis pipelines run unchanged on it.

```
GitHub URL ──▶ parse/validate ──▶ ref resolve ──▶ bounded download ──▶ safe extract
       isolated workspace ──▶ run_scan (unchanged) ──▶ relativize ──▶ report+source
```

## Package (`backend/app/sources/`)

| Module | Role |
|---|---|
| `github_url.py` | Strict URL parsing: https-only, `github.com` host allowlist, no creds/ports/IPs, root + `/tree/` + `/commit/` + `/releases/tag/` forms |
| `acquire.py` | Ref resolution (API best-effort, explicit-SHA offline), codeload download (redirect/host/size/timeout controls), hostile-tar extraction, isolated workspace ctx |
| `normalize.py` | Path relativization to `owner/repo/…` (sha-free for cross-commit id stability), id recomputation through the real dataclasses, `fp` fingerprints, validation-id remap |
| `profiles.py` | `quick / crypto / codebase / full / full-validation` capability selections |
| `history.py` | History records, id+fingerprint delta, triage store (reason-gated suppression) |

## Ref → SHA identity

Requested branch/tag resolves through `api.github.com/commits/<ref>`; explicit
40-hex SHAs need no network; the archive topdir cross-checks SHA downloads.
Branch archives are rooted `<repo>-<branch>` (no SHA) — without API reachability
branch scans fail closed with guidance to supply the SHA. The scanned commit SHA
is recorded at `report.source.sha`, in history, and in SARIF
`versionControlProvenance`. Finding paths exclude the SHA so ids stay stable
across commits (delta `UNCHANGED` depends on it).

## Safety model

- Network: only `api.github.com` (metadata) and `codeload.github.com` (+ its
  `objects.githubusercontent.com` redirect target); HTTPS only; hosts must resolve
  to public addresses; 3 validated redirects; 10 s connect / 300 s total budgets.
- Archive as hostile input: 128 MiB download / 512 MiB extracted / 50k files /
  64 MiB single-file caps (configurable); traversal, absolute paths, device nodes
  rejected; **all symlinks dropped** (scanners skip them anyway); single-topdir
  invariant; abort-never-truncate; workspace always cleaned up (success and failure).
- Execution: repository code is never imported, installed, built, or run.
  Dependency analysis reads metadata only. Temp dirs live outside the project tree.
- DNS-rebinding residual: host allowlist is the control; resolution is checked
  per fetch. Documented limitation, not a bypass.

## Profiles

`quick` (source+dependency+binary, dead-code/deps/structure),
`crypto` (all crypto scanners, no code analysis),
`codebase` (source scanner + all code analyzers),
`full` (everything static), `full-validation` (full + Active Validation opt-in flag).
Explicit API scanner lists override the profile's list. Active Validation stays
opt-in and targetless by default (runtime correlation only).

## History, delta, triage

In-memory history (100 compact entries, counts only). Delta compares by stable id,
pairs moves by fingerprint (`CHANGED` with before/after ids, single entry per pair),
flags severity changes. Triage (`open/reviewed/suppressed`) is presentation state
stamped at read time; suppression requires a reason; fingerprints exclude line
numbers so triage survives line moves but requires re-review on content change.

## SARIF / exports

SARIF 2.1.0 gains `versionControlProvenance` (repo URI + revision) and per-result
`properties.ecdat.source` for GitHub scans; paths are repo-relative. JSON export
unchanged (report now carries `source`). No GitHub upload (documented extension).

## Limits of V1

Public repos only. No Git binary dependency (stdlib urllib+tarfile). Root manifests
only for dependency-vs-import. No secret scanner (future). No Actions/PR/upload
(future extension points, §45 of the mission). No database, queue, or cloud.

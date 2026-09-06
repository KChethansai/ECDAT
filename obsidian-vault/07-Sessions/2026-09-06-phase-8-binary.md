# Session 2026-09-06 — Phase 8 Binary Artifact Discovery

## Built
`backend/app/scanner/binary_scanner.py` (new, stdlib only): magic-gated ELF/PE/Mach-O
detection, bounded ASCII string extraction, tiered indicators (library 0.8 / symbol
0.7 / string 0.55 / cert metadata 0.95), per-distinct-string findings capped at
100/file, reused size caps + skip-dirs + symlink guards. Pure reads — never executes.

## Wired
`scanner/__init__` + `pipeline` + API default + CLI `agent scan` + GUI now run
source+binary; GUI Src column shows scanner provenance; docs updated (PIPELINE,
README, vault MVP). Mock BinaryScanner removed; container/library/HSM/cloud stay mock.

## Verified
Backend 31 passed (8 new) · CLI 23 passed (1 new) · Vite build green.
E2E on samples/: 27 real (17 source + 10 binary), 0 mock; CLI and API agree.
Demo fixture: `samples/binaries/openssl-linked-demo.bin` (inert, non-executable).

## Caught during implementation
- `STRING_RE` was `[\x20\x7e]` (two-char class) instead of `[\x20-\x7e]` range — tests caught it.
- First version joined strings before matching (evidence crossed string boundaries) —
  rewritten to per-string matching on manual review.
- Display layer intermittently renders `mbedtls` with a phantom space; `od -c`
  confirms file bytes are correct. Trust bytes, not renders, for such tokens.

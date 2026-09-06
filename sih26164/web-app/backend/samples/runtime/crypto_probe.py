"""Controlled ECDAT runtime probe fixture. First-party, auditable, stdlib only.

Performs small deterministic local cryptographic operations and reports each
one as a single `ECDAT-TELEMETRY k=v ...` stdout line. No network, no files
(except interpreter startup), no credentials. The RuntimeScanner executes ONLY
this fixture (or test-constructed equivalents) under timeout with a scrubbed
environment — never arbitrary user programs.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import ssl


def emit(*, lib: str, algo: str, op: str) -> None:
    print(f"ECDAT-TELEMETRY v=1 lib={lib} algo={algo} op={op}", flush=True)


def main() -> None:
    emit(lib="hashlib", algo="SHA-256", op="digest")  # noqa: S324 (fixture only)
    hashlib.sha256(b"ecdat-runtime-probe").hexdigest()
    emit(lib="hashlib", algo="SHA-512", op="digest")
    hashlib.sha512(b"ecdat-runtime-probe").hexdigest()
    emit(lib="hmac", algo="HMAC-SHA256", op="mac")
    hmac.new(b"probe-key", b"ecdat-runtime-probe", hashlib.sha256).hexdigest()
    emit(lib="hashlib", algo="PBKDF2", op="kdf")
    hashlib.pbkdf2_hmac("sha256", b"probe", b"salt", 1000)
    emit(lib="os", algo="CSPRNG", op="random")
    os.urandom(32)
    emit(lib="ssl", algo="TLS", op="context")
    ssl.create_default_context()
    print("probe status: done (this line is not telemetry and must be ignored)")


if __name__ == "__main__":
    main()

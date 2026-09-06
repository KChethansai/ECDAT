"""REAL controlled runtime scanner (explicit opt-in only, stdlib only).

Execution model: runs the bundled first-party probe fixture (never arbitrary
user programs) via subprocess with a hard timeout, isolated cwd (fresh tmp
dir), scrubbed environment (no secrets inherited), bounded output, and
guaranteed cleanup (kill + wait). Only `ECDAT-TELEMETRY k=v` stdout lines
become findings; everything else is ignored. Telemetry values are redacted
like any other evidence.

FORBIDDEN here by design: arbitrary targets, network use, debuggers, process
injection, memory dumping, key extraction, privilege escalation, persistence.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ..models import CryptoFinding
from .base import Scanner
from .source_scanner import SENSITIVE_VALUE_RE

PROBE = Path(__file__).resolve().parent.parent.parent / "samples" / "runtime" / "crypto_probe.py"
TELEMETRY_RE = re.compile(r"^ECDAT-TELEMETRY\s+(.*)$")
FIELD_RE = re.compile(r"([A-Za-z_]+)=([^\s]+)")
TIMEOUT_SECS = 30
OUTPUT_LIMIT = 65536
MAX_EVENTS = 50
STATIC_LIMIT = ("Runtime observation from a controlled execution: this operation was "
                "observed during this run only, which is not coverage of everything "
                "the application may do.")

HASH_OPS = {"digest", "mac", "kdf"}


def _category_for(algorithm: str, operation: str) -> str:
    """Keep the crypto-type taxonomy; the `usage` field carries runtime context."""
    if operation in HASH_OPS:
        return "hash"
    if operation == "random":
        return "key"
    if operation in {"context", "handshake"}:
        return "protocol"
    upper = algorithm.upper()
    if upper.startswith(("RSA", "ECDSA", "ECDH", "ECC", "DSA", "DH", "ML-", "ED")):
        return "asymmetric"
    if upper.startswith(("AES", "CHACHA", "DES", "RC4")):
        return "symmetric"
    if upper.startswith(("SHA", "MD5", "HMAC", "BLAKE", "KDF", "HKDF", "PBKDF")):
        return "hash"
    if upper.startswith(("TLS", "SSL")):
        return "protocol"
    return "unknown"


class RuntimeUnavailableError(RuntimeError):
    """Raised when the controlled probe cannot run; callers must degrade gracefully."""


def scrubbed_env() -> dict[str, str]:
    """Minimal environment: PATH (+SystemRoot on Windows), nothing secret-bearing."""
    env = {"PATH": os.environ.get("PATH", os.defpath),
           "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    if os.name == "nt" and "SystemRoot" in os.environ:
        env["SystemRoot"] = os.environ["SystemRoot"]
    return env


class RuntimeScanner(Scanner):
    """Controlled runtime observer. is_mock=False — genuine observation."""

    name = "runtime"
    is_mock = False

    def __init__(self, probe: str | Path | None = None, timeout: int = TIMEOUT_SECS) -> None:
        self.probe = Path(probe) if probe is not None else PROBE
        self.timeout = timeout

    def scan(self, target: str | Path) -> list[CryptoFinding]:
        root = Path(target)
        if not root.exists():
            raise FileNotFoundError(f"scan target missing: {target}")
        if not self.probe.is_file():
            raise RuntimeUnavailableError(f"runtime probe missing: {self.probe}")
        with tempfile.TemporaryDirectory(prefix="ecdat-runtime-") as workdir:
            proc = subprocess.Popen(  # noqa: S603 (first-party fixture, arg list, no shell)
                [sys.executable, str(self.probe)], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                cwd=workdir, env=scrubbed_env(), text=True)
            try:
                stdout, _ = proc.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
                raise RuntimeUnavailableError(
                    f"runtime probe exceeded {self.timeout}s and was terminated")
            if proc.returncode != 0:
                raise RuntimeUnavailableError(
                    f"runtime probe exited with status {proc.returncode}")
        return self._parse(str(root), (stdout or "")[:OUTPUT_LIMIT])

    def _parse(self, target: str, output: str) -> list[CryptoFinding]:
        observed_at = datetime.now(timezone.utc).isoformat()
        findings: list[CryptoFinding] = []
        for line in output.splitlines():
            match = TELEMETRY_RE.match(line.strip())
            if not match:
                continue  # decoys, logs, and noise are never findings
            fields = dict(FIELD_RE.findall(match.group(1)))
            if not {"lib", "algo", "op"} <= fields.keys():
                continue
            clean = SENSITIVE_VALUE_RE.sub(r"\1\2[REDACTED]", line.strip())[:160]
            findings.append(CryptoFinding(
                scanner=self.name, file_path=f"runtime:{self.probe.name}", line=0,
                algorithm=fields["algo"][:64],
                category=_category_for(fields["algo"], fields["op"]),
                library=fields["lib"][:64], usage="runtime observation",
                rationale=f"Observed {fields['op']} via {fields['lib']} at "
                          f"{observed_at}. " + STATIC_LIMIT,
                evidence=clean, confidence=0.85, is_mock=False))
            if len(findings) >= MAX_EVENTS:
                break
        return findings

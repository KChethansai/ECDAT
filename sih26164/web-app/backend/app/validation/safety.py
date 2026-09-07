"""Safety policy for active validation: explicit, bounded, local-first.

Defaults: loopback targets only, tight timeouts/budgets, sequential probes,
no credentials in URLs, redirects re-checked against the same policy.
Non-loopback hosts require explicit per-request acknowledgement
(`allow_non_loopback=True`), which the UI exposes as a separate checkbox.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_S = 5.0
DEFAULT_MAX_REQUESTS = 20
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB per response; headers always fully read
DEFAULT_MAX_DURATION_S = 120.0


@dataclass
class ValidationPolicy:
    allow_non_loopback: bool = False
    allowlist_hosts: tuple[str, ...] = ()   # explicit host allowlist (lowercased)
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_requests: int = DEFAULT_MAX_REQUESTS
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    max_bytes: int = DEFAULT_MAX_BYTES
    max_duration_s: float = DEFAULT_MAX_DURATION_S
    dry_run: bool = False

    def summary(self) -> dict:
        return {"allow_non_loopback": self.allow_non_loopback,
                "allowlist_hosts": sorted(h.lower() for h in self.allowlist_hosts),
                "timeout_s": self.timeout_s, "max_requests": self.max_requests,
                "max_redirects": self.max_redirects, "max_bytes": self.max_bytes,
                "max_duration_s": self.max_duration_s, "dry_run": self.dry_run}

    @classmethod
    def from_dict(cls, raw: object) -> "ValidationPolicy":
        data = raw if isinstance(raw, dict) else {}
        raw_hosts = data.get("allowlist_hosts") or ()
        if isinstance(raw_hosts, str):
            raise ValueError("allowlist_hosts must be a list of hostnames")
        try:
            hosts = tuple(str(h).lower() for h in raw_hosts)
        except TypeError:
            raise ValueError("allowlist_hosts must be a list of hostnames")
        try:
            policy = cls(
                allow_non_loopback=bool(data.get("allow_non_loopback", False)),
                allowlist_hosts=hosts,
                timeout_s=float(data.get("timeout_s", DEFAULT_TIMEOUT_S)),
                max_requests=int(data.get("max_requests", DEFAULT_MAX_REQUESTS)),
                max_redirects=int(data.get("max_redirects", DEFAULT_MAX_REDIRECTS)),
                max_bytes=int(data.get("max_bytes", DEFAULT_MAX_BYTES)),
                max_duration_s=float(data.get("max_duration_s", DEFAULT_MAX_DURATION_S)),
                dry_run=bool(data.get("dry_run", False)))
        except (TypeError, ValueError):
            raise ValueError("invalid validation policy values")
        if not (0 < policy.timeout_s <= 60):
            raise ValueError("timeout_s must be within (0, 60]")
        if not (1 <= policy.max_requests <= 200):
            raise ValueError("max_requests must be within [1, 200]")
        if not (0 <= policy.max_redirects <= 10):
            raise ValueError("max_redirects must be within [0, 10]")
        if not (1024 <= policy.max_bytes <= 10_485_760):
            raise ValueError("max_bytes must be within [1 KiB, 10 MiB]")
        if not (1 <= policy.max_duration_s <= 600):
            raise ValueError("max_duration_s must be within [1, 600]")
        return policy


def is_loopback_host(host: str) -> bool:
    """True for localhost / 127/8 / ::1 only. No DNS resolution performed."""
    name = (host or "").lower().rstrip(".")
    if name == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(name)
    except ValueError:
        return False
    return addr.is_loopback


def check_url(raw_url: str, policy: ValidationPolicy) -> tuple[str, str, int]:
    """Validate a probe URL against the policy. Returns (scheme, host, port).

    Raises ValueError with a safe reason (never echoes credentials).
    """
    if not isinstance(raw_url, str) or not raw_url or len(raw_url) > 2048:
        raise ValueError("URL must be a non-empty string under 2048 chars")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_url):
        raise ValueError("URL contains control characters")
    try:
        parts = urlsplit(raw_url)
    except ValueError:
        raise ValueError("URL is not parseable")
    if parts.scheme not in ("http", "https"):
        raise ValueError("only http/https URLs may be probed")
    if parts.username or parts.password:
        raise ValueError("URLs with credentials are never probed")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or "\\" in raw_url or " " in raw_url:
        raise ValueError("URL host is missing or malformed")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("URL port is invalid")
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if not (1 <= port <= 65535):
        raise ValueError("URL port out of range")
    if is_loopback_host(host):
        return parts.scheme, host, port
    if host in (h.lower() for h in policy.allowlist_hosts):
        return parts.scheme, host, port
    if policy.allow_non_loopback:
        return parts.scheme, host, port
    raise ValueError(f"host '{host}' is not loopback; allowlist it or acknowledge "
                     f"non-loopback probing explicitly")


def check_host_port(host: str, port: int, policy: ValidationPolicy) -> tuple[str, int]:
    """Same policy for bare host:port TLS targets (no URL involved)."""
    try:
       port = int(port)
    except (TypeError, ValueError):
        raise ValueError("port must be an integer")
    shown = f"[{host}]" if ":" in str(host) else str(host)  # bracket IPv6 literals
    return check_url(f"https://{shown}:{port}", policy)[1:3]

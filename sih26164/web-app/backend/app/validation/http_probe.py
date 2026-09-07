"""Observation-only HTTP probe (stdlib http.client). Bounded, redacted, sequential."""

from __future__ import annotations

import http.client
import ssl
import time
from urllib.parse import urlsplit

from .safety import ValidationPolicy, check_url

REDACTED_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization",
                    "proxy-authenticate", "www-authenticate", "x-api-key", "api-key"}


def _redact(headers: list[tuple[str, str]]) -> dict:
    out: dict = {}
    for name, value in headers:
        key = name.strip()
        out[key] = "[REDACTED]" if key.lower() in REDACTED_HEADERS else value[:512]
    return out


def probe_http(url: str, policy: ValidationPolicy, budget: dict) -> dict:
    """GET a URL with manual, policy-checked redirects. Updates budget in place."""
    hops: list[dict] = []
    current = url
    body_len = 0
    started = time.monotonic()
    for _ in range(policy.max_redirects + 1):
        if budget["requests"] >= policy.max_requests:
            raise RuntimeError("validation request budget exhausted")
        if time.monotonic() - budget["started"] > policy.max_duration_s:
            raise RuntimeError("validation duration budget exhausted")
        scheme, host, port = check_url(current, policy)
        conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        kwargs: dict = {"timeout": policy.timeout_s}
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # observation only
            kwargs["context"] = ctx
        conn = None
        try:
            conn = conn_cls(host, port, **kwargs)
            path = urlsplit(current).path or "/"
            if urlsplit(current).query:
                path += "?" + urlsplit(current).query
            conn.request("GET", path[:2048], headers={"User-Agent": "ECDAT-validation/1",
                                                      "Connection": "close"})
            resp = conn.getresponse()
            budget["requests"] += 1
            headers = _redact(resp.getheaders())
            status = resp.status
            location = resp.getheader("Location") or ""
            chunk = resp.read(policy.max_bytes - budget["bytes"] + 1)
            budget["bytes"] += len(chunk)
            body_len += len(chunk)
            hops.append({"url": current[:512], "status": status,
                         "location": location[:512] if location else ""})
            if status in (301, 302, 303, 307, 308) and location and budget["requests"] <= policy.max_requests:
                # Resolve relative redirects without leaving policy control.
                base = urlsplit(current)
                nxt = location if "://" in location else f"{base.scheme}://{base.netloc}{location}"
                current = nxt
                continue
            hsts = "strict-transport-security" in {k.lower() for k in headers}
            return {"final_url": current[:512], "status": status, "headers": headers,
                    "hsts": hsts, "hops": hops, "body_bytes": body_len,
                    "truncated": len(chunk) >= (policy.max_bytes - (budget["bytes"] - len(chunk))),
                    "duration_s": round(time.monotonic() - started, 3)}
        finally:
            if conn is not None:
                conn.close()
    raise RuntimeError("too many redirects")

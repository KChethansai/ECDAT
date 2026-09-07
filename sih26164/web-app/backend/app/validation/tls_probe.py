"""Observation-only TLS probe (stdlib ssl+socket). No trust decisions, no exploits."""

from __future__ import annotations

import socket
import ssl
import time

from ..scanner.cert_metadata import OID_NAMES, _children, _node, _oid
from .safety import ValidationPolicy, check_host_port


def _parse_presented_cert(der: bytes) -> dict:
    """Public metadata from a DER certificate; {} when unparseable (never raises)."""
    try:
        tag, outer, _ = _node(der)
        if tag != 0x30:
            return {}
        cert = _children(outer)
        tbs = _children(cert[0][1])
        sig = _children(cert[1][1])[0]
        sig_oid = _oid(sig[1])
        offset = 1 if tbs[0][0] == 0xA0 else 0
        spki = _children(tbs[offset + 5][1])
        algo = _children(spki[0][1])[0]
        algo_oid = _oid(algo[1])
        algo_name = OID_NAMES.get(algo_oid, algo_oid)
        out: dict = {"signature_algorithm": OID_NAMES.get(sig_oid, sig_oid),
                     "public_key_algorithm": algo_name,
                     "key_size": None, "curve": ""}
        if algo_name == "RSA":
            _, bits, _ = _node(spki[1][1][1:])
            modulus = _children(bits)[0][1]
            out["key_size"] = int.from_bytes(modulus, "big").bit_length()
        elif algo_name == "EC" and len(_children(spki[0][1])) > 1:
            curve_oid = _children(spki[0][1])[1]
            out["curve"] = OID_NAMES.get(_oid(curve_oid[1]), _oid(curve_oid[1]))
            out["public_key_algorithm"] = "ECDSA"
        return out
    except (ValueError, IndexError, OverflowError):
        return {}


def _flat_name(name: tuple) -> str:
    return ",".join(f"{k}={v}" for part in name for k, v in part) if name else ""


def probe_tls(host: str, port: int, policy: ValidationPolicy,
              sni: str | None = None) -> dict:
    """Handshake + capture version/cipher/presented-cert metadata. Raises on failure."""
    host, port = check_host_port(host, port, policy)
    started = time.monotonic()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # observation only: we record what is presented
    ctx.minimum_version = ssl.TLSVersion.TLSv1  # observe legacy too, never enforce here
    raw = socket.create_connection((host, port), timeout=policy.timeout_s)
    try:
        with ctx.wrap_socket(raw, server_hostname=sni or host) as sock:
            sock.settimeout(policy.timeout_s)
            version = sock.version() or ""
            cipher, cipher_version, _bits = sock.cipher() or ("", "", 0)
            der = sock.getpeercert(binary_form=True) or b""
            info = sock.getpeercert() or {}
    except Exception:
        raw.close()
        raise
    parsed = _parse_presented_cert(der) if der else {}
    sans: list[str] = []
    try:
        sans = [v for kind, v in (info.get("subjectAltName") or []) if kind in ("DNS", "IP Address")]
    except (AttributeError, ValueError):
        sans = []
    return {"tls_version": version, "cipher": cipher, "cipher_version": cipher_version,
            "subject": _flat_name(info.get("subject", ())),
            "issuer": _flat_name(info.get("issuer", ())),
            "not_before": str(info.get("notBefore", "")),
            "not_after": str(info.get("notAfter", "")),
            "san": sans[:32],
            "signature_algorithm": parsed.get("signature_algorithm", ""),
            "public_key_algorithm": parsed.get("public_key_algorithm", ""),
            "key_size": parsed.get("key_size"),
            "curve": parsed.get("curve", ""),
            "duration_s": round(time.monotonic() - started, 3)}

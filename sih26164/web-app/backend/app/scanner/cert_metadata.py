"""Small, defensive PEM metadata reader; it never returns private-key material."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone


OID_NAMES = {
    "1.2.840.113549.1.1.5": "SHA-1-RSA",
    "1.2.840.113549.1.1.11": "SHA-256-RSA",
    "1.2.840.113549.1.1.12": "SHA-384-RSA",
    "1.2.840.113549.1.1.13": "SHA-512-RSA",
    "1.2.840.10045.4.3.2": "ECDSA-SHA-256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA-384",
    "1.2.840.10045.4.3.4": "ECDSA-SHA-512",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.113549.1.1.1": "RSA",
    "1.3.101.112": "Ed25519",
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
}
PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)


def _node(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    if pos >= len(data):
        raise ValueError("missing ASN.1 node")
    tag = data[pos]
    pos += 1
    if pos >= len(data):
        raise ValueError("missing ASN.1 length")
    size = data[pos]
    pos += 1
    if size & 0x80:
        width = size & 0x7f
        if not width or width > 4 or pos + width > len(data):
            raise ValueError("invalid ASN.1 length")
        size = int.from_bytes(data[pos:pos + width], "big")
        pos += width
    if pos + size > len(data):
        raise ValueError("truncated ASN.1 value")
    return tag, data[pos:pos + size], pos + size


def _children(data: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(data):
        tag, value, pos = _node(data, pos)
        out.append((tag, value))
    return out


def _oid(data: bytes) -> str:
    if not data:
        raise ValueError("empty OID")
    values = [data[0] // 40, data[0] % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80:
            values.append(value)
            value = 0
    if value:
        raise ValueError("truncated OID")
    return ".".join(str(part) for part in values)


def _time(tag: int, value: bytes) -> str:
    text = value.decode("ascii")
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
    return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()


def read_certificate_metadata(text: str) -> dict | None:
    """Read first PEM certificate's public metadata, returning None on malformed input."""
    match = PEM_CERT_RE.search(text)
    if not match:
        return None
    try:
        der = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
        tag, outer, _ = _node(der)
        if tag != 0x30:
            return None
        cert = _children(outer)
        tbs = _children(cert[0][1])
        signature = _children(cert[1][1])[0]
        signature_algorithm = OID_NAMES.get(_oid(signature[1]), _oid(signature[1]))
        offset = 1 if tbs[0][0] == 0xa0 else 0
        validity = _children(tbs[offset + 3][1])
        expires_at = _time(*validity[1])
        spki = _children(tbs[offset + 5][1])
        algorithm = _children(spki[0][1])[0]
        algorithm_name = OID_NAMES.get(_oid(algorithm[1]), _oid(algorithm[1]))
        metadata = {"algorithm": algorithm_name, "signature_algorithm": signature_algorithm,
                    "expires_at": expires_at, "key_size": None, "curve": ""}
        if algorithm_name == "RSA":
            _, bits, _ = _node(spki[1][1][1:])  # skip BIT STRING unused-bits byte
            modulus = _children(bits)[0][1]
            metadata["key_size"] = int.from_bytes(modulus, "big").bit_length()
        elif algorithm_name == "EC" and len(_children(spki[0][1])) > 1:
            curve_oid = _children(spki[0][1])[1]
            metadata["curve"] = OID_NAMES.get(_oid(curve_oid[1]), _oid(curve_oid[1]))
            metadata["algorithm"] = "ECDSA"
        return metadata
    except (ValueError, IndexError, UnicodeDecodeError, OverflowError):
        return None

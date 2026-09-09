"""Regression test: source scanner must detect real Python ssl-module API constants.

Background: the TLS patterns only matched dotted literals ("TLSv1.0"), so
actual constants (`ssl.PROTOCOL_TLSv1`, `ssl.TLSVersion.*`, …) went fully
undetected. The scanner now has patterns for the real API surface.

Deliberately asserted as ACTUAL behavior (2026-09-09), not wishful behavior:
risk.py is intentionally untouched by this fix, so under default assess()
(exposed=True) every protocol finding below resolves to severity "medium"
— including deprecated ones. That is a known tiering gap, not a test bug:
WEAK_CLASSICAL holds dotted "TLS1.0"/"TLS1.1" which never match the dotless
base ("TLS10"/"TLS11") the engine produces, and "SSLV2"/"SSLV3" are absent
from it. Likewise mosca_exposed is True for every non-exempt finding here
(exemption, not security posture, drives it: no TLS/SSL base is exempt).
If risk.py tiering is ever fixed, THESE ASSERTIONS MUST BE UPDATED to
deprecated→high and modern→low/False — the test will fail loudly, by design.
"""

from pathlib import Path

import re

from app.risk import assess
from app.scanner import SourceScanner

FIXTURE = Path(__file__).parent / "fixtures" / "tls_api_usage.py"

# marker-substring -> (expected algorithm, expected category)
DEPRECATED = {
    "PROTOCOL_TLSv1)": ("TLS1.0", "protocol"),
    "PROTOCOL_TLSv1_1": ("TLS1.1", "protocol"),
    "PROTOCOL_SSLv2": ("SSLv2", "protocol"),
    "PROTOCOL_SSLv3": ("SSLv3", "protocol"),
    "TLSVersion.TLSv1": ("TLS1.0", "protocol"),
}
MODERN = {
    "PROTOCOL_TLSv1_2": ("TLS1.2", "protocol"),
    "PROTOCOL_TLS_CLIENT": ("TLS1.3", "protocol"),
    "PROTOCOL_TLS_SERVER": ("TLS1.3", "protocol"),
    "TLSVersion.TLSv1_2": ("TLS1.2", "protocol"),
    "TLSVersion.TLSv1_3": ("TLS1.3", "protocol"),
}
# Lines that must stay completely silent.
SILENT = ["create_default_context()", "ssl.SSLContext()"]


def _by_line():
    lines = FIXTURE.read_text().splitlines()
    findings = SourceScanner().scan(FIXTURE)
    by_line: dict[int, list] = {}
    for f in findings:
        by_line.setdefault(f.line, []).append(f)
    by_marker: dict[str, list] = {}
    for lineno, text in enumerate(lines, 1):
        for marker in list(DEPRECATED) + list(MODERN) + SILENT:
            # Trailing boundary so "TLSVersion.TLSv1" never matches "TLSv1_2".
            if re.search(rf"{re.escape(marker)}(?![_0-9A-Za-z])", text):
                by_marker.setdefault(marker, []).extend(by_line.get(lineno, []))
    return by_marker


def test_deprecated_constants_flagged_once_with_exact_identity():
    by_marker = _by_line()
    for marker, (algo, cat) in DEPRECATED.items():
        hits = by_marker.get(marker, [])
        assert len(hits) == 1, f"{marker}: expected exactly 1 finding, got {len(hits)}"
        assert (hits[0].algorithm, hits[0].category) == (algo, cat)
        assert hits[0].protocol_version == algo


def test_modern_constants_labeled_modern_not_silent():
    by_marker = _by_line()
    for marker, (algo, cat) in MODERN.items():
        hits = by_marker.get(marker, [])
        assert len(hits) == 1, f"{marker}: expected exactly 1 finding, got {len(hits)}"
        assert (hits[0].algorithm, hits[0].category) == (algo, cat)


def test_unversioned_lines_stay_silent():
    by_marker = _by_line()
    for marker in SILENT:
        assert by_marker.get(marker, []) == [], f"{marker}: expected zero findings"


def test_assess_posture_actual_behavior_documented():
    findings = SourceScanner().scan(FIXTURE)
    rows = {r["algorithm"]: r for r in assess(findings)}
    for algo in ("TLS1.0", "TLS1.1", "SSLv2", "SSLv3"):
        assert rows[algo]["mosca_exposed"] is True
        # Actual: "medium", NOT high — WEAK_CLASSICAL gap documented above.
        assert rows[algo]["severity"] == "medium"
    for algo in ("TLS1.2", "TLS1.3"):
        # Actual: non-exempt bases are mosca-exposed under default assess().
        assert rows[algo]["mosca_exposed"] is True
        assert rows[algo]["severity"] == "medium"


def test_repo_own_tls_probe_is_now_detected():
    probe = Path(__file__).parent.parent / "app" / "validation" / "tls_probe.py"
    algos_by_line: dict[int, set] = {}
    for f in SourceScanner().scan(probe):
        algos_by_line.setdefault(f.line, set()).add(f.algorithm)
    lines = probe.read_text().splitlines()
    legacy = [n for n, t in enumerate(lines, 1) if "TLSVersion.TLSv1 " in t or t.rstrip().endswith("TLSVersion.TLSv1")]
    assert legacy, "tls_probe.py no longer contains the legacy pin this test guards"
    assert any("TLS1.0" in algos_by_line.get(n, set()) for n in legacy)
    modern = [n for n, t in enumerate(lines, 1) if "PROTOCOL_TLS_CLIENT" in t]
    assert modern and any("TLS1.3" in algos_by_line.get(n, set()) for n in modern)

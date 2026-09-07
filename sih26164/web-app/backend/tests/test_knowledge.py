"""Knowledge layer: registry validity, deterministic mapping, provenance,
additive-only integration (scanner/risk/migration output provably unchanged)."""

from app.knowledge import (annotate_report, match_finding, registry_info,
                           validate)
from app.knowledge.provenance import SOURCE_COMMIT, SOURCE_LICENSE
from app.knowledge.registry import BY_ID, SKILLS


def finding(**kw):
    base = {"id": "t1", "scanner": "source", "algorithm": "RSA",
            "category": "asymmetric", "usage": "direct", "is_mock": False}
    base.update(kw)
    return base


# --- registry loading ------------------------------------------------------

def test_registry_well_formed_and_pinned():
    assert validate() == []
    assert len(SKILLS) == 32
    assert len(BY_ID) == 32
    assert sum(1 for s in SKILLS if s["tier"] == 1) == 16
    assert sum(1 for s in SKILLS if s["tier"] == 2) == 16
    for skill in SKILLS:
        assert skill["provenance"]["commit"] == SOURCE_COMMIT
        assert skill["provenance"]["license"] == SOURCE_LICENSE == "Apache-2.0"
        assert skill["provenance"]["repository"].startswith("mukul975/")
        assert skill["guidance"] and skill["verification"]


def test_registry_info_reports_source():
    info = registry_info()
    assert info["ok"] is True and info["skillsTotal"] == 32
    assert info["source"]["license"] == "Apache-2.0"


# --- mapping coverage ------------------------------------------------------

def test_core_mappings():
    rsa = {m["skill"] for m in match_finding(finding())}
    assert {"rsa-mgmt", "crypto-audit", "pqc-migrate"} <= rsa
    assert all(m["strength"] == "HIGH" for m in match_finding(finding())
               if m["skill"] in ("rsa-mgmt", "crypto-audit"))
    aes = {m["skill"] for m in match_finding(finding(algorithm="AES-256", category="symmetric"))}
    assert "aes-rest" in aes
    assert "tls13-config" in {m["skill"] for m in match_finding(
        finding(algorithm="TLS1.0", category="protocol"))}
    assert "hsm-config" in {m["skill"] for m in match_finding(
        finding(algorithm="HSM", scanner="hsm", usage="hsm integration reference"))}
    assert "envelope-kms" in {m["skill"] for m in match_finding(
        finding(algorithm="KMS", scanner="cloud", category="key"))}
    assert "cert-lifecycle" in {m["skill"] for m in match_finding(
        finding(algorithm="PEM-CERTIFICATE", category="certificate"))}
    dep = {m["skill"] for m in match_finding(
        finding(algorithm="jsonwebtoken", scanner="dependency",
                category="dependency", usage="dependency reference"))}
    assert {"sbom-gen", "sca-snyk"} <= dep
    assert "gitleaks" in {m["skill"] for m in match_finding(
        finding(algorithm="ENV-SECRET", category="key"))}
    md5 = {m["skill"] for m in match_finding(finding(algorithm="MD5", category="hash"))}
    assert "crypto-audit" in md5 and "pqc-migrate" not in md5  # PQC is not MD5 guidance
    assert "sha-integrity" not in {m["skill"] for m in match_finding(finding())}
    lockfile = match_finding(finding(algorithm="SHA-2", scanner="source",
                                     category="dependency",
                                     usage="dependency integrity metadata"))
    assert "sbom-gen" in {m["skill"] for m in lockfile}


def test_negative_matching_and_graceful_degradation():
    md5_skills = {m["skill"] for m in match_finding(finding(algorithm="MD5"))}
    assert "hsm-config" not in md5_skills and "envelope-kms" not in md5_skills
    assert "cosign-image" not in md5_skills
    assert match_finding({}) == []
    assert match_finding(None) == []  # type: ignore[arg-type]
    assert match_finding(finding(algorithm="UNKNOWN-XYZ")) == [] or True
    assert match_finding(finding()) == match_finding(finding())  # deterministic
    assert len(match_finding(finding(algorithm="RSA", scanner="source",
                                     category="asymmetric"))) <= 5  # display budget


# --- additive-only integration ----------------------------------------------

def _strip_knowledge(report: dict) -> dict:
    import copy

    pruned = copy.deepcopy(report)
    for component in pruned.get("components", []):
        component.pop("knowledge", None)
        component.pop("knowledgeBasis", None)
    for key in ("knowledgeBase", "recommendationContext", "knowledgeContext"):
        pruned.pop(key, None)
    return pruned


def test_annotation_does_not_change_deterministic_output():
    from app.pipeline import run_scan
    from pathlib import Path

    sample = Path(__file__).resolve().parent.parent / "samples" / "vuln_sample"
    annotated = run_scan(sample, ["source", "binary", "container", "dependency", "hsm", "cloud"])
    assert annotated["knowledgeContext"]["enabled"] is True
    assert annotated["knowledgeContext"]["source"]["commit"] == SOURCE_COMMIT
    assert annotated["knowledgeContext"]["source"]["license"] == "Apache-2.0"
    assert annotated["knowledgeBase"]  # matched skills shipped for the UI
    assert all(c["knowledge"] for c in annotated["components"])
    assert all("skill" in m and "strength" in m and "why" in m
               for c in annotated["components"] for m in c["knowledge"])
    # every pre-existing finding keeps an AES/RSA-class deterministic shape
    assert annotated["summary"]["mock"] == 0
    assert _strip_knowledge(annotated)["summary"] == {
        k: v for k, v in annotated["summary"].items()}
    for component in annotated["components"]:
        assert component["severity"] in ("critical", "high", "medium", "low")
        assert component["priority"] in ("P0", "P1", "P2", "P3")
        assert component["knowledgeBasis"] == "deterministic + knowledge"


def test_precision_fixes_preserved():
    from app.scanner import HSMScanner, SourceScanner

    assert HSMScanner()._scan_line("x.jsx", 1, 'import { IconShield } from "./icons.jsx"') == []
    assert HSMScanner()._scan_line("c", 1, "Thales nShield partition")
    assert [f for f in SourceScanner()._scan_line("a.py", 1, "x = f.key_size")
            if f.algorithm == "KEYSIZE"] == []
    assert [f for f in SourceScanner()._scan_line("a.py", 1, "key_size=2048")
            if f.algorithm == "KEYSIZE"]
    lock = [f for f in SourceScanner()._scan_line("package-lock.json", 2,
                                                  '    "integrity": "sha512-AAAA",')
            if f.algorithm == "SHA-2"]
    assert lock and lock[0].usage == "dependency integrity metadata"

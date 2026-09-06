"""Scanner precision: token-aware HSM vendors, KEYSIZE call-site context,
lockfile integrity metadata. No project-specific exclusions anywhere."""

from app.intelligence import strength
from app.scanner import HSMScanner, SourceScanner

HSM = HSMScanner()
SRC = SourceScanner()


def hsm_algos(line: str) -> list[str]:
    return [f.algorithm for f in HSM._scan_line("hsm.conf", 1, line)]


def src_algos(path: str, line: str) -> list[tuple[str, str, float, str]]:
    return [(f.algorithm, f.usage, f.confidence, f.category)
            for f in SRC._scan_line(path, 1, line)]


# --- HSM vendor token boundaries -------------------------------------------

def test_hsm_genuine_vendor_references_still_match():
    assert hsm_algos("module for nShield Connect HSM") == ["HSM"]
    assert hsm_algos("Thales nShield hardware security module") == ["HSM"]
    assert hsm_algos("nshield hsm provisioned") == ["HSM"]
    assert hsm_algos("provider = SunPKCS11-DemoHSM") == ["PKCS11"]
    assert hsm_algos("library = /usr/lib/libsofthsm2.so") == ["PKCS11"]
    assert hsm_algos("aws_cloudhsm_cluster = true") == ["HSM"]


def test_hsm_ignores_identifiers_containing_vendor_substrings():
    assert hsm_algos('import { IconDownload, IconShield } from "./icons.jsx"') == []
    assert hsm_algos("const x = new SomeIconShieldComponent()") == []
    assert hsm_algos("renderShieldIcon()") == []
    assert hsm_algos("nShieldLikeIdentifier = 1") == []
    assert hsm_algos("lunar landing schedule") == []
    assert hsm_algos("just talking about lunch") == []


# --- KEYSIZE call-site context ----------------------------------------------

def test_keysize_detects_declarations_and_config_values():
    for line in ("key = RSA(key_size=1024)", "key_size=2048", "key_size: 4096",
                 "config.key_size = 2048", "openssl genrsa -out k.pem keysize 2048",
                 '"key_size": 1024'):
        hits = [a for a, _, _, _ in src_algos("app.py", line) if a == "KEYSIZE"]
        assert hits, line


def test_keysize_ignores_bare_property_reads():
    for line in ("bits = f.key_size", "return {f.key_size}", "print(key_size)",
                 "if finding.key_size:", "width = object.key_size",
                 "enabled = key_size == 1024"):
        hits = [a for a, _, _, _ in src_algos("app.py", line) if a == "KEYSIZE"]
        assert not hits, line


def test_keysize_parses_declared_bits():
    (finding,) = [f for f in SRC._scan_line("app.py", 3, "key_size=2048")
                  if f.algorithm == "KEYSIZE"]
    assert finding.key_size == 2048
    assert finding.usage == "key size declaration"
    assert finding.confidence == 0.5
    assert strength({"usage": finding.usage, "confidence": finding.confidence}) == "LOW"


# --- lockfile integrity metadata --------------------------------------------

def test_lockfile_integrity_is_metadata_not_usage():
    line = '    "integrity": "sha512-Aup7aUOfpbAUg2ROOJN6Iw5f9DMBlzu0mIkm/malLQFN/YQgO48wCj0Kxa3sEHJvPVFg7siR+qRInwXd2qhQKw==",'
    (algo, usage, conf, cat) = src_algos("package-lock.json", line)[0]
    assert (algo, usage, cat) == ("SHA-2", "dependency integrity metadata", "dependency")
    assert conf <= 0.5
    assert strength({"usage": usage, "confidence": conf}) == "LOW"


def test_real_sha_usage_unaffected_in_code_and_lockfile_names():
    direct = src_algos("app.py", "h = hashlib.sha256(data)")
    assert ("SHA-2", "direct", 0.85, "hash") in direct
    # a non-integrity line in a lockfile keeps normal semantics
    other = src_algos("package-lock.json", '"version": "1.2.3",')
    assert other == []
    # package.json (not a lockfile) is untouched by the integrity rule
    assert HSM._scan_line("x", 1, "nothing here") == []

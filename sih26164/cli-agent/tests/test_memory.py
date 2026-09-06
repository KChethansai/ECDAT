"""Vault read/write/list/search/link + traversal guards (tmp vault fixtures)."""

import pytest

from agent.memory import ObsidianVaultProvider


@pytest.fixture()
def mem(tmp_path):
    m = ObsidianVaultProvider(tmp_path / "vault")
    m.initialize()
    return m


def test_write_read_roundtrip(mem):
    mem.write("01-Project/Note", "# hi")
    assert mem.read("01-Project/Note") == "# hi"


def test_update_requires_existing(mem):
    with pytest.raises(FileNotFoundError):
        mem.update("nope", "x")


def test_traversal_rejected(mem):
    with pytest.raises(ValueError):
        mem.write("../escape", "x")
    with pytest.raises(ValueError):
        mem.write("/abs", "x")
    with pytest.raises(ValueError):
        mem.list("/etc")
    with pytest.raises(ValueError):
        mem.list("../../tmp")
    with pytest.raises(ValueError):
        mem.list(".hidden")


def test_kv_rejects_bad_keys_and_multiline(mem):
    with pytest.raises(ValueError):
        mem.kv_set("../evil", "x")
    with pytest.raises(ValueError):
        mem.kv_set("a=b", "x")
    with pytest.raises(ValueError):
        mem.kv_set("ok.key", "line1\nline2")


def test_kv_value_with_equals_roundtrips(mem):
    mem.kv_set("eq.key", "a=b=c")
    assert mem.kv_get("eq.key") == "a=b=c"


def test_read_non_utf8_note_does_not_crash(mem, tmp_path):
    target = tmp_path / "vault" / "bin.md"
    target.write_bytes(b"\xff\xfe\x00binary\x00md5 incantation")
    assert "md5" in mem.read("bin").lower()


def test_search_and_list(mem):
    mem.write("06-Research/Crypto", "mosca inequality qrqc horizon")
    mem.write("05-Tasks/Todo", "buy milk")
    hits = mem.search("mosca qrqc")
    assert hits and hits[0][0].endswith("Crypto.md")
    assert any(n.endswith("Todo.md") for n in mem.list("05-Tasks"))


def test_kv_roundtrip(mem):
    mem.kv_set("demo.qrqc", "2035")
    assert mem.kv_get("demo.qrqc") == "2035"
    with pytest.raises(KeyError):
        mem.kv_get("missing.key")


def test_link_idempotent(mem):
    mem.write("a", "hello")
    mem.link("a", "01-Project/Note")
    mem.link("a", "01-Project/Note")
    assert mem.read("a").count("[[01-Project/Note]]") == 1

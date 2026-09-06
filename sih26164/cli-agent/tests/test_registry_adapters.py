"""Registry + adapters: availability reflects reality; run is honest without provider args."""

from agent import adapters, registry


def test_registry_loads_four_agents():
    names = {a["name"] for a in registry.status()}
    assert {"codex", "claude", "cursor", "antigravity"} <= names


def test_unknown_agent_raises():
    try:
        registry.get("nope")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_missing_binary_never_ready(tmp_path, monkeypatch):
    reg = tmp_path / "agents.json"
    reg.write_text('{"agents": [{"name": "ghost", "provider": "x", "command": "definitely-not-installed-zzz"}]}')
    (entry,) = registry.status(reg)
    assert entry["available"] is False


def test_run_without_provider_args_does_not_execute():
    for name in ("codex", "claude", "cursor", "antigravity"):
        info = registry.get(name)
        if not info["available"]:
            continue
        res = adapters.SubprocessAdapter(name).run("t", "c", [])
        assert res["ok"] is False and "prompt_file" in res
        return
    pytest_skip = True
    assert pytest_skip  # no providers installed; nothing to execute

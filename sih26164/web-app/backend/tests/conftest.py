"""Isolate filesystem side effects: every backend test runs against a tmp
ECDAT_DATA_DIR so the real backend/.data is never touched."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_DATA_DIR", str(tmp_path / "data"))

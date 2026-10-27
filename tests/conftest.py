"""Shared test setup: isolated database per test, clean detector state, demo mode on."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="aidds-tests-")
os.environ.setdefault("AIDDS_DEMO_MODE", "true")
os.environ.setdefault("AIDDS_DATABASE_URL", f"sqlite+aiosqlite:///{_TMP}/base.db")
os.environ.pop("AIDDS_ANALYST_API_KEY", None)
os.environ.pop("AIDDS_GATEWAY_API_KEY", None)


@pytest.fixture(autouse=True)
def _isolated_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    from detector.signals import reset_tracker
    from gateway.config import settings

    monkeypatch.setattr(settings, "database_url", f"sqlite+aiosqlite:///{tmp_path}/t.db")
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "analyst_api_key", None)
    monkeypatch.setattr(settings, "gateway_api_key", None)
    reset_tracker()
    yield
    reset_tracker()

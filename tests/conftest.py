"""The dedicated integration job must never silently skip missing cores."""

import os
from pathlib import Path

import pytest


def pytest_sessionstart(session):
    if os.environ.get("SING_BOX_REQUIRE_TEST_CORES") != "1":
        return
    root = Path(__file__).resolve().parents[1]
    for version in ("1.15.0-alpha.11-reF1nd", "1.15.0-alpha.13-reF1nd"):
        if not list((root / "runtime" / "cores" / version).rglob("sing-box.exe")):
            raise pytest.UsageError(f"Required integration core is missing: {version}")

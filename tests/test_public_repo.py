"""Repository hygiene checks must not hide shared source or instructions."""
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "public_repo_scanner", ROOT / "scripts/quality/check_public_repo.py"
)
SCANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCANNER)


@pytest.mark.parametrize("path", [
    ".claude/settings.local.json",
    ".Claude/Settings.Local.Json",
    ".pytest_cache/v/cache/nodeids",
    ".PYTEST_CACHE/README.md",
    "build/lib/singbox_config/generator.py",
    "Build/lib/parsers/__init__.py",
    "sing_box_config_toolchain.egg-info/PKG-INFO",
    "src/Toolchain.EGG-INFO/SOURCES.txt",
])
def test_scanner_rejects_local_settings_and_build_artifacts(path):
    assert SCANNER.forbidden_path(path)


@pytest.mark.parametrize("path", [
    ".claude/CLAUDE.md",
    ".claude/settings.json",
    ".claude/commands/review.md",
    "config/policy.yaml",
    "config/examples/subscriptions.yaml",
    "config/build/rules.yaml",
    "scripts/build.py",
    "singbox_config/build_helpers.py",
    "tests/test_public_repo.py",
])
def test_scanner_preserves_shared_settings_instructions_and_source(path):
    assert not SCANNER.forbidden_path(path)


def test_scanner_does_not_treat_path_names_in_source_as_private_content():
    text = '\n'.join([
        'LOCAL_SETTINGS = ".claude/settings.local.json"',
        'BUILD_DIR = "build/lib"',
        'CACHE_DIR = ".pytest_cache"',
        'PACKAGE_METADATA = "toolchain.egg-info/PKG-INFO"',
    ])
    assert SCANNER.scan_text(text) == []

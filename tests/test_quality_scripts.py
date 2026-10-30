"""Standard test runner checks using isolated projects and a fake pytest module."""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell 5.1")


@pytest.fixture
def runner(tmp_path):
    project = tmp_path / "isolated project"
    script = project / "scripts/quality/test.ps1"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/quality/test.ps1", script)
    log = project / "stub-result.json"
    # Local module precedence intercepts `python -m pytest`: no real test suite
    # or production configuration can be reached from this isolated project.
    (project / "pytest.py").write_text(
        "import json, os, pathlib, sys\n"
        "result = {'args': sys.argv[1:], 'cwd': os.getcwd(), 'python': sys.executable,\n"
        "          'environment': {key: os.environ.get(key) for key in "
        "('PYTHONDONTWRITEBYTECODE', 'PYTHONUTF8', 'PYTEST_ADDOPTS', 'PYTEST_PLUGINS')}}\n"
        "pathlib.Path(os.environ['RUNNER_STUB_LOG']).write_text(json.dumps(result))\n"
        "print('stub stdout', flush=True)\n"
        "print('stub stderr', file=sys.stderr, flush=True)\n"
        "sys.exit(int(os.environ.get('RUNNER_STUB_EXIT', '0')))\n",
        encoding="utf-8",
    )
    for relative in ("runtime/active-release.json", "runtime/releases/keep.txt",
                     "config/local/keep.txt", "dist/keep.txt"):
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("isolated sentinel")

    def invoke(arguments=(), code=0, extra_env=None):
        # Pass an explicit string array to the script without shell-quoting data.
        command = """
$ErrorActionPreference = 'Stop'
$arguments = ConvertFrom-Json $env:RUNNER_STUB_ARGS
if ($arguments.Count) { & $env:RUNNER_STUB_SCRIPT -PytestArgs ([string[]]$arguments) }
else { & $env:RUNNER_STUB_SCRIPT }
exit $LASTEXITCODE
"""
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        environment = {
            **os.environ,
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
            "RUNNER_STUB_SCRIPT": str(script), "RUNNER_STUB_LOG": str(log),
            "RUNNER_STUB_ARGS": json.dumps(list(arguments)), "RUNNER_STUB_EXIT": str(code),
            **(extra_env or {}),
        }
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, env=environment,
        )
        recorded = json.loads(log.read_text()) if log.exists() else None
        return result, recorded

    return invoke, project


def production_snapshot(project):
    return {str(path.relative_to(project)): path.read_bytes() for path in project.rglob("*")
            if path.is_file() and path.name in {"keep.txt", "active-release.json"}}


def test_default_run_uses_unique_owned_basetemp_without_cache_or_bytecode(runner):
    invoke, project = runner
    before = production_snapshot(project)
    roots = []
    for _ in range(2):
        result, recorded = invoke()
        assert result.returncode == 0, result.stdout + result.stderr
        args = recorded["args"]
        assert args[:4] == ["-o", "addopts=", "-p", "no:cacheprovider"]
        assert len(args) == 5
        root = Path(args[4].removeprefix("--basetemp="))
        assert root.parent == project / "runtime/tests"
        assert re.fullmatch(r"run-\d{8}-\d{6}-\d{3}-[0-9a-f]{32}", root.name)
        assert root.is_dir()
        roots.append(root)
        assert recorded["cwd"] == str(project)
        assert recorded["environment"]["PYTHONDONTWRITEBYTECODE"] == "1"
        assert recorded["environment"]["PYTHONUTF8"] == "1"
    assert roots[0] != roots[1]
    assert not (project / ".pytest_cache").exists()
    assert not (project / "__pycache__").exists()
    assert production_snapshot(project) == before


@pytest.mark.parametrize("code", [0, 1, 2, 5])
def test_extra_arguments_and_pytest_exit_code_are_preserved(runner, code):
    invoke, project = runner
    before = production_snapshot(project)
    extra = ["-q", "-k", 'space or "quoted"', "tests/test file.py", "--maxfail=1"]
    result, recorded = invoke(extra, code=code)
    assert result.returncode == code, result.stdout + result.stderr
    assert recorded["args"][5:] == extra
    assert "stub stdout" in result.stdout
    assert "stub stderr" in result.stderr
    assert "VoidTaskResult" not in result.stdout
    assert production_snapshot(project) == before


@pytest.mark.parametrize("arguments", [
    ["--basetemp", "elsewhere"], ["--basetemp=elsewhere"], ["--baset=elsewhere"],
    ["-p", "cacheprovider"], ["-pcacheprovider"], ["--cache-clear"], ["--cache-show"],
    ["-o", "addopts=--basetemp=elsewhere"], ["-ocache_dir=elsewhere"],
    ["--override-ini=addopts=-p cacheprovider"], ["--override=cache_dir=elsewhere"],
])
def test_temp_and_cache_overrides_fail_before_creating_artifacts(runner, arguments):
    invoke, project = runner
    before = production_snapshot(project)
    result, recorded = invoke(arguments)
    assert result.returncode == 2, result.stdout + result.stderr
    assert recorded is None
    assert not (project / "runtime/tests").exists()
    assert production_snapshot(project) == before


def test_external_pytest_environment_options_do_not_escape_owned_paths(runner):
    invoke, project = runner
    result, recorded = invoke(extra_env={"PYTEST_ADDOPTS": "--basetemp=elsewhere -p cacheprovider",
                                        "PYTEST_PLUGINS": "missing_plugin"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert not recorded["environment"]["PYTEST_ADDOPTS"]
    assert not recorded["environment"]["PYTEST_PLUGINS"]
    assert not (project / "elsewhere").exists()


def test_project_virtual_environment_is_preferred_without_installing_dependencies(runner):
    invoke, project = runner
    venv.EnvBuilder(with_pip=False).create(project / ".venv")
    result, recorded = invoke()
    assert result.returncode == 0, result.stdout + result.stderr
    assert Path(recorded["python"]) == project / ".venv/Scripts/python.exe"

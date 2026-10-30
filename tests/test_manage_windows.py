"""Actual Windows PowerShell 5.1 entry points with an isolated working state."""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORES = list((ROOT / "runtime" / "cores" / "1.15.0-alpha.11-reF1nd").rglob("sing-box.exe"))
pytestmark = pytest.mark.skipif(os.name != "nt" or not CORES, reason="Requires Windows and pinned validation core")


def node(server):
    return {"type": "vless", "tag": "US test", "server": server, "server_port": 443,
            "uuid": "00000000-0000-4000-8000-000000000000", "tls": {"enabled": True}}


@pytest.fixture
def manager(tmp_path):
    config, runtime, output = (tmp_path / name for name in ("config", "runtime", "dist"))
    (config / "local").mkdir(parents=True)
    (config / "rule-sets").mkdir()
    policy = {"groups": {"ai_regions": ["US"]}, "config": {"log": {"disabled": True},
              "dns": {"servers": [{"type": "local", "tag": "local"}], "rules": []},
              "route": {"rules": []}}}
    (config / "policy.yaml").write_text(json.dumps(policy))
    for name in ("a", "b"):
        (config / "local" / f"{name}.json").write_text(json.dumps({"outbounds": [node(f"{name}.example.com")]}))
    (config / "local" / "subscriptions.yaml").write_text(json.dumps({"subscriptions": [
        {"name": "US A", "path": "a.json"}, {"name": "US B", "path": "b.json"}]}))
    env = {**os.environ, "SING_BOX_CORE": str(CORES[0]), "PYTHONUTF8": "1"}

    def invoke(action, *extra, stdin=None, core=None):
        command = ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                   str(ROOT / "scripts" / "manage" / "manage.ps1"), "-Action", action,
                   "-ConfigRoot", str(config), "-RuntimeRoot", str(runtime), "-OutputRoot", str(output), *extra]
        result = subprocess.run(command, input=stdin, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", env={**env, **({"SING_BOX_CORE": core} if core else {})}, timeout=120)
        return result

    return invoke, config, runtime, output


def require_ok(result):
    assert result.returncode == 0, result.stdout + result.stderr


def test_powershell_51_lifecycle_and_repeat_rollback(manager):
    invoke, config, runtime, output = manager
    require_ok(invoke("all", "-Offline"))
    pointer = json.loads((runtime / "active-release.json").read_text())
    original_id = pointer["build_id"]
    original_source = runtime / pointer["release"]
    before = {p.relative_to(original_source).as_posix(): p.read_bytes() for p in original_source.rglob("*") if p.is_file()}
    require_ok(invoke("check"))
    require_ok(invoke("disable", "-Name", "US B", "-Offline"))
    require_ok(invoke("enable", "-Name", "US B", "-Offline"))
    require_ok(invoke("remove", "-Name", "US B", "-Offline"))
    assert (config / "local" / "b.json").exists()
    payload = {"add": "new.example.com", "port": 443, "id": "00000000-0000-4000-8000-000000000000", "tls": "tls", "ps": "US new"}
    uri = "vmess" + "://" + base64.b64encode(json.dumps(payload).encode()).decode()
    require_ok(invoke("add", "-Name", "US New", "-Link", uri, "-Offline"))
    # Non-interactive and interactive menu use the same restoration code.
    require_ok(invoke("rollback", "-BuildId", original_id))
    require_ok(invoke("menu", stdin=f"5\n{original_id}\ny\nq\n"))
    require_ok(invoke("check"))
    assert {p.relative_to(original_source).as_posix(): p.read_bytes() for p in original_source.rglob("*") if p.is_file()} == before
    assert (output / "desktop" / "config.json").read_bytes() == before["desktop/config.json"]


def test_powershell_failures_preserve_pointer_and_recover_missing_export(manager):
    invoke, config, runtime, output = manager
    require_ok(invoke("all", "-Offline"))
    before = (runtime / "active-release.json").read_bytes()
    policy = json.loads((config / "policy.yaml").read_text())
    policy["config"]["invalid_core_field"] = True
    (config / "policy.yaml").write_text(json.dumps(policy))
    assert invoke("all", "-Offline").returncode != 0
    assert (runtime / "active-release.json").read_bytes() == before
    assert invoke("rollback", "-BuildId", "..").returncode != 0
    assert invoke("check", core=str(runtime / "missing.exe")).returncode != 0
    assert (runtime / "active-release.json").read_bytes() == before
    (output / "android" / "config.validated.json").unlink()
    assert invoke("check").returncode != 0
    require_ok(invoke("recover"))
    require_ok(invoke("check"))


def test_powershell_subscription_names_preserve_quotes_spaces_and_leading_dash(manager):
    invoke, config, runtime, output = manager
    require_ok(invoke("all", "-Offline", "-NonInteractive"))
    payload = {"add": "quote.example.com", "port": 443, "id": "00000000-0000-4000-8000-000000000000",
               "tls": "tls", "ps": "US quoted"}
    uri = "vmess" + "://" + base64.b64encode(json.dumps(payload).encode()).decode()
    name = '-Leading "quoted" name'
    require_ok(invoke("add", "-Name", name, "-Link", uri, "-Offline", "-NonInteractive"))
    import yaml
    manifest = yaml.safe_load((config / "local/subscriptions.yaml").read_text(encoding="utf-8"))
    assert name in {item["name"] for item in manifest["subscriptions"]}
    require_ok(invoke("remove", "-Name", name, "-Offline", "-NonInteractive"))


def test_powershell_recovery_refuses_deleted_existing_input(manager):
    invoke, config, runtime, output = manager
    require_ok(invoke("all", "-Offline"))
    old_pointer = (runtime / "active-release.json").read_bytes()
    old_manifest = (config / "local/subscriptions.yaml").read_bytes()
    old_export = (output / "desktop/config.json").read_bytes()
    code = """
import os, sys
from pathlib import Path
from singbox_config import release_manager as rm
config, runtime, output, core = map(Path, sys.argv[1:])
recover = rm.recover
calls = 0
def interrupt(*args):
    global calls
    calls += 1
    if calls == 2:
        os._exit(29)
    return recover(*args)
rm.recover = interrupt
rm.build(config_root=config, runtime_root=runtime, output_root=output, core=core,
         mode='disable', name='US B', offline=True)
"""
    process = subprocess.run([sys.executable, "-c", code, str(config), str(runtime), str(output), str(CORES[0])],
                             cwd=ROOT, capture_output=True, timeout=120)
    assert process.returncode == 29, process.stderr.decode(errors="replace")
    committed_pointer = (runtime / "active-release.json").read_bytes()
    assert committed_pointer != old_pointer
    source = config / "local/a.json"
    original = source.read_bytes()
    source.unlink()
    for _ in range(2):
        result = invoke("recover")
        assert result.returncode != 0
        assert "input changed externally" in result.stdout + result.stderr
        assert not source.exists()
        assert (runtime / "projection-journal.json").exists()
        assert (runtime / "active-release.json").read_bytes() == committed_pointer
        assert (config / "local/subscriptions.yaml").read_bytes() == old_manifest
        assert (output / "desktop/config.json").read_bytes() == old_export
    source.write_bytes(original)
    require_ok(invoke("recover"))
    require_ok(invoke("check"))

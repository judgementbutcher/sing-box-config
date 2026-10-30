import base64
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from parsers.vmess import parse_uri
from singbox_config.generator import load_sources
from singbox_config.manifest import read_manifest, validate_manifest
from singbox_config.publisher import PublisherHandler, main as publisher_main
from singbox_config.errors import OperationError, safe_error_message

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("error", [
    OperationError("Cannot use https://user'MARKER@private.example.invalid/path?token=MARKER"),
    RuntimeError("MARKER private.example.invalid"),
    TypeError("MARKER private.example.invalid"),
    KeyError("MARKER private.example.invalid"),
    OSError("MARKER private.example.invalid"),
    subprocess.TimeoutExpired(["core", "MARKER", "private.example.invalid"], 1),
])
def test_safe_errors_hide_unexpected_values_and_complete_uri_userinfo(error):
    message = safe_error_message(error)
    assert "MARKER" not in message
    assert "private.example.invalid" not in message


@pytest.mark.parametrize("tls,enabled", [("tls", True), ("TLS", True), (True, True), ("none", False), ("", False), (False, False)])
def test_vmess_tls_enum(tls, enabled):
    payload = {"add": "node.example.com", "port": 443, "id": "00000000-0000-4000-8000-000000000000", "tls": tls}
    uri = "vmess" + "://" + base64.b64encode(json.dumps(payload).encode()).decode()
    node = parse_uri(uri)
    assert node.get("tls", {}).get("enabled", False) == enabled


@pytest.mark.parametrize("path,address,allowed", [
    ("/desktop/config.json", "127.0.0.1", True),
    ("/desktop/config.json", "127.0.0.2", True),
    ("/desktop/config.json", "::1", True),
    ("/desktop/config.json", "192.0.2.1", False),
    ("/android/config.json", "127.0.0.1", False),
    ("/desktop/config.json", "invalid", False),
])
def test_desktop_exemption_is_only_loopback(path, address, allowed):
    assert PublisherHandler.desktop_loopback_exemption(path, address) is allowed


def test_rotation_refuses_running_service_without_changing_credentials(tmp_path, monkeypatch):
    path = tmp_path / "credentials.json"
    path.write_text('{"username":"sfa","password":"original"}')
    old = path.read_bytes()
    monkeypatch.setattr("singbox_config.publisher.publisher_running", lambda *_a: True)
    assert publisher_main(["--credentials", str(path), "--rotate-credentials"]) == 1
    assert path.read_bytes() == old


def test_rotation_cannot_bypass_running_server_lock_with_another_port(tmp_path, monkeypatch):
    from singbox_config.release_manager import FileLock
    path = tmp_path / "credentials.json"
    path.write_text('{"username":"sfa","password":"original"}')
    old = path.read_bytes()
    monkeypatch.setattr("singbox_config.publisher.publisher_running", lambda *_a: False)
    with FileLock(path.with_suffix(".lock")):
        assert publisher_main(["--credentials", str(path), "--port", "1", "--rotate-credentials"]) == 1
    assert path.read_bytes() == old


@pytest.mark.parametrize("item", [
    {"name": "AI", "path": "a"}, {"name": "Off", "path": "../a", "enabled": False},
    {"name": "Off", "path": "a", "enabled": "false"}, {"name": "Off", "path": "a", "exclude": "x"},
])
def test_manifest_rejects_reserved_and_bad_disabled_sources(tmp_path, item):
    with pytest.raises(ValueError):
        validate_manifest({"subscriptions": [item]}, {}, tmp_path)


def test_manifest_accepts_yaml_merges_but_rejects_duplicate_explicit_fields(tmp_path):
    path = tmp_path / "subscriptions.yaml"
    path.write_text('subscriptions:\n - &base {name: A, path: a}\n - <<: *base\n   name: B\n', encoding="utf-8")
    assert [e["name"] for e in read_manifest(path, {})["subscriptions"]] == ["A", "B"]
    path.write_text('subscriptions:\n - name: A\n   path: a\n   path: b\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate YAML"):
        read_manifest(path, {})


def test_renamed_node_detour_is_rewritten_in_its_source(tmp_path):
    def node(tag, server, **extra):
        return {"type": "vless", "tag": tag, "server": server, "server_port": 443,
                "uuid": "00000000-0000-4000-8000-000000000000", **extra}
    (tmp_path / "a.json").write_text(json.dumps({"outbounds": [node("US front", "a.example"), node("US spare", "s.example")]}))
    (tmp_path / "b.json").write_text(json.dumps({"outbounds": [node("US front", "b.example"), node("US end", "c.example", detour="US front")]}))
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(json.dumps({"subscriptions": [{"name": "A", "path": "a.json"}, {"name": "B", "path": "b.json"}]}))
    sources = load_sources(manifest, {"groups": {"ai_regions": ["US"]}})
    assert sources[1].nodes[0]["tag"] == "US front [B]"
    assert sources[1].nodes[1]["detour"] == "US front [B]"


@pytest.mark.parametrize("state", ["untracked", "staged", "tracked"])
def test_scanner_forbids_provider_output_even_when_content_has_no_url(tmp_path, state):
    spec = importlib.util.spec_from_file_location("scanner", ROOT / "scripts" / "quality" / "check_public_repo.py")
    scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner)
    scanner.ROOT = tmp_path
    assert scanner.forbidden_path("Dist-Provider/desktop/config.json")
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)
    git("init")
    output = tmp_path / "dist-provider" / "desktop" / "config.json"
    output.parent.mkdir(parents=True)
    output.write_text('{"outbounds":[]}')
    if state != "untracked":
        git("add", "dist-provider")
    if state == "tracked":
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture")
    assert scanner.main() == 1


def test_manager_does_not_modify_system_services_or_firewall():
    script = (ROOT / "scripts" / "manage" / "manage.ps1").read_text(encoding="utf-8-sig")
    assert "Stop-Service" not in script
    assert "New-NetFirewallRule" not in script
    assert "excludedportrange" not in script

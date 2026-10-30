"""Management inspection must never mutate, repair, start a core, or fetch inputs."""
import json
import ipaddress
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
import requests

from singbox_config import generator, management as mg, release_manager as rm


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def tree(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    config, runtime, output = (tmp_path / name for name in ("config", "runtime", "dist"))
    policy = {"subscription": {"cache_max_age": "3d"}, "groups": {"services": [
        {"tag": "Business", "filter": "trusted", "candidates": [{"source": "Home", "names": ["Home"]}]}]},
        "config": {"dns": {"servers": [{"tag": "private-dns", "type": "fakeip"}],
                            "rules": [{"domain_suffix": ["service.invalid"], "server": "private-dns"}],
                            "final": "private-dns"},
                   "route": {"rules": [{"protocol": "stun", "action": "reject"},
                                         {"process_name": "special.exe", "outbound": "Home"},
                                         {"rule_set": "business", "outbound": "Business"}],
                             "final": "direct"}}}
    write(config / "policy.yaml", policy)
    (config / "rule-sets").mkdir()
    (config / "rule-sets/business.txt").write_text("service.invalid\n", encoding="utf-8")
    write(config / "local/subscriptions.yaml", {"subscriptions": [
        {"name": "Home", "path": "home.txt", "user_agent": "test-agent"},
        {"name": "Disabled", "path": "disabled.txt", "enabled": False}]})
    (config / "local/home.txt").write_text("https://private.invalid/token-SENSITIVE", encoding="utf-8")
    (config / "local/disabled.txt").write_text("not downloaded", encoding="utf-8")
    core = tmp_path / "core.exe"
    core.write_bytes(b"synthetic core, never execute")
    release = runtime / "releases/test-release"
    release.mkdir(parents=True)
    shutil.copytree(config, release / "inputs/config")
    (release / "subscription-cache").mkdir()
    cache = generator.subscription_cache_path("https://private.invalid/token-SENSITIVE", "test-agent",
                                               cache_dir=release / "subscription-cache")
    cache.write_text("SECRET-cache-content", encoding="utf-8")
    identity = {"validator": rm.CORE_VERSION, "core_sha256": rm.sha256_file(core)}
    for platform in rm.PLATFORMS:
        data = json.loads(json.dumps(policy["config"]))
        data["route"]["rule_set"] = [{"type": "inline", "tag": "business", "rules": [{"domain_suffix": ["service.invalid"]}]}]
        data["outbounds"] = [{"type": "vless", "tag": "Home", "server": "SECRET-host.invalid", "password": "SECRET-password"},
                             {"type": "selector", "tag": "Business", "outbounds": ["Home"], "default": "Home"},
                             {"type": "direct", "tag": "direct"}]
        write(release / platform / "config.json", data)
        write(release / platform / "config.validated.json", {"build_id": release.name, **identity,
              "sha256": rm.sha256_file(release / platform / "config.json")})
        shutil.copytree(release / platform, output / platform)
    write(release / "release.json", {"schema_version": 1, "build_id": release.name, **identity,
                                     "platforms": list(rm.PLATFORMS), "created_at": "2026-10-30T00:00:00Z",
                                     "origin": "build"})
    write(release / "manifest.json", rm._files(release))
    write(runtime / rm.POINTER_NAME, {"schema_version": 1, "build_id": release.name, "release": "releases/test-release"})
    assert rm.validate_release(release)

    def forbidden(*_args, **_kwargs):
        pytest.fail("read-only inspection attempted a mutation, subprocess or network operation")

    for name in ("verify", "recover", "_write_json", "_write_bytes", "_run_core", "core_identity"):
        monkeypatch.setattr(rm, name, forbidden)
    monkeypatch.setattr(generator, "load_sources", forbidden)
    monkeypatch.setattr(generator, "download", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    return dict(config_root=config, runtime_root=runtime, output_root=output, core=core)


def test_every_command_preserves_files_and_omits_credentials(workspace, tmp_path):
    write(workspace["runtime_root"] / rm.JOURNAL_NAME, {"secret": "SECRET-journal"})
    before = tree(tmp_path)
    results = [mg.status(**workspace), mg.sources(**workspace), mg.history(**workspace),
               mg.explain(**workspace, domain="service.invalid"), mg.lint(**workspace)]
    assert tree(tmp_path) == before
    text = json.dumps(results)
    assert "SECRET" not in text and "SENSITIVE" not in text and "private.invalid" not in text
    assert results[0]["pending_recovery"] is True
    assert results[0]["core"]["state"] == "matches_active"
    assert results[0]["publisher"]["state"] == "unknown"
    assert results[0]["exports"]["state"] == "synced"


def test_status_distinguishes_working_edits_stale_exports_and_missing_core(workspace):
    assert mg.status(**workspace)["working_config"]["state"] == "same"
    (workspace["config_root"] / "rule-sets/business.txt").write_text("changed.invalid\n", encoding="utf-8")
    (workspace["output_root"] / "desktop/config.json").write_text("stale", encoding="utf-8")
    result = mg.status(**{**workspace, "core": workspace["core"].with_name("missing.exe")})
    assert result["working_config"]["state"] == "changed"
    assert result["exports"]["state"] == "stale"
    assert result["core"]["state"] == "missing"
    (workspace["output_root"] / "android/config.json").unlink()
    assert mg.status(**workspace)["exports"]["state"] == "missing"


def test_sources_counts_are_explicitly_active_snapshot_and_cache_is_ua_scoped(workspace):
    result = mg.sources(**workspace)
    home, disabled = result["items"]
    assert home["node_count"] == 1 and home["node_count_basis"] == "active_snapshot"
    assert home["required_by"] == ["Business"] and home["cache_status"] == "fresh"
    assert disabled["node_count"] is None and disabled["enabled"] is False
    manifest = workspace["config_root"] / "local/subscriptions.yaml"
    data = json.loads(manifest.read_text())
    data["subscriptions"][0]["user_agent"] = "new-agent"
    write(manifest, data)
    assert mg.sources(**workspace)["items"][0]["cache_status"] == "missing"


def test_history_reports_invalid_candidates_without_repair(workspace):
    incomplete = workspace["runtime_root"] / "releases/incomplete"
    incomplete.mkdir()
    result = mg.history(**workspace)
    assert {row["build_id"]: row["valid"] for row in result["items"]} == {"test-release": True, "incomplete": False}
    assert next(row for row in result["items"] if row["active"])["build_id"] == "test-release"


def test_explain_does_not_discard_unknown_earlier_rules_or_claim_actual_selection(workspace):
    result = mg.explain(**workspace, domain="service.invalid")
    assert result["basis"] == "validated_active_release"
    assert result["route"]["certainty"] == "conditional"
    assert result["route"]["candidates"][0]["match"] == "unknown"
    assert result["route"]["candidate"]["outbound"] == "Business"
    assert result["dns"]["A"]["certainty"] == "determinate"
    assert result["groups"][0]["default"] == "Home"
    assert result["groups"][0]["actual_selection"] == "unknown"
    known = mg.explain(**workspace, domain="service.invalid", protocol="tls", process_name="other.exe")
    assert known["route"]["certainty"] == "determinate"


def test_missing_active_uses_only_local_rules_and_never_downloads(workspace):
    (workspace["runtime_root"] / rm.POINTER_NAME).unlink()
    policy_path = workspace["config_root"] / "policy.yaml"
    policy = json.loads(policy_path.read_text())
    policy["rule_set_urls"] = {"geosite": "https://remote.invalid/SECRET/{tag}.srs"}
    policy["config"]["route"]["rules"].insert(0, {"rule_set": "geosite-unknown", "outbound": "direct"})
    write(policy_path, policy)
    result = mg.explain(**workspace, domain="service.invalid", protocol="tls", process_name="other.exe")
    assert result["basis"] == "working_policy_local_rules_only"
    assert result["route"]["certainty"] == "conditional"
    assert result["route"]["candidates"][0]["match"] == "unknown"
    assert "SECRET" not in json.dumps(result)


def test_lint_required_sources_and_intentional_overlaps(workspace):
    manifest = workspace["config_root"] / "local/subscriptions.yaml"
    data = json.loads(manifest.read_text())
    data["subscriptions"][0]["enabled"] = False
    write(manifest, data)
    (workspace["config_root"] / "rule-sets/second.txt").write_text("service.invalid\nservice.invalid\n", encoding="utf-8")
    result = mg.lint(**workspace)
    assert any(item["code"] == "required_source_unavailable" and item["severity"] == "error" for item in result["issues"])
    assert any(item["code"] == "duplicate_suffix" for item in result["issues"])
    assert all(item["severity"] == "info" for item in result["issues"] if item["code"] == "cross_list_overlap")


def test_cli_error_is_structured_and_does_not_leak_raw_yaml(workspace, capsys):
    (workspace["config_root"] / "policy.yaml").write_text("SECRET-password: [", encoding="utf-8")
    code = mg.main(["lint", "--json", "--config-root", str(workspace["config_root"]),
                    "--runtime-root", str(workspace["runtime_root"]), "--output-root", str(workspace["output_root"])])
    text = capsys.readouterr().out
    assert code == 1 and "SECRET" not in text
    assert json.loads(text)["command"] == "lint"


def test_match_logic_unknown_is_not_false():
    domain = {"domain": "a.example.invalid"}
    assert mg._match({"domain_suffix": ["example.invalid"], "process_name": "x.exe"}, domain, {}) is None
    assert mg._match({"domain_suffix": ["other.invalid"], "process_name": "x.exe"}, domain, {}) is False
    assert mg._match({"type": "logical", "mode": "or", "rules": [
        {"domain_suffix": ["example.invalid"]}, {"process_name": "x.exe"}]}, domain, {}) is True
    assert mg._match({"rule_set": "missing"}, domain, {}) is None
    assert mg._match({"domain_regex": ["(a+)+$"]}, domain, {}) is None
    assert mg._match({"domain_suffix": ["example.invalid"], "ip_cidr": ["192.0.2.0/24"]}, domain, {}) is None
    assert mg._match({"domain_future_predicate": ["example.invalid"]}, domain, {}) is None


@pytest.mark.parametrize("query,number", [("A", 1), ("AAAA", 28), ("HTTPS", 65), ("SVCB", 64)])
def test_numeric_dns_query_types_match_symbolic_context(query, number):
    assert mg._match({"query_type": [number]}, {"query_type": query}, {}) is True
    assert mg._match({"query_type": [query.lower()]}, {"query_type": number}, {}) is True
    assert mg._match({"query_type": [number]}, {"query_type": "NS"}, {}) is False
    assert mg._match({"query_type": ["unsupported-type"]}, {"query_type": query}, {}) is None


@pytest.mark.parametrize("domain", ["example.com", "child.example.com", "unrelated.invalid"])
def test_leading_dot_suffixes_remain_unknown_without_core_semantic_verification(domain):
    assert mg._match({"domain_suffix": [".example.com"]}, {"domain": domain}, {}) is None


def test_response_rule_cannot_be_disproved_by_connection_destination_ip():
    sets = {"geoip-cn": {"type": "inline", "rules": [{"ip_cidr": ["1.0.1.0/24"]}]}}
    rule = {"match_response": True, "rule_set": "geoip-cn", "server": "domestic"}
    for address in ("8.8.8.8", "1.0.1.1"):
        assert mg._match(rule, {"domain": "unlisted.invalid", "ip": ipaddress.ip_address(address)}, sets) is None


def test_explain_does_not_use_route_ip_or_transport_for_dns(workspace):
    (workspace["runtime_root"] / rm.POINTER_NAME).unlink()
    policy_path = workspace["config_root"] / "policy.yaml"
    policy = json.loads(policy_path.read_text())
    policy["config"]["dns"]["rules"] = [
        {"query_type": [1], "ip_cidr": ["1.0.1.0/24"], "server": "domestic"},
        {"port": 53, "server": "dns-transport"},
        {"server": "private-dns"}]
    policy["config"]["route"]["rules"] = [{"ip_cidr": ["8.8.8.0/24"], "outbound": "Home"}]
    write(policy_path, policy)
    result = mg.explain(**workspace, domain="unlisted.invalid", ip="8.8.8.8", port=443, network="tcp")
    assert result["route"]["certainty"] == "determinate"
    assert result["route"]["candidate"]["outbound"] == "Home"
    assert result["dns"]["A"]["certainty"] == "conditional"
    assert [(item["server"], item["match"]) for item in result["dns"]["A"]["candidates"]] == [
        ("domestic", "unknown"), ("dns-transport", "unknown"), ("private-dns", "true")]


def test_dns_response_evaluation_remains_conditional():
    section = {"rules": [{"action": "evaluate", "server": "proxy"},
                          {"match_response": True, "ip_cidr": ["192.0.2.0/24"], "server": "domestic"},
                          {"action": "respond"}]}
    result = mg._explain_rules(section, {"domain": "unlisted.invalid"}, {})
    assert result["certainty"] == "conditional"
    assert result["requires_runtime_evaluation"] is True
    assert result["candidate"]["action"] == "respond"


def test_invalid_active_release_is_not_used_for_explanation(workspace):
    path = workspace["runtime_root"] / "releases/test-release/desktop/config.json"
    path.write_text("SECRET-corrupted", encoding="utf-8")
    result = mg.explain(**workspace, domain="service.invalid")
    assert result["basis"] == "working_policy_local_rules_only"
    assert any("Invalid active" in warning for warning in result["warnings"])
    assert "SECRET" not in json.dumps(result)
    assert mg.status(**workspace)["active"]["state"] == "invalid"


def test_no_active_release_does_not_create_runtime_directory(tmp_path):
    roots = dict(config_root=tmp_path / "config", runtime_root=tmp_path / "runtime", output_root=tmp_path / "dist")
    result = mg.status(**roots)
    assert result["active"]["state"] == "missing"
    assert result["working_config"]["state"] == "unknown"
    assert not list(tmp_path.iterdir())

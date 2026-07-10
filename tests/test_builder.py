import json
from pathlib import Path

from build_singbox import build_config_from_subscriptions
from singbox_config.audit import audit_config


def write_subscription(path: Path, nodes):
    path.write_text(json.dumps({"outbounds": nodes}, ensure_ascii=False), encoding="utf-8")


def make_node(tag, server, *, insecure=False):
    node = {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": 443,
        "uuid": f"00000000-0000-0000-0000-{server.split('.')[0]:0>12}",
        "tls": {"enabled": True, "server_name": server},
    }
    if insecure:
        node["tls"]["insecure"] = True
    return node


def test_builder_deduplicates_limits_and_creates_disjoint_pools(tmp_path):
    primary_path = tmp_path / "primary.json"
    backup_path = tmp_path / "backup.json"
    primary_nodes = [
        make_node("HK 1", "1.example"),
        make_node("JP 1", "2.example"),
        make_node("US 1", "3.example"),
        make_node("SG 1", "4.example"),
        make_node("TW 1", "5.example"),
        make_node("GB 1", "6.example"),
    ]
    backup_nodes = [
        make_node("HK duplicate", "1.example"),
        make_node("US backup", "7.example"),
        make_node("JP insecure", "8.example", insecure=True),
    ]
    write_subscription(primary_path, primary_nodes)
    write_subscription(backup_path, backup_nodes)
    subscriptions = [
        {
            "name": "primary",
            "parser": "singbox-json",
            "source": "file",
            "path": str(primary_path),
            "priority": 10,
            "role": "primary",
            "flat_group": True,
            "include_in_available": True,
        },
        {
            "name": "backup",
            "parser": "singbox-json",
            "source": "file",
            "path": str(backup_path),
            "priority": 20,
            "role": "backup",
            "flat_group": True,
            "include_in_available": True,
        },
    ]
    template = {
        "log": {"disabled": True},
        "dns": {"servers": [{"type": "https", "tag": "remote", "detour": "DNS-Out"}]},
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.18.0.1/30"]}],
        "route": {
            "rules": [{"domain_suffix": ["private.example"], "action": "route", "outbound": "Private-Primary"}],
            "rule_set": [],
            "final": "Available",
        },
        "experimental": {"cache_file": {"enabled": True, "path": "cache.db"}},
    }
    profile = {
        "name": "test",
        "platform": "android",
        "runtime": {
            "disable_provider_urltests": True,
            "role_limits": {
                "primary": {"max_nodes_per_region": 2, "max_other_nodes": 2, "max_total_nodes": 6},
                "backup": {"max_nodes_per_region": 1, "max_other_nodes": 1, "max_total_nodes": 3},
            },
        },
        "auto": {
            "enabled": True,
            "available_max": 2,
            "ai_max": 2,
            "include_roles": ["primary"],
            "fallback_roles": ["backup"],
            "exclude_insecure": True,
            "available_regions": ["HK", "JP", "SG", "TW"],
            "ai_regions": ["US"],
            "interval": "30m",
            "idle_timeout": "30m",
        },
        "control": {
            "max_nodes": 2,
            "include_roles": ["primary"],
            "exclude_insecure": True,
        },
    }
    metadata = {}
    conf = build_config_from_subscriptions(
        subscriptions,
        template,
        tmp_path,
        available_urltest=True,
        profile=profile,
        generation_metadata=metadata,
        cache_dir=None,
        policy_aliases={"Private-Primary": "primary"},
    )
    report = audit_config(conf, {"max_nodes": 9, "max_urltest_members": 6})
    assert report["ok"] is True
    assert metadata["deduplicated_nodes"] == 1
    assert report["counts"]["duplicate_node_entries"] == 0
    assert report["counts"]["urltest_members"] == report["counts"]["urltest_unique_members"]
    assert not report["singleton_urltests"]
    aliases = [outbound for outbound in conf["outbounds"] if outbound.get("tag") == "Private-Primary"]
    assert aliases and aliases[0]["outbounds"] == ["primary"]

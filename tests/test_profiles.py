from singbox_config.profiles import apply_profile_to_template


def template():
    return {
        "log": {"disabled": False, "level": "warn", "timestamp": True},
        "dns": {
            "servers": [{"type": "https", "tag": "remote", "detour": "Available"}],
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "route_address": ["0.0.0.0/1"],
                "route_exclude_address": ["10.0.0.0/8"],
                "stack": "mixed",
            },
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
        ],
        "route": {
            "final": "Available",
            "rule_set": [{"tag": "cn", "type": "remote", "url": "https://example/cn.srs"}],
            "rules": [],
        },
        "experimental": {
            "clash_api": {"external_controller": "127.0.0.1:9090", "external_ui": "dashboard"},
            "cache_file": {"enabled": True, "path": "cache.db"},
        },
    }


def test_android_profile_removes_desktop_only_features_and_uses_113_download_detour():
    profile = {
        "name": "android-test",
        "platform": "android",
        "core": {"version": "1.13.14"},
        "control": {"dns_detour": "DNS-Out", "update_detour": "Update-Out"},
        "tuning": {
            "dns_strategy": "prefer_ipv4",
            "dns_cache_capacity": 4096,
            "tun_stack": "system",
            "tun_mtu": 1420,
            "udp_timeout": "2m",
            "rule_set_update_interval": "7d",
            "cache_path": "cache.android.db",
        },
        "clash_api": {"enabled": False},
    }
    conf = apply_profile_to_template(template(), profile)
    assert len(conf["inbounds"]) == 1
    assert "route_address" not in conf["inbounds"][0]
    assert conf["dns"]["servers"][0]["detour"] == "DNS-Out"
    assert conf["route"]["rule_set"][0]["download_detour"] == "Update-Out"
    assert "http_clients" not in conf
    assert "clash_api" not in conf["experimental"]


def test_114_profile_uses_http_client_and_secret():
    profile = {
        "name": "desktop-test",
        "platform": "windows",
        "core": {"version": "1.14.0-alpha.41"},
        "control": {"dns_detour": "DNS-Out", "update_detour": "Update-Out"},
        "tuning": {},
        "clash_api": {"enabled": True, "external_ui": True},
    }
    conf = apply_profile_to_template(template(), profile, clash_secret="secret-value")
    assert conf["http_clients"][0]["detour"] == "Update-Out"
    assert conf["route"]["default_http_client"] == "rule-set-downloader"
    assert conf["route"]["rule_set"][0]["http_client"] == "rule-set-downloader"
    assert conf["experimental"]["clash_api"]["secret"] == "secret-value"


def test_profile_removes_tun_ipv6_address():
    base = template()
    base["inbounds"][0]["address"] = ["172.18.0.1/30", "fdfe:dcba:9876::1/126"]
    profile = {
        "name": "desktop-test",
        "platform": "windows",
        "core": {"version": "1.14.0-alpha.41"},
        "control": {},
        "tuning": {},
        "clash_api": {"enabled": False},
    }
    conf = apply_profile_to_template(base, profile)
    assert conf["inbounds"][0]["address"] == ["172.18.0.1/30"]


def test_android_profile_applies_per_app_exclusions(tmp_path):
    app_file = tmp_path / "android_apps.yaml"
    app_file.write_text("mode: exclude\npackages:\n  - com.example.local\n", encoding="utf-8")
    profile = {
        "name": "android-apps",
        "platform": "android",
        "_base_dir": str(tmp_path),
        "core": {"version": "1.13.14"},
        "control": {},
        "tuning": {},
        "clash_api": {"enabled": False},
        "android_apps": {"file": "android_apps.yaml"},
    }
    conf = apply_profile_to_template(template(), profile)
    assert conf["inbounds"][0]["exclude_package"] == ["com.example.local"]


def test_force_direct_profile_replaces_policy_routes():
    base = template()
    base["route"]["rules"] = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"domain_suffix": ["example.com"], "action": "route", "outbound": "Available"},
    ]
    base["dns"]["rules"] = [{"domain_suffix": ["example.com"], "action": "route", "server": "remote"}]
    profile = {
        "name": "direct",
        "platform": "android",
        "core": {"version": "1.13.14"},
        "control": {},
        "tuning": {
            "force_direct": True,
            "force_local_dns": True,
            "dns_final": "local",
        },
        "clash_api": {"enabled": False},
    }
    conf = apply_profile_to_template(base, profile)
    assert conf["route"]["rules"][-1] == {"action": "route", "outbound": "direct"}
    assert conf["dns"]["rules"] == []
    assert conf["dns"]["final"] == "local"

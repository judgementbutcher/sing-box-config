from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from singbox_config import simple_generator as simple


ROOT = Path(__file__).resolve().parents[1]

LOCAL_READY = (ROOT / "config" / "local" / "subscriptions.yaml").exists() and (
    ROOT / "config" / "local" / "custom-rules.yaml"
).exists()
requires_local = pytest.mark.skipif(
    not LOCAL_READY,
    reason="config/local 本机订阅与规则不存在（CI 环境）",
)


def test_single_ai_does_not_escape_ai_policy_boundary():
    source = simple.BuiltSource(
        name="single-us",
        order=10,
        entry_tag="US-One",
        node_tags=["US-One"],
        nodes=[],
        groups=[],
        ai_node_tags=["US-One"],
    )
    profile = simple.load_yaml(ROOT / "config" / "profiles" / "desktop.yaml")

    outbounds = simple.build_outbounds(
        [source],
        {"selectors": {"available": "Available", "ai": "AI"}},
        profile,
    )

    ai = next(outbound for outbound in outbounds if outbound.get("tag") == "AI")
    assert ai["outbounds"] == ["US-One"]
    assert ai["default"] == "US-One"


def test_managed_group_adds_selector_and_domain_route():
    source = simple.BuiltSource(
        name="provider",
        order=10,
        entry_tag="Provider",
        node_tags=["Provider"],
        nodes=[{"type": "direct", "tag": "Provider"}],
        groups=[],
        ai_node_tags=["Provider"],
    )
    policy = {"selectors": {"available": "Available", "ai": "AI", "direct": "direct", "emby": "Emby"}}
    profile = {"platform": "desktop"}
    managed = {
        "schema_version": 1,
        "groups": [{"tag": "xxx", "outbounds": ["Provider", "direct"], "domains": ["xxx.com"]}],
    }

    conf = simple.build_config("desktop", policy, profile, {"schema_version": 1}, [source], managed)

    group = next(outbound for outbound in conf["outbounds"] if outbound.get("tag") == "xxx")
    assert group["type"] == "selector"
    assert group["outbounds"] == ["Provider", "direct"]
    assert group["default"] == "Provider"
    assert {
        "domain_suffix": ["xxx.com"],
        "action": "route",
        "outbound": "xxx",
    } in conf["route"]["rules"]


def test_managed_group_rejects_unknown_outbound():
    source = simple.BuiltSource(
        name="provider",
        order=10,
        entry_tag="Provider",
        node_tags=["Provider"],
        nodes=[],
        groups=[],
        ai_node_tags=["Provider"],
    )

    with pytest.raises(ValueError, match="不存在的出站"):
        simple.build_outbounds(
            [source],
            {"selectors": {"available": "Available", "ai": "AI", "direct": "direct", "emby": "Emby"}},
            {},
            {"groups": [{"tag": "xxx", "outbounds": ["Missing"]}]},
        )


def test_routing_rule_can_target_policy_owned_selector_without_recreating_it():
    source = simple.BuiltSource(
        name="provider",
        order=10,
        entry_tag="Provider",
        node_tags=["Provider"],
        nodes=[{"type": "direct", "tag": "Provider"}],
        groups=[],
        ai_node_tags=["Provider"],
    )
    policy = {"selectors": {"available": "Available", "ai": "AI", "direct": "direct", "emby": "Emby"}}
    managed = {
        "schema_version": 1,
        "groups": [{"tag": "AI", "outbounds": [], "domains": ["example.com"]}],
    }

    conf = simple.build_config("desktop", policy, {"platform": "desktop"}, {"schema_version": 1}, [source], managed)

    assert [item["tag"] for item in conf["outbounds"]].count("AI") == 1
    assert {"domain_suffix": ["example.com"], "action": "route", "outbound": "AI"} in conf["route"]["rules"]


@requires_local
def test_current_sources_generate_small_valid_profiles(monkeypatch, tmp_path):
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    sources = simple.load_sources(
        ROOT / "config" / "local" / "subscriptions.yaml",
        policy,
        offline=False,
        fetch_proxy=None,
    )
    monkeypatch.setattr(
        simple,
        "node_route_exclusions",
        lambda _nodes: ["23.146.4.24/32", "156.239.11.161/32"],
    )
    custom = simple.load_yaml(ROOT / "config" / "local" / "custom-rules.yaml")

    desktop = simple.build_config(
        "desktop",
        policy,
        simple.load_yaml(ROOT / "config" / "profiles" / "desktop.yaml"),
        custom,
        sources,
    )
    android = simple.build_config(
        "android",
        policy,
        simple.load_yaml(ROOT / "config" / "profiles" / "android.yaml"),
        custom,
        sources,
    )

    assert [item["tag"] for item in desktop["outbounds"][:4]] == [
        "Available",
        "AI",
        "direct",
        "Emby",
    ]
    assert "clash_api" not in desktop["experimental"]
    assert "services" not in desktop
    assert len([item for item in desktop["outbounds"] if item.get("type") == "vless"]) >= 4
    assert len(desktop["route"]["rules"]) == 20
    assert {
        "domain_suffix": ["emby.bbqwq.com", "emby.wawajiao.cc.cd", "emby.kingemby.com"],
        "action": "route",
        "outbound": "direct",
    } in desktop["route"]["rules"]
    assert {
        "domain_suffix": ["emby.bbqwq.com", "emby.wawajiao.cc.cd"],
        "action": "route",
        "server": "google",
    } in desktop["dns"]["rules"]
    assert desktop["inbounds"][0]["strict_route"] is True
    assert desktop["inbounds"][0]["route_exclude_address_set"] == ["geoip-cn"]
    assert not any("bind_interface" in outbound for outbound in desktop["outbounds"])
    assert desktop["experimental"]["cache_file"]["path"] == "cache.db"
    assert not any("initial_path" in item for item in desktop["route"]["rule_set"])
    china_rule_set = next(item for item in desktop["route"]["rule_set"] if item.get("tag") == "china-direct")
    assert china_rule_set["tag"] == "china-direct"
    assert china_rule_set["type"] == "inline"
    assert china_rule_set["rules"]
    assert "path" not in china_rule_set
    assert "format" not in china_rule_set
    assert len(android["route"]["rules"]) == 20
    assert any(rule.get("rule_set") == ["geosite-telegram"] and rule.get("outbound") == "Available" for rule in desktop["route"]["rules"])
    assert any(rule.get("rule_set") == ["geosite-telegram"] and rule.get("server") == "google" for rule in desktop["dns"]["rules"])
    assert not any(outbound.get("type") == "urltest" or "/Auto" in str(outbound.get("tag") or "") for outbound in [*desktop["outbounds"], *android["outbounds"]])
    assert not any("clash_mode" in rule for conf in (desktop, android) for rule in conf["route"]["rules"])
    assert "services" not in android


def test_shared_local_rule_sets_are_embedded_for_remote_profiles():
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    desktop_profile = simple.load_yaml(ROOT / "config" / "profiles" / "desktop.yaml")
    android_profile = simple.load_yaml(ROOT / "config" / "profiles" / "android.yaml")

    desktop = {
        item["tag"]: item
        for item in simple.build_rule_sets(policy, desktop_profile, {})
        if isinstance(item["tag"], str)
    }
    android = {
        item["tag"]: item
        for item in simple.build_rule_sets(policy, android_profile, {})
        if isinstance(item["tag"], str)
    }

    for tag in ("china-direct", "ai-domains", "emby-domains", "direct-cdn"):
        for rule_set in (desktop[tag], android[tag]):
            assert rule_set["type"] == "inline"
            assert rule_set["rules"]
            assert "path" not in rule_set
            assert "format" not in rule_set


def test_manifest_rejects_legacy_fields(tmp_path):
    manifest = tmp_path / "subscriptions.yaml"
    source = tmp_path / "node.txt"
    source.write_text(
        "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls#US-One",
        encoding="utf-8",
    )
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: old
    format: uri
    source: file
    path: node.txt
    priority: 10
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="不支持的旧订阅字段: priority"):
        simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)


def test_subscription_user_agent_is_forwarded(monkeypatch, tmp_path):
    url_file = tmp_path / "provider.txt"
    url_file.write_text("https://example.com/subscription", encoding="utf-8")
    calls = []

    monkeypatch.setattr(simple, "read_cache", lambda _url, _max_age: None)
    monkeypatch.setattr(simple, "write_cache", lambda _url, _text: None)

    def fake_download(url, timeout, proxy=None, user_agent=None):
        calls.append((url, timeout, proxy, user_agent))
        return "subscription-body"

    monkeypatch.setattr(simple, "download_text", fake_download)
    item = {
        "name": "provider",
        "source": "url_file",
        "path": url_file.name,
        "user_agent": "sing-box",
    }

    assert simple.load_subscription_text(item, tmp_path, {"subscription": {}}) == "subscription-body"
    assert calls == [("https://example.com/subscription", 20, None, "sing-box")]


def test_provider_group_and_urltest_are_explicit(tmp_path):
    source = tmp_path / "provider.txt"
    source.write_text(
        "\n".join(
            [
                "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls&sni=one.example#US-One",
                "vless" + "://22222222-2222-2222-2222-222222222222@two.example:443?security=tls&sni=two.example#HK-Two",
            ]
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: provider
    format: uri
    source: file
    path: provider.txt
    group: Provider
    urltest: true
""",
        encoding="utf-8",
    )
    sources = simple.load_sources(
        manifest,
        {
            "subscription": {},
            "urltest": {"url": "https://example.com/204", "interval": "10m", "tolerance": 80},
        },
        offline=False,
        fetch_proxy=None,
    )
    assert sources[0].entry_tag == "Provider"
    assert sources[0].node_tags == ["Provider/US-One", "Provider/HK-Two"]
    # ``urltest: true`` is accepted for manifest compatibility but never
    # creates an implicit ``*/Auto`` group.
    assert [group["tag"] for group in sources[0].groups] == ["Provider"]
    assert all(group["type"] == "selector" for group in sources[0].groups)


def test_placeholder_info_nodes_are_dropped_before_group_default(tmp_path):
    source = tmp_path / "provider.txt"
    source.write_text(
        "\n".join(
            [
                # Airport divider line: loopback server, port 1.
                "ss://" + "YWVzLTEyOC1nY206cGFzcw==" + "@127.0.0.1:1#------HK------",
                "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls&sni=one.example#HK-One",
                "vless" + "://22222222-2222-2222-2222-222222222222@two.example:443?security=tls&sni=two.example#HK-Two",
            ]
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: provider
    format: uri
    source: file
    path: provider.txt
    group: Provider
    prefix_node_tags: false
""",
        encoding="utf-8",
    )

    sources = simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)

    assert sources[0].node_tags == ["HK-One", "HK-Two"]
    assert sources[0].groups[0]["default"] == "HK-One"
    assert all(node["server"] != "127.0.0.1" for node in sources[0].nodes)


def test_placeholder_detection_rules():
    assert simple.is_placeholder_node({"server": "127.0.0.1", "server_port": 443})
    assert simple.is_placeholder_node({"server": "0.0.0.0", "server_port": 443})
    assert simple.is_placeholder_node({"server": "real.example", "server_port": 0})
    assert simple.is_placeholder_node({"server": "localhost", "server_port": 443})
    assert not simple.is_placeholder_node({"server": "real.example", "server_port": 443})
    assert not simple.is_placeholder_node({"server": "192.168.1.10", "server_port": 8443})


def test_provider_can_keep_all_named_nodes_without_urltest(tmp_path):
    source = tmp_path / "provider.txt"
    source.write_text(
        "\n".join(
            [
                "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls&sni=one.example#First",
                "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls&sni=one.example#Second",
            ]
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: provider
    format: uri
    source: file
    path: provider.txt
    group: Provider
    urltest: false
    deduplicate: false
""",
        encoding="utf-8",
    )

    sources = simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)
    conf = simple.build_config(
        "android",
        {"selectors": {"available": "Available", "ai": "AI", "direct": "direct"}},
        {"config": {}},
        {},
        sources,
    )

    assert sources[0].node_tags == ["Provider/First", "Provider/Second"]
    assert [group["tag"] for group in sources[0].groups] == ["Provider"]
    assert next(item for item in conf["outbounds"] if item["tag"] == "Provider")["outbounds"] == [
        "Provider/First",
        "Provider/Second",
    ]


def test_unsupported_uri_requires_explicit_opt_out(tmp_path):
    source = tmp_path / "mixed.txt"
    source.write_text(
        "\n".join(
            [
                "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls#US-One",
                "unknown://value",
            ]
        ),
        encoding="utf-8",
    )
    strict_manifest = tmp_path / "strict.yaml"
    strict_manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: strict
    format: uri
    source: file
    path: mixed.txt
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="未接受的解析问题"):
        simple.load_sources(strict_manifest, {"subscription": {}}, offline=False, fetch_proxy=None)

    allowed_manifest = tmp_path / "allowed.yaml"
    allowed_manifest.write_text(
        strict_manifest.read_text(encoding="utf-8") + "    allow_unsupported: true\n",
        encoding="utf-8",
    )
    sources = simple.load_sources(allowed_manifest, {"subscription": {}}, offline=False, fetch_proxy=None)
    assert sources[0].node_tags == ["US-One"]


def test_insecure_tls_requires_explicit_opt_out(tmp_path):
    source = tmp_path / "insecure.txt"
    source.write_text(
        "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls&allowInsecure=true#US-One",
        encoding="utf-8",
    )
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: insecure
    format: uri
    source: file
    path: insecure.txt
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="关闭了 TLS 证书校验"):
        simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)

    allowed_manifest = tmp_path / "allowed.yaml"
    allowed_manifest.write_text(
        manifest.read_text(encoding="utf-8") + "    allow_insecure: true\n",
        encoding="utf-8",
    )
    sources = simple.load_sources(allowed_manifest, {"subscription": {}}, offline=False, fetch_proxy=None)
    assert sources[0].node_tags == ["US-One"]


@requires_local
def test_custom_rules_are_inserted_between_pre_rules_and_business(monkeypatch):
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    sources = simple.load_sources(
        ROOT / "config" / "local" / "subscriptions.yaml",
        policy,
        offline=False,
        fetch_proxy=None,
    )
    monkeypatch.setattr(simple, "node_route_exclusions", lambda _nodes: ["192.0.2.1/32"])
    custom = {
        "schema_version": 1,
        "route_rules_front": [{"domain": ["front.example"], "action": "reject"}],
        "route_rules": [{"domain": ["normal.example"], "action": "route", "outbound": "Available"}],
        "dns_rules": [],
        "rule_sets": [],
    }
    conf = simple.build_config(
        "desktop",
        policy,
        simple.load_yaml(ROOT / "config" / "profiles" / "desktop.yaml"),
        custom,
        sources,
    )
    rules = conf["route"]["rules"]
    front_index = next(i for i, rule in enumerate(rules) if rule.get("domain") == ["front.example"])
    sniff_index = next(i for i, rule in enumerate(rules) if rule.get("action") == "sniff")
    normal_index = next(i for i, rule in enumerate(rules) if rule.get("domain") == ["normal.example"])
    store_index = next(i for i, rule in enumerate(rules) if rule.get("rule_set") == "microsoft-store")
    assert front_index < sniff_index < normal_index < store_index


@requires_local
def test_generated_json_contains_no_legacy_download_detour(monkeypatch, tmp_path):
    monkeypatch.setattr(simple, "node_route_exclusions", lambda _nodes: ["192.0.2.1/32"])
    simple.generate("all", output_dir=tmp_path)
    for target in ("desktop", "android"):
        config_path = tmp_path / target / "config.json"
        text = config_path.read_text(encoding="utf-8")
        assert "download_detour" not in text
        json.loads(text)
        stamp = json.loads((tmp_path / target / "config.validated.json").read_text(encoding="utf-8"))
        assert stamp["sha256"] == hashlib.sha256(config_path.read_bytes()).hexdigest()
        assert stamp["validator"] == "生成器内置结构校验"


def test_parse_route_matcher_normalizes_and_validates():
    assert simple.parse_route_matcher("example.com") == ("domain_suffix", "example.com")
    assert simple.parse_route_matcher("suffix:example.com") == ("domain_suffix", "example.com")
    assert simple.parse_route_matcher("full:www.example.com") == ("domain", "www.example.com")
    assert simple.parse_route_matcher("domain:exact.example") == ("domain", "exact.example")
    assert simple.parse_route_matcher("keyword:track") == ("domain_keyword", "track")
    assert simple.parse_route_matcher("domain_keyword:track") == ("domain_keyword", "track")
    assert simple.parse_route_matcher("regexp:^ad[0-9]+") == ("domain_regex", "^ad[0-9]+")
    assert simple.parse_route_matcher("ip:1.2.3.4") == ("ip_cidr", "1.2.3.4/32")
    assert simple.parse_route_matcher("ip_cidr:10.0.0.0/8") == ("ip_cidr", "10.0.0.0/8")
    assert simple.parse_route_matcher("ip_cidr:2001:db8::1") == ("ip_cidr", "2001:db8::1/128")
    with pytest.raises(ValueError, match="正则无效"):
        simple.parse_route_matcher("regexp:[")
    with pytest.raises(ValueError, match="IP/CIDR"):
        simple.parse_route_matcher("ip:999.1.1.1")
    with pytest.raises(ValueError, match="缺少匹配内容"):
        simple.parse_route_matcher("keyword:")


def test_managed_typed_matchers_build_typed_route_and_dns_rules():
    source = simple.BuiltSource(
        name="provider",
        order=10,
        entry_tag="Provider",
        node_tags=["Provider"],
        nodes=[{"type": "direct", "tag": "Provider"}],
        groups=[],
        ai_node_tags=["Provider"],
    )
    policy = {
        "selectors": {"available": "Available", "ai": "AI", "direct": "direct", "emby": "Emby"},
        "config": {"dns": {"servers": [{"tag": "local"}, {"tag": "google"}]}},
    }
    managed = {
        "schema_version": 1,
        "groups": [
            {
                "tag": "direct",
                "outbounds": [],
                "domains": [
                    "domain_suffix:deepseek.com",
                    "full:docs.deepseek.com",
                    "keyword:cdn",
                    "regexp:^ad[0-9]+",
                    "ip_cidr:1.2.3.0/24",
                ],
            }
        ],
    }
    conf = simple.build_config("desktop", policy, {"platform": "desktop"}, {"schema_version": 1}, [source], managed)
    rules = conf["route"]["rules"]
    assert {"domain_suffix": ["deepseek.com"], "action": "route", "outbound": "direct"} in rules
    assert {"domain": ["docs.deepseek.com"], "action": "route", "outbound": "direct"} in rules
    assert {"domain_keyword": ["cdn"], "action": "route", "outbound": "direct"} in rules
    assert {"domain_regex": ["^ad[0-9]+"], "action": "route", "outbound": "direct"} in rules
    assert {"ip_cidr": ["1.2.3.0/24"], "action": "route", "outbound": "direct"} in rules
    dns = conf["dns"]["rules"]
    assert {"domain_suffix": ["deepseek.com"], "action": "route", "server": "local"} in dns
    assert {"domain": ["docs.deepseek.com"], "action": "route", "server": "local"} in dns
    assert {"domain_keyword": ["cdn"], "action": "route", "server": "local"} in dns
    assert {"domain_regex": ["^ad[0-9]+"], "action": "route", "server": "local"} in dns
    assert not any("ip_cidr" in rule for rule in dns)
    # A rule-only group on an existing outbound must not recreate the outbound.
    assert [item["tag"] for item in conf["outbounds"]].count("direct") == 1


def test_managed_rule_on_policy_selector_uses_proxy_dns():
    source = simple.BuiltSource(
        name="provider",
        order=10,
        entry_tag="Provider",
        node_tags=["Provider"],
        nodes=[{"type": "direct", "tag": "Provider"}],
        groups=[],
        ai_node_tags=["Provider"],
    )
    policy = {
        "selectors": {"available": "Available", "ai": "AI", "direct": "direct", "emby": "Emby"},
        "config": {"dns": {"servers": [{"tag": "local"}, {"tag": "google"}]}},
    }
    managed = {
        "schema_version": 1,
        "groups": [{"tag": "AI", "outbounds": [], "domains": ["domain_suffix:openai.com"]}],
    }
    conf = simple.build_config("desktop", policy, {"platform": "desktop"}, {"schema_version": 1}, [source], managed)
    assert {"domain_suffix": ["openai.com"], "action": "route", "server": "google"} in conf["dns"]["rules"]


def test_managed_dns_rules_are_skipped_when_no_servers_declared():
    route, dns = simple.build_managed_rules(
        {"groups": [{"tag": "direct", "domains": ["domain_suffix:deepseek.com"]}]},
        "direct",
    )
    assert dns == []
    assert route == [{"domain_suffix": ["deepseek.com"], "action": "route", "outbound": "direct"}]

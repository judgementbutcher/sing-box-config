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


def dns_matcher_covers(rule: dict, field: str, value: str) -> bool:
    """True when ``rule`` (plain or logical OR) matches ``value`` via ``field``."""
    if rule.get("type") == "logical":
        return any(dns_matcher_covers(child, field, value) for child in rule.get("rules", []))
    return value in simple.as_list(rule.get(field))


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

    assert [item["tag"] for item in desktop["outbounds"][:5]] == [
        "Available",
        "AI",
        "direct",
        "Emby",
        "YouTube",
    ]
    selector_by_tag = {item["tag"]: item for item in desktop["outbounds"] if item.get("type") == "selector"}
    # The YouTube group mirrors Available's entries and follows Available by
    # default, so it only changes behaviour once a node is pinned in the panel.
    assert selector_by_tag["YouTube"]["outbounds"] == [
        "Available",
        *selector_by_tag["Available"]["outbounds"],
    ]
    assert selector_by_tag["YouTube"]["default"] == "Available"
    assert "clash_api" not in desktop["experimental"]
    assert "services" not in desktop
    assert len([item for item in desktop["outbounds"] if item.get("type") == "vless"]) >= 4
    assert len(desktop["route"]["rules"]) == 22
    assert {
        "domain_suffix": ["emby.bbqwq.com", "emby.wawajiao.cc.cd", "emby.kingemby.com"],
        "action": "route",
        "outbound": "direct",
    } in desktop["route"]["rules"]
    emby_dns_evaluations = [
        rule
        for rule in desktop["dns"]["rules"]
        if rule.get("action") == "evaluate"
        and dns_matcher_covers(rule, "domain_suffix", "emby.bbqwq.com")
    ]
    assert {rule["server"] for rule in emby_dns_evaluations} == {"google", "cloudflare"}
    # Adjacent same-resolver rules are folded into one block, so the emby
    # hosts share their evaluate legs with the other proxy-resolved matchers.
    assert all(dns_matcher_covers(rule, "rule_set", "geosite-telegram") for rule in emby_dns_evaluations)
    # respond legs carry no matcher: an unevaluated response tag never matches.
    for rule in desktop["dns"]["rules"]:
        if rule.get("action") == "respond" and str(rule.get("match_response", "")).startswith("failover-"):
            assert set(rule) == {"match_response", "action", "race"}, rule
    assert desktop["inbounds"][0]["strict_route"] is True
    assert desktop["inbounds"][0]["route_exclude_address_set"] == ["geoip-cn"]
    assert not any("bind_interface" in outbound for outbound in desktop["outbounds"])
    assert desktop["experimental"]["cache_file"]["path"] == "cache.db"
    # sing-box 1.15: the built-in sing-tun stack is selected by omitting
    # ``stack``; cache writes are buffered and flushed on a timer.
    assert "stack" not in desktop["inbounds"][0]
    assert "stack" not in android["inbounds"][0]
    assert desktop["experimental"]["cache_file"]["flush_interval"] == "1m"
    assert android["experimental"]["cache_file"]["flush_interval"] == "5m"
    assert "optimistic" not in desktop["dns"]
    assert "optimistic" not in android["dns"]
    assert desktop["route"]["default_domain_resolver"] == {
        "server": "domestic",
        "timeout": "2s",
    }
    domain_node = next(
        outbound
        for outbound in desktop["outbounds"]
        if outbound.get("server") and not simple._is_ip_address(str(outbound["server"]))
    )
    assert domain_node["domain_resolver"] == {"server": "domestic", "timeout": "2s"}
    assert not any("initial_path" in item for item in desktop["route"]["rule_set"])
    china_rule_set = next(item for item in desktop["route"]["rule_set"] if item.get("tag") == "china-direct")
    assert china_rule_set["tag"] == "china-direct"
    assert china_rule_set["type"] == "inline"
    assert china_rule_set["rules"]
    assert "path" not in china_rule_set
    assert "format" not in china_rule_set
    assert len(android["route"]["rules"]) == 22
    assert any(rule.get("rule_set") == ["geosite-telegram"] and rule.get("outbound") == "Available" for rule in desktop["route"]["rules"])
    # YouTube must be carved out before the generic Google suffixes, or
    # googlevideo.com would be routed to Available again.
    youtube_rule = next(
        rule for rule in desktop["route"]["rules"] if rule.get("outbound") == "YouTube"
    )
    assert "googlevideo.com" in youtube_rule["domain_suffix"]
    google_rule = next(
        rule
        for rule in desktop["route"]["rules"]
        if rule.get("outbound") == "Available" and rule.get("domain_suffix") == [
            "gstatic.com",
            "googleapis.com",
            "googleusercontent.com",
            "ggpht.com",
        ]
    )
    assert desktop["route"]["rules"].index(youtube_rule) < desktop["route"]["rules"].index(google_rule)
    # YouTube resolves through resolvers detoured via the YouTube selector so
    # the video edge matches the egress actually used for playback.
    youtube_evaluations = [
        rule
        for rule in desktop["dns"]["rules"]
        if rule.get("action") == "evaluate" and dns_matcher_covers(rule, "domain_suffix", "googlevideo.com")
    ]
    assert {rule["server"] for rule in youtube_evaluations} == {"google-youtube", "cloudflare-youtube"}
    assert {
        server["detour"] for server in desktop["dns"]["servers"] if server["tag"] in {"google-youtube", "cloudflare-youtube"}
    } == {"YouTube"}
    google_evaluations = [
        rule
        for rule in desktop["dns"]["rules"]
        if rule.get("action") == "evaluate" and dns_matcher_covers(rule, "domain_suffix", "googleapis.com")
    ]
    assert {rule["server"] for rule in google_evaluations} == {"google", "cloudflare"}
    # YouTube legs must precede the generic Google legs: youtubei.googleapis.com
    # matches both, and only the first block may claim it.
    assert desktop["dns"]["rules"].index(youtube_evaluations[0]) < desktop["dns"]["rules"].index(google_evaluations[0])
    assert {
        rule.get("server")
        for rule in desktop["dns"]["rules"]
        if rule.get("action") == "evaluate" and dns_matcher_covers(rule, "rule_set", "geosite-telegram")
    } == {"google", "cloudflare"}
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

    for tag in ("china-direct", "ai-domains", "emby-domains", "direct-cdn", "spotify-direct"):
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


def test_exclude_types_drops_nodes_the_core_cannot_load(tmp_path):
    """免费池里核心加载不了的 outbound 类型必须按 type 跳过。

    hysteria/wireguard 之类的节点若留在配置里，sing-box check 会 FATAL，
    连带双端生成一起失败，所以这里断言它们被剔除而不是原样带出去。
    """
    payload = {
        "outbounds": [
            {"type": "vless", "tag": "US-One", "server": "one.example", "server_port": 443},
            {"type": "hysteria", "tag": "DE-Twelve", "server": "de.example", "server_port": 20088},
            {"type": "wireguard", "tag": "CN-Thirteen", "server": "wg.example", "server_port": 2408},
        ]
    }
    (tmp_path / "pool.json").write_text(json.dumps(payload), encoding="utf-8")
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: pool
    format: sing-box-json
    source: file
    path: pool.json
    exclude_types: [hysteria, wireguard]
""",
        encoding="utf-8",
    )

    sources = simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)
    assert sources[0].node_tags == ["US-One"]


def test_exclude_types_can_empty_a_subscription(tmp_path):
    """全部被类型过滤掉时要明确报错，而不是生成一个空分组。"""
    payload = {"outbounds": [{"type": "wireguard", "tag": "CN-One", "server": "wg.example", "server_port": 2408}]}
    (tmp_path / "pool.json").write_text(json.dumps(payload), encoding="utf-8")
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: pool
    format: sing-box-json
    source: file
    path: pool.json
    exclude_types: [wireguard]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="筛选后没有可用节点"):
        simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)


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
        "dns_resolvers": {"domestic": "domestic", "proxy": "google"},
        "config": {"dns": {"servers": [{"tag": "domestic"}, {"tag": "google"}]}},
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
    assert {"domain_suffix": ["deepseek.com"], "action": "route", "server": "domestic"} in dns
    assert {"domain": ["docs.deepseek.com"], "action": "route", "server": "domestic"} in dns
    assert {"domain_keyword": ["cdn"], "action": "route", "server": "domestic"} in dns
    assert {"domain_regex": ["^ad[0-9]+"], "action": "route", "server": "domestic"} in dns
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
        "dns_resolvers": {"domestic": "domestic", "proxy": "google"},
        "config": {"dns": {"servers": [{"tag": "domestic"}, {"tag": "google"}]}},
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
        None,
        None,
    )
    assert dns == []
    assert route == [{"domain_suffix": ["deepseek.com"], "action": "route", "outbound": "direct"}]


def test_managed_dns_rules_follow_declared_resolver_tags():
    """Resolvers come from policy.dns_resolvers, not from the server set order."""
    _, dns = simple.build_managed_rules(
        {
            "groups": [
                {"tag": "direct", "domains": ["domain_suffix:deepseek.com"]},
                {"tag": "AI", "domains": ["domain_suffix:openai.com"]},
            ]
        },
        "direct",
        "domestic",
        "google",
    )
    assert {"domain_suffix": ["deepseek.com"], "action": "route", "server": "domestic"} in dns
    assert {"domain_suffix": ["openai.com"], "action": "route", "server": "google"} in dns


def test_dns_failover_expands_route_into_bounded_response_race():
    rules = simple.expand_dns_failover_rules(
        [{"domain_suffix": ["example.com"], "action": "route", "server": "primary"}],
        {"timeout": "1500ms", "servers": {"primary": ["primary", "backup"]}},
    )

    assert [rule["action"] for rule in rules] == [
        "evaluate",
        "evaluate",
        "respond",
        "respond",
        "predefined",
    ]
    assert [rule.get("server") for rule in rules[:2]] == ["primary", "backup"]
    assert all(rule["timeout"] == "1500ms" for rule in rules[:2])
    assert all(rule["domain_suffix"] == ["example.com"] for rule in (rules[0], rules[1], rules[4]))
    assert rules[2] == {"match_response": "failover-1-primary", "action": "respond", "race": True}
    assert rules[3] == {"match_response": "failover-1-backup", "action": "respond", "race": True}
    assert rules[-1]["rcode"] == "SERVFAIL"


def test_dns_failover_merges_adjacent_same_server_rules_only():
    settings = {"servers": {"proxy": ["proxy", "proxy-b"], "cn": ["cn", "cn-b"]}}
    rules = simple.expand_dns_failover_rules(
        [
            {"domain_suffix": ["a.com"], "action": "route", "server": "proxy"},
            {"rule_set": ["set-a"], "action": "route", "server": "proxy"},
            {"domain_suffix": ["b.com"], "action": "route", "server": "proxy"},
            # Different resolver: must start a new block so priority is kept.
            {"domain_suffix": ["c.cn"], "action": "route", "server": "cn"},
            # Same resolver again, but not adjacent to the first block.
            {"domain_suffix": ["d.com"], "action": "route", "server": "proxy"},
            # Custom query options split blocks as well.
            {"domain_suffix": ["e.com"], "action": "route", "server": "proxy", "rewrite_ttl": 60},
            # Non-route rules pass through untouched and break adjacency.
            {"action": "predefined", "rcode": "NXDOMAIN", "domain": ["ads.example"]},
        ],
        settings,
    )
    evaluates = [rule for rule in rules if rule.get("action") == "evaluate"]
    assert [rule["tag"] for rule in evaluates] == [
        "failover-1-proxy",
        "failover-1-proxy-b",
        "failover-2-cn",
        "failover-2-cn-b",
        "failover-3-proxy",
        "failover-3-proxy-b",
        "failover-4-proxy",
        "failover-4-proxy-b",
    ]
    first = evaluates[0]
    assert first["type"] == "logical" and first["mode"] == "or"
    assert {"domain_suffix": ["a.com", "b.com"]} in first["rules"]
    assert {"rule_set": ["set-a"]} in first["rules"]
    assert evaluates[2]["domain_suffix"] == ["c.cn"] and "type" not in evaluates[2]
    assert evaluates[4]["domain_suffix"] == ["d.com"]
    assert evaluates[6]["domain_suffix"] == ["e.com"] and evaluates[6]["rewrite_ttl"] == 60
    assert rules[-1] == {"action": "predefined", "rcode": "NXDOMAIN", "domain": ["ads.example"]}
    # Every block ends with a SERVFAIL carrying the same matcher as its evaluates.
    servfails = [rule for rule in rules if rule.get("rcode") == "SERVFAIL"]
    assert len(servfails) == 4
    for servfail, evaluate in zip(servfails, evaluates[::2]):
        assert {k: v for k, v in servfail.items() if k not in ("action", "rcode")} == {
            k: v for k, v in evaluate.items() if k not in ("action", "server", "tag", "timeout", "rewrite_ttl")
        }


def test_dns_failover_keeps_inverted_and_multi_field_matchers_as_branches():
    rules = simple.expand_dns_failover_rules(
        [
            {"domain_suffix": ["a.com"], "action": "route", "server": "p"},
            {"rule_set": ["x"], "invert": True, "action": "route", "server": "p"},
            {"domain_suffix": ["b.com"], "query_type": ["A"], "action": "route", "server": "p"},
        ],
        {"servers": {"p": ["p", "q"]}},
    )
    matcher = rules[0]
    assert matcher["type"] == "logical"
    assert matcher["rules"] == [
        {"domain_suffix": ["a.com"]},
        {"rule_set": ["x"], "invert": True},
        {"domain_suffix": ["b.com"], "query_type": ["A"]},
    ]


def test_dns_final_rules_are_appended_last():
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
        "config": {
            "dns": {
                "final": "google",
                "servers": [{"tag": "local"}, {"tag": "node-resolver"}, {"tag": "google"}],
            }
        },
        "dns_rules": {
            "business_rules": [{"domain_suffix": ["a.com"], "action": "route", "server": "google"}],
            "domestic_rules": [{"domain_suffix": ["cn.com"], "action": "route", "server": "local"}],
            "final_rules": [
                {"action": "evaluate", "server": "node-resolver", "tag": "domestic"},
                {"action": "evaluate", "server": "google", "tag": "foreign"},
                {"match_response": "domestic", "action": "route", "server": "node-resolver", "race": True},
                {"match_response": "foreign", "action": "route", "server": "google", "race": True},
            ],
        },
    }
    conf = simple.build_config(
        "desktop",
        policy,
        {"platform": "desktop"},
        {"schema_version": 1},
        [source],
    )
    rules = conf["dns"]["rules"]
    assert rules[-4:] == policy["dns_rules"]["final_rules"]
    # final_rules sit after domestic rules, so they only see unmatched queries.
    assert {"domain_suffix": ["cn.com"], "action": "route", "server": "local"} == rules[-5]
    assert {"domain_suffix": ["a.com"], "action": "route", "server": "google"} == rules[-6]


def test_policy_dns_fallback_never_trusts_domestic_answers_blindly():
    """Regression guard for the 2026-09-13 intermittent-failure root cause.

    The fallback used to race domestic and overseas resolvers with plain
    ``respond`` rules, so the (faster) domestic resolver usually won for
    unlisted foreign domains and handed out GFW-polluted addresses.  Domestic
    answers may only be accepted when they land in geoip-cn; every other case
    must deterministically fall through to the proxy-side resolvers.
    """
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    final_rules = policy["dns_rules"]["final_rules"]
    domestic_tags = {"domestic", "domestic-backup"}

    evaluates = [rule for rule in final_rules if rule.get("action") == "evaluate"]
    responders = [rule for rule in final_rules if rule.get("action") == "respond"]
    assert evaluates and responders
    # Every evaluate must precede the first rule that references a response.
    first_reference = next(i for i, rule in enumerate(final_rules) if rule.get("match_response"))
    assert all(final_rules.index(rule) < first_reference for rule in evaluates)

    tag_to_server = {rule["tag"]: rule["server"] for rule in evaluates}
    domestic_responders = [r for r in responders if tag_to_server[r["match_response"]] in domestic_tags]
    overseas_responders = [r for r in responders if tag_to_server[r["match_response"]] not in domestic_tags]
    assert domestic_responders and overseas_responders
    for rule in domestic_responders:
        assert "geoip-cn" in rule.get("rule_set", []), rule
    for rule in overseas_responders:
        assert not rule.get("race"), rule
    # Domestic (race) responders are listed before the ordered overseas ones,
    # and the block is bounded by an explicit SERVFAIL.
    assert max(final_rules.index(r) for r in domestic_responders) < min(
        final_rules.index(r) for r in overseas_responders
    )
    assert final_rules[-1] == {"action": "predefined", "rcode": "SERVFAIL"}
    # The generator must pass these rules through untouched.
    assert simple.expand_dns_failover_rules(final_rules, policy.get("dns_failover")) == final_rules

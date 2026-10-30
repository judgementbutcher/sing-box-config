import hashlib
import json
import os
import time

import pytest
import requests

from singbox_config import generator
from singbox_config.generator import (
    Source,
    build_config,
    build_outbounds,
    build_rule_sets,
    detect_format,
    for_platform,
    load_sources,
    load_yaml,
)


POLICY = {
    "groups": {
        "ai_regions": ["US", "JP"],
        "services": [
            {"tag": "YouTube"},
            {"tag": "Spotify", "direct": "first", "expand": True},
            {"tag": "Emby", "direct": "last"},
        ],
    },
}


def node(tag, server="node.example.com", **extra):
    return {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000000",
        "tls": {"enabled": True},
        **extra,
    }


def manifest(tmp_path, *items):
    """items: (订阅条目, 节点列表)。节点写成 sing-box JSON 订阅文件。"""
    entries = []
    for index, (entry, nodes) in enumerate(items):
        path = tmp_path / f"sub{index}.json"
        path.write_text(json.dumps({"outbounds": nodes}), encoding="utf-8")
        entries.append({"path": path.name, **entry})
    target = tmp_path / "subscriptions.yaml"
    target.write_text(json.dumps({"subscriptions": entries}), encoding="utf-8")
    return target


def by_tag(outbounds):
    return {outbound["tag"]: outbound for outbound in outbounds}


# ---------------------------------------------------------------- 平台过滤

def test_for_platform_keeps_matching_items_and_strips_the_marker():
    value = {
        "inbounds": [
            {"only": "desktop", "tag": "a"},
            {"only": "android", "tag": "b"},
            {"tag": "c", "rule_set": ["x", "y"]},
        ]
    }
    assert for_platform(value, "desktop") == {
        "inbounds": [{"tag": "a"}, {"tag": "c", "rule_set": ["x", "y"]}]
    }
    assert [item["tag"] for item in for_platform(value, "android")["inbounds"]] == ["b", "c"]


def test_for_platform_rejects_unknown_platform():
    with pytest.raises(ValueError, match="only"):
        for_platform([{"only": "ios"}], "desktop")


# ---------------------------------------------------------------- 规则集

def test_rule_sets_are_built_from_references(tmp_path):
    (tmp_path / "mine.txt").write_text("# 注释\nexample.com  # 行尾注释\n\nexample.org\n", encoding="utf-8")
    config = {
        "dns": {"rules": [{"rule_set": ["mine", "geosite-cn"], "server": "x"}]},
        "route": {
            "rules": [
                {"rule_set": "geosite-cn", "outbound": "direct"},
                {"type": "logical", "rules": [{"rule_set": "geoip-cn"}]},
                {"ip_is_private": True, "outbound": "direct"},
            ]
        },
    }
    urls = {"geosite": "https://rules.example/{tag}.srs", "geoip": "https://ip.example/{tag}.srs"}
    assert build_rule_sets(config, urls, tmp_path) == [
        {"type": "inline", "tag": "mine", "rules": [{"domain_suffix": ["example.com", "example.org"]}]},
        {"type": "remote", "tag": "geosite-cn", "url": "https://rules.example/geosite-cn.srs"},
        {"type": "remote", "tag": "geoip-cn", "url": "https://ip.example/geoip-cn.srs"},
    ]


def test_unknown_or_empty_rule_set_is_an_error(tmp_path):
    config = {"dns": {}, "route": {"rules": [{"rule_set": "nowhere", "outbound": "direct"}]}}
    with pytest.raises(ValueError, match="nowhere"):
        build_rule_sets(config, {}, tmp_path)
    (tmp_path / "nowhere.txt").write_text("# 只有注释\n", encoding="utf-8")
    with pytest.raises(ValueError, match="空名单"):
        build_rule_sets(config, {}, tmp_path)


# ---------------------------------------------------------------- 订阅

def test_detect_format():
    assert detect_format('{"outbounds": []}') == "sing-box"
    assert detect_format("port: 7890\nproxies:\n  - name: a\n") == "clash"
    assert detect_format("vless://placeholder\n") == "uri"


def test_sources_keep_manifest_order_and_clean_nodes(tmp_path):
    path = manifest(
        tmp_path,
        ({"name": "B", "exclude": ["^剩余流量"]}, [
            node("US 01", "b1.example.com"),
            node("剩余流量 10G", "b2.example.com"),
            node("官网", "127.0.0.1"),
            node("JP 01", "b3.example.com", domain_resolver="their-dns"),
        ]),
        ({"name": "A"}, [node("HK 01", "a1.example.com")]),
        ({"name": "Off", "enabled": False}, [node("US 09", "off.example.com")]),
    )
    sources = load_sources(path, POLICY)
    assert [source.name for source in sources] == ["B", "A"]
    assert [item["tag"] for item in sources[0].nodes] == ["US 01", "JP 01"]
    assert "domain_resolver" not in sources[0].nodes[1]
    # 只有一个节点的订阅：节点直接用订阅名。
    assert [item["tag"] for item in sources[1].nodes] == ["A"]


def test_duplicate_nodes_are_dropped_and_tag_collisions_renamed(tmp_path):
    path = manifest(
        tmp_path,
        ({"name": "A"}, [node("US 01", "same.example.com"), node("US 02", "a.example.com")]),
        ({"name": "B"}, [
            node("另一个名字", "same.example.com"),
            node("US 02", "b.example.com"),
            node("US 03", "b3.example.com"),
        ]),
    )
    sources = load_sources(path, POLICY)
    assert [item["tag"] for item in sources[1].nodes] == ["US 02 [B]", "US 03"]


def test_insecure_nodes_need_explicit_opt_in(tmp_path):
    insecure = node("US 01", tls={"enabled": True, "insecure": True})
    secure = node("US 02", "b.example.com")
    with pytest.raises(ValueError, match="allow_insecure"):
        load_sources(manifest(tmp_path, ({"name": "A"}, [insecure, secure])), POLICY)

    def ai(**entry):
        path = manifest(tmp_path, ({"name": "A", "allow_insecure": True, **entry}, [insecure, secure]))
        return load_sources(path, POLICY)[0].ai

    # 无论 ai 是 auto 还是 true，insecure 节点均严格禁止进入 AI 分组
    assert ai() == ["US 02"]
    assert ai(ai=True) == ["US 02"]
    assert ai(ai=False) == []


def test_ai_membership_follows_regions_and_ai_include(tmp_path):
    nodes = [node("HK 01", "h.example.com"), node("JP 01", "j.example.com"), node("home-lab", "l.example.com")]
    assert load_sources(manifest(tmp_path, ({"name": "A"}, nodes)), POLICY)[0].ai == ["JP 01"]
    path = manifest(tmp_path, ({"name": "A", "ai_include": ["^home-"]}, nodes))
    assert load_sources(path, POLICY)[0].ai == ["JP 01", "home-lab"]


def test_ai_insecure_exception_is_exact_and_scoped_to_one_source(tmp_path):
    def insecure(tag, host):
        return node(tag, host, tls={"enabled": True, "insecure": True})

    path = manifest(
        tmp_path,
        ({"name": "A", "allow_insecure": True, "ai_allow_insecure": ["US Comcast"]}, [
            insecure("US Comcast", "one.example.com"),
            insecure("US Comcast extra", "extra.example.com"),
            insecure("US Other", "other.example.com"),
        ]),
        ({"name": "B", "allow_insecure": True}, [
            insecure("US Comcast", "two.example.com"),
            insecure("US Other", "three.example.com"),
        ]),
    )
    a, b = load_sources(path, POLICY)
    assert a.ai == ["US Comcast"]
    assert b.ai == []
    # This is a membership exception; it does not silently change TLS settings.
    assert all(n["tls"]["insecure"] for s in (a, b) for n in s.nodes)


def test_ai_insecure_exception_respects_source_disable_and_import_opt_in(tmp_path):
    nodes = [node("US Comcast", tls={"enabled": True, "insecure": True})]
    entry = {"name": "A", "ai_allow_insecure": ["US Comcast"]}
    with pytest.raises(ValueError, match="allow_insecure"):
        load_sources(manifest(tmp_path, (entry, nodes)), POLICY)
    entry.update(allow_insecure=True, ai=False)
    assert load_sources(manifest(tmp_path, (entry, nodes)), POLICY)[0].ai == []
    entry["ai_allow_insecure"] = "US Comcast"
    with pytest.raises(ValueError, match="exact node names"):
        load_sources(manifest(tmp_path, (entry, nodes)), POLICY)


def test_manifest_typos_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="exclude_nodes"):
        load_sources(manifest(tmp_path, ({"name": "A", "exclude_nodes": []}, [node("US 01")])), POLICY)
    with pytest.raises(ValueError, match="重复"):
        load_sources(
            manifest(tmp_path, ({"name": "A"}, [node("US 01")]), ({"name": "A"}, [node("US 02")])), POLICY
        )


def test_url_subscription_is_downloaded_cached_and_never_leaked(tmp_path, monkeypatch, capsys):
    url = "https://sub.example.invalid/private-SECRET"
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(generator, "CACHE_DIR", cache_dir)
    (tmp_path / "a.url.txt").write_text(url + "\n", encoding="utf-8")
    path = tmp_path / "subscriptions.yaml"
    path.write_text(json.dumps({"subscriptions": [{"name": "A", "path": "a.url.txt"}]}), encoding="utf-8")
    policy = {**POLICY, "subscription": {"cache_max_age": "1d", "retry_proxy": "http://127.0.0.1:1"}}
    body = json.dumps({"outbounds": [node("US 01"), node("US 02", "b.example.com")]})

    attempts = []

    def offline(url, timeout, user_agent, proxy=None):
        attempts.append(proxy)
        raise requests.ConnectionError(f"cannot reach {url}")

    monkeypatch.setattr(generator, "download", offline)
    with pytest.raises(RuntimeError, match="缓存") as failure:
        load_sources(path, policy)
    assert attempts == [None, "http://127.0.0.1:1"]
    assert "SECRET" not in capsys.readouterr().err + str(failure.value)

    monkeypatch.setattr(generator, "download", lambda *args, **kwargs: body)
    assert len(load_sources(path, policy)[0].nodes) == 2
    # 模拟在流水线通过后提交缓存
    generator.commit_staged_cache()
    cache = generator.subscription_cache_path(url, cache_dir=cache_dir)
    assert cache.read_text(encoding="utf-8") == body

    monkeypatch.setattr(generator, "download", offline)
    assert len(load_sources(path, policy)[0].nodes) == 2
    assert len(load_sources(path, policy, offline=True)[0].nodes) == 2
    stale = time.time() - 2 * 86400
    os.utime(cache, (stale, stale))
    with pytest.raises(RuntimeError, match="缓存"):
        load_sources(path, policy, offline=True)


def test_subscription_cache_identity_includes_user_agent(tmp_path, monkeypatch):
    url = "https://subscription.example.invalid/same"
    monkeypatch.setattr(generator, "CACHE_DIR", tmp_path / "cache")
    (tmp_path / "source.txt").write_text(url, encoding="utf-8")
    path = tmp_path / "subscriptions.yaml"
    entries = [{"name": ua, "path": "source.txt", "user_agent": ua} for ua in ("UA-A", "UA-B")]
    path.write_text(json.dumps({"subscriptions": entries}), encoding="utf-8")
    bodies = {ua: json.dumps({"outbounds": [node("US node", ua.lower() + ".example.com")]}) for ua in ("UA-A", "UA-B")}
    monkeypatch.setattr(generator, "download", lambda _url, _timeout, ua, _proxy: bodies[ua])
    online = load_sources(path, POLICY)
    generator.commit_staged_cache()
    assert generator.subscription_cache_path(url, "UA-A") != generator.subscription_cache_path(url, "UA-B")
    assert len(list((tmp_path / "cache").iterdir())) == 2
    monkeypatch.setattr(generator, "download", lambda *_a: pytest.fail("offline used network"))
    cached = load_sources(path, POLICY, offline=True)
    assert [source.nodes for source in cached] == [source.nodes for source in online]


@pytest.mark.parametrize("user_agent", ["sing-box", "custom-agent"])
def test_legacy_url_only_cache_requires_online_migration(tmp_path, monkeypatch, user_agent):
    url = "https://subscription.example.invalid/legacy"
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    legacy = cache_dir / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".txt")
    legacy.write_text(json.dumps({"outbounds": [node("US node")]}), encoding="utf-8")
    monkeypatch.setattr(generator, "CACHE_DIR", cache_dir)
    (tmp_path / "source.txt").write_text(url, encoding="utf-8")
    path = tmp_path / "subscriptions.yaml"
    path.write_text(json.dumps({"subscriptions": [{"name": "A", "path": "source.txt", "user_agent": user_agent}]}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="User-Agent"):
        load_sources(path, POLICY, offline=True)
    assert legacy.is_file()
    assert not generator.subscription_cache_path(url, user_agent).exists()


@pytest.mark.parametrize("mode", ["online", "local", "offline"])
def test_subscription_parser_errors_never_echo_input(tmp_path, monkeypatch, capsys, mode):
    secret = "AUDIT-SENSITIVE-MARKER"
    body = f"proxies:\n  - name: safe\n    private: {secret}: invalid\n"
    url = "https://subscription.example.invalid/private"
    monkeypatch.setattr(generator, "CACHE_DIR", tmp_path / "cache")
    (tmp_path / "source.txt").write_text(body if mode == "local" else url, encoding="utf-8")
    path = tmp_path / "subscriptions.yaml"
    path.write_text(json.dumps({"subscriptions": [{"name": "A", "path": "source.txt"}]}), encoding="utf-8")
    if mode == "offline":
        cache = generator.subscription_cache_path(url)
        cache.parent.mkdir()
        cache.write_text(body, encoding="utf-8")
    monkeypatch.setattr(generator, "download", lambda *_a: body)
    with pytest.raises((ValueError, RuntimeError)) as caught:
        load_sources(path, POLICY, offline=mode == "offline")
    assert secret not in str(caught.value) + capsys.readouterr().err


def test_parser_warning_does_not_echo_raw_exception_or_node_name(tmp_path, capsys):
    secret = "AUDIT-WARNING-MARKER"
    path = manifest(tmp_path, ({"name": "A"}, [node("US node")]))
    (tmp_path / "sub0.json").write_text(
        f"proxies:\n - {{type: vless, name: safe, server: node.example.com, port: 443, uuid: test}}\n"
        f" - {{type: vless, name: other, server: node.example.com, port: {secret}, uuid: test}}\n"
        f" - {{type: unsupported, name: {secret}}}\n", encoding="utf-8")
    assert load_sources(path, POLICY)
    output = capsys.readouterr().err
    assert "2 项" in output
    assert secret not in output


# ---------------------------------------------------------------- 出站与分组

def test_outbound_layout():
    sources = [
        Source("Air", [node("JP 01"), node("US 01"), node("Mystery")], ["JP 01", "US 01"]),
        Source("SG-Home", [node("SG-Home")], []),
    ]
    outbounds = build_outbounds(sources, POLICY["groups"])
    tags = by_tag(outbounds)
    assert [item["tag"] for item in outbounds] == [
        "Available", "AI", "direct", "Other", "YouTube", "Spotify", "Emby", "Air",
        "JP 01", "US 01", "Mystery", "SG-Home",
    ]
    assert tags["Available"]["outbounds"] == ["Air", "SG-Home", "Other"]
    # AI 按 ai_regions 的顺序排，第一个就是默认；严格白名单不追加未分类的 Other
    assert tags["AI"]["outbounds"] == ["US 01", "JP 01"]
    assert tags["Other"]["outbounds"] == ["Mystery"]
    assert tags["YouTube"]["outbounds"] == ["Available", "Air", "SG-Home"]
    # 展开成员的同时保留 Available，直连仍为默认。
    assert tags["Spotify"]["outbounds"] == ["direct", "Available", "Air", "SG-Home", "Other"]
    assert tags["Emby"]["outbounds"] == ["Available", "Air", "SG-Home", "direct"]
    assert tags["Air"]["outbounds"] == ["JP 01", "US 01", "Mystery"]


def test_ai_group_rejects_empty_candidates_and_other_is_optional():
    with pytest.raises(ValueError, match="AI 分组未筛选出任何可用节点"):
        build_outbounds([Source("Air", [node("HK 01"), node("HK 02")], [])], POLICY["groups"])


def test_expand_group_keeps_available_and_lists_subscriptions():
    sources = [Source("Air", [node("JP 01")], ["JP 01"]), Source("SG-Home", [node("SG-Home")], [])]
    outbounds = by_tag(build_outbounds(sources, {"services": [
        {"tag": "Plain"},
        {"tag": "Flat", "direct": "first", "expand": True},
    ]}))
    assert outbounds["Plain"]["outbounds"] == ["Available", "Air", "SG-Home"]
    assert outbounds["Flat"]["outbounds"] == ["direct", "Available", "Air", "SG-Home"]


def test_expand_group_rejects_non_boolean():
    with pytest.raises(ValueError, match="expand"):
        build_outbounds([Source("Air", [node("JP 01")], ["JP 01"])], {"services": [{"tag": "X", "expand": "yes"}]})


def test_auto_transit_uses_source_scoped_candidates_without_changing_other_groups():
    sources = [
        Source("West", [node("HK 01", "west.example.com"), node("US 01", "us.example.com")], ["US 01"]),
        Source("Other", [node("HK 02", "other.example.com")], []),
        Source("Tested", [node("HK 03", "tested.example.com"), node("HK 04", "untested.example.com")], []),
    ]
    group = {"tag": "Aether-前置", "type": "urltest", "filter": "aether_transit",
             "include_direct": True, "candidates": [
                 {"source": "West", "regions": ["HK"]},
                 {"source": "Tested", "names": ["HK 03"]},
             ]}
    out = by_tag(build_outbounds(sources, {"services": [group, {"tag": "YouTube"}]}))
    auto = out["Aether-前置"]
    assert auto["type"] == "urltest"
    assert auto["outbounds"] == ["HK 01", "HK 03", "direct"]
    assert auto["interval"] == "3m" and auto["tolerance"] == 50
    assert auto["interrupt_exist_connections"] is False
    assert out["AI"]["outbounds"] == ["US 01"]
    assert out["YouTube"]["type"] == out["Available"]["type"] == "selector"


@pytest.mark.parametrize("interrupt", [False, True])
def test_urltest_preserves_explicit_connection_policy(interrupt):
    sources = [Source("West", [node("HK 01"), node("US 01")], ["US 01"])]
    group = {"tag": "Front", "type": "urltest", "filter": "aether_transit",
             "candidates": [{"source": "West", "names": ["HK 01"]}],
             "interrupt_exist_connections": interrupt, "interval": "5m", "tolerance": 200}
    out = by_tag(build_outbounds(sources, {"services": [group]}))
    assert out["Front"]["interrupt_exist_connections"] is interrupt
    assert out["Front"]["interval"] == "5m"
    assert out["Front"]["tolerance"] == 200
    # Manual switches still close connections, as before.
    assert out["Available"]["interrupt_exist_connections"] is True


@pytest.mark.parametrize("interrupt", ["false", 0, None])
def test_urltest_rejects_non_boolean_connection_policy(interrupt):
    sources = [Source("West", [node("HK 01"), node("US 01")], ["US 01"])]
    group = {"tag": "Front", "type": "urltest", "filter": "aether_transit",
             "candidates": [{"source": "West", "names": ["HK 01"]}],
             "interrupt_exist_connections": interrupt}
    with pytest.raises(ValueError, match="interrupt_exist_connections"):
        build_outbounds(sources, {"services": [group]})


def test_auto_transit_rejects_recursive_detours_and_empty_pools():
    group = {"tag": "Aether-前置", "type": "urltest", "filter": "aether_transit",
             "candidates": [{"source": "A", "names": ["HK front"]}]}
    sources = [Source("A", [node("HK front", detour="US relay"),
                            node("US relay", "relay.example.com", detour="Aether-前置")], ["US relay"])]
    with pytest.raises(ValueError, match="依赖自身分组"):
        build_outbounds(sources, {"services": [group]})
    group["candidates"][0]["names"] = ["missing"]
    with pytest.raises(ValueError, match="没有候选"):
        build_outbounds(sources, {"services": [group]})


def test_explicit_members_are_source_scoped_and_allow_existing_insecure_choices():
    sources = [Source("Home", [node("US Home", tls={"enabled": True, "insecure": True})], ["US Home"]),
               Source("Airport", [node("US Other")], ["US Other"])]
    group = {"tag": "Google", "members": ["AI", "Available", {"source": "Home", "names": ["US Home"]}]}
    result = by_tag(build_outbounds(sources, {"services": [group]}))
    assert result["Google"]["outbounds"] == ["AI", "Available", "US Home"]
    group["members"][2]["source"] = "Airport"
    with pytest.raises(ValueError, match="缺失"):
        build_outbounds(sources, {"services": [group]})


def test_manual_front_and_full_graph_reject_detour_cycles_and_missing_references():
    group = {"tag": "Front", "type": "selector", "filter": "aether_transit",
             "candidates": [{"source": "Home", "names": ["HK Front"]}]}
    with pytest.raises(ValueError, match="依赖自身"):
        build_outbounds([Source("Home", [node("HK Front", detour="Front"), node("US Home")], ["US Home"])],
                        {"services": [group]})
    for outbounds in ([{"tag": "a", "outbounds": ["b"]}, {"tag": "b", "detour": "a"}],
                      [{"tag": "a", "outbounds": ["missing"]}]):
        with pytest.raises(ValueError, match="循环|不存在"):
            generator.validate_outbound_graph(outbounds)


# ---------------------------------------------------------------- 仓库里的 policy.yaml

SOURCES = [
    Source("CloudLeadInno-US", [node("CloudLeadInno-US", "cloudlead.example.com")], []),
    Source("Meow-US", [node("Meow-US-hy2", "meow-hy2.example.com"),
                       node("Meow-US-vless", "meow-vless.example.com")], []),
    Source("Air", [node("US 01"), node("HK 01", "hk.example.com")], ["US 01"]),
    Source("Solo", [node("Solo", "solo.example.com")], []),
    Source("西部数据", [node("Hong Kong | 01", "west.example.com")], []),
    Source("羽迹", [node("香港-1", "backup.example.com")], []),
    Source("Aether-US", [node(f"Aether-US-{city}-v6", f"{city.lower()}.example.com",
                              detour="Aether-前置") for city in ("CHI", "SFO", "ATL")]
           + [node("Aether-US-LAX-v4", "lax.example.com", detour="Aether-前置")], []),
]


@pytest.fixture(scope="module", params=generator.PLATFORMS)
def built(request):
    return request.param, build_config(request.param, load_yaml(generator.POLICY), SOURCES)


def rule_set_tags(rule):
    value = rule.get("rule_set") or []
    return [value] if isinstance(value, str) else value


def test_policy_references_resolve(built):
    platform, config = built
    assert '"only":' not in json.dumps(config)
    outbounds = {item["tag"] for item in config["outbounds"]}
    servers = {item["tag"] for item in config["dns"]["servers"]}
    rule_sets = {item["tag"] for item in config["route"]["rule_set"]}
    for rule in config["route"]["rules"]:
        assert rule.get("outbound", "direct") in outbounds, rule
        assert set(rule_set_tags(rule)) <= rule_sets
    for rule in config["dns"]["rules"]:
        assert rule.get("server", "proxy") in servers, rule
        assert set(rule_set_tags(rule)) <= rule_sets
    for server in config["dns"]["servers"]:
        assert server.get("detour", "Available") in outbounds
        assert set(server.get("servers", [])) <= servers
    assert config["dns"]["final"] in servers
    assert config["route"]["final"] in outbounds
    resolver = config["route"]["default_domain_resolver"]
    resolver_tag = resolver["server"] if isinstance(resolver, dict) else resolver
    assert resolver_tag in servers
    assert ("Google Play" in outbounds) == (platform == "android")
    assert any(item["type"] == "mixed" for item in config["inbounds"]) == (platform == "desktop")


def test_policy_dns_servers_never_mix_trust_levels(built):
    servers = {item["tag"]: item for item in built[1]["dns"]["servers"]}
    for server in servers.values():
        # 当前策略使用显式 DoH；不依赖平台 local DNS，也不对空 direct 出站设置 detour。
        assert server["type"] != "local"
        assert server.get("detour") != "direct"
    # 国内解析器对被墙域名又快又假，和海外解析器放进同一个并发组就是让假答案赢。
    assert all("detour" not in servers[tag] for tag in servers["domestic"]["servers"])
    assert all("detour" in servers[tag] for tag in servers["proxy"]["servers"])


def test_policy_unlisted_names_are_decided_by_the_proxy_side_answer(built):
    dns = built[1]["dns"]
    assert dns["rules"][-3:] == [
        {"action": "evaluate", "server": "proxy"},
        {"match_response": True, "rule_set": "geoip-cn", "server": "domestic"},
        {"action": "respond"},
    ]
    assert dns["final"] == "proxy"
    # 除了上面按代理侧答案改判的那一条，交给国内解析器的只能是明确的名单。
    for rule in dns["rules"]:
        if rule.get("server") == "domestic" and not rule.get("match_response"):
            assert (rule_set_tags(rule) or rule.get("domain_suffix") or rule.get("domain")) and not rule.get("invert"), rule


def test_policy_dns_rules_mirror_route_rules(built):
    """走代理的名单用代理侧解析，直连的用国内解析，拦截的不解析；先后顺序两边一致。"""
    config = built[1]

    def dns_kind(rule):
        if rule.get("action") == "predefined" and rule.get("rcode") == "NXDOMAIN":
            return "block"
        return "domestic" if rule.get("server") == "domestic" else "proxy"

    def route_kind(rule):
        if rule.get("action") == "reject":
            return "block"
        return "domestic" if rule["outbound"] == "direct" else "proxy"

    def kinds(rules, kind, skip):
        result = []
        for rule in rules:
            for tag in rule_set_tags(rule):
                if not skip(rule, tag) and tag not in dict(result):
                    result.append((tag, kind(rule)))
        return result

    dns = kinds(
        config["dns"]["rules"],
        dns_kind,
        lambda rule, tag: rule.get("match_response")
        or (rule.get("action") == "predefined" and rule.get("rcode") != "NXDOMAIN"),
    )
    route = kinds(
        config["route"]["rules"],
        route_kind,
        # 协议、包名限制过滤规则不改变这些域名的最终出站属性
        lambda rule, tag: tag.startswith("geoip-")
        or (rule.get("network") == "udp" and rule.get("port") == 443)
        or rule.get("ip_version") == 6
        or "package_name" in rule,
    )
    assert dns == route


def test_youtube_explicit_domains_precede_generic_proxy_rules(built):
    config = built[1]
    youtube_domains = {
        "youtube.com",
        "youtu.be",
        "yt.be",
        "youtube-nocookie.com",
        "youtubekids.com",
        "ytimg.com",
        "googlevideo.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "yt3.ggpht.com",
        "yt4.ggpht.com",
        "yt3.googleusercontent.com",
        "yt4.googleusercontent.com",
    }

    dns_rules = config["dns"]["rules"]
    dns_youtube = next(rule for rule in dns_rules if rule.get("server") == "youtube" and "domain_suffix" in rule)
    assert set(dns_youtube["domain_suffix"]) == youtube_domains
    assert dns_rules.index(dns_youtube) < next(
        index for index, rule in enumerate(dns_rules) if "ai" in rule_set_tags(rule)
    )
    assert dns_rules.index(dns_youtube) < next(
        index for index, rule in enumerate(dns_rules) if rule.get("rule_set") == "proxy"
    )

    route_rules = config["route"]["rules"]
    route_youtube = next(rule for rule in route_rules if rule.get("outbound") == "YouTube" and "domain_suffix" in rule)
    assert set(route_youtube["domain_suffix"]) == youtube_domains
    assert route_rules.index(route_youtube) < next(
        index for index, rule in enumerate(route_rules) if "ai" in rule_set_tags(rule)
    )
    ai_quic = next(
        index for index, rule in enumerate(route_rules)
        if rule.get("network") == "udp" and rule.get("port") == 443 and "ai" in rule_set_tags(rule)
    )
    ai_outbound = next(
        index for index, rule in enumerate(route_rules)
        if rule.get("outbound") == "AI" and "ai" in rule_set_tags(rule)
    )
    assert route_rules.index(route_youtube) < ai_quic < ai_outbound
    assert route_rules.index(route_youtube) < next(
        index for index, rule in enumerate(route_rules) if rule.get("rule_set") == "proxy"
    )


def test_info_entries_are_kept_for_display_only(tmp_path):
    path = manifest(
        tmp_path,
        ({"name": "A", "exclude": ["官网"]}, [
            node("US 01"),
            node("剩余流量：10 GB", "127.0.0.1"),
            node("Expire: 2027-01-01", "b.example.com"),
            node("官网 example.com", "127.0.0.1"),
        ]),
        ({"name": "B"}, [node("JP 01", "c.example.com"), node("剩余流量：10 GB", "d.example.com")]),
    )
    sources = load_sources(path, POLICY)
    assert [item["tag"] for item in sources[0].nodes] == ["US 01"]
    assert sources[0].info == ["剩余流量：10 GB", "Expire: 2027-01-01"]
    assert sources[1].info == ["剩余流量：10 GB [B]"]
    assert sources[0].ai == ["US 01"]

    outbounds = build_outbounds(sources, POLICY["groups"])
    tags = by_tag(outbounds)
    assert tags["A"]["outbounds"] == ["US 01", "剩余流量：10 GB", "Expire: 2027-01-01"]
    assert tags["B"]["outbounds"] == ["JP 01", "剩余流量：10 GB [B]"]
    assert tags["Expire: 2027-01-01"] == {"type": "block", "tag": "Expire: 2027-01-01"}
    assert "Other" not in tags
    for group in ("Available", "AI", "YouTube"):
        assert not any("流量" in member or "Expire" in member for member in tags[group]["outbounds"])


def test_ai_group_contains_v6_and_v4_nodes():
    sources = [
        Source("Aether-US", [
            node("Aether-US-LAX-v4"),
            node("Aether-US-CHI-v6"),
            node("Aether-US-SFO-v6"),
        ], ["Aether-US-LAX-v4", "Aether-US-CHI-v6", "Aether-US-SFO-v6"]),
        Source("ISP-Cloud", [
            node("HK-01-家宽isp"),
            node("US-Comcast"),
            node("Ordinary-JP"),
        ], ["US-Comcast", "Ordinary-JP"]),
    ]
    groups = {
        "ai_regions": ["US", "JP"],
    }
    outbounds = build_outbounds(sources, groups)
    tags = by_tag(outbounds)

    # 统一 AI 分组包含 Aether 全部节点（v4 与 v6）和白名单地区的节点
    ai_members = tags["AI"]["outbounds"]
    assert "Aether-US-CHI-v6" in ai_members
    assert "Aether-US-SFO-v6" in ai_members
    assert "Aether-US-LAX-v4" in ai_members
    assert "Ordinary-JP" in ai_members
    assert "HK-01-家宽isp" not in ai_members



def test_google_ecosystem_is_separate_from_shared_ai_dependencies(built):
    config = built[1]
    rule_sets = {
        rs["tag"]: rs.get("rules", [{}])[0].get("domain_suffix", [])
        for rs in config["route"]["rule_set"]
        if "tag" in rs
    }
    ai_domains = rule_sets.get("ai", [])
    assert "challenges.cloudflare.com" in ai_domains  # Shared host; cannot identify its caller by domain alone.
    assert "claude.app" in rule_sets["claude"] and "claude.app" not in ai_domains
    google_domains = rule_sets["google"]
    assert "gemini.google.com" in google_domains and "gemini.google.com" not in ai_domains
    assert "perplexity.ai" in ai_domains
    # Google's own hosts share the Google selector; third-party verification retains AI.
    for domain in (
        "google.com",
        "google.com.hk",
        "google.cn",
        "gmail.com",
        "gstatic.com",
        "googleapis.com",
        "googleusercontent.com",
        "google.dev",
        "withgoogle.com",
        "recaptcha.net",
        "google",
        "goog",
    ):
        assert domain in google_domains and domain not in ai_domains, domain
    assert {"one.google.com", "accounts.google.com", "payments.google.com", "google.co.jp", "google.co.uk", "google.com.cn"} <= set(google_domains)
    assert {"sheerid.com", "sheerid.net"} <= set(ai_domains)
    proxy_domains = rule_sets.get("proxy", [])
    for domain in ("google.com", "gmail.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "sheerid.com"):
        assert domain not in proxy_domains, domain


def test_gemini_exceptions_precede_google_family(built):
    """Time remains direct; explicit Play rules precede broad Google, shared GMS is later."""
    platform, config = built

    def index_of(rules, pred):
        return next(i for i, rule in enumerate(rules) if pred(rule))

    expectations = (
        (config["dns"]["rules"], "server", "domestic"),
        (config["route"]["rules"], "outbound", "direct"),
    )
    for rules, field, expected in expectations:
        time_rule = index_of(rules, lambda rule: "time.google.com" in (rule.get("domain_suffix") or []))
        google_rule = index_of(rules, lambda rule: "google" in rule_set_tags(rule))
        assert time_rule < google_rule
        assert rules[time_rule][field] == expected

    if platform != "android":
        return
    route_rules = config["route"]["rules"]
    package_rule = index_of(
        route_rules, lambda rule: "com.android.vending" in (rule.get("package_name") or [])
    )
    google_rule = index_of(route_rules, lambda rule: "google" in rule_set_tags(rule))
    play_rule = index_of(route_rules, lambda rule: "geosite-google-play" in rule_set_tags(rule))
    gms_rule = index_of(route_rules, lambda rule: "com.google.android.gms" in rule.get("package_name", []))
    assert play_rule < package_rule < google_rule < gms_rule
    dns_rules = config["dns"]["rules"]
    assert index_of(dns_rules, lambda rule: "geosite-google-play" in rule_set_tags(rule)) < index_of(
        dns_rules, lambda rule: "google" in rule_set_tags(rule)
    )

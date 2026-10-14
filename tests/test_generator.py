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

    assert ai() == ["US 02"]
    assert ai(ai=True) == ["US 01", "US 02"]
    assert ai(ai=False) == []


def test_ai_membership_follows_regions_and_ai_include(tmp_path):
    nodes = [node("HK 01", "h.example.com"), node("JP 01", "j.example.com"), node("home-lab", "l.example.com")]
    assert load_sources(manifest(tmp_path, ({"name": "A"}, nodes)), POLICY)[0].ai == ["JP 01"]
    path = manifest(tmp_path, ({"name": "A", "ai_include": ["^home-"]}, nodes))
    assert load_sources(path, POLICY)[0].ai == ["JP 01", "home-lab"]


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
    cache = cache_dir / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".txt")
    assert cache.read_text(encoding="utf-8") == body

    monkeypatch.setattr(generator, "download", offline)
    assert len(load_sources(path, policy)[0].nodes) == 2
    assert len(load_sources(path, policy, offline=True)[0].nodes) == 2
    stale = time.time() - 2 * 86400
    os.utime(cache, (stale, stale))
    with pytest.raises(RuntimeError, match="缓存"):
        load_sources(path, policy, offline=True)


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
    # AI 按 ai_regions 的顺序排，第一个就是默认。
    assert tags["AI"]["outbounds"] == ["US 01", "JP 01", "Other"]
    assert tags["Other"]["outbounds"] == ["Mystery"]
    assert tags["YouTube"]["outbounds"] == ["Available", "Air", "SG-Home"]
    # expand: true 不引用 Available，而是把它展开成成员，直连排在最前作为默认。
    assert tags["Spotify"]["outbounds"] == ["direct", "Air", "SG-Home", "Other"]
    assert tags["Emby"]["outbounds"] == ["Available", "Air", "SG-Home", "direct"]
    assert tags["Air"]["outbounds"] == ["JP 01", "US 01", "Mystery"]


def test_ai_group_falls_back_to_available_and_other_is_optional():
    outbounds = by_tag(build_outbounds([Source("Air", [node("HK 01"), node("HK 02")], [])], POLICY["groups"]))
    assert outbounds["AI"]["outbounds"] == ["Available"]
    assert "Other" not in outbounds


def test_expand_group_lists_subscriptions_instead_of_available():
    sources = [Source("Air", [node("JP 01")], ["JP 01"]), Source("SG-Home", [node("SG-Home")], [])]
    outbounds = by_tag(build_outbounds(sources, {"services": [
        {"tag": "Plain"},
        {"tag": "Flat", "direct": "first", "expand": True},
    ]}))
    assert outbounds["Plain"]["outbounds"] == ["Available", "Air", "SG-Home"]
    assert outbounds["Flat"]["outbounds"] == ["direct", "Air", "SG-Home"]


def test_expand_group_rejects_non_boolean():
    with pytest.raises(ValueError, match="expand"):
        build_outbounds([Source("Air", [node("JP 01")], [])], {"services": [{"tag": "X", "expand": "yes"}]})


# ---------------------------------------------------------------- 仓库里的 policy.yaml

SOURCES = [
    Source("Air", [node("US 01"), node("HK 01", "hk.example.com")], ["US 01"]),
    Source("Solo", [node("Solo", "solo.example.com")], []),
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
    assert config["route"]["default_domain_resolver"] in servers
    assert ("Google Play" in outbounds) == (platform == "android")
    assert any(item["type"] == "mixed" for item in config["inbounds"]) == (platform == "desktop")


def test_policy_dns_servers_never_mix_trust_levels(built):
    servers = {item["tag"]: item for item in built[1]["dns"]["servers"]}
    for server in servers.values():
        # TUN 把系统 DNS 指向自己，local 会查回 sing-box；detour: direct 核心拒绝启动。
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
            assert rule_set_tags(rule) and not rule.get("invert"), rule


def test_policy_dns_rules_mirror_route_rules(built):
    """走代理的名单用代理侧解析，直连的用国内解析，拦截的不解析；先后顺序两边一致。"""
    config = built[1]

    def dns_kind(rule):
        if rule.get("action") == "predefined":
            return "block"
        return rule["server"]

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

    dns = kinds(config["dns"]["rules"], dns_kind, lambda rule, tag: rule.get("match_response"))
    route = kinds(config["route"]["rules"], route_kind, lambda rule, tag: tag.startswith("geoip-"))
    assert dns == route


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

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


# One resolver per role keeps derived DNS rules unexpanded (no race).
SINGLE_UPSTREAMS = {
    "domestic": [{"tag": "domestic", "server": "223.5.5.5", "server_name": "dns.alidns.com"}],
    "proxy": [{"tag": "google", "server": "8.8.8.8", "server_name": "dns.google"}],
    "proxy_detours": {"Available": ""},
}


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


def test_ai_region_whitelist_gates_membership(tmp_path):
    """AI 组成员由 selectors.ai_regions 白名单决定；HK 永远进不了 AI 组。

    Claude/ChatGPT 拒绝香港出口，所以即使订阅设置 ai: true（放宽 insecure
    限制），地区门槛仍然生效。
    """
    source = tmp_path / "provider.txt"
    source.write_text(
        "\n".join(
            [
                "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls#US-One",
                "vless" + "://22222222-2222-2222-2222-222222222222@two.example:443?security=tls#JP-One",
                "vless" + "://33333333-3333-3333-3333-333333333333@three.example:443?security=tls#SG-One",
                "vless" + "://44444444-4444-4444-4444-444444444444@four.example:443?security=tls#TW-One",
                "vless" + "://55555555-5555-5555-5555-555555555555@five.example:443?security=tls#HK-One",
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

    allowed = simple.load_sources(
        manifest,
        {"selectors": {"ai_regions": ["US", "JP", "SG", "TW"]}},
        offline=False,
        fetch_proxy=None,
    )
    assert allowed[0].ai_node_tags == ["US-One", "JP-One", "SG-One", "TW-One"]

    # Without an explicit whitelist the historical US-only behaviour applies.
    default = simple.load_sources(
        manifest, {"selectors": {}}, offline=False, fetch_proxy=None
    )
    assert default[0].ai_node_tags == ["US-One"]

    # ai: true only lifts the insecure-TLS restriction, never the region gate.
    force_manifest = tmp_path / "force.yaml"
    force_manifest.write_text(
        manifest.read_text(encoding="utf-8") + "    ai: true\n",
        encoding="utf-8",
    )
    forced = simple.load_sources(
        force_manifest,
        {"selectors": {"ai_regions": ["US", "JP", "SG", "TW"]}},
        offline=False,
        fetch_proxy=None,
    )
    assert forced[0].ai_node_tags == ["US-One", "JP-One", "SG-One", "TW-One"]


def test_ai_group_orders_regions_by_whitelist_and_defaults_to_first():
    """ai_regions 列表顺序即优先级：美国默认出口，其余地区只作备用。"""
    source = simple.BuiltSource(
        name="provider",
        order=10,
        entry_tag="Provider",
        node_tags=["JP-One", "US-One", "US-Two"],
        nodes=[],
        groups=[],
        ai_node_tags=["JP-One", "US-One", "US-Two"],
    )
    outbounds = simple.build_outbounds(
        [source],
        {"selectors": {"available": "Available", "ai": "AI", "ai_regions": ["US", "JP"]}},
        {"platform": "desktop"},
    )
    ai = next(outbound for outbound in outbounds if outbound.get("tag") == "AI")
    # Region priority reorders members; the original order inside one region
    # (US-One before US-Two) is preserved.
    assert ai["outbounds"] == ["US-One", "US-Two", "JP-One"]
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
def test_current_sources_generate_small_valid_profiles():
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    sources = simple.load_sources(
        ROOT / "config" / "local" / "subscriptions.yaml",
        policy,
        offline=False,
        fetch_proxy=None,
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

    assert [item["tag"] for item in desktop["outbounds"][:9]] == [
        "Available",
        "AI",
        "direct",
        "Other",
        "Emby",
        "YouTube",
        "Spotify",
        "Telegram",
        "Twitch",
    ]
    selector_by_tag = {item["tag"]: item for item in desktop["outbounds"] if item.get("type") == "selector"}
    outbound_by_tag = {item["tag"]: item for item in desktop["outbounds"] if item.get("tag")}
    # Service groups mirror Available's entries and follow Available by default,
    # so they only diverge once a node is pinned in the panel.  The cold-region
    # "Other" pool is the one exception: it joins Available after those groups
    # captured their membership, so it is not repeated in each of them.
    available_members = outbound_by_tag["Available"]["outbounds"]
    assert available_members[-1] == "Other"
    service_members = ["Available", *available_members[:-1]]
    assert selector_by_tag["YouTube"]["outbounds"] == service_members
    assert selector_by_tag["YouTube"]["default"] == "Available"
    # Spotify keeps direct as the default: the account-region check rejects
    # datacentre proxy exits. Proxy members remain selectable in the panel.
    assert selector_by_tag["Spotify"]["outbounds"] == ["direct", *service_members]
    assert selector_by_tag["Spotify"]["default"] == "direct"
    # Telegram is proxy-only: no direct member, follows Available by default.
    assert selector_by_tag["Telegram"]["outbounds"] == service_members
    assert selector_by_tag["Telegram"]["default"] == "Available"
    assert "direct" not in selector_by_tag["Telegram"]["outbounds"]
    # Twitch mirrors Telegram: proxy-only, follows Available by default.
    assert selector_by_tag["Twitch"]["outbounds"] == selector_by_tag["Telegram"]["outbounds"]
    assert selector_by_tag["Twitch"]["default"] == "Available"
    assert "direct" not in selector_by_tag["Twitch"]["outbounds"]
    # AI membership stays inside the selectors.ai_regions whitelist plus any node
    # a subscription explicitly opts in via ai_include (PPFlight names carry no
    # region keyword, so its nodes are Others and only qualify through the
    # pattern).  The trailing "Other" entry is the cold-region pool selector
    # (selectors.other), not a node — it only routes there when explicitly
    # picked in the panel.
    manifest = simple.load_yaml(ROOT / "config" / "local" / "subscriptions.yaml")
    ai_includes = [
        pattern
        for item in manifest.get("subscriptions", [])
        for pattern in simple.compile_patterns(item.get("ai_include"), "ai_include")
    ]
    ai_members = selector_by_tag["AI"]["outbounds"]
    assert ai_members[-1] == "Other"
    for member in ai_members[:-1]:
        assert simple.detect_region(member) in {"US", "JP", "SG", "TW"} or simple.matches_any(
            ai_includes, member
        ), member
    # Region priority follows the whitelist order: US members lead and the
    # group default is a US node; JP/SG/TW only serve as backup.  ai_include
    # nodes have no whitelist region, so they sort last, right before "Other".
    priority = {"US": 0, "JP": 1, "SG": 2, "TW": 3}
    ordered_regions = [
        r
        for r in (priority.get(simple.detect_region(member)) for member in ai_members[:-1])
        if r is not None
    ]
    assert ordered_regions == sorted(ordered_regions)
    assert simple.detect_region(selector_by_tag["AI"]["default"]) == "US"
    # The cold-region pool holds only Others-region nodes.  It is a member of
    # Available (so it can be picked at all) and of AI (after the whitelist
    # nodes), but NOT of the service groups: those follow Available
    # member-for-member, and every Other node has an unrecognised region.
    other_group = selector_by_tag["Other"]
    assert other_group["outbounds"] and simple.detect_region(other_group["default"]) == "Others"
    assert {simple.detect_region(member) for member in other_group["outbounds"]} == {"Others"}
    assert "Other" in selector_by_tag["Available"]["outbounds"]
    assert "Other" in selector_by_tag["AI"]["outbounds"]
    # The service groups are built from the Available membership captured before
    # Other joins it, so they mirror Available minus that trailing entry.  Other
    # stays reachable through them by being picked inside Available itself.
    declared = {
        str(group["tag"]): str(group.get("direct") or "")
        for group in policy["selectors"]["groups"]
    }
    for tag in ("Emby", "YouTube", "Spotify", "Telegram", "Twitch"):
        expected = list(service_members)
        if declared[tag] == "last":
            expected.append("direct")
        elif declared[tag] == "default":
            expected.insert(0, "direct")
        assert "Other" not in selector_by_tag[tag]["outbounds"], tag
        assert selector_by_tag[tag]["outbounds"] == expected, tag
    # Google Play is referenced only by the Android profile, so the desktop
    # panel must not contain the group.
    assert "Google Play" not in outbound_by_tag
    android_selector_by_tag = {
        item["tag"]: item for item in android["outbounds"] if item.get("type") == "selector"
    }
    assert [item["tag"] for item in android["outbounds"][:10]] == [
        "Available",
        "AI",
        "direct",
        "Other",
        "Emby",
        "YouTube",
        "Spotify",
        "Telegram",
        "Twitch",
        "Google Play",
    ]
    assert android_selector_by_tag["Google Play"]["outbounds"] == selector_by_tag["Telegram"]["outbounds"]
    assert android_selector_by_tag["Google Play"]["default"] == "Available"
    assert outbound_by_tag["Available"]["type"] == "selector"
    assert "providers" not in outbound_by_tag["Available"]
    assert "providers" not in desktop
    for subscription_tag in ("特朗普云", "羽迹"):
        assert "Meow-US" not in outbound_by_tag[subscription_tag]["outbounds"]
    assert desktop["experimental"]["urltest_unified_delay"] is True
    assert outbound_by_tag["Available"]["default"] == outbound_by_tag["Available"]["outbounds"][0]
    assert "fallback" not in outbound_by_tag["Available"]
    assert "clash_api" not in desktop.get("experimental", {})
    assert "services" not in desktop
    # The current manifest uses static expansion so the original node names
    # remain visible in each subscription selector.
    assert len([item for item in desktop["outbounds"] if item.get("type") == "vless"]) >= 4
    assert desktop["experimental"]["cache_file"]["store_dns"] is True
    assert len(desktop["route"]["rules"]) == 33
    assert {
        "domain_suffix": ["emby.kingemby.com", "media.wybcs.work"],
        "action": "route",
        "outbound": "direct",
    } in desktop["route"]["rules"]
    # bbqwq/wawajiao are retired: neither route nor DNS rules may keep them.
    assert not any(
        "emby.bbqwq.com" in simple.as_list(rule.get("domain_suffix") or [])
        or "emby.wawajiao.cc.cd" in simple.as_list(rule.get("domain_suffix") or [])
        for rule in desktop["route"]["rules"]
    )
    assert not any(
        dns_matcher_covers(rule, "domain_suffix", "emby.bbqwq.com")
        or dns_matcher_covers(rule, "domain_suffix", "emby.wawajiao.cc.cd")
        for rule in desktop["dns"]["rules"]
    )
    # Emby group domains resolve through both proxy resolvers.
    emby_group_evaluations = [
        rule
        for rule in desktop["dns"]["rules"]
        if rule.get("action") == "evaluate" and dns_matcher_covers(rule, "rule_set", "emby-domains")
    ]
    assert {rule["server"] for rule in emby_group_evaluations} == {"google-emby", "cloudflare-emby"}
    assert {
        server["detour"] for server in desktop["dns"]["servers"] if server["tag"] in {"google-emby", "cloudflare-emby"}
    } == {"Emby"}
    # The exact folded matcher set depends on the business-rule ordering; the
    # important contract here is that both proxy resolvers cover the Emby host.
    # Response-code matching separates successful answers from NXDOMAIN; only
    # successful answers participate in the race.
    for rule in desktop["dns"]["rules"]:
        if rule.get("action") != "respond" or not str(rule.get("match_response", "")).startswith("failover-"):
            continue
        # Domestic races answer only when the NOERROR is outside the sinkhole set.
        if rule.get("rule_set") == ["domestic-dns-answers"]:
            assert rule.get("race") is True and rule.get("response_rcode") == "NOERROR"
            continue
        assert {"match_response", "action", "response_rcode"}.issubset(rule), rule
        if rule["response_rcode"] == "NOERROR":
            assert rule.get("race") is True
        else:
            assert "race" not in rule
    assert desktop["inbounds"][0]["strict_route"] is True
    assert "route_exclude_address_set" not in desktop["inbounds"][0]
    dns_server_ips = {
        f"{server['server']}/32"
        for server in desktop["dns"]["servers"]
        if simple._is_ip_address(str(server.get("server") or ""))
    }
    # Desktop relies on auto_detect_interface instead of materializing node
    # address exclusions, so DNS server IPs do not need a generated list.
    assert "route_exclude_address" not in desktop["inbounds"][0]
    assert desktop["route"]["auto_detect_interface"] is True
    assert "find_process" not in desktop["route"]
    route_rules = desktop["route"]["rules"]
    hijack_index = next(i for i, rule in enumerate(route_rules) if rule.get("action") == "hijack-dns")
    dns_pin = route_rules[hijack_index + 1]
    assert dns_pin["outbound"] == "direct" and dns_pin["port"] == 443
    assert dns_pin["ip_cidr"] == ["223.5.5.5/32", "1.12.12.12/32"]
    sniff_index = next(i for i, rule in enumerate(route_rules) if rule.get("action") == "sniff")
    assert hijack_index < route_rules.index(dns_pin) < sniff_index
    peer_index = next(i for i, rule in enumerate(route_rules) if rule.get("ip_cidr") == [
        "172.18.0.0/30", "fdfe:dcba:9876::/126"
    ])
    private_index = next(i for i, rule in enumerate(route_rules) if rule.get("ip_is_private"))
    assert hijack_index < peer_index < private_index
    assert route_rules[peer_index]["action"] == "reject"
    assert route_rules[peer_index]["method"] == "drop"
    assert not any("bind_interface" in outbound for outbound in desktop["outbounds"])
    # sing-box 1.15: the built-in sing-tun stack is selected by omitting
    # ``stack``. Provider cache paths are separate per remote source.
    assert "stack" not in desktop["inbounds"][0]
    assert "stack" not in android["inbounds"][0]
    assert "udp_timeout" not in android["inbounds"][0]
    assert "mtu" not in android["inbounds"][0]
    assert "mtu" not in desktop["inbounds"][0]
    assert "udp_timeout" not in desktop["inbounds"][0]
    assert "172.18.0.0/30" not in android["inbounds"][0]["route_exclude_address"]
    assert "172.16.0.0/15" in android["inbounds"][0]["route_exclude_address"]
    assert "172.18.0.4/30" in android["inbounds"][0]["route_exclude_address"]
    assert desktop["experimental"]["urltest_unified_delay"] is True
    assert android["experimental"]["urltest_unified_delay"] is True
    # Optimistic caching serves the stale record immediately and refreshes in
    # the background, so an expired TTL never costs an application a DoH race.
    expected_optimistic = {"enabled": True, "timeout": "3d"}
    assert desktop["dns"]["optimistic"] == expected_optimistic
    assert android["dns"]["optimistic"] == expected_optimistic
    assert desktop["route"]["default_domain_resolver"] == {
        "server": "domestic-bootstrap",
        "timeout": "2s",
    }
    domain_nodes = [
        outbound
        for outbound in desktop["outbounds"]
        if outbound.get("server") and not simple._is_ip_address(str(outbound["server"]))
    ]
    assert domain_nodes
    assert all(node["domain_resolver"] == {"server": "domestic-bootstrap", "timeout": "2s"} for node in domain_nodes)
    assert desktop["dns"]["cache_capacity"] == 4096
    assert desktop["dns"]["min_cache_ttl"] == 60
    assert desktop["dns"]["max_cache_ttl"] == 1800
    bootstrap = next(server for server in desktop["dns"]["servers"] if server.get("tag") == "domestic-bootstrap")
    assert bootstrap == {"type": "group", "tag": "domestic-bootstrap", "servers": ["domestic", "domestic-backup"]}
    assert not any("initial_path" in item for item in desktop["route"]["rule_set"])
    china_rule_set = next(item for item in desktop["route"]["rule_set"] if item.get("tag") == "china-direct")
    assert china_rule_set["tag"] == "china-direct"
    assert china_rule_set["type"] == "inline"
    assert china_rule_set["rules"]
    assert "path" not in china_rule_set
    assert "format" not in china_rule_set
    assert len(android["route"]["rules"]) == 33
    # B 站 PCDN（MCDN）取流节点必须被拒：手机端 playurl 的主地址和第一备用
    # 都是这类节点（os=mcdn，8082/4483 端口），走 TUN 时对传建不起来会卡住
    # 播放器；拒掉后播放器改用已签发的普通 CDN 备用地址（upos-*，443）。
    # 规则必须排在 china-direct 之前——mcdn.bilivideo.cn 本身命中 bilivideo.cn。
    pcdn_index = next(
        i
        for i, rule in enumerate(desktop["route"]["rules"])
        if rule.get("action") == "reject" and dns_matcher_covers(rule, "domain_suffix", "mcdn.bilivideo.cn")
    )
    china_direct_index = next(
        i for i, rule in enumerate(desktop["route"]["rules"]) if rule.get("rule_set") == ["china-direct"]
    )
    assert pcdn_index < china_direct_index
    for suffix in ("mcdn.bilivideo.cn", "mcdn.bilivideo.com", "szbdyd.com", "edge.mountaintoys.cn"):
        assert dns_matcher_covers(desktop["route"]["rules"][pcdn_index], "domain_suffix", suffix)
        # 同一个 reject 规则会推导出同序的 NXDOMAIN，取流地址连解析都拿不到。
        assert any(
            rule.get("action") == "predefined"
            and rule.get("rcode") == "NXDOMAIN"
            and dns_matcher_covers(rule, "domain_suffix", suffix)
            for rule in desktop["dns"]["rules"]
        )
    assert any(rule.get("rule_set") == ["geosite-telegram"] and rule.get("outbound") == "Telegram" for rule in desktop["route"]["rules"])
    assert any(rule.get("rule_set") == ["geosite-twitch"] and rule.get("outbound") == "Twitch" for rule in desktop["route"]["rules"])
    assert any(
        "91.105.192.0/23" in simple.as_list(rule.get("ip_cidr") or [])
        and "91.108.4.0/22" in simple.as_list(rule.get("ip_cidr") or [])
        and rule.get("outbound") == "Telegram"
        for rule in desktop["route"]["rules"]
    )
    assert any(rule.get("rule_set") == ["spotify-direct"] and rule.get("outbound") == "Spotify" for rule in desktop["route"]["rules"])
    # AI vendor coverage: Anthropic's newer domains (claude.com etc.) and the
    # shared Turnstile/Arkose auth endpoints must ride the AI group. Letting
    # them fall through to geolocation-!cn would exit via Available, whose
    # default node sits in an unsupported region (HK) for Claude/ChatGPT.
    ai_route_rule = next(rule for rule in desktop["route"]["rules"] if rule.get("outbound") == "AI")
    assert ai_route_rule["rule_set"] == ["geosite-anthropic", "geosite-openai", "ai-domains"]
    assert {
        rule["server"]
        for rule in desktop["dns"]["rules"]
        if rule.get("action") == "evaluate" and dns_matcher_covers(rule, "rule_set", "geosite-anthropic")
    } == {"google-ai", "cloudflare-ai"}
    ai_domain_rule_set = next(item for item in desktop["route"]["rule_set"] if item.get("tag") == "ai-domains")
    ai_suffixes = ai_domain_rule_set["rules"][0]["domain_suffix"]
    assert {
        "claude.com",
        "claude.dev",
        "clau.de",
        "claudemcpclient.com",
        "claudemcpcontent.com",
        "challenges.cloudflare.com",
        "client-api.arkoselabs.com",
    } <= set(ai_suffixes)
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
            "google.com",
            "google.com.hk",
            "gmail.com",
            "gstatic.com",
            "googleapis.com",
            "googleusercontent.com",
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
    assert all(rule.get("rewrite_ttl") == 60 and rule.get("remove_client_subnet") is True for rule in youtube_evaluations)
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
    } == {"google-telegram", "cloudflare-telegram"}
    assert {
        server["detour"]
        for server in desktop["dns"]["servers"]
        if server["tag"] in {"google-telegram", "cloudflare-telegram"}
    } == {"Telegram"}
    # Google Play exists only on Android, so its resolvers must not detour a
    # missing outbound on desktop.
    assert not any(server.get("detour") == "Google Play" for server in desktop["dns"]["servers"])
    assert {
        server["detour"] for server in android["dns"]["servers"] if server["tag"] in {"google-play", "cloudflare-play"}
    } == {"Google Play"}
    assert {
        rule["server"]
        for rule in android["dns"]["rules"]
        if rule.get("action") == "evaluate" and dns_matcher_covers(rule, "package_name", "com.android.vending")
    } == {"google-play", "cloudflare-play"}
    play_suffixes = next(
        item["rules"][0]["domain_suffix"]
        for item in android["route"]["rule_set"]
        if item.get("tag") == "google-play"
    )
    assert "play-lh.googleusercontent.com" in play_suffixes
    assert "googleusercontent.com" not in play_suffixes
    # Twitch resolves through resolvers detoured via the Twitch selector, same
    # rationale as YouTube: stream edges follow the egress region.
    twitch_evaluations = [
        rule
        for rule in desktop["dns"]["rules"]
        if rule.get("action") == "evaluate" and dns_matcher_covers(rule, "rule_set", "geosite-twitch")
    ]
    assert {rule["server"] for rule in twitch_evaluations} == {"google-twitch", "cloudflare-twitch"}
    assert {
        server["detour"] for server in desktop["dns"]["servers"] if server["tag"] in {"google-twitch", "cloudflare-twitch"}
    } == {"Twitch"}
    assert next(outbound for outbound in android["outbounds"] if outbound["tag"] == "Available")["type"] == "selector"
    assert any(
        rule.get("rule_set") == "google-play" and rule.get("outbound") == "Google Play"
        for rule in android["route"]["rules"]
    )
    assert any(
        "com.android.vending" in simple.as_list(rule.get("package_name") or [])
        and rule.get("outbound") == "Google Play"
        for rule in android["route"]["rules"]
    )
    assert not any("/Auto" in str(outbound.get("tag") or "") for outbound in [*desktop["outbounds"], *android["outbounds"]])
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


def test_subscription_groups_are_manual_selectors(tmp_path):
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
""",
        encoding="utf-8",
    )
    sources = simple.load_sources(
        manifest,
        {"subscription": {}},
        offline=False,
        fetch_proxy=None,
    )
    assert sources[0].entry_tag == "Provider"
    assert sources[0].node_tags == ["Provider/US-One", "Provider/HK-Two"]
    # Subscription groups are intentionally manual selectors; there is no
    # implicit ``*/Auto`` urltest group.
    assert [group["tag"] for group in sources[0].groups] == ["Provider"]
    assert all(group["type"] == "selector" for group in sources[0].groups)


def test_legacy_urltest_field_is_rejected(tmp_path):
    source = tmp_path / "provider.txt"
    source.write_text(
        "vless" + "://11111111-1111-1111-1111-111111111111@one.example:443?security=tls&sni=one.example#US-One",
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
    with pytest.raises(ValueError, match="不支持的旧订阅字段: urltest"):
        simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)


def test_remote_subscription_builds_stable_provider_cache_and_filters(tmp_path):
    url_file = tmp_path / "source.url.txt"
    url_file.write_text("https://example.invalid/subscription", encoding="utf-8")
    source_file = tmp_path / "source.json"
    source_file.write_text(
        json.dumps({"outbounds": [
            {"type": "vless", "tag": "One", "server": "one.example", "server_port": 443, "uuid": "one"},
            {"type": "vless", "tag": "Two", "server": "two.example", "server_port": 443, "uuid": "two"},
        ]}),
        encoding="utf-8",
    )
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: 测试订阅
    format: singbox-json
    source: url_file
    path: source.url.txt
    group: Test
    exclude: [过期]
    exclude_node_tags: [剩余流量]
""",
        encoding="utf-8",
    )
    # The fetched body is independently supplied by the existing generator.
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(simple, "download_text", lambda *_args, **_kwargs: source_file.read_text(encoding="utf-8"))
    try:
        sources = simple.load_sources(
            manifest,
            {"subscription": {"cache_max_age": "1d"}, "providers": {"update_interval": "12h"}},
            offline=False,
            fetch_proxy=None,
        )
    finally:
        monkeypatch.undo()

    provider = sources[0].provider
    assert provider["type"] == "remote"
    assert provider["tag"].startswith("provider-")
    assert provider["path"].startswith("providers/")
    assert provider["update_interval"] == "12h"
    assert "过期" in provider["exclude"] and "剩余流量" in provider["exclude"]


def test_remote_provider_is_enabled_for_both_platforms_and_stays_in_group():
    bootstrap = simple.BuiltSource(
        name="bootstrap",
        order=1,
        entry_tag="Bootstrap",
        node_tags=["Bootstrap"],
        nodes=[{
            "type": "vless",
            "tag": "Bootstrap",
            "server": "bootstrap.example",
            "server_port": 443,
            "uuid": "bootstrap",
            "tls": {"enabled": True, "server_name": "bootstrap.example"},
        }],
        groups=[],
        ai_node_tags=["Bootstrap"],
    )
    source = simple.BuiltSource(
        name="airport",
        order=10,
        entry_tag="Airport",
        node_tags=["Airport/One", "Airport/Two"],
        nodes=[
            {"type": "vless", "tag": "Airport/One", "server": "one.example", "server_port": 443, "uuid": "one"},
            {"type": "vless", "tag": "Airport/Two", "server": "two.example", "server_port": 443, "uuid": "two"},
        ],
        groups=[{"type": "selector", "tag": "Airport", "outbounds": ["Airport/One", "Airport/Two"], "default": "Airport/One"}],
        ai_node_tags=["Airport/One"],
        provider={
            "type": "remote",
            "tag": "provider-airport-12345678",
            "url": "https://example.invalid/subscription",
            "path": "providers/airport-12345678.json",
            "update_interval": "24h",
        },
    )
    policy = {
        "providers": {"enabled": True},
        "selectors": {"available": "Available", "ai": "AI", "direct": "direct", "emby": "Emby", "youtube": "YouTube"},
    }
    custom = {"schema_version": 1}

    desktop = simple.build_config("desktop", policy, {"platform": "desktop"}, custom, [bootstrap, source])
    android = simple.build_config("android", policy, {"platform": "android"}, custom, [bootstrap, source])

    available = next(item for item in desktop["outbounds"] if item.get("tag") == "Available")
    assert available["type"] == "selector"
    assert "providers" not in available
    assert available["outbounds"] == ["Bootstrap", "Airport"]
    assert available["default"] == "Bootstrap"
    assert "fallback" not in available
    for config in (desktop, android):
        provider = config["providers"][0]
        assert {key: provider[key] for key in source.provider} == source.provider
        assert provider["http_client"] == {"detour": "Bootstrap"}
    assert next(item for item in desktop["outbounds"] if item.get("tag") == "Airport")["providers"] == ["provider-airport-12345678"]
    assert next(item for item in android["outbounds"] if item.get("tag") == "Airport")["providers"] == ["provider-airport-12345678"]


def test_available_manually_selects_subscription_group_and_standalone_node():
    grouped = simple.BuiltSource(
        name="airport",
        order=10,
        entry_tag="Airport",
        node_tags=["Airport/One", "Airport/Two"],
        nodes=[{"type": "direct", "tag": "Airport/One"}, {"type": "direct", "tag": "Airport/Two"}],
        groups=[{"type": "selector", "tag": "Airport", "outbounds": ["Airport/One", "Airport/Two"]}],
        ai_node_tags=[],
    )
    standalone = simple.BuiltSource(
        name="single",
        order=20,
        entry_tag="Single",
        node_tags=["Single"],
        nodes=[{"type": "direct", "tag": "Single"}],
        groups=[],
        ai_node_tags=[],
    )
    outbounds = simple.build_outbounds(
        [grouped, standalone],
        {"providers": {"enabled": True}},
        {"platform": "android"},
    )
    available = next(item for item in outbounds if item["tag"] == "Available")
    assert available["type"] == "selector"
    assert available["outbounds"] == ["Airport", "Single"]
    assert available["default"] == "Airport"
    assert next(item for item in outbounds if item["tag"] == "Airport")["type"] == "selector"


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
    assert simple.is_placeholder_node({"server": "Dont.use.this.node", "server_port": 8888})
    assert not simple.is_placeholder_node({"server": "real.example", "server_port": 443})
    assert not simple.is_placeholder_node({"server": "192.168.1.10", "server_port": 8443})


def test_provider_can_keep_all_named_nodes_with_dedup_disabled(tmp_path):
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
def test_custom_rules_are_inserted_between_pre_rules_and_business():
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    sources = simple.load_sources(
        ROOT / "config" / "local" / "subscriptions.yaml",
        policy,
        offline=False,
        fetch_proxy=None,
    )
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


def test_ssh_port_is_routed_direct_after_the_pre_rule_guards():
    """Port 22 must bypass route.final (Available), whose proxy exits drop it.

    The rule has to sit after the IPv6 and TUN-address rejects so those still
    win, and it must not carry ``ip_version: 4``: that matcher only compares
    literal addresses, so a domain destination (``ssh host``) would slip past
    it and fall through to the proxy exit.
    """
    conf: dict = {}
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    simple.assemble_rules(
        conf,
        policy,
        simple.load_yaml(ROOT / "config" / "profiles" / "desktop.yaml"),
        {"schema_version": 1},
        layout=simple.build_dns_layout(policy),
    )
    rules = conf["route"]["rules"]

    ssh_index = next(
        i
        for i, rule in enumerate(rules)
        if rule.get("port") == 22 and rule.get("action") == "route"
    )
    assert rules[ssh_index] == {"port": 22, "action": "route", "outbound": "direct"}

    # The IPv6 and TUN-self rejects must still match before the direct rule.
    ipv6_reject = next(i for i, rule in enumerate(rules) if rule.get("ip_version") == 6)
    tun_reject = next(
        i
        for i, rule in enumerate(rules)
        if rule.get("ip_cidr") == ["172.18.0.0/30", "fdfe:dcba:9876::/126"]
    )
    assert ipv6_reject < ssh_index
    assert tun_reject < ssh_index
    # It must still beat every domain-based rule: a proxy exit that drops :22
    # would otherwise be chosen for a host whose domain matches a later rule.
    business_index = next(
        i for i, rule in enumerate(rules) if rule.get("rule_set") == ["geosite-geolocation-!cn"]
    )
    assert ssh_index < business_index


@requires_local
def test_generated_json_contains_no_legacy_download_detour(tmp_path):
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
        "selectors": {"available": "Available", "ai": "AI", "direct": "direct"},
        "dns_upstreams": SINGLE_UPSTREAMS,
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
        "selectors": {"available": "Available", "ai": "AI", "direct": "direct"},
        "dns_upstreams": SINGLE_UPSTREAMS,
    }
    managed = {
        "schema_version": 1,
        "groups": [{"tag": "AI", "outbounds": [], "domains": ["domain_suffix:openai.com"]}],
    }
    conf = simple.build_config("desktop", policy, {"platform": "desktop"}, {"schema_version": 1}, [source], managed)
    assert {"domain_suffix": ["openai.com"], "action": "route", "server": "google"} in conf["dns"]["rules"]


def test_derived_dns_rules_are_skipped_when_no_upstreams_declared():
    rules = simple.build_managed_rules({"groups": [{"tag": "direct", "domains": ["domain_suffix:deepseek.com"]}]})
    assert rules == [{"domain_suffix": ["deepseek.com"], "action": "route", "outbound": "direct"}]
    assert simple.derive_dns_rules(rules, simple.build_dns_layout({})) == []


def test_derived_dns_rules_follow_outbound_resolvers():
    layout = simple.build_dns_layout(
        {"dns_upstreams": {**SINGLE_UPSTREAMS, "proxy_detours": {"Available": "", "AI": "ai"}}}
    )
    assert [server["tag"] for server in layout.servers] == ["domestic", "google", "google-ai"]
    assert next(server for server in layout.servers if server["tag"] == "google-ai")["detour"] == "AI"
    assert "detour" not in layout.servers[0]
    dns = simple.derive_dns_rules(
        [
            {"domain_suffix": ["deepseek.com"], "action": "route", "outbound": "direct"},
            {"domain_suffix": ["openai.com"], "action": "route", "outbound": "AI"},
            # Outbounds without a dedicated resolver use the Available one.
            {"domain_suffix": ["emby.example"], "action": "route", "outbound": "Emby"},
            {"rule_set": ["spotify"], "action": "route", "outbound": "Spotify", "dns": "domestic"},
            {"rule_set": ["ads"], "action": "reject"},
            {"rule_set": ["geoip-cn"], "action": "route", "outbound": "direct", "dns": False},
            {"ip_cidr": ["1.2.3.0/24"], "action": "route", "outbound": "direct"},
            {"process_name": ["app.exe"], "action": "route", "outbound": "Available"},
            {"action": "sniff"},
        ],
        layout,
    )
    assert dns == [
        {"domain_suffix": ["deepseek.com"], "action": "route", "server": "domestic"},
        {"domain_suffix": ["openai.com"], "action": "route", "server": "google-ai"},
        {"domain_suffix": ["emby.example"], "action": "route", "server": "google"},
        {"rule_set": ["spotify"], "action": "route", "server": "domestic"},
        {"rule_set": ["ads"], "action": "predefined", "rcode": "NXDOMAIN"},
        {"process_name": ["app.exe"], "action": "route", "server": "google"},
    ]


def test_proxy_detour_skips_optional_groups_and_rejects_unknown():
    policy = {
        "selectors": {"groups": [{"tag": "Google Play", "when_referenced": True}]},
        "dns_upstreams": {**SINGLE_UPSTREAMS, "proxy_detours": {"Available": "", "Google Play": "play"}},
    }
    layout = simple.build_dns_layout(policy, {"Available", "direct"})
    assert {server["tag"] for server in layout.servers} == {"domestic", "google"}
    policy["dns_upstreams"] = {**policy["dns_upstreams"], "proxy_detours": {"Available": "", "Missing": "x"}}
    with pytest.raises(ValueError, match="不存在的出站: Missing"):
        simple.build_dns_layout(policy, {"Available", "direct"})


def test_proxy_detour_rejects_colliding_suffixes():
    """Two detours sharing a suffix would render the same tag twice.

    The core keeps whichever server it saw first, so a dns rule naming the
    intended exit would quietly resolve through another one — a far-away CDN
    edge, or a domestic answer handed to proxied traffic.  Nothing downstream
    can detect it, so the generator refuses to render the config.
    """
    policy = {
        "dns_upstreams": {
            **SINGLE_UPSTREAMS,
            "proxy_detours": {"Available": "", "YouTube": "dup", "Twitch": "dup"},
        }
    }
    with pytest.raises(ValueError, match="重复的 DNS server tag: google-dup"):
        simple.build_dns_layout(policy, {"Available", "YouTube", "Twitch"})
    # Distinct suffixes still render fine.
    policy["dns_upstreams"]["proxy_detours"] = {"Available": "", "YouTube": "yt", "Twitch": "tw"}
    tags = [server["tag"] for server in simple.build_dns_layout(policy, {"Available", "YouTube", "Twitch"}).servers]
    assert tags == ["domestic", "google", "google-yt", "google-tw"]


def test_derived_dns_rejects_mixed_route_only_matchers():
    layout = simple.build_dns_layout({"dns_upstreams": SINGLE_UPSTREAMS})
    with pytest.raises(ValueError, match="dns: false"):
        simple.derive_dns_rules(
            [{"domain_suffix": ["a.com"], "port": [443], "action": "route", "outbound": "direct"}], layout
        )


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
        "respond",
        "respond",
        "predefined",
    ]
    assert [rule.get("server") for rule in rules[:2]] == ["primary", "backup"]
    assert all(rule["timeout"] == "1500ms" for rule in rules[:2])
    assert all(rule["domain_suffix"] == ["example.com"] for rule in (rules[0], rules[1], rules[-1]))
    assert rules[2] == {
        "match_response": "failover-1-primary",
        "response_rcode": "NOERROR",
        "action": "respond",
        "race": True,
    }
    assert rules[3] == {
        "match_response": "failover-1-backup",
        "response_rcode": "NOERROR",
        "action": "respond",
        "race": True,
    }
    assert rules[4] == {
        "match_response": "failover-1-primary",
        "response_rcode": "NXDOMAIN",
        "action": "respond",
    }
    assert rules[5] == {
        "match_response": "failover-1-backup",
        "response_rcode": "NXDOMAIN",
        "action": "respond",
    }
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


def test_dns_final_race_is_appended_last():
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
        "selectors": {"available": "Available", "ai": "AI", "direct": "direct"},
        "dns_upstreams": {
            "domestic": [{"tag": "cn", "server": "223.5.5.5", "server_name": "dns.alidns.com"}],
            "proxy": [
                {"tag": "google", "server": "8.8.8.8", "server_name": "dns.google"},
                {"tag": "cloudflare", "server": "1.1.1.1", "server_name": "cloudflare-dns.com"},
            ],
            "proxy_detours": {"Available": ""},
        },
        "config": {"dns": {"final": "google"}},
        "route": {
            "business_rules": [{"domain_suffix": ["a.cn"], "action": "route", "outbound": "direct"}],
            # Same resolver as dns.final: folded into the trailing catch-all race.
            "domestic_rules": [{"rule_set": ["foreign"], "action": "route", "outbound": "Available"}],
        },
        "rule_sets": [{"tag": "foreign", "type": "inline", "rules": [{"domain_suffix": ["a.com"]}]}],
    }
    conf = simple.build_config(
        "desktop",
        policy,
        {"platform": "desktop"},
        {"schema_version": 1},
        [source],
    )
    rules = conf["dns"]["rules"]
    assert rules[0] == {"domain_suffix": ["a.cn"], "action": "route", "server": "cn"}
    # Unknown domains race both proxy resolvers and never reach the domestic one.
    assert rules[1:] == [
        {
            "action": "evaluate",
            "server": "google",
            "tag": "failover-1-google",
            "timeout": "2s",
            "remove_client_subnet": True,
        },
        {
            "action": "evaluate",
            "server": "cloudflare",
            "tag": "failover-1-cloudflare",
            "timeout": "2s",
            "remove_client_subnet": True,
        },
        {"match_response": "failover-1-google", "response_rcode": "NOERROR", "action": "respond", "race": True},
        {"match_response": "failover-1-cloudflare", "response_rcode": "NOERROR", "action": "respond", "race": True},
        {"match_response": "failover-1-google", "response_rcode": "NXDOMAIN", "action": "respond"},
        {"match_response": "failover-1-cloudflare", "response_rcode": "NXDOMAIN", "action": "respond"},
        {"action": "predefined", "rcode": "SERVFAIL"},
    ]
    assert {server["detour"] for server in conf["dns"]["servers"] if server["tag"] in {"google", "cloudflare"}} == {
        "Available"
    }


def test_dns_race_strips_ecs_caps_proxy_ttl_and_drops_domestic_sinkholes():
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
        "selectors": {"available": "Available", "ai": "AI", "direct": "direct"},
        "dns_upstreams": {
            "timeout": "2s",
            "proxy_rewrite_ttl": 60,
            "domestic_reject_answers": ["0.0.0.0/32", "10.0.0.0/8"],
            "domestic": [
                {"tag": "domestic", "server": "223.5.5.5", "server_name": "dns.alidns.com"},
                {"tag": "domestic-backup", "server": "1.12.12.12", "server_name": "doh.pub"},
            ],
            "proxy": [
                {"tag": "google", "server": "8.8.8.8", "server_name": "dns.google"},
                {"tag": "cloudflare", "server": "1.1.1.1", "server_name": "cloudflare-dns.com"},
            ],
            "proxy_detours": {"Available": ""},
        },
        "config": {"dns": {"final": "google"}},
        "route": {
            "pre_rules": [
                {"port": 53, "action": "hijack-dns"},
                {"action": "sniff", "timeout": "300ms"},
            ],
            "domestic_rules": [
                {"domain_suffix": ["a.cn"], "action": "route", "outbound": "direct"},
                {"domain_suffix": ["a.com"], "action": "route", "outbound": "Available"},
            ],
        },
    }
    conf = simple.build_config("desktop", policy, {"platform": "desktop"}, {"schema_version": 1}, [source])
    route_rules = conf["route"]["rules"]
    assert route_rules[0]["action"] == "hijack-dns"
    assert route_rules[1] == {
        "port": 443,
        "ip_cidr": ["223.5.5.5/32", "1.12.12.12/32"],
        "action": "route",
        "outbound": "direct",
    }
    assert route_rules[2]["action"] == "sniff"
    assert "8.8.8.8/32" not in route_rules[1]["ip_cidr"]

    domestic = next(
        rule for rule in conf["dns"]["rules"]
        if rule.get("action") == "respond" and rule.get("match_response") == "failover-1-domestic"
    )
    assert domestic == {
        "match_response": "failover-1-domestic",
        "response_rcode": "NOERROR",
        "rule_set": ["domestic-dns-answers"],
        "action": "respond",
        "race": True,
    }
    answer_set = next(item for item in conf["route"]["rule_set"] if item.get("tag") == "domestic-dns-answers")
    assert answer_set["rules"] == [{"ip_cidr": ["0.0.0.0/32", "10.0.0.0/8"], "invert": True}]
    proxy = next(
        rule for rule in conf["dns"]["rules"]
        if rule.get("action") == "respond" and rule.get("match_response") == "failover-2-google"
    )
    assert proxy == {
        "match_response": "failover-2-google",
        "response_rcode": "NOERROR",
        "action": "respond",
        "race": True,
    }
    proxy_query = next(rule for rule in conf["dns"]["rules"] if rule.get("tag") == "failover-2-google")
    assert proxy_query["rewrite_ttl"] == 60 and proxy_query["remove_client_subnet"] is True
    domestic_query = next(rule for rule in conf["dns"]["rules"] if rule.get("tag") == "failover-1-domestic")
    assert "rewrite_ttl" not in domestic_query and domestic_query["remove_client_subnet"] is True

    policy["dns_upstreams"]["domestic_reject_answers"] = ["not-a-prefix"]
    with pytest.raises(ValueError, match="domestic_reject_answers"):
        simple.build_config("desktop", policy, {"platform": "desktop"}, {"schema_version": 1}, [source])


def test_profiles_reject_hand_written_dns_rules():
    with pytest.raises(ValueError, match="dns_rules_front"):
        simple.assemble_rules({}, {}, {"dns_rules_front": []}, {})


def test_china_domain_rules_precede_foreign_fallbacks():
    """New Chinese TLDs stay direct even before remote geosite updates."""
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    route_rules = policy["route"]["domestic_rules"]

    route_suffix_rule = next(rule for rule in route_rules if rule.get("domain_suffix") == ["cn", "xn--fiqs8s"])
    route_cn_index = next(i for i, rule in enumerate(route_rules) if rule.get("rule_set") == ["geosite-cn"])
    route_foreign_index = next(i for i, rule in enumerate(route_rules) if rule.get("rule_set") == ["geosite-geolocation-!cn"])

    assert route_suffix_rule["outbound"] == "direct"
    assert "dns" not in route_suffix_rule
    assert route_cn_index < route_foreign_index


def test_route_follows_official_sets_and_kernel_defaults():
    """Playback domains, Telegram DCs and TUN defaults follow upstream, not stale local copies."""
    policy = simple.load_yaml(ROOT / "config" / "policy.yaml")
    source = simple.BuiltSource(
        name="node",
        order=1,
        entry_tag="US-One",
        node_tags=["US-One"],
        nodes=[{"type": "direct", "tag": "US-One"}],
        groups=[],
        ai_node_tags=["US-One"],
    )
    empty = {"schema_version": 1}
    desktop = simple.build_config(
        "desktop", policy, simple.load_yaml(ROOT / "config" / "profiles" / "desktop.yaml"), empty, [source]
    )
    android = simple.build_config(
        "android", policy, simple.load_yaml(ROOT / "config" / "profiles" / "android.yaml"), empty, [source]
    )

    for conf in (desktop, android):
        inbound = conf["inbounds"][0]
        assert "mtu" not in inbound
        assert "udp_timeout" not in inbound
        assert "stack" not in inbound
        assert conf["log"]["level"] == "warn"
        assert "disabled" not in conf["log"]

    rules = desktop["route"]["rules"]
    youtube = next(rule for rule in rules if rule.get("outbound") == "YouTube" and rule.get("domain_suffix"))
    youtube_set = next(rule for rule in rules if rule.get("rule_set") == ["geosite-youtube"])
    google = next(rule for rule in rules if rule.get("domain_suffix") and "googleapis.com" in rule["domain_suffix"])
    assert rules.index(youtube) < rules.index(youtube_set) < rules.index(google)
    for name in (
        "googlevideo.com",
        "ggpht.com",
        "yt3.googleusercontent.com",
        "youtubeembeddedplayer.googleapis.com",
        "wide-youtube.l.google.com",
    ):
        assert name in youtube["domain_suffix"]
    assert "ggpht.com" not in google["domain_suffix"]
    assert {"google.com", "google.com.hk", "gmail.com"} <= set(google["domain_suffix"])
    ai_index = next(i for i, rule in enumerate(rules) if rule.get("outbound") == "AI")
    assert ai_index < rules.index(google)

    telegram = next(rule for rule in rules if rule.get("outbound") == "Telegram" and rule.get("ip_cidr"))
    assert "91.105.192.0/23" in telegram["ip_cidr"]
    assert not any("/" in item and ":" in item.split("/")[0] for item in telegram["ip_cidr"])

    china = next(item for item in desktop["route"]["rule_set"] if item.get("tag") == "china-direct")
    china_names = china["rules"][0]["domain_suffix"]
    assert china_names
    assert not any(name == "cn" or name.endswith(".cn") for name in china_names)
    assert "bilibili.com" in china_names and "bilivideo.cn" not in china_names

    spotify = next(item for item in desktop["route"]["rule_set"] if item.get("tag") == "spotify-direct")
    spotify_names = set(spotify["rules"][0]["domain_suffix"])
    assert {
        "spotifycdn.net",
        "audio4-ak-spotify-com.akamaized.net",
        "audio-akp-spotify-com.akamaized.net",
    } <= spotify_names
    cdn = next(item for item in desktop["route"]["rule_set"] if item.get("tag") == "direct-cdn")
    assert "steamcdn-a.akamaihd.net" in cdn["rules"][0]["domain_suffix"]
    assert "akamaihd.net" not in cdn["rules"][0]["domain_suffix"]

    remote_tags = [
        tag
        for item in desktop["route"]["rule_set"]
        if item.get("type") == "remote"
        for tag in simple.rule_set_tags(item)
    ]
    assert "geosite-youtube" in remote_tags

    pcdn = next(
        i
        for i, rule in enumerate(rules)
        if rule.get("action") == "reject" and "mcdn.bilivideo.cn" in simple.as_list(rule.get("domain_suffix"))
    )
    cn_suffix = next(i for i, rule in enumerate(rules) if rule.get("domain_suffix") == ["cn", "xn--fiqs8s"])
    assert pcdn < cn_suffix


CLASH_WITH_HOSTS = """
hosts:
  node.example.com: real.example.net
  chain.example.com: node.example.com
proxies:
  - name: HK
    type: trojan
    server: node.example.com
    port: 443
    password: secret
    sni: cover.example
    skip-cert-verify: true
  - name: Chained
    type: trojan
    server: chain.example.com
    port: 8443
    password: secret
    sni: cover.example
    skip-cert-verify: true
"""


def test_use_hosts_rewrites_only_the_marked_clash_subscription(tmp_path):
    (tmp_path / "west.yaml").write_text(CLASH_WITH_HOSTS, encoding="utf-8")
    (tmp_path / "plain.yaml").write_text(
        CLASH_WITH_HOSTS.replace("name: HK", "name: PlainHK").replace("name: Chained", "name: PlainChain"),
        encoding="utf-8",
    )
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: west
    format: clash
    source: file
    path: west.yaml
    provider: false
    group: West
    prefix_node_tags: false
    allow_insecure: true
    use_hosts: true
  - name: plain
    format: clash
    source: file
    path: plain.yaml
    provider: false
    group: Plain
    prefix_node_tags: false
    allow_insecure: true
""",
        encoding="utf-8",
    )
    sources = simple.load_sources(
        manifest,
        {"subscription": {}, "node_dns_resolver": {"server": "domestic", "timeout": "2s"}},
        offline=False,
        fetch_proxy=None,
    )
    by_name = {source.name: source for source in sources}
    west = {node["tag"]: node for node in by_name["west"].nodes}
    plain = {node["tag"]: node for node in by_name["plain"].nodes}
    assert west["HK"]["server"] == "real.example.net"
    assert west["Chained"]["server"] == "real.example.net"
    assert west["HK"]["tls"]["server_name"] == "cover.example"
    assert west["HK"]["domain_resolver"] == {"server": "domestic", "timeout": "2s"}
    assert plain["PlainHK"]["server"] == "node.example.com"
    assert plain["PlainChain"]["server"] == "chain.example.com"


def test_use_hosts_rejects_non_clash_subscription(tmp_path):
    (tmp_path / "node.json").write_text(
        json.dumps({"outbounds": [{"type": "vless", "tag": "One", "server": "one.example", "server_port": 443, "uuid": "one"}]}),
        encoding="utf-8",
    )
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_text(
        """schema_version: 1
subscriptions:
  - name: local
    format: singbox-json
    source: file
    path: node.json
    provider: false
    use_hosts: true
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="use_hosts 只适用于 clash 订阅"):
        simple.load_sources(manifest, {"subscription": {}}, offline=False, fetch_proxy=None)

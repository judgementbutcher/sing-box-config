import json
from pathlib import Path

from singbox_config.generator import generate_configs
from parsers.common import detect_region
from singbox_config.audit import is_proxy_outbound


def make_node(tag: str, index: int) -> dict:
    return {
        "type": "vless",
        "tag": tag,
        "server": f"node-{index}.example",
        "server_port": 443,
        "uuid": f"00000000-0000-0000-0000-{index:012d}",
        "tls": {"enabled": True, "server_name": f"node-{index}.example"},
    }


def write_template(
    path: Path,
    *,
    github_direct_rule: bool = False,
    accelerator_direct_rule: bool = False,
    cn_rule_set: bool = False,
) -> None:
    route_rules = []
    if github_direct_rule:
        route_rules.append(
            {
                "ip_cidr": ["185.199.108.0/22", "154.17.2.113/32"],
                "action": "route",
                "outbound": "direct",
                "tls_record_fragment": True,
            }
        )
    if accelerator_direct_rule:
        route_rules.append(
            {
                "process_name": [
                    "GuGuai.exe",
                    "guguai.exe",
                    "guguaiwebhelper.exe",
                    "XunYou.exe",
                    "xunyou.exe",
                    "xunyouservice.exe",
                    "xyaccelerator.exe",
                    "UUAccelerator.exe",
                    "uu.exe",
                    "uuassistant.exe",
                    "uuservice.exe",
                    "Leigod.exe",
                    "leigod.exe",
                    "leigodacc.exe",
                    "leigodservice.exe",
                    "Qiyou.exe",
                    "qiyou.exe",
                    "qiyouservice.exe",
                    "biubiu.exe",
                    "biubiuhelper.exe",
                    "biubiuservice.exe",
                    "AKAccelerator.exe",
                    "akaccelerator.exe",
                    "AKService.exe",
                    "Booster.exe",
                    "GameBooster.exe",
                    "WattToolkit.exe",
                ],
                "action": "route",
                "outbound": "direct",
            }
        )
    dns_rules = []
    route_rule_set = []
    if cn_rule_set:
        # Mirror the real template's trailing China rule-sets so ordering and
        # download-convention cloning can be exercised.
        route_rule_set = [
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://example.invalid/geosite-cn.srs",
                "update_interval": "1d",
                "download_detour": "Available",
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://example.invalid/geoip-cn.srs",
                "update_interval": "1d",
                "download_detour": "Available",
            },
        ]
        dns_rules = [{"rule_set": ["geosite-cn"], "action": "route", "server": "local"}]
    path.write_text(
        json.dumps(
            {
                "log": {"disabled": True},
                "dns": {
                    "servers": [
                        {"type": "https", "tag": "remote", "detour": "Available"},
                        {"type": "https", "tag": "google", "detour": "Available"},
                        {"type": "udp", "tag": "local", "server": "223.5.5.5"},
                    ],
                    "rules": dns_rules,
                },
                "inbounds": [
                    {"type": "tun", "tag": "tun-in", "address": ["172.18.0.1/30"]},
                    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
                ],
                "route": {"rules": route_rules, "rule_set": route_rule_set, "final": "Available"},
                "experimental": {"cache_file": {"enabled": True, "path": "cache.db"}},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def write_manifest(
    path: Path,
    nodes: list[dict],
    *,
    self_nodes: list[dict] | None = None,
    include_self_in_ai: bool = False,
) -> None:
    subscription = path.parent / "subscription.json"
    subscription.write_text(json.dumps({"outbounds": nodes}, ensure_ascii=False), encoding="utf-8")
    self_subscription = path.parent / "self.json"
    if self_nodes is not None:
        self_subscription.write_text(json.dumps({"outbounds": self_nodes}, ensure_ascii=False), encoding="utf-8")
    self_entry = ""
    if self_nodes is not None:
        self_entry = (
            "  - name: self-hosted\n"
            "    role: primary\n"
            "    parser: singbox-json\n"
            "    source: file\n"
            f"    path: {self_subscription.name}\n"
            + ("    ai_include: true\n" if include_self_in_ai else "")
        )
    path.write_text(
        "subscriptions:\n"
        "  - name: provider\n"
        "    parser: singbox-json\n"
        "    source: file\n"
        f"    path: {subscription.name}\n"
        "    hot_regions_only: true\n"
        "    limits:\n"
        "      max_total_nodes: 1\n"
        + self_entry,
        encoding="utf-8",
    )


def test_simple_generator_groups_airports_self_hosted_regions_and_us_ai(tmp_path):
    nodes = [
        make_node("Hong Kong HK", 1),
        make_node("United States US", 2),
        make_node("Taiwan TW", 3),
        make_node("Japan JP", 4),
        make_node("Singapore SG", 5),
        make_node("Paris France FR", 6),
        make_node("London UK", 7),
        make_node("Germany DE", 8),
    ]
    manifest = tmp_path / "subscriptions.yaml"
    self_nodes = [make_node("Self-hosted Other", 9), make_node("Self-hosted US", 10)]
    write_manifest(manifest, nodes, self_nodes=self_nodes, include_self_in_ai=True)
    desktop_template = tmp_path / "desktop.json"
    android_template = tmp_path / "android.json"
    write_template(desktop_template, github_direct_rule=True, accelerator_direct_rule=True)
    write_template(android_template, github_direct_rule=True, accelerator_direct_rule=True)

    results = generate_configs(
        ("desktop", "android"),
        subscriptions_path=manifest,
        output_dir=tmp_path / "dist",
        cache_dir=None,
        policy_aliases_path=None,
        template_paths={"desktop": desktop_template, "android": android_template},
    )

    assert [result.target for result in results] == ["desktop", "android"]
    # The provider requests hot regions only, so Germany is filtered while all
    # hot-region and self-hosted nodes remain despite the legacy numeric cap.
    expected_nodes = len(nodes) - 1 + len(self_nodes)
    assert all(result.node_count == expected_nodes for result in results)
    android = json.loads((tmp_path / "dist" / "android" / "config.json").read_text(encoding="utf-8"))
    desktop = json.loads((tmp_path / "dist" / "desktop" / "config.json").read_text(encoding="utf-8"))
    assert desktop["log"].get("level") is None
    def _optimistic_enabled(value) -> bool:
        return value is True or (isinstance(value, dict) and value.get("enabled") is True)

    assert _optimistic_enabled(desktop["dns"]["optimistic"])
    assert desktop["dns"]["optimistic"]["timeout"] == "30m"
    assert desktop["dns"]["timeout"] == "5s"
    assert desktop["dns"]["cache_capacity"] == 8192
    assert desktop["inbounds"][0]["dns_mode"] == "hijack"
    assert desktop["experimental"]["cache_file"]["store_dns"] is True
    assert [inbound["type"] for inbound in android["inbounds"]] == ["tun"]
    # Android keeps a bounded optimistic-DNS window without persisting DNS cache.
    assert _optimistic_enabled(android["dns"]["optimistic"])
    assert android["dns"]["optimistic"]["timeout"] == "15m"
    assert android["dns"]["timeout"] == "5s"
    assert android["dns"]["cache_capacity"] == 4096
    assert android["inbounds"][0]["dns_mode"] == "hijack"
    assert android["experimental"]["cache_file"]["store_dns"] is False
    assert android["inbounds"][0]["udp_timeout"] == "1m"
    assert all(server["tag"] != "cloudflare" for server in android["dns"]["servers"])
    assert all(server["tag"] != "local-backup" for server in android["dns"]["servers"])
    assert not any("clash_mode" in rule for rule in android["route"]["rules"])
    assert not any("clash_mode" in rule for rule in android["dns"]["rules"])
    assert sum(
        1
        for outbound in android["outbounds"]
        if isinstance(outbound, dict) and is_proxy_outbound(outbound)
    ) == expected_nodes
    selectors = {outbound["tag"]: outbound for outbound in android["outbounds"] if outbound.get("type") == "selector"}
    urltests = {
        outbound["tag"]: outbound
        for outbound in android["outbounds"]
        if outbound.get("type") == "urltest"
    }
    assert "Google Play" not in selectors
    assert "self-hosted" not in selectors
    assert "游戏平台" not in selectors
    self_node_tags = ["self-hosted/Self-hosted US", "self-hosted/Self-hosted Other"]
    assert "自建" not in selectors
    assert selectors["Available"]["outbounds"] == ["provider", *self_node_tags]
    assert selectors["Available"]["default"] == "provider"
    # No airport urltest in this fixture; AI stays fully manual.
    assert urltests == {}
    # AI lists US nodes plus explicitly opted-in self-hosted nodes.
    ai_nodes = selectors["AI"]["outbounds"]
    assert selectors["AI"]["default"] == ai_nodes[0]
    assert set(self_node_tags) <= set(ai_nodes)
    assert all(
        tag in set(self_node_tags) or detect_region(tag) == "US"
        for tag in ai_nodes
    )
    assert selectors["Emby"]["outbounds"] == ["Available", "provider", *self_node_tags, "direct"]
    assert set(selectors) == {"provider", "Available", "AI", "Emby"}
    assert not any("auto" in tag.lower() for tag in selectors)
    # Play QUIC (UDP/443) must NOT be rejected: a working airport proxies HTTP/3
    # fine, and rejecting it only forced a slow timeout-then-TCP fallback.
    assert not any(
        rule.get("action") == "reject" and rule.get("network") == "udp" and rule.get("port") == 443
        for rule in android["route"]["rules"]
    )
    assert any(
        rule.get("action") == "reject" and "doubleclick.net" in rule.get("domain_suffix", [])
        for rule in android["route"]["rules"]
    )
    assert android["inbounds"][0]["mtu"] == 1360
    # Routing stays limited to direct, Available, AI, and Emby for user traffic.
    assert desktop["inbounds"][0]["strict_route"] is True
    assert "strict_route" not in android["inbounds"][0]
    assert not any(
        isinstance(rule, dict) and rule.get("process_name")
        for rule in android["route"]["rules"]
    )
    play_rule = next(
        rule
        for rule in android["route"]["rules"]
        if "dl.google.com" in rule.get("domain_suffix", [])
    )
    assert play_rule["outbound"] == "Available"
    play_package_rule = next(
        rule
        for rule in android["route"]["rules"]
        if "com.android.vending" in rule.get("package_name", [])
    )
    assert play_package_rule["outbound"] == "Available"
    assert android["dns"]["rules"][0]["domain_suffix"] == play_rule["domain_suffix"]
    route_rules = desktop["route"]["rules"]
    outbounds_in_order = [rule.get("outbound") for rule in route_rules if rule.get("outbound")]
    # process(accel direct), process(store proxy), store domains, private, dns ips,
    # ntp, bittorrent, emby, AI, force-proxy rule-sets, telegram IPs, clash modes,
    # geolocation-!cn, geosite-cn, geoip-cn
    assert outbounds_in_order[:7] == [
        "direct",  # game accelerators
        "Available",  # store processes
        "Available",  # store domains
        "direct",  # private
        "direct",  # local DNS IPs
        "direct",  # ntp
        "direct",  # bittorrent
    ]
    assert "Emby" in outbounds_in_order
    assert "AI" in outbounds_in_order
    assert outbounds_in_order[-3:] == ["Available", "direct", "direct"]
    assert any(rule.get("action") == "reject" for rule in route_rules)
    ai_domain_rule = next(
        rule
        for rule in route_rules
        if rule.get("outbound") == "AI" and rule.get("domain_suffix")
    )
    assert {"openai.com", "anthropic.com", "gemini.google.com"} <= set(ai_domain_rule["domain_suffix"])
    assert any(
        rule.get("outbound") == "AI" and "geosite-openai" in (rule.get("rule_set") or [])
        for rule in route_rules
    )
    assert any(
        "geosite-telegram" in (rule.get("rule_set") or []) and rule.get("outbound") == "Available"
        for rule in route_rules
    )
    assert any(
        "geosite-category-ads-all" in (rule.get("rule_set") or [])
        and rule.get("action") == "route"
        and rule.get("outbound") == "direct"
        for rule in route_rules
    )
    assert any(
        "time.windows.com" in (rule.get("domain_suffix") or []) and rule.get("outbound") == "direct"
        for rule in route_rules
    )
    assert desktop["route"].get("default_domain_resolver") == "bootstrap"
    assert any(
        isinstance(server, dict) and server.get("tag") == "bootstrap" and not server.get("detour")
        for server in desktop["dns"]["servers"]
    )
    openai_rs = next(rs for rs in desktop["route"]["rule_set"] if rs.get("tag") == "geosite-openai")
    assert openai_rs.get("type") == "remote"
    assert openai_rs.get("url")
    emby_rule = next(rule for rule in route_rules if rule.get("outbound") == "Emby")
    assert emby_rule["domain_suffix"] == [
        "emby.media",
        "mb3admin.com",
        "link00.okemby.org",
        "link01.okemby.org",
        "emby.taotu.ink",
        "feimu.tv",
        "emby.wawajiao.cc.cd",
    ]
    assert "domain_keyword" not in emby_rule
    store_process_rule = next(
        rule for rule in route_rules if "MicrosoftStore.exe" in rule.get("process_name", [])
    )
    assert store_process_rule["outbound"] == "Available"
    store_domain_rule = next(
        rule for rule in route_rules if "storeedgefd.dsx.mp.microsoft.com" in rule.get("domain_suffix", [])
    )
    assert store_domain_rule["outbound"] == "Available"
    assert desktop["dns"]["rules"][0]["domain_suffix"] == store_domain_rule["domain_suffix"]
    assert desktop["dns"]["final"] == android["dns"]["final"] == "google"
    google_dns = next(server for server in desktop["dns"]["servers"] if server["tag"] == "google")
    assert google_dns["server"] == "8.8.8.8"
    assert google_dns["detour"] == "Available"
    assert desktop["http_clients"] == [{"tag": "rule-set-downloader"}]
    assert android["http_clients"] == [{"tag": "rule-set-downloader"}]
    assert desktop["experimental"]["clash_api"]["external_ui_download_detour"] == "direct"
    accelerator_rule = next(
        rule for rule in route_rules if "GuGuai.exe" in rule.get("process_name", [])
    )
    assert accelerator_rule["outbound"] == "direct"


def test_unknown_dns_uses_clean_resolver_while_cn_domains_stay_local(tmp_path):
    nodes = [
        make_node("Hong Kong HK", 1),
        make_node("United States US", 2),
        make_node("Taiwan TW", 3),
        make_node("Japan JP", 4),
        make_node("Singapore SG", 5),
        make_node("Paris France FR", 6),
        make_node("London UK", 7),
    ]
    manifest = tmp_path / "subscriptions.yaml"
    write_manifest(manifest, nodes)
    desktop_template = tmp_path / "desktop.json"
    android_template = tmp_path / "android.json"
    write_template(desktop_template, cn_rule_set=True)
    write_template(android_template, cn_rule_set=True)

    generate_configs(
        ("desktop", "android"),
        subscriptions_path=manifest,
        output_dir=tmp_path / "dist",
        cache_dir=None,
        policy_aliases_path=None,
        template_paths={"desktop": desktop_template, "android": android_template},
    )

    android = json.loads((tmp_path / "dist" / "android" / "config.json").read_text(encoding="utf-8"))
    desktop = json.loads((tmp_path / "dist" / "desktop" / "config.json").read_text(encoding="utf-8"))

    # Unknown names use clean proxied DoH so domains missing from geosite do not
    # fall through to a pollution-prone local resolver.
    assert android["dns"]["final"] == "google"
    # Genuinely overseas names (geolocation-!cn) still get the clean resolver.
    non_cn_dns_rule = next(
        rule
        for rule in android["dns"]["rules"]
        if rule.get("server") == "google" and "geosite-geolocation-!cn" in (rule.get("rule_set") or [])
    )
    assert non_cn_dns_rule["action"] == "route"
    assert any(
        rule_set.get("tag") == "geosite-geolocation-!cn" and rule_set.get("type") == "remote"
        for rule_set in android["route"]["rule_set"]
    )
    # The new rule-set clones the CN rule-sets' download convention so it obeys
    # the same core-version handling (http_client on 1.14 profiles).
    non_cn_rule_set = next(
        rs for rs in android["route"]["rule_set"] if rs.get("tag") == "geosite-geolocation-!cn"
    )
    assert non_cn_rule_set.get("http_client") == "rule-set-downloader" or non_cn_rule_set.get(
        "download_detour"
    ) in {"Available", "direct"}
    # The clean-resolver rule must sit before the explicit geosite-cn local-DNS
    # rule; unknown names use dns.final (Google DoH).
    servers = [rule.get("server") for rule in android["dns"]["rules"]]
    rule_sets = [rule.get("rule_set") or [] for rule in android["dns"]["rules"]]
    non_cn_index = next(i for i, rs in enumerate(rule_sets) if "geosite-geolocation-!cn" in rs)
    cn_index = next(i for i, rs in enumerate(rule_sets) if "geosite-cn" in rs)
    assert non_cn_index < cn_index
    assert servers[cn_index] == "local"
    # Desktop and Android now share the same split-DNS policy.
    assert desktop["dns"]["final"] == "google"
    assert any(
        rule_set.get("tag") == "geosite-geolocation-!cn"
        for rule_set in desktop["route"]["rule_set"]
    )
    # Routing must mirror split DNS: known overseas names are proxied before
    # geoip-cn can mistakenly send a CDN address to direct.
    non_cn_route_index = next(
        i
        for i, rule in enumerate(desktop["route"]["rules"])
        if "geosite-geolocation-!cn" in (rule.get("rule_set") or [])
    )
    cn_route_index = next(
        i
        for i, rule in enumerate(desktop["route"]["rules"])
        if "geosite-cn" in (rule.get("rule_set") or [])
    )
    assert non_cn_route_index < cn_route_index
    assert desktop["route"]["rules"][non_cn_route_index]["outbound"] == "Available"


def test_simple_generator_keeps_selector_surface_small(tmp_path):
    manifest = tmp_path / "subscriptions.yaml"
    write_manifest(
        manifest,
        [
            make_node("Hong Kong HK", 1),
            make_node("United States US", 2),
            make_node("Taiwan TW", 3),
            make_node("Japan JP", 4),
            make_node("Singapore SG", 5),
            make_node("London UK", 7),
        ],
    )
    template = tmp_path / "desktop.json"
    write_template(template)
    generate_configs(
        ("desktop",),
        subscriptions_path=manifest,
        output_dir=tmp_path / "dist",
        cache_dir=None,
        policy_aliases_path=None,
        template_paths={"desktop": template},
    )

    conf = json.loads((tmp_path / "dist" / "desktop" / "config.json").read_text(encoding="utf-8"))
    selectors = {
        outbound["tag"]: outbound
        for outbound in conf["outbounds"]
        if outbound.get("type") == "selector"
    }
    urltests = {
        outbound["tag"]: outbound
        for outbound in conf["outbounds"]
        if outbound.get("type") == "urltest"
    }
    assert set(selectors) == {"provider", "Available", "AI", "Emby"}
    # Available is manual; Auto only appears when a subscription opts into
    # urltest (none in this fixture).
    assert selectors["Available"]["outbounds"] == ["provider"]
    assert selectors["Available"]["default"] == "provider"
    assert urltests == {}
    assert selectors["Emby"]["outbounds"] == ["Available", "provider", "direct"]


def test_provider_urltest_scopes_auto_to_that_airport_only(tmp_path):
    manifest = tmp_path / "subscriptions.yaml"
    nodes = [
        make_node("Hong Kong HK", 1),
        make_node("United States US", 2),
        make_node("Taiwan TW", 3),
        make_node("Japan JP", 4),
        make_node("Singapore SG", 5),
    ]
    subscription = tmp_path / "subscription.json"
    subscription.write_text(json.dumps({"outbounds": nodes}, ensure_ascii=False), encoding="utf-8")
    other = tmp_path / "other.json"
    other_nodes = [
        make_node("Other Hong Kong HK", 11),
        make_node("Other United States US", 12),
        make_node("Other Taiwan TW", 13),
        make_node("Other Japan JP", 14),
        make_node("Other Singapore SG", 15),
    ]
    other.write_text(json.dumps({"outbounds": other_nodes}, ensure_ascii=False), encoding="utf-8")
    manifest.write_text(
        "subscriptions:\n"
        "  - name: provider\n"
        "    parser: singbox-json\n"
        "    source: file\n"
        f"    path: {subscription.name}\n"
        "    urltest: true\n"
        "  - name: other\n"
        "    parser: singbox-json\n"
        "    source: file\n"
        f"    path: {other.name}\n",
        encoding="utf-8",
    )
    desktop_template = tmp_path / "desktop.json"
    android_template = tmp_path / "android.json"
    write_template(desktop_template)
    write_template(android_template)
    generate_configs(
        ("desktop", "android"),
        subscriptions_path=manifest,
        output_dir=tmp_path / "dist",
        cache_dir=None,
        policy_aliases_path=None,
        template_paths={"desktop": desktop_template, "android": android_template},
    )

    for target in ("desktop", "android"):
        conf = json.loads((tmp_path / "dist" / target / "config.json").read_text(encoding="utf-8"))
        selectors = {
            outbound["tag"]: outbound
            for outbound in conf["outbounds"]
            if outbound.get("type") == "selector"
        }
        urltests = {
            outbound["tag"]: outbound
            for outbound in conf["outbounds"]
            if outbound.get("type") == "urltest"
        }
        assert set(selectors["Available"]["outbounds"]) == {"provider", "other"}, target
        assert "Auto" not in selectors["Available"]["outbounds"], target
        assert "provider/Auto" in urltests, target
        assert urltests["provider/Auto"]["interrupt_exist_connections"] is False, target
        provider_nodes = [tag for tag in selectors["provider"]["outbounds"] if tag != "provider/Auto"]
        assert selectors["provider"]["default"] == "provider/Auto", target
        assert selectors["provider"]["outbounds"][0] == "provider/Auto", target
        assert set(urltests["provider/Auto"]["outbounds"]) == set(provider_nodes), target
        assert selectors["AI"]["default"] == selectors["AI"]["outbounds"][0], target
        assert selectors["other"].get("default") is None, target
        assert "other/Auto" not in urltests, target
        assert "Auto" not in urltests, target
        assert "AI/Auto" not in urltests, target


def test_desktop_template_routes_accelerator_processes_directly():
    template = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "config"
            / "examples"
            / "templates"
            / "desktop-windows-sing-box-1.14.json"
        ).read_text(
            encoding="utf-8"
        )
    )
    route = template["route"]
    direct_rule = next(rule for rule in route["rules"] if "GuGuai.exe" in rule.get("process_name", []))
    assert route["find_process"] is True
    assert direct_rule["outbound"] == "direct"
    assert {"GuGuai.exe", "guguaiwebhelper.exe", "xunyou.exe", "UUAccelerator.exe", "leigod.exe", "qiyou.exe", "biubiu.exe"} <= set(direct_rule["process_name"])

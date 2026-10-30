"""Policy-shape regressions, not a substitute for live sing-box routing tests."""

import pytest

from singbox_config.generator import POLICY, Source, build_config, load_yaml


AI_RULE_SETS = {"geosite-openai", "ai"}
CLAUDE_RULE_SETS = {"geosite-anthropic", "claude"}
CLAUDE_IP_RANGES = {"160.79.104.0/21", "2607:6bc0::/32"}
PUBLIC_RESOURCES = ("downloads.claude.ai", "servd-anthropic-website.b-cdn.net",
                    "persistent.oaistatic.com", "dl.google.com")
CLAUDE_IPV4_RESOURCES = PUBLIC_RESOURCES[:2]
AVAILABLE_RESOURCES = PUBLIC_RESOURCES[2:]
DOMESTIC_RULE_SETS = {"direct", "geosite-private", "geosite-cn", "geoip-cn"}


def values(rule, key):
    value = rule.get(key, [])
    return {value} if isinstance(value, str) else set(value)


def one(rules, predicate):
    matches = [(index, rule) for index, rule in enumerate(rules) if predicate(rule)]
    assert len(matches) == 1, matches
    return matches[0]


def node(tag, server):
    return {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000000",
        "tls": {"enabled": True},
    }


@pytest.fixture(scope="module", params=("desktop", "android"))
def policy_config(request):
    sources = [
        Source("Meow-US", [node("Meow-US-hy2", "meow-hy2.example.invalid"),
                           node("Meow-US-vless", "meow-vless.example.invalid")], []),
        Source(
            "Test-Air",
            [node("US Test", "us.example.invalid"), node("HK Test", "hk.example.invalid")],
            ["US Test"],
        ),
        Source("Test-Solo", [node("Test-Solo", "solo.example.invalid")], []),
        Source("西部数据", [node("Hong Kong | 01", "west.example.invalid")], []),
        Source("羽迹", [node("香港-1", "backup.example.invalid")], []),
        Source("Aether-US", [dict(node(f"Aether-US-{city}-v6", f"{city.lower()}.example.invalid"),
                                  detour="Aether-前置") for city in ("CHI", "SFO", "ATL")]
               + [dict(node("Aether-US-LAX-v4", "lax.example.invalid"), detour="Aether-前置")], []),
        Source("CloudLeadInno-US", [node("CloudLeadInno-US", "cloudlead.example.invalid")], []),
    ]
    return request.param, build_config(request.param, load_yaml(POLICY), sources)


def test_ai_dns_keeps_ipv4_fakeip_and_empty_service_binding_answers(policy_config):
    _, config = policy_config
    dns = config["dns"]
    _, fakeip = one(dns["servers"], lambda server: server["tag"] == "fakeip-ai")
    assert fakeip["type"] == "fakeip"
    assert fakeip["inet4_range"] == "198.18.0.0/15"
    assert not fakeip.get("inet6_range")
    assert dns["strategy"] == "ipv4_only"
    assert config["experimental"]["cache_file"]["enabled"] is True
    assert config["experimental"]["cache_file"]["store_fakeip"] is True

    ai_dns = [rule for rule in dns["rules"] if values(rule, "rule_set") & AI_RULE_SETS]
    assert len(ai_dns) == 3
    assert all(values(rule, "rule_set") == AI_RULE_SETS for rule in ai_dns)
    binding, address, other = ai_dns
    assert values(binding, "query_type") == {"HTTPS", "SVCB"}
    assert binding["action"] == "predefined"
    assert binding["rcode"] == "NOERROR"
    assert not any(binding.get(key) for key in ("answer", "ns", "extra", "server"))
    assert values(address, "query_type") == {"A", "AAAA"}
    assert address["server"] == "fakeip-ai"
    assert "action" not in address
    assert "query_type" not in other
    assert other["server"] == "ai"
    claude_address = next(rule for rule in dns["rules"] if rule.get("server") == "fakeip-ai"
                          and values(rule, "rule_set") == CLAUDE_RULE_SETS)
    fake_rules = [rule for rule in dns["rules"] if rule.get("server") == "fakeip-ai"]
    assert claude_address in fake_rules and address in fake_rules
    assert all(values(rule, "query_type") == {"A", "AAAA"} for rule in fake_rules)
    assert len(fake_rules) == (4 if policy_config[0] == "android" else 3)


@pytest.mark.parametrize(("outbound", "rule_sets"), [("AI", AI_RULE_SETS), ("Claude", CLAUDE_RULE_SETS)])
def test_ai_rejects_quic_before_domain_and_ip_outbounds_not_all_ipv6(policy_config, outbound, rule_sets):
    _, config = policy_config
    rules = config["route"]["rules"]
    domain_index, _ = one(
        rules, lambda rule: rule.get("outbound") == outbound and values(rule, "rule_set") == rule_sets
    )
    cases = [("rule_set", rule_sets, domain_index)]
    if outbound == "Claude":
        ip_index, _ = one(rules, lambda rule: rule.get("outbound") == "Claude"
                          and values(rule, "ip_cidr") == CLAUDE_IP_RANGES)
        cases.append(("ip_cidr", CLAUDE_IP_RANGES, ip_index))
    for field, expected, outbound_index in cases:
        reject_index, reject = one(
            rules, lambda rule: rule.get("action") == "reject" and values(rule, field) == expected
        )
        assert reject_index < outbound_index
        assert reject["network"] == "udp"
        assert reject["port"] == 443
        assert "ip_version" not in reject


def test_flexible_services_and_direct_rules_precede_remaining_traffic_guards(policy_config):
    _, config = policy_config
    rules = config["route"]["rules"]
    udp_index, _ = one(rules, lambda rule: rule == {"network": "udp", "port": 443, "action": "reject"})
    ipv6_index, _ = one(rules, lambda rule: rule == {"ip_version": 6, "action": "reject"})
    target_fields = {"domain", "domain_suffix", "rule_set", "ip_cidr", "package_name"}
    for index, rule in enumerate(rules):
        if rule.get("action") != "reject":
            continue
        if rule.get("ip_version") == 6 or (rule.get("network") == "udp" and rule.get("port") == 443):
            if not target_fields.intersection(rule):
                assert index in {udp_index, ipv6_index}, rule
        assert not (values(rule, "rule_set") & (DOMESTIC_RULE_SETS | {"emby", "geosite-spotify"})), rule

    for outbound in ("Claude", "AI", "Emby", "Spotify"):
        selected = [index for index, rule in enumerate(rules) if rule.get("outbound") == outbound]
        assert selected
        assert max(selected) < min(udp_index, ipv6_index)
    for tag in DOMESTIC_RULE_SETS:
        index, rule = one(
            rules,
            lambda rule: values(rule, "rule_set") == {tag}
            and rule.get("outbound") == "direct" and "package_name" not in rule,
        )
        assert index < min(udp_index, ipv6_index)
        assert not any(key in rule for key in ("network", "port", "ip_version"))


@pytest.mark.parametrize(("dns_tag", "outbound", "rule_set"), (
    ("youtube", "YouTube", "geosite-youtube"),
    ("twitch", "Twitch", "geosite-twitch"),
))
def test_media_dns_uses_its_own_selector_not_available(policy_config, dns_tag, outbound, rule_set):
    _, config = policy_config
    servers = {server["tag"]: server for server in config["dns"]["servers"]}
    group = servers[dns_tag]
    assert group["type"] == "group"
    assert len(set(group["servers"])) >= 2
    for member in group["servers"]:
        assert servers[member]["type"] == "https"
        assert servers[member]["detour"] == outbound
    _, dns_rule = one(config["dns"]["rules"], lambda rule: values(rule, "rule_set") == {rule_set})
    assert dns_rule["server"] == dns_tag
    _, route_rule = one(
        config["route"]["rules"],
        lambda rule: values(rule, "rule_set") == {rule_set} and "outbound" in rule,
    )
    assert route_rule["outbound"] == outbound
    _, selector = one(config["outbounds"], lambda item: item["tag"] == outbound)
    assert selector["type"] == "selector"


def test_domestic_apps_and_tcp_22_follow_destination_rules(policy_config):
    _, config = policy_config
    rules = config["route"]["rules"]
    app_direct = [rule for rule in rules if "package_name" in rule and rule.get("outbound") == "direct"]
    assert not app_direct
    assert not any(rule.get("network") == "tcp" and rule.get("port") == 22 for rule in rules)
    assert any(rule.get("network") == "udp" and rule.get("port") == 123 and rule.get("outbound") == "direct" for rule in rules)
    assert all(any(rule.get("rule_set") == tag and rule.get("outbound") == "direct" for rule in rules) for tag in DOMESTIC_RULE_SETS)


def test_current_emby_and_spotify_selectors_keep_manual_direct_options(policy_config):
    _, config = policy_config
    outbounds = {outbound["tag"]: outbound for outbound in config["outbounds"]}
    assert outbounds["direct"]["type"] == "direct"
    emby = outbounds["Emby"]
    spotify = outbounds["Spotify"]
    assert emby["type"] == spotify["type"] == "selector"
    assert emby["outbounds"][0] == "Available"
    assert emby["outbounds"][-1] == "direct"
    assert emby.get("default", "Available") == "Available"
    assert spotify["outbounds"][0] == "direct"
    assert spotify.get("default", "direct") == "direct"
    assert "Available" in spotify["outbounds"]
    assert set(outbounds["Available"]["outbounds"]) <= set(spotify["outbounds"])
    for rule_set in ("emby", "geosite-spotify"):
        _, rule = one(config["dns"]["rules"], lambda rule: rule_set in values(rule, "rule_set"))
        assert rule["server"] == ("emby" if rule_set == "emby" else "proxy")


def test_business_groups_offer_available_except_ai_and_aether_landings(policy_config):
    _, config = policy_config
    outbounds = {item["tag"]: item for item in config["outbounds"]}
    services = {rule["outbound"] for rule in config["route"]["rules"] if "outbound" in rule}
    for tag in services - {"Available", "direct", "AI", "Claude", "Aether-US"}:
        assert outbounds[tag]["type"] == "selector"
        assert outbounds[tag]["outbounds"].count("Available") == 1
    assert outbounds["AI"]["outbounds"][0] == "US Test"
    assert "Available" not in outbounds["AI"]["outbounds"]
    assert "Available" not in outbounds["Aether-US"]["outbounds"]


def test_claude_keeps_only_approved_leaf_landings_and_shared_front(policy_config):
    _, config = policy_config
    out = {item["tag"]: item for item in config["outbounds"]}
    group = out["Claude"]
    assert group["type"] == "selector"
    assert group["default"] == "Aether-US-CHI-v6"
    aether = [f"Aether-US-{city}-v6" for city in ("CHI", "SFO", "ATL")] + ["Aether-US-LAX-v4"]
    assert group["outbounds"] == [*aether, "CloudLeadInno-US"]
    assert group["interrupt_exist_connections"] is True
    assert all(out[tag]["type"] == "vless" and out[tag]["detour"] == "Aether-前置"
               for tag in aether)
    assert out["CloudLeadInno-US"]["type"] == "vless"
    assert not out["CloudLeadInno-US"].get("detour")
    assert not any(tag.startswith("Claude-") for tag in out)


def test_claude_dns_never_uses_general_ai_or_direct_resolvers(policy_config):
    _, config = policy_config
    dns = config["dns"]
    rules = [rule for rule in dns["rules"] if values(rule, "rule_set") & CLAUDE_RULE_SETS]
    assert len(rules) == 3
    binding, address, other = rules
    assert values(binding, "query_type") == {"HTTPS", "SVCB"}
    assert binding["action"] == "predefined" and binding["rcode"] == "NOERROR"
    assert values(address, "query_type") == {"A", "AAAA"} and address["server"] == "fakeip-ai"
    assert other["server"] == "claude" and "query_type" not in other
    servers = {s["tag"]: s for s in dns["servers"]}
    assert servers["claude"]["type"] == "group"
    members = [servers[tag] for tag in servers["claude"]["servers"]]
    assert len(members) == 4
    assert all(member["type"] == "https" and member["detour"] == "Claude" for member in members)
    assert {":" in member["server"] for member in members} == {False, True}
    assert max(dns["rules"].index(rule) for rule in rules) < min(
        i for i, rule in enumerate(dns["rules"]) if values(rule, "rule_set") & AI_RULE_SETS)


def inline_domains(config, tag):
    item = next(item for item in config["route"]["rule_set"] if item["tag"] == tag)
    return {domain for rule in item.get("rules", []) for domain in rule.get("domain_suffix", [])}


def test_google_and_play_have_only_explicit_members_and_stable_defaults(policy_config):
    platform, config = policy_config
    out = {item["tag"]: item for item in config["outbounds"]}
    leaves = ["Meow-US-hy2", "Meow-US-vless", "Aether-US-LAX-v4", "Aether-US-CHI-v6", "Aether-US-SFO-v6", "Aether-US-ATL-v6", "CloudLeadInno-US"]
    assert out["Google"]["type"] == "selector" and out["Google"]["default"] == "AI"
    assert out["Google"]["outbounds"] == ["AI", "Available", "Claude", *leaves]
    if platform == "android":
        assert out["Google Play"]["default"] == "Available"
        assert out["Google Play"]["outbounds"] == ["Available", *leaves, "Claude"]
    else:
        assert "Google Play" not in out


@pytest.mark.parametrize(("dns_tag", "outbound"), [
    ("proxy", "Available"), ("claude", "Claude"), ("google-services", "Google"), ("ai", "AI"),
    ("youtube", "YouTube"), ("twitch", "Twitch"), ("emby", "Emby"), ("telegram", "Telegram"), ("google-play", "Google Play")])
def test_business_dns_transports_follow_one_group_with_both_address_families(policy_config, dns_tag, outbound):
    platform, config = policy_config
    servers = {item["tag"]: item for item in config["dns"]["servers"]}
    if dns_tag == "google-play" and platform == "desktop":
        assert dns_tag not in servers
        return
    members = [servers[tag] for tag in servers[dns_tag]["servers"]]
    assert len(members) == 4
    assert all(member["type"] == "https" and member["detour"] == outbound for member in members)
    assert {":" in member["server"] for member in members} == {False, True}
    assert {member["tls"]["server_name"] for member in members} == {"dns.google", "cloudflare-dns.com"}


@pytest.mark.parametrize(("tags", "server"), [({"geosite-google", "google"}, "google-services"),
                                            ({"geosite-google-play", "google-play"}, "google-play")])
def test_google_and_play_use_fakeip_before_broad_rules(policy_config, tags, server):
    platform, config = policy_config
    matches = [rule for rule in config["dns"]["rules"] if values(rule, "rule_set") == tags]
    if server == "google-play" and platform == "desktop":
        assert not matches
        return
    assert len(matches) == 3
    assert values(matches[0], "query_type") == {"HTTPS", "SVCB"} and matches[0]["rcode"] == "NOERROR"
    assert values(matches[1], "query_type") == {"A", "AAAA"} and matches[1]["server"] == "fakeip-ai"
    assert matches[2]["server"] == server


def test_telegram_ipv6_and_business_priority_are_preserved(policy_config):
    _, config = policy_config
    rules = config["route"]["rules"]
    index, dc = one(rules, lambda rule: rule.get("outbound") == "Telegram" and "ip_cidr" in rule)
    assert {"2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48", "2001:b28:f23c::/48", "2a0a:f280::/32"} <= set(dc["ip_cidr"])
    ipv6_index, _ = one(rules, lambda rule: rule == {"ip_version": 6, "action": "reject"})
    ads_index, _ = one(rules, lambda rule: rule.get("rule_set") == "geosite-category-ads-all")
    assert index < ipv6_index < ads_index
    for outbound in ("Google", "Claude", "AI", "Emby", "Spotify"):
        assert all(i < ads_index for i, rule in enumerate(rules) if rule.get("outbound") == outbound)


@pytest.mark.parametrize("domain", ["claude.ai", "api.anthropic.com", "claude.com", "sub.servd-anthropic-website.b-cdn.net", "sub.downloads.claude.ai",
                                     "claudeusercontent.com", "anthropic.auth0.com", "claude.googleapis.com",
                                     "claudemcpcontent.com"])
def test_claude_account_domains_cannot_hit_ai_or_available_exceptions(policy_config, domain):
    _, config = policy_config
    matches = lambda name, suffix: name == suffix or name.endswith("." + suffix)
    tags = {tag for tag in ("claude", "ai") if any(matches(domain, s) for s in inline_domains(config, tag))}
    assert "claude" in tags
    route_rules = [rule for rule in config["route"]["rules"] if "outbound" in rule
                   and values(rule, "rule_set") & tags]
    assert route_rules[0]["outbound"] == "Claude"
    assert not any(domain in values(rule, "domain") and rule.get("outbound") != "Claude"
                   for rule in config["route"]["rules"] if "outbound" in rule)
    assert not any(domain in values(rule, "domain") and rule.get("server") not in {"claude", "fakeip-ai"}
                   for rule in config["dns"]["rules"] if "server" in rule)
    claude_index = config["route"]["rules"].index(route_rules[0])
    assert all(claude_index < i for i, rule in enumerate(config["route"]["rules"])
               if rule.get("outbound") in {"AI", "Available", "direct"}
               and not (values(rule, "domain") and values(rule, "domain") <= set(PUBLIC_RESOURCES)))


def test_extra_ai_domains_are_narrow_and_shared_services_stay_separate(policy_config):
    _, config = policy_config
    ai = inline_domains(config, "ai")
    assert {"grok.com", "x.ai", "meta.ai", "ai.meta.com", "perplexity.ai", "poe.com"} <= ai
    assert not {"x.com", "facebook.com", "instagram.com", "whatsapp.com", "meta.com", "ai"} & ai
    assert not (inline_domains(config, "claude") & ai)


@pytest.mark.parametrize("failure", ["front", "landing"])
def test_real_core_claude_failure_does_not_fall_back_but_other_ai_works(policy_config, tmp_path, failure):
    """Exercise actual routing with local synthetic peers; never start a TUN or real node."""
    import copy
    import json
    import socket
    import socketserver
    import subprocess
    import threading
    import time
    from pathlib import Path

    import requests

    cores = list((Path(__file__).resolve().parents[1] / "runtime/cores/1.15.0-alpha.13-reF1nd").rglob("sing-box.exe"))
    if not cores:
        pytest.skip("optional local alpha.13 core is not installed")
    seen = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(3)
            first = self.rfile.readline()
            if not first:
                return
            while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                pass
            if first.startswith(b"CONNECT "):
                seen.append(first.split()[1].decode())
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.wfile.flush()
                self.rfile.readline()
                while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
            else:
                seen.append(first.split()[1].decode())
            self.wfile.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(("127.0.0.1", 0), Handler) as good, socket.socket() as dead, socket.socket() as reserved:
        threading.Thread(target=good.serve_forever, daemon=True).start()
        dead.bind(("127.0.0.1", 0))  # Held but not listening: deterministic connection refusal.
        reserved.bind(("127.0.0.1", 0))
        port, dead_port = reserved.getsockname()[1], dead.getsockname()[1]
        cfg = copy.deepcopy(policy_config[1])
        cfg["experimental"] = {}  # No client selection/Fake-IP databases are opened.
        cfg["log"] = {"level": "warn"}
        cfg["inbounds"] = [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}]
        claude_tags = next(o["outbounds"] for o in cfg["outbounds"] if o["tag"] == "Claude")
        front_tags = {"Hong Kong | 01", "香港-1"}
        for index, outbound in enumerate(cfg["outbounds"]):
            tag = outbound["tag"]
            if outbound["type"] in {"selector", "urltest"}:
                continue
            if tag in claude_tags:
                cfg["outbounds"][index] = {"type": "http", "tag": tag, "server": "127.0.0.1",
                                            "server_port": dead_port, "detour": "Aether-前置"}
            elif tag in front_tags and failure == "landing":
                cfg["outbounds"][index] = {"type": "direct", "tag": tag}
            else:
                cfg["outbounds"][index] = {"type": "http", "tag": tag, "server": "127.0.0.1",
                                            "server_port": dead_port if tag in front_tags else good.server_address[1]}
        # Remote rule data is synthetic; the local Claude/AI rules and their actual order are retained.
        for index, rule_set in enumerate(cfg["route"]["rule_set"]):
            if rule_set["type"] == "remote":
                domain = {"geosite-openai": "chatgpt.com", "geosite-anthropic": "anthropic.com"}.get(rule_set["tag"], "unused.invalid")
                cfg["route"]["rule_set"][index] = {"type": "inline", "tag": rule_set["tag"], "rules": [{"domain_suffix": [domain]}]}
        path = tmp_path / "isolated.json"
        path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        reserved.close()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with (tmp_path / "core.log").open("wb") as log:
            proc = subprocess.Popen([str(cores[0]), "run", "-c", str(path)], cwd=tmp_path,
                                    stdout=log, stderr=log, creationflags=flags)
            session = requests.Session()
            session.trust_env = False
            session.proxies = {"http": f"http://127.0.0.1:{port}"}
            try:
                for _ in range(60):
                    if proc.poll() is not None:
                        pytest.fail((tmp_path / "core.log").read_text(encoding="utf-8", errors="replace"))
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    pytest.fail("isolated core did not start")
                for host in (*CLAUDE_IPV4_RESOURCES, "claude.ai", "claude.googleapis.com", "api.anthropic.com",
                             "160.79.104.1", "[2607:6bc0::1]"):
                    try:
                        result = session.get(f"http://{host}/", timeout=2)
                    except requests.RequestException:
                        continue
                    assert result.status_code >= 400, (failure, host, result.status_code)
                assert seen == []  # Any AI / Available / direct fallback would reach the good peer.
                # Only the unrelated public resources bypass a broken Aether chain.
                for host in (*AVAILABLE_RESOURCES, "chatgpt.com"):
                    assert session.get(f"http://{host}/", timeout=2).status_code == 204
                assert seen == [host + ":80" for host in (*AVAILABLE_RESOURCES, "chatgpt.com")]
            finally:
                session.close()
                proc.terminate()  # Only the Popen process created above; the running client is untouched.
                proc.wait(timeout=10)
                good.shutdown()


def test_aether_uses_west_by_default_and_requires_manual_backup_selection(policy_config):
    _, config = policy_config
    outbounds = {item["tag"]: item for item in config["outbounds"]}
    front = outbounds["Aether-前置"]
    assert front["type"] == "selector"
    assert front["outbounds"] == ["Aether-前置-西部数据", "Aether-前置-备用"]
    assert outbounds["Aether-前置-西部数据"]["type"] == "selector"
    assert outbounds["Aether-前置-西部数据"]["outbounds"] == ["Hong Kong | 01"]
    assert outbounds["Aether-前置-备用"]["type"] == "selector"
    assert outbounds["Aether-前置-备用"]["outbounds"] == ["香港-1"]
    for tag in ("Aether-前置-西部数据", "Aether-前置-备用"):
        pool = outbounds[tag]
        assert not {"url", "interval", "tolerance", "idle_timeout"} & pool.keys()
        assert pool["interrupt_exist_connections"] is True
    assert not any(item["type"] == "urltest" for item in config["outbounds"])


@pytest.mark.parametrize("domain", PUBLIC_RESOURCES)
def test_explicit_resources_follow_their_selected_group_before_account_rules(policy_config, domain):
    _, config = policy_config
    dns_rules, route_rules = config["dns"]["rules"], config["route"]["rules"]
    dns_index, dns = one(dns_rules, lambda rule: domain in values(rule, "domain"))
    route_index, route = one(route_rules, lambda rule: domain in values(rule, "domain") and "outbound" in rule)
    claude_resource = domain in CLAUDE_IPV4_RESOURCES
    expected = set(CLAUDE_IPV4_RESOURCES if claude_resource else AVAILABLE_RESOURCES)
    assert values(dns, "domain") == values(route, "domain") == expected
    assert dns["server"] == ("aether-resources" if claude_resource else "proxy")
    assert route["outbound"] == ("Aether-US" if claude_resource else "Available")
    assert "domain_suffix" not in dns and "domain_suffix" not in route
    assert dns_index < min(i for i, rule in enumerate(dns_rules) if values(rule, "rule_set") & (AI_RULE_SETS | CLAUDE_RULE_SETS))
    assert route_index < min(i for i, rule in enumerate(route_rules) if values(rule, "rule_set") & (AI_RULE_SETS | CLAUDE_RULE_SETS))
    guards = [rule for rule in route_rules[:route_index] if domain in values(rule, "domain") and rule.get("action") == "reject"]
    assert len(guards) == 2
    assert any(rule.get("network") == "udp" and rule.get("port") == 443 for rule in guards)
    assert any(rule.get("ip_version") == 6 for rule in guards)


def test_leak_guards_precede_every_direct_and_business_route(policy_config):
    _, config = policy_config
    rules = config["route"]["rules"]
    dns_index, dns = one(rules, lambda rule: rule.get("action") == "hijack-dns")
    assert dns["type"] == "logical" and dns["mode"] == "or"
    assert {"protocol": "dns"} in dns["rules"] and {"port": 53} in dns["rules"]
    stun_index, _ = one(rules, lambda rule: rule.get("protocol") == "stun")
    dot_index, _ = one(rules, lambda rule: rule.get("port") == 853)
    assert rules[stun_index]["action"] == rules[dot_index]["action"] == "reject"
    assert max(dns_index, stun_index, dot_index) < min(
        i for i, rule in enumerate(rules) if "outbound" in rule)
    tun = next(item for item in config["inbounds"] if item["type"] == "tun")
    assert tun["auto_route"] and tun["strict_route"]
    assert not tun.get("route_exclude_address")


def test_claude_ipv4_resource_dns_uses_aether_without_available_fallback(policy_config):
    _, config = policy_config
    servers = {item["tag"]: item for item in config["dns"]["servers"]}
    members = [servers[tag] for tag in servers["aether-resources"]["servers"]]
    assert len(members) == 4
    assert {item["server"] for item in members} == {"2001:4860:4860::8888", "2606:4700:4700::1111", "8.8.8.8", "1.1.1.1"}
    assert all(item["type"] == "https" and item["detour"] == "Aether-US" for item in members)
    assert {":" in item["server"] for item in members} == {False, True}


def test_android_claude_package_name_is_isolated(policy_config):
    platform, config = policy_config
    rules = config["route"]["rules"]
    claude_packages = [rule for rule in rules if "com.anthropic.claude" in (rule.get("package_name") or [])]
    if platform == "desktop":
        assert not claude_packages
        return
    assert len(claude_packages) == 2
    reject, outbound = claude_packages
    assert reject["action"] == "reject"
    assert reject["network"] == "udp"
    assert reject["port"] == 443
    assert outbound["outbound"] == "Claude"

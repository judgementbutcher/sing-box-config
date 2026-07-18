import json
from pathlib import Path

from generate_config import generate_configs
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
    path.write_text(
        json.dumps(
            {
                "log": {"disabled": True},
                "dns": {
                    "servers": [
                        {"type": "https", "tag": "remote", "detour": "Available"},
                        {"type": "https", "tag": "google", "detour": "Available"},
                        {"type": "udp", "tag": "local", "server": "223.5.5.5"},
                    ]
                },
                "inbounds": [
                    {"type": "tun", "tag": "tun-in", "address": ["172.18.0.1/30"]},
                    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
                ],
                "route": {"rules": route_rules, "rule_set": [], "final": "Available"},
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
    assert all(result.node_count == len(nodes) - 1 + len(self_nodes) for result in results)
    android = json.loads((tmp_path / "dist" / "android" / "config.json").read_text(encoding="utf-8"))
    desktop = json.loads((tmp_path / "dist" / "desktop" / "config.json").read_text(encoding="utf-8"))
    assert desktop["log"].get("level") is None
    assert desktop["dns"]["optimistic"] is True
    assert desktop["dns"]["timeout"] == "8s"
    assert desktop["inbounds"][0]["dns_mode"] == "hijack"
    assert desktop["experimental"]["cache_file"]["store_dns"] is True
    assert [inbound["type"] for inbound in android["inbounds"]] == ["tun"]
    assert "optimistic" not in android["dns"]
    assert "timeout" not in android["dns"]
    assert "dns_mode" not in android["inbounds"][0]
    assert "store_dns" not in android["experimental"]["cache_file"]
    assert sum(
        1
        for outbound in android["outbounds"]
        if isinstance(outbound, dict) and is_proxy_outbound(outbound)
    ) == len(nodes) - 1 + len(self_nodes)
    selectors = {outbound["tag"]: outbound for outbound in android["outbounds"] if outbound.get("type") == "selector"}
    # Region groups have been removed; only functional groups remain.
    assert not any(tag.startswith("地区/") for tag in selectors)
    assert "Google Play" not in selectors
    assert "self-hosted" not in selectors
    assert len(selectors["自建"]["outbounds"]) == len(self_nodes)
    assert selectors["Available"]["outbounds"] == ["provider", "自建"]
    ai_nodes = selectors["AI"]["outbounds"]
    assert ai_nodes[0].startswith("self-hosted/")
    assert any(tag.startswith("self-hosted/") for tag in ai_nodes)
    assert any(detect_region(tag) == "US" for tag in ai_nodes)
    assert all("default" not in selector for selector in selectors.values())
    # Each big service gets its own selector whose members mirror Available with
    # Available listed first, so it defaults to following the global pick.
    for tag in ("谷歌", "YouTube", "Netflix", "Telegram", "社交媒体", "微软", "苹果", "游戏平台"):
        assert selectors[tag]["outbounds"] == ["Available", "provider", "自建"]
    # Play traffic rides the 谷歌 service group (which mirrors Available).
    play_rule = next(
        rule
        for rule in android["route"]["rules"]
        if rule.get("outbound") == "谷歌" and "dl.google.com" in rule.get("domain_suffix", [])
    )
    assert play_rule["domain_suffix"] == [
        "play.google.com",
        "play.googleapis.com",
        "play-fe.googleapis.com",
        "android.clients.google.com",
        "android.googleapis.com",
        "dl.google.com",
        "gvt1.com",
        "gvt2.com",
        "gvt3.com",
        "googleusercontent.com",
    ]
    # Play QUIC (UDP/443) must NOT be rejected: a working airport proxies HTTP/3
    # fine, and rejecting it only forced a slow timeout-then-TCP fallback.
    assert not any(
        rule.get("action") == "reject" and rule.get("network") == "udp" and rule.get("port") == 443
        for rule in android["route"]["rules"]
    )
    assert android["dns"]["rules"][0]["domain_suffix"] == play_rule["domain_suffix"]
    assert android["inbounds"][0]["mtu"] == 1360
    assert not any(rule.get("outbound") == "Google Play" for rule in desktop["route"]["rules"])
    github_domains = [
        "github.com",
        "githubusercontent.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ]
    github_route = next(
        rule
        for rule in desktop["route"]["rules"]
        if set(rule.get("domain_suffix", [])) >= set(github_domains)
    )
    assert github_route["outbound"] == "Available"
    github_ip_rule = next(
        rule
        for rule in desktop["route"]["rules"]
        if set(rule.get("ip_cidr", [])) >= {"185.199.108.0/22", "154.17.2.113/32"}
    )
    assert github_ip_rule["outbound"] == "Available"
    assert "tls_record_fragment" not in github_ip_rule
    assert any(
        rule.get("server") == "google" and set(rule.get("domain_suffix", [])) >= set(github_domains)
        for rule in desktop["dns"]["rules"]
    )
    accelerator_rule = next(
        rule
        for rule in desktop["route"]["rules"]
        if "process_name" in rule and "WattToolkit.exe" in rule.get("process_name", [])
    )
    assert accelerator_rule["outbound"] == "direct"
    assert {
        "GuGuai.exe",
        "xunyou.exe",
        "xunyouservice.exe",
        "UUAccelerator.exe",
        "uuassistant.exe",
        "uuservice.exe",
        "leigodservice.exe",
        "qiyouservice.exe",
        "biubiuservice.exe",
        "AKAccelerator.exe",
        "AKService.exe",
        "GameBooster.exe",
        "WattToolkit.exe",
    } <= set(accelerator_rule["process_name"])
    route_rules = desktop["route"]["rules"]

    def route_for(domain: str) -> tuple[int, dict]:
        return next(
            (index, rule)
            for index, rule in enumerate(route_rules)
            if domain in rule.get("domain_suffix", [])
        )

    steam_index, steam_rule = route_for("steamcontent.com")
    steam_server_index, steam_server_rule = route_for("steamserver.net")
    ms_download_index, ms_download_rule = route_for("download.microsoft.com")
    copilot_index, copilot_rule = route_for("copilot.microsoft.com")
    microsoft_index, microsoft_rule = route_for("microsoft.com")
    steam_static_index, steam_static_rule = route_for("steamstatic.com")
    docker_index, docker_rule = route_for("registry-1.docker.io")
    assert steam_rule["outbound"] == "direct"
    assert steam_server_rule["outbound"] == "游戏平台"
    assert ms_download_rule["outbound"] == "微软"
    assert copilot_rule["outbound"] == "AI"
    assert microsoft_rule["outbound"] == "微软"
    assert steam_static_rule["outbound"] == "游戏平台"
    assert docker_rule["outbound"] == "Available"
    # Ordering: game bulk goes direct first; AI precedes the service groups;
    # service groups follow SERVICE_GROUPS order (微软 before 游戏平台); and the
    # Available remainder (docker) comes after every service group.
    assert steam_index < copilot_index < microsoft_index
    assert microsoft_index < steam_server_index
    assert steam_server_index == steam_static_index
    assert microsoft_index < docker_index

    dns_rules = desktop["dns"]["rules"]

    def dns_for(domain: str) -> tuple[int, dict]:
        return next(
            (index, rule)
            for index, rule in enumerate(dns_rules)
            if domain in rule.get("domain_suffix", [])
        )

    _, steam_dns_rule = dns_for("steamcontent.com")
    steam_server_dns_index, steam_server_dns_rule = dns_for("steamserver.net")
    ms_download_dns_index, ms_download_dns_rule = dns_for("download.microsoft.com")
    copilot_dns_index, copilot_dns_rule = dns_for("copilot.microsoft.com")
    microsoft_dns_index, microsoft_dns_rule = dns_for("microsoft.com")
    _, steam_static_dns_rule = dns_for("steamstatic.com")
    _, docker_dns_rule = dns_for("registry-1.docker.io")
    assert steam_dns_rule["server"] == "local"
    assert steam_server_dns_rule["server"] == "google"
    assert ms_download_dns_rule["server"] == "google"
    assert copilot_dns_rule["server"] == "google"
    assert microsoft_dns_rule["server"] == "google"
    assert steam_static_dns_rule["server"] == "google"
    assert docker_dns_rule["server"] == "google"
    assert steam_server_dns_index == microsoft_dns_index
    assert ms_download_dns_index == microsoft_dns_index
    assert copilot_dns_index < microsoft_dns_index


def test_simple_generator_emits_no_region_groups(tmp_path):
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
    selectors = {outbound["tag"] for outbound in conf["outbounds"] if outbound.get("type") == "selector"}
    assert not any(tag.startswith("地区/") for tag in selectors)


def test_desktop_template_routes_accelerator_processes_directly():
    template = json.loads(
        (Path(__file__).resolve().parents[1] / "templates" / "desktop-windows-sing-box-1.14.json").read_text(
            encoding="utf-8"
        )
    )
    route = template["route"]
    direct_rule = next(rule for rule in route["rules"] if "GuGuai.exe" in rule.get("process_name", []))
    assert route["find_process"] is True
    assert direct_rule["outbound"] == "direct"
    assert {"GuGuai.exe", "guguaiwebhelper.exe", "xunyou.exe", "UUAccelerator.exe", "leigod.exe", "qiyou.exe", "biubiu.exe"} <= set(direct_rule["process_name"])

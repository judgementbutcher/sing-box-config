#!/usr/bin/env python3
"""Generate the two everyday sing-box configuration files.

This is deliberately a small facade over the subscription parser.  It does
not deploy a Windows service, manage core versions, or expose profile choices.
"""

from __future__ import annotations

import argparse
import copy
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from build_singbox import (
    build_selector,
    build_config_from_subscriptions,
    configured_group_tag,
    load_json,
    load_policy_aliases,
    load_subscription_manifest,
)
from parsers.common import detect_region
from singbox_config.audit import is_proxy_outbound, require_valid_config
from singbox_config.io_utils import atomic_write_json
from singbox_config.profiles import apply_profile_to_template


ROOT = Path(__file__).resolve().parent
REQUIRED_REGIONS = ("HK", "US", "TW", "JP", "SG", "FR", "GB")
SELF_HOSTED_ROLES = {"primary", "self", "self-hosted", "selfhosted", "personal"}
REGION_LABELS = {
    "HK": "香港",
    "US": "美国",
    "TW": "台湾",
    "JP": "日本",
    "SG": "新加坡",
    "FR": "法国",
    "GB": "英国",
}
GOOGLE_PLAY_DOMAINS = (
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
)
GITHUB_DOWNLOAD_DOMAINS = (
    "github.com",
    "githubusercontent.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)
GITHUB_DOWNLOAD_IP_CIDRS = ("185.199.108.0/22", "154.17.2.113/32")
DIRECT_DOWNLOAD_DOMAINS = (
    # Only force game bulk payloads direct.  Smaller daily downloads should keep
    # the proxy-first experience and are listed in AVAILABLE_PROXY_DOMAINS.
    "steamcontent.com",
    "steamcdn-a.akamaihd.net",
    "epicgames-download1.akamaized.net",
    "download.epicgames.com",
    "download2.epicgames.com",
    "download3.epicgames.com",
    "download4.epicgames.com",
    "epicgamescdn.com",
    "cloudflare.epicgamescdn.com",
    "blzddist1-a.akamaihd.net",
    "level3.blizzard.com",
    "cdn.blizzard.com",
    "riotcdn.net",
    "riotgamespatcher-a.akamaihd.net",
    "lolstatic-a.akamaihd.net",
    "origin-a.akamaihd.net",
    "akamai.cdn.ea.com",
    "ubistatic-a.akamaihd.net",
    "uplaypc-s-ubisoft.cdn.ubi.com",
)
DOMESTIC_DIRECT_DOMAINS = (
    # Domestic AI and domestic SaaS stay direct because the base policy is China-direct.
    "deepseek.com",
    "deepseek.cn",
    "moonshot.cn",
    "kimi.com",
    "doubao.com",
    "volces.com",
    "volcengine.com",
    "aliyun.com",
    "aliyuncs.com",
    "qianwen.aliyun.com",
    "tongyi.aliyun.com",
    "baidu.com",
    "yiyan.baidu.com",
    "tencent.com",
    "hunyuan.tencent.com",
    "yuanbao.tencent.com",
    "zhipuai.cn",
    "bigmodel.cn",
)
AI_PROXY_DOMAINS = (
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "claude.ai",
    "claudeusercontent.com",
    "perplexity.ai",
    "pplx.ai",
    "poe.com",
    "grok.com",
    "x.ai",
    "mistral.ai",
    "mistralcdn.com",
    "huggingface.co",
    "hf.co",
    "huggingfacehub.com",
    "replicate.com",
    "openrouter.ai",
    "groq.com",
    "cohere.ai",
    "together.ai",
    "phind.com",
    "cursor.com",
    "cursor.sh",
    "anysphere.co",
    "codeium.com",
    "windsurf.com",
    "exafunction.com",
    "githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "copilot.microsoft.com",
    "sydney.bing.com",
    "edgeservices.bing.com",
    "ai.google.dev",
    "gemini.google.com",
    "aistudio.google.com",
    "makersuite.google.com",
    "notebooklm.google.com",
    "generativelanguage.googleapis.com",
    "developerprofiles-pa.googleapis.com",
    "content-developerprofiles-pa.googleapis.com",
)
# --- Per-service domain buckets -------------------------------------------
# Big or commonly pinned services each get their own selector group so a
# specific airport can be chosen per service.  Every group mirrors the
# ``Available`` member list, so by default they follow the global pick.
GOOGLE_DOMAINS = (
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "ggpht.com",
    "gvt1.com",
    "gvt2.com",
    "gvt3.com",
)
YOUTUBE_DOMAINS = (
    "youtube.com",
    "youtubei.googleapis.com",
    "googlevideo.com",
    "youtu.be",
    "ytimg.com",
)
NETFLIX_DOMAINS = (
    "netflix.com",
    "nflxvideo.net",
    "nflximg.net",
    "nflxso.net",
)
TELEGRAM_DOMAINS = (
    "telegram.org",
    "t.me",
    "telegram.me",
    "telegram.dog",
    "tdesktop.com",
)
TELEGRAM_IP_CIDRS = (
    # Telegram data centers are frequently reached by IP before DNS resolves.
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "149.154.160.0/20",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
    "2001:67c:4e8::/48",
)
SOCIAL_DOMAINS = (
    "x.com",
    "twitter.com",
    "twimg.com",
    "facebook.com",
    "fbcdn.net",
    "instagram.com",
    "cdninstagram.com",
    "whatsapp.com",
    "signal.org",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "reddit.com",
    "redd.it",
    "redditmedia.com",
    "redditstatic.com",
    "medium.com",
    "wikipedia.org",
    "wikimedia.org",
    "pixiv.net",
    "fanbox.cc",
    "patreon.com",
)
MICROSOFT_DOMAINS = (
    "bing.com",
    "live.com",
    "microsoft.com",
    "msftauth.net",
    "msauth.net",
    "visualstudio.com",
    "windows.net",
    "skype.com",
    # Windows/Office/VS downloads: prioritize usability over saving proxy quota.
    "download.microsoft.com",
    "download.visualstudio.microsoft.com",
    "download.windowsupdate.com",
    "dl.delivery.mp.microsoft.com",
    "officecdn.microsoft.com",
    "officecdn.microsoft.com.edgesuite.net",
    "update.microsoft.com",
    "windowsupdate.com",
    "windowsupdate.microsoft.com",
    "ntservicepack.microsoft.com",
    "vscode.download.prss.microsoft.com",
)
APPLE_DOMAINS = (
    "swcdn.apple.com",
    "updates.cdn-apple.com",
    "appldnld.apple.com",
    "mesu.apple.com",
    "xp.apple.com",
)
STEAM_DOMAINS = (
    "steamserver.net",
    "steamstatic.com",
    "steamcommunity.com",
    "steampowered.com",
    "steamusercontent.com",
    "steam-chat.com",
    "steamgames.com",
)
# Ordered service groups.  Each name becomes a selector whose members mirror
# ``Available`` (with ``Available`` first, so the default follows the global
# pick), and whose domains route to that selector.  Kept deliberately modest
# to avoid cluttering the client's group list.  Order matters where one
# service's domain is a subdomain of another's: ``YouTube`` precedes ``谷歌``
# so ``youtubei.googleapis.com`` matches YouTube before the broader
# ``googleapis.com`` in the 谷歌 bucket.
SERVICE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("YouTube", YOUTUBE_DOMAINS),
    ("谷歌", GOOGLE_DOMAINS),
    ("Netflix", NETFLIX_DOMAINS),
    ("Telegram", TELEGRAM_DOMAINS),
    ("社交媒体", SOCIAL_DOMAINS),
    ("微软", MICROSOFT_DOMAINS),
    ("苹果", APPLE_DOMAINS),
    ("游戏平台", STEAM_DOMAINS),
)
SERVICE_GROUP_TAGS: tuple[str, ...] = tuple(tag for tag, _ in SERVICE_GROUPS)
AVAILABLE_PROXY_DOMAINS = (
    # Remainder that should stay on the proxy but doesn't warrant its own
    # per-service group: music/streaming that rarely needs airport pinning,
    # plus daily software / OS / driver / package-manager / developer
    # downloads.  Everything here routes to the general ``Available`` proxy.
    "spotify.com",
    "scdn.co",
    "spotifycdn.com",
    "twitch.tv",
    "ttvnw.net",
    "download.jetbrains.com",
    "download-cdn.jetbrains.com",
    "cache-redirector.jetbrains.com",
    "download.nvidia.com",
    "international.download.nvidia.com",
    "drivers.amd.com",
    "downloadmirror.intel.com",
    "pypi.org",
    "files.pythonhosted.org",
    "python.org",
    "nodejs.org",
    "npmjs.org",
    "registry.npmjs.org",
    "yarnpkg.com",
    "pnpm.io",
    "docker.com",
    "docker.io",
    "registry-1.docker.io",
    "production.cloudflare.docker.com",
    "ghcr.io",
    "pkg-containers.githubusercontent.com",
    "quay.io",
    "gcr.io",
    "pkg.go.dev",
    "proxy.golang.org",
    "golang.org",
    "go.dev",
    "rust-lang.org",
    "crates.io",
    "static.crates.io",
    "maven.org",
    "maven.apache.org",
    "repo.maven.apache.org",
    "gradle.org",
    "services.gradle.org",
    "linux.do",
    "flowlauncher.com",
)

TARGETS: Dict[str, Dict[str, Any]] = {
    "desktop": {
        "label": "桌面端",
        "template_candidates": (
            "templates/desktop-windows-sing-box-1.14.json",
            "template.json",
            "template.example.json",
        ),
        "profile": {
            "name": "desktop",
            "platform": "windows",
            "core": {"version": "1.14.0-alpha.45"},
            "runtime": {"disable_provider_urltests": True},
            "auto": {"enabled": False},
            "control": {
                "max_nodes": 0,
                "dns_detour": "Available",
                "update_detour": "Available",
            },
            "tuning": {
                "tun_stack": "system",
                "tun_mtu": 1500,
                "tun_dns_mode": "hijack",
                "dns_optimistic": True,
                "dns_timeout": "8s",
                "cache_store_dns": True,
            },
            "clash_api": {
                "enabled": True,
                "controller": "127.0.0.1:9090",
                "default_mode": "Rule",
                "external_ui": True,
                "external_ui_path": "dashboard",
                "external_ui_download_url": "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip",
            },
        },
    },
    "android": {
        "label": "安卓端",
        "template_candidates": (
            # Single authoritative template: Android reuses the desktop policy
            # and lets profiles.py derive the platform variant.  The dedicated
            # Android file and template.json remain as fallbacks.
            "templates/desktop-windows-sing-box-1.14.json",
            "templates/mobile-android-sing-box-1.13.14.json",
            "template.json",
            "template.example.json",
        ),
        "profile": {
            "name": "android",
            "platform": "android",
            "core": {"version": "1.13.14"},
            "runtime": {"disable_provider_urltests": True},
            "auto": {"enabled": False},
            "control": {
                "max_nodes": 0,
                "dns_detour": "Available",
                "update_detour": "Available",
            },
            "tuning": {
                "tun_stack": "system",
                # Mobile networks and tunneled proxy transports can have a
                # substantially smaller path MTU than Ethernet.
                "tun_mtu": 1360,
                "udp_timeout": "2m",
                "rule_set_update_interval": "7d",
                # Android reuses the desktop authoritative template, so keep a
                # separate cache file instead of sharing the desktop one.
                "cache_path": "cache.android.db",
            },
            "clash_api": {"enabled": False},
        },
    },
}


class RequiredRegionsError(RuntimeError):
    """Raised before publishing when a required country is missing."""


@dataclass(frozen=True)
class GeneratedConfig:
    target: str
    output_path: Path
    node_count: int
    region_counts: Dict[str, int]


def resolve_targets(value: str) -> tuple[str, ...]:
    if value == "all":
        return ("desktop", "android")
    if value not in TARGETS:
        raise ValueError(f"未知目标: {value}")
    return (value,)


def resolve_template_path(
    target: str,
    *,
    root: Path = ROOT,
    template_paths: Mapping[str, Path | str] | None = None,
) -> Path:
    if template_paths and target in template_paths:
        path = Path(template_paths[target])
        if path.exists():
            return path
        raise FileNotFoundError(f"{TARGETS[target]['label']}模板不存在: {path}")

    for relative_path in TARGETS[target]["template_candidates"]:
        path = root / relative_path
        if path.exists():
            return path
    candidates = ", ".join(str(root / value) for value in TARGETS[target]["template_candidates"])
    raise FileNotFoundError(f"未找到{TARGETS[target]['label']}模板。请准备其中之一: {candidates}")


def is_self_hosted_subscription(item: Mapping[str, Any]) -> bool:
    explicit = item.get("self_hosted", item.get("self-hosted"))
    if explicit is not None:
        return str(explicit).strip().lower() in {"1", "true", "yes", "on"}
    category = str(item.get("category") or item.get("kind") or "").strip().lower()
    if category in {"self", "self-hosted", "selfhosted", "personal"}:
        return True
    return str(item.get("role") or "default").strip().lower() in SELF_HOSTED_ROLES


def simplify_subscriptions(subscriptions: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """Normalize active sources into airport and self-hosted groups."""

    simple_items = copy.deepcopy(list(subscriptions))
    for item in simple_items:
        item["_simple_group_kind"] = "self-hosted" if is_self_hosted_subscription(item) else "airport"
        item["include_in_available"] = False
        item["flat_group"] = True
        item["urltest"] = False
        item.pop("include_in_selectors", None)
    return simple_items


def proxy_region_counts(conf: Dict[str, Any]) -> Counter[str]:
    return Counter(
        detect_region(str(outbound.get("tag") or ""))
        for outbound in conf.get("outbounds", [])
        if isinstance(outbound, dict) and is_proxy_outbound(outbound)
    )


def require_required_regions(region_counts: Mapping[str, int]) -> None:
    missing = [REGION_LABELS[region] for region in REQUIRED_REGIONS if not region_counts.get(region)]
    if missing:
        raise RequiredRegionsError(
            f"订阅中缺少必需地区：{'、'.join(missing)}；为避免覆盖现有配置，本次未写入任何配置文件。"
        )


def set_selector(
    conf: Dict[str, Any],
    tag: str,
    choices: Sequence[str],
) -> None:
    outbounds = conf.setdefault("outbounds", [])
    selector = next(
        (
            outbound
            for outbound in outbounds
            if isinstance(outbound, dict) and outbound.get("type") == "selector" and outbound.get("tag") == tag
        ),
        None,
    )
    if selector is None:
        outbounds.append(build_selector(tag, list(choices)))
        return
    selector["outbounds"] = list(dict.fromkeys(choices))
    selector.pop("default", None)


def rewrite_references(conf: Dict[str, Any], replacements: Mapping[str, str]) -> None:
    def replace(value: Any) -> Any:
        return replacements.get(str(value), value)

    route = conf.get("route") if isinstance(conf.get("route"), dict) else {}
    if route.get("final"):
        route["final"] = replace(route["final"])
    for rule in route.get("rules", []):
        if isinstance(rule, dict) and rule.get("outbound"):
            rule["outbound"] = replace(rule["outbound"])
    for outbound in conf.get("outbounds", []):
        if isinstance(outbound, dict) and isinstance(outbound.get("outbounds"), list):
            outbound["outbounds"] = [replace(value) for value in outbound["outbounds"]]
            if outbound.get("default"):
                outbound["default"] = replace(outbound["default"])


def normalized_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def policy_insert_index(rules: Sequence[Any]) -> int:
    index = 0
    while index < len(rules):
        rule = rules[index]
        if not isinstance(rule, dict):
            break
        if rule.get("action") == "sniff" or rule.get("protocol") == "dns":
            index += 1
            continue
        break
    return index


def drop_managed_domain_rules(
    rules: Sequence[Any],
    managed_domains: set[str],
    *,
    key: str,
    targets: set[str],
) -> list[Any]:
    retained: list[Any] = []
    for rule in rules:
        if not isinstance(rule, dict):
            retained.append(rule)
            continue
        suffixes = set(normalized_string_list(rule.get("domain_suffix")))
        if (
            suffixes
            and suffixes.issubset(managed_domains)
            and rule.get("action") == "route"
            and str(rule.get(key) or "") in targets
        ):
            continue
        retained.append(rule)
    return retained


def insert_domain_route_rule(
    rules: list[Any],
    index: int,
    domains: Sequence[str],
    outbound: str,
) -> int:
    rules.insert(
        index,
        {
            "domain_suffix": list(dict.fromkeys(domains)),
            "action": "route",
            "outbound": outbound,
        },
    )
    return index + 1


def insert_ip_route_rule(
    rules: list[Any],
    index: int,
    cidrs: Sequence[str],
    outbound: str,
) -> int:
    rules.insert(
        index,
        {
            "ip_cidr": list(dict.fromkeys(cidrs)),
            "action": "route",
            "outbound": outbound,
        },
    )
    return index + 1


def insert_domain_dns_rule(
    rules: list[Any],
    index: int,
    domains: Sequence[str],
    server: str,
) -> int:
    rules.insert(
        index,
        {
            "domain_suffix": list(dict.fromkeys(domains)),
            "action": "route",
            "server": server,
        },
    )
    return index + 1


def configure_service_split_policy(conf: Dict[str, Any]) -> None:
    """Install the everyday split policy with per-service selector groups.

    Route order (inserted right after the sniff/hijack-dns rules):
    1. game bulk payloads go direct to avoid wasting proxy quota;
    2. domestic AI/SaaS stays direct as part of the China-direct baseline;
    3. overseas AI goes to ``AI`` before broad Google/Microsoft rules;
    4. each big service routes to its own selector group (谷歌/YouTube/Netflix/
       Telegram/社交媒体/微软/苹果/游戏平台) for per-service airport pinning;
    5. remaining overseas services and daily downloads go to ``Available``;
    6. existing geosite-cn/geoip-cn rules keep the rest of China direct;
    7. route.final remains ``Available`` for everything else.

    DNS mirrors this: direct/domestic names resolve through ``local`` and every
    proxied name (AI, each service, and the Available remainder) resolves
    through the clean ``google`` server before the trailing geosite-cn rule.
    """

    direct_domains = list(dict.fromkeys(DIRECT_DOWNLOAD_DOMAINS))
    domestic_domains = list(dict.fromkeys(DOMESTIC_DIRECT_DOMAINS))
    ai_domains = list(dict.fromkeys(AI_PROXY_DOMAINS))
    service_buckets = [(tag, list(dict.fromkeys(domains))) for tag, domains in SERVICE_GROUPS]
    available_domains = list(dict.fromkeys(AVAILABLE_PROXY_DOMAINS))
    service_domains = [domain for _, domains in service_buckets for domain in domains]
    managed_domains = set(
        direct_domains + domestic_domains + ai_domains + service_domains + available_domains
    )
    proxy_targets = {"direct", "Available", "AI", *SERVICE_GROUP_TAGS}

    route = conf.setdefault("route", {})
    route_rules = route.setdefault("rules", [])
    route["rules"] = drop_managed_domain_rules(
        route_rules,
        managed_domains,
        key="outbound",
        targets=proxy_targets,
    )
    route_rules = route["rules"]
    insert_at = policy_insert_index(route_rules)
    insert_at = insert_domain_route_rule(route_rules, insert_at, direct_domains, "direct")
    insert_at = insert_domain_route_rule(route_rules, insert_at, domestic_domains, "direct")
    insert_at = insert_domain_route_rule(route_rules, insert_at, ai_domains, "AI")
    for tag, domains in service_buckets:
        insert_at = insert_domain_route_rule(route_rules, insert_at, domains, tag)
        if tag == "Telegram":
            insert_at = insert_ip_route_rule(route_rules, insert_at, TELEGRAM_IP_CIDRS, tag)
    insert_domain_route_rule(route_rules, insert_at, available_domains, "Available")

    dns = conf.setdefault("dns", {})
    dns_rules = dns.setdefault("rules", [])
    dns_server_tags = {
        str(server.get("tag"))
        for server in dns.get("servers", [])
        if isinstance(server, dict) and server.get("tag")
    }
    dns["rules"] = drop_managed_domain_rules(
        dns_rules,
        managed_domains,
        key="server",
        targets={"local", "google"},
    )
    dns_rules = dns["rules"]
    insert_at = 0
    if "local" in dns_server_tags:
        insert_at = insert_domain_dns_rule(dns_rules, insert_at, direct_domains, "local")
        insert_at = insert_domain_dns_rule(dns_rules, insert_at, domestic_domains, "local")
    if "google" in dns_server_tags:
        insert_at = insert_domain_dns_rule(dns_rules, insert_at, ai_domains, "google")
        insert_at = insert_domain_dns_rule(dns_rules, insert_at, service_domains, "google")
        insert_domain_dns_rule(dns_rules, insert_at, available_domains, "google")


def organize_groups(
    conf: Dict[str, Any],
    subscriptions: Sequence[Dict[str, Any]],
    policy_aliases: Mapping[str, str],
) -> None:
    """Expose only airport, self-hosted, regional, Available, and AI selectors."""

    outbounds = conf.setdefault("outbounds", [])
    proxy_tags = {
        str(outbound["tag"])
        for outbound in outbounds
        if isinstance(outbound, dict) and is_proxy_outbound(outbound) and outbound.get("tag")
    }
    source_tags = {
        "self-hosted": [],
        "airport": [],
    }
    ai_preferred_source_tags: list[str] = []
    for item in subscriptions:
        kind = str(item.get("_simple_group_kind") or "airport")
        if kind not in source_tags:
            continue
        source_tag = configured_group_tag(item, str(item["name"]))
        source_tags[kind].append(source_tag)
        if item.get("ai_include") is True:
            ai_preferred_source_tags.append(source_tag)

    selectors = {
        str(outbound.get("tag")): outbound
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("type") == "selector" and outbound.get("tag")
    }
    airport_groups: list[str] = []
    self_node_tags: list[str] = []
    for kind, tags in source_tags.items():
        for tag in tags:
            selector = selectors.get(tag)
            if not selector:
                continue
            node_tags = [str(value) for value in selector.get("outbounds", []) if str(value) in proxy_tags]
            if kind == "airport":
                if node_tags:
                    selector["outbounds"] = node_tags
                    selector.pop("default", None)
                    airport_groups.append(tag)
            else:
                self_node_tags.extend(node_tags)

    self_group = "自建"
    if self_node_tags:
        if self_group in selectors and self_group not in source_tags["self-hosted"]:
            raise RuntimeError(f"自建分组名称与现有 outbound 冲突: {self_group}")
        set_selector(conf, self_group, list(dict.fromkeys(self_node_tags)))

    self_tags = set(source_tags["self-hosted"])
    if self_node_tags:
        rewrite_references(conf, {tag: self_group for tag in self_tags})

    available_choices = airport_groups + ([self_group] if self_node_tags else [])
    if not available_choices:
        raise RuntimeError("没有可放入 Available 的机场或自建分组")
    set_selector(conf, "Available", available_choices)

    ai_nodes = [
        str(node_tag)
        for source_tag in ai_preferred_source_tags
        for node_tag in selectors.get(source_tag, {}).get("outbounds", [])
        if str(node_tag) in proxy_tags
    ]
    us_nodes = [
        str(outbound["tag"])
        for outbound in conf.get("outbounds", [])
        if isinstance(outbound, dict)
        and is_proxy_outbound(outbound)
        and outbound.get("tag")
        and detect_region(str(outbound["tag"])) == "US"
    ]
    ai_nodes = list(dict.fromkeys(ai_nodes + us_nodes))
    if not ai_nodes:
        raise RequiredRegionsError("订阅中缺少可用于 AI 的节点")
    set_selector(conf, "AI", ai_nodes)

    alias_replacements: Dict[str, str] = {}
    for alias in policy_aliases:
        selector = selectors.get(alias)
        if not selector:
            continue
        choices = [str(value) for value in selector.get("outbounds", []) if str(value).strip()]
        if len(choices) == 1:
            alias_replacements[str(alias)] = choices[0]
    if alias_replacements:
        rewrite_references(conf, alias_replacements)

    remove_tags = self_tags | set(alias_replacements) | {"DNS-Out", "Update-Out"}
    conf["outbounds"] = [
        outbound
        for outbound in conf.get("outbounds", [])
        if not isinstance(outbound, dict) or str(outbound.get("tag") or "") not in remove_tags
    ]
    for outbound in conf["outbounds"]:
        if isinstance(outbound, dict) and outbound.get("type") == "selector":
            outbound.pop("default", None)

    # Per-service selector groups mirror Available with Available listed first,
    # so each one defaults to following the global pick but can be pinned to a
    # specific airport for finer-grained routing.
    service_members = ["Available"] + available_choices
    for tag in SERVICE_GROUP_TAGS:
        set_selector(conf, tag, service_members)


def configure_android_google_play(conf: Dict[str, Any]) -> None:
    """Keep Play traffic on the proxy with clean DNS, via the 谷歌 group.

    Play flows through the ``谷歌`` service group (which mirrors ``Available``)
    just like other Google traffic.  Two explicit rules are still needed:
    ``dl.google.com`` (Play's main download CDN) is listed in geosite-cn, so
    without an override the trailing geosite-cn rule would force it to direct +
    domestic DNS, which is slow or unreachable in China and would defeat the
    point.  The route rule keeps Play on the proxy and the DNS rule keeps its
    names resolved through Google.
    """

    route = conf.setdefault("route", {})
    rules = route.setdefault("rules", [])
    play_rule = {
        "domain_suffix": list(GOOGLE_PLAY_DOMAINS),
        "action": "route",
        "outbound": "谷歌",
    }
    # Keep sniffing and DNS hijacking first, then match Play before the
    # trailing geosite-cn rule can grab dl.google.com for direct routing.
    insert_at = min(2, len(rules))
    rules.insert(insert_at, play_rule)

    dns = conf.setdefault("dns", {})
    dns_rules = dns.setdefault("rules", [])
    dns_server_tags = {
        str(server.get("tag"))
        for server in dns.get("servers", [])
        if isinstance(server, dict) and server.get("tag")
    }
    if "google" in dns_server_tags:
        dns_rules.insert(
            0,
            {
                "domain_suffix": list(GOOGLE_PLAY_DOMAINS),
                "action": "route",
                "server": "google",
            },
        )


def configure_github_downloads(conf: Dict[str, Any]) -> None:
    """Keep GitHub release traffic on the proxy instead of the direct path."""

    github_domains = list(GITHUB_DOWNLOAD_DOMAINS)
    github_domain_set = set(GITHUB_DOWNLOAD_DOMAINS)
    github_ip_set = set(GITHUB_DOWNLOAD_IP_CIDRS)

    route = conf.setdefault("route", {})
    rules = route.setdefault("rules", [])
    github_route_rule = None
    github_ip_rule = None
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        suffixes = rule.get("domain_suffix")
        if isinstance(suffixes, str):
            suffixes = [suffixes]
        if isinstance(suffixes, list) and github_domain_set.issubset(
            {str(value) for value in suffixes if str(value).strip()}
        ):
            github_route_rule = rule
        cidrs = rule.get("ip_cidr")
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        if isinstance(cidrs, list) and github_ip_set.issubset(
            {str(value) for value in cidrs if str(value).strip()}
        ):
            github_ip_rule = rule

    if github_route_rule is None:
        insert_at = min(2, len(rules))
        rules.insert(
            insert_at,
            {
                "domain_suffix": github_domains,
                "action": "route",
                "outbound": "Available",
            },
        )
    else:
        github_route_rule["action"] = "route"
        github_route_rule["outbound"] = "Available"

    if github_ip_rule is not None:
        github_ip_rule["action"] = "route"
        github_ip_rule["outbound"] = "Available"
        github_ip_rule.pop("tls_record_fragment", None)

    dns = conf.setdefault("dns", {})
    dns_rules = dns.setdefault("rules", [])
    dns_server_tags = {
        str(server.get("tag"))
        for server in dns.get("servers", [])
        if isinstance(server, dict) and server.get("tag")
    }
    github_dns_rule = None
    for rule in dns_rules:
        if not isinstance(rule, dict) or rule.get("server") != "google":
            continue
        suffixes = rule.get("domain_suffix")
        if isinstance(suffixes, str):
            suffixes = [suffixes]
        if isinstance(suffixes, list) and github_domain_set.issubset(
            {str(value) for value in suffixes if str(value).strip()}
        ):
            github_dns_rule = rule
            break

    if github_dns_rule is None and "google" in dns_server_tags:
        dns_rules.insert(
            0,
            {
                "domain_suffix": github_domains,
                "action": "route",
                "server": "google",
            },
        )
    elif github_dns_rule is not None:
        github_dns_rule["action"] = "route"
        github_dns_rule["server"] = "google"


def stage_target(
    target: str,
    *,
    subscriptions_path: Path,
    fetch_proxy: str | None,
    offline: bool,
    cache_dir: Path | None,
    policy_aliases_path: Path | None,
    root: Path = ROOT,
    template_paths: Mapping[str, Path | str] | None = None,
) -> tuple[Dict[str, Any], Counter[str]]:
    template_path = resolve_template_path(target, root=root, template_paths=template_paths)
    template = load_json(str(template_path))
    profile = copy.deepcopy(TARGETS[target]["profile"])
    template = apply_profile_to_template(template, profile)

    subscriptions = simplify_subscriptions(
        load_subscription_manifest(subscriptions_path, "subscriptions/example-provider.txt")
    )
    aliases = load_policy_aliases(policy_aliases_path)
    conf = build_config_from_subscriptions(
        subscriptions=subscriptions,
        template=template,
        manifest_base_dir=subscriptions_path.parent,
        max_nodes_per_region=0,
        max_other_nodes=0,
        keep_info_nodes=False,
        cache_dir=cache_dir,
        fetch_proxy=fetch_proxy,
        available_urltest=False,
        profile=profile,
        offline=offline,
        policy_aliases=aliases,
        preserve_all_nodes=True,
        included_regions=set(REQUIRED_REGIONS),
        unfiltered_roles=SELF_HOSTED_ROLES,
        skip_empty_groups=True,
        policy_alias_fallback="Available",
    )
    organize_groups(conf, subscriptions, aliases)
    configure_service_split_policy(conf)
    configure_github_downloads(conf)
    if target == "android":
        configure_android_google_play(conf)
    require_valid_config(conf)
    region_counts = proxy_region_counts(conf)
    return conf, region_counts


def generate_configs(
    targets: Sequence[str],
    *,
    subscriptions_path: Path | str = ROOT / "subscriptions.yaml",
    output_dir: Path | str = ROOT / "dist",
    fetch_proxy: str | None = None,
    offline: bool = False,
    cache_dir: Path | str | None = ROOT / "runtime" / "subscription-cache",
    policy_aliases_path: Path | str | None = ROOT / "policy_aliases.yaml",
    root: Path = ROOT,
    template_paths: Mapping[str, Path | str] | None = None,
) -> list[GeneratedConfig]:
    """Build all requested targets first, then atomically publish their configs."""

    subscriptions_path = Path(subscriptions_path)
    output_dir = Path(output_dir)
    cache_path = Path(cache_dir) if cache_dir is not None else None
    aliases_path = Path(policy_aliases_path) if policy_aliases_path is not None else None
    staged: list[tuple[str, Dict[str, Any], Counter[str], Path]] = []

    for target in targets:
        if target not in TARGETS:
            raise ValueError(f"未知目标: {target}")
        conf, region_counts = stage_target(
            target,
            subscriptions_path=subscriptions_path,
            fetch_proxy=fetch_proxy,
            offline=offline,
            cache_dir=cache_path,
            policy_aliases_path=aliases_path,
            root=root,
            template_paths=template_paths,
        )
        staged.append((target, conf, region_counts, output_dir / target / "config.json"))

    generated: list[GeneratedConfig] = []
    for target, conf, region_counts, output_path in staged:
        atomic_write_json(output_path, conf)
        generated.append(
            GeneratedConfig(
                target=target,
                output_path=output_path,
                node_count=sum(
                    1
                    for outbound in conf.get("outbounds", [])
                    if isinstance(outbound, dict) and is_proxy_outbound(outbound)
                ),
                region_counts={region: int(region_counts.get(region, 0)) for region in REQUIRED_REGIONS},
            )
        )
    return generated


def project_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="生成桌面端和安卓端 sing-box 配置")
    parser.add_argument("target", choices=("all", "desktop", "android"), nargs="?", default="all")
    parser.add_argument("--subscriptions", default="subscriptions.yaml", help="订阅清单，默认 subscriptions.yaml")
    parser.add_argument("--output-dir", default="dist", help="输出目录，默认 dist")
    parser.add_argument("--fetch-proxy", default=None, help="下载订阅时使用的 HTTP/SOCKS 代理")
    parser.add_argument("--offline", action="store_true", help="只使用本地订阅缓存")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        results = generate_configs(
            resolve_targets(args.target),
            subscriptions_path=project_path(args.subscriptions),
            output_dir=project_path(args.output_dir),
            fetch_proxy=args.fetch_proxy,
            offline=args.offline,
        )
    except Exception as exc:
        print(f"生成失败: {exc}", file=sys.stderr)
        return 1

    for result in results:
        regions = "、".join(
            f"{REGION_LABELS[region]} {result.region_counts[region]}"
            for region in REQUIRED_REGIONS
        )
        print(f"{TARGETS[result.target]['label']}配置已生成: {result.output_path}")
        print(f"  节点 {result.node_count} 个；{regions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

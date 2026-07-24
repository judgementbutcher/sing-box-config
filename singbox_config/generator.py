#!/usr/bin/env python3
"""Generate the desktop and Android sing-box configurations."""

from __future__ import annotations

import argparse
import copy
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from .builder import (
    build_selector,
    build_urltest,
    build_config_from_subscriptions,
    configured_group_tag,
    load_json,
    load_policy_aliases,
    load_subscription_manifest,
    parse_bool,
)
from parsers.common import ALL_REGIONS, detect_region
from singbox_config.audit import is_proxy_outbound, require_valid_config
from singbox_config.io_utils import atomic_write_json
from singbox_config.profiles import apply_profile_to_template


ROOT = Path(__file__).resolve().parents[1]
LOCAL_CONFIG_DIR = ROOT / "config" / "local"
CORE_VERSION_DESKTOP = "1.14.0-beta.1"
# Android client is upgraded by the user; keep the same 1.14 feature gate as desktop.
CORE_VERSION_ANDROID = "1.14.0-beta.1"
REQUIRED_REGIONS = ("HK", "US", "TW", "JP", "SG", "FR", "GB")
# Regions enforced before publishing: if a subscription silently loses one of
# these, the whole run aborts without overwriting the working config.  Kept to
# the reliably-present core; FR/GB are optional and often absent.
ESSENTIAL_REGIONS = ("HK", "US", "TW", "JP", "SG")
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
# A Play install is not always a TLS connection with a usable hostname.  The
# store and Play services can hand a CDN IP to a background worker directly;
# in that case domain rules cannot stop geoip-cn from selecting ``direct``.
# Android exposes the originating package to sing-box, so match it explicitly.
GOOGLE_PLAY_PACKAGES = (
    "com.android.vending",
    "com.google.android.gms",
    "com.google.android.gsf",
)
# Microsoft Store can download from a CDN IP handed to a UWP worker instead of
# opening a hostname-bearing TLS connection.  A domain-only rule can therefore
# fall through to geoip-cn and direct routing.  On desktop, route the Store's
# own processes explicitly and resolve its catalog/licensing/download names
# through the proxied DNS server.
MICROSOFT_STORE_PROCESS_NAMES = (
    "WinStore.App.exe",
    "MicrosoftStore.exe",
    "StoreExperienceHost.exe",
)
MICROSOFT_STORE_DOMAINS = (
    "storeedgefd.dsx.mp.microsoft.com",
    "displaycatalog.md.mp.microsoft.com",
    "displaycatalog.mp.microsoft.com",
    "purchase.md.mp.microsoft.com",
    "licensing.mp.microsoft.com",
    "dl.delivery.mp.microsoft.com",
    "tlu.dl.delivery.mp.microsoft.com",
    "assets1.xboxlive.com",
    "assets2.xboxlive.com",
    "dlassets-ssl.xboxlive.com",
)
# Game accelerators must bypass the TUN proxy; nesting them causes double-NAT
# and high latency.  Matched by process name on Windows only.
GAME_ACCELERATOR_PROCESS_NAMES = (
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
)
# Direct-connect DNS resolvers and private-path helpers.  Keep them off the
# proxy so DoH bootstrap and domestic resolvers do not recurse through Available.
LOCAL_DNS_IP_CIDRS = (
    "223.5.5.5/32",
    "119.29.29.29/32",
    "8.8.8.8/32",
    "8.8.4.4/32",
    "1.1.1.1/32",
    "1.0.0.1/32",
)
# Telegram DC ranges.  There is no standalone geoip-telegram rule-set in
# SagerNet/sing-geoip, so keep a minimal hard-coded allowlist for pure-IP dials.
TELEGRAM_IP_CIDRS = (
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
# Domains that must never fall through to geosite-cn/geoip-cn direct routing.
# Google/YouTube/GitHub/Telegram hostnames are covered by geosite-geolocation-!cn
# (and dedicated telegram/openai rule-sets below).  Keep only a small cold-start
# force-proxy list for names that are easy to mis-classify before rule-sets load.
FORCE_PROXY_DOMAINS = (
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "github.io",
    # gstatic sits inside geosite-cn, so without an explicit force-proxy entry it
    # falls through to the China direct tail (and the pollution-prone local
    # resolver) even though the rest of Google is proxied.  The suffix covers
    # www.gstatic.com / ssl.gstatic.com and the Chrome/Windows connectivity check.
    "gstatic.com",
)
# Lightweight ad / tracker suffixes.  Prefer a small inline list over a remote
# category rule-set so first boot cannot hard-fail on a missing download.
ADS_DOMAIN_SUFFIXES = (
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "ads.youtube.com",
    "moatads.com",
    "scorecardresearch.com",
)
# Complement of geosite-cn: everything the SagerNet ruleset considers overseas.
# Used to keep the clean, proxied resolver for non-China names while defaulting
# everything else (domestic + unknown) to the local China DNS.
GEOSITE_NON_CN_RULE_SET = "geosite-geolocation-!cn"
GEOSITE_OPENAI_RULE_SET = "geosite-openai"
GEOSITE_TELEGRAM_RULE_SET = "geosite-telegram"
GEOSITE_ADS_RULE_SET = "geosite-category-ads-all"
GEOSITE_RULE_SET_BASE = "https://fastly.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set"
GEOIP_RULE_SET_BASE = "https://fastly.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set"
GEOSITE_NON_CN_URL = f"{GEOSITE_RULE_SET_BASE}/geosite-geolocation-!cn.srs"
GEOSITE_CN_URL = f"{GEOSITE_RULE_SET_BASE}/geosite-cn.srs"
GEOIP_CN_URL = f"{GEOIP_RULE_SET_BASE}/geoip-cn.srs"
GEOSITE_OPENAI_URL = f"{GEOSITE_RULE_SET_BASE}/geosite-openai.srs"
GEOSITE_TELEGRAM_URL = f"{GEOSITE_RULE_SET_BASE}/geosite-telegram.srs"
GEOSITE_ADS_URL = f"{GEOSITE_RULE_SET_BASE}/geosite-category-ads-all.srs"
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
EMBY_DOMAINS = (
    # Official Emby services plus the servers currently in use.  Match only
    # canonical hostnames so unrelated Emby community servers keep following
    # the normal Available policy.
    "emby.media",
    "mb3admin.com",
    "link00.okemby.org",
    "link01.okemby.org",
    "emby.taotu.ink",
    "feimu.tv",
    "emby.wawajiao.cc.cd",
)
# Time sync should never depend on a proxy (clock skew breaks TLS).
NTP_DOMAINS = (
    "time.windows.com",
    "time.nist.gov",
    "pool.ntp.org",
    "ntp.org",
    "time.apple.com",
    "time.android.com",
    "time.google.com",
)
# Provider/AI Auto: slightly calmer than builder defaults; do not interrupt
# long-lived flows when the best node changes.
SCOPED_URLTEST_INTERVAL = "15m"
SCOPED_URLTEST_TOLERANCE = 100
SCOPED_URLTEST_IDLE_TIMEOUT = "30m"
# Drop ultra-cheap/low-priority tags from Auto pools (still selectable manually).
AUTO_EXCLUDE_NAME_RE = re.compile(r"0\.1x", re.IGNORECASE)
TARGETS: Dict[str, Dict[str, Any]] = {
    "desktop": {
        "label": "桌面端",
        "template_candidates": (
            "config/local/templates/desktop-windows-sing-box-1.14.json",
            "config/examples/templates/desktop-windows-sing-box-1.14.json",
        ),
        "profile": {
            "name": "desktop",
            "platform": "windows",
            "core": {"version": CORE_VERSION_DESKTOP},
            # Manual selectors only.  DNS follows the selected Available
            # outbound and updater traffic bootstraps directly.
            "runtime": {"disable_provider_urltests": True},
            "control": {
                "enabled": False,
                "dns_detour": "Available",
                "update_detour": "direct",
            },
            "tuning": {
                "tun_stack": "system",
                "tun_mtu": 1400,
                "tun_dns_mode": "hijack",
                "dns_cache_capacity": 8192,
                "dns_optimistic": {"enabled": True, "timeout": "30m"},
                "dns_timeout": "5s",
                "cache_store_dns": True,
                # On Windows strict routing installs the WFP protection that
                # prevents multihomed DNS requests from leaking outside TUN.
                "strict_route": True,
                # Open (full-cone) NAT for smoother multiplayer/UDP — the portable
                # form of the 1.14.0-alpha.46 udp_mapping/udp_filtering feature.
                "endpoint_independent_nat": True,
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
            # Android reuses the same policy template; platform differences are
            # applied in profiles.py (TUN-only, package rules, no process match).
            "config/local/templates/desktop-windows-sing-box-1.14.json",
            "config/examples/templates/desktop-windows-sing-box-1.14.json",
        ),
        "profile": {
            "name": "android",
            "platform": "android",
            # Match current SFA 1.14 alpha so optimistic DNS / dns_mode / http_clients apply.
            "core": {"version": CORE_VERSION_ANDROID},
            "runtime": {"disable_provider_urltests": True},
            "control": {
                "enabled": False,
                "dns_detour": "Available",
                "update_detour": "direct",
            },
            "tuning": {
                "tun_stack": "system",
                # Mobile networks and tunneled proxy transports can have a
                # substantially smaller path MTU than Ethernet.
                "tun_mtu": 1360,
                "tun_dns_mode": "hijack",
                "dns_cache_capacity": 4096,
                "dns_optimistic": {"enabled": True, "timeout": "15m"},
                "dns_timeout": "5s",
                "cache_store_dns": False,
                "udp_timeout": "1m",
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
        # The final Available selector lists airport groups and self-hosted
        # nodes for explicit manual choice.  Per-airport Auto is opt-in via
        # ``urltest`` / ``auto_select`` on the subscription entry.
        item["include_in_available"] = True
        item["flat_group"] = True
        item["urltest"] = parse_bool(item.get("urltest", item.get("auto_select")), default=False)
        item.pop("include_in_selectors", None)
    return simple_items


def proxy_region_counts(conf: Dict[str, Any]) -> Counter[str]:
    return Counter(
        detect_region(str(outbound.get("tag") or ""))
        for outbound in conf.get("outbounds", [])
        if isinstance(outbound, dict) and is_proxy_outbound(outbound)
    )


def require_required_regions(
    region_counts: Mapping[str, int], regions: Sequence[str] = ESSENTIAL_REGIONS
) -> None:
    missing = [REGION_LABELS[region] for region in regions if not region_counts.get(region)]
    if missing:
        raise RequiredRegionsError(
            f"订阅中缺少必需地区：{'、'.join(missing)}；为避免覆盖现有配置，本次未写入任何配置文件。"
        )


def set_selector(
    conf: Dict[str, Any],
    tag: str,
    choices: Sequence[str],
    *,
    default: str | None = None,
    interrupt_exist_connections: bool = True,
) -> None:
    outbounds = conf.setdefault("outbounds", [])
    unique_choices = list(dict.fromkeys(str(value) for value in choices if str(value).strip()))
    if not unique_choices:
        raise RuntimeError(f"selector {tag} 没有候选 outbound")
    selector = next(
        (
            outbound
            for outbound in outbounds
            if isinstance(outbound, dict) and outbound.get("type") == "selector" and outbound.get("tag") == tag
        ),
        None,
    )
    if selector is None:
        outbounds.append(
            build_selector(
                tag,
                unique_choices,
                default=default,
                interrupt_exist_connections=interrupt_exist_connections,
            )
        )
        return
    selector["outbounds"] = unique_choices
    selector["interrupt_exist_connections"] = interrupt_exist_connections
    if default and default in unique_choices:
        selector["default"] = default
    else:
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


def _clone_rule_set_transport(source: Dict[str, Any] | None, target: Dict[str, Any]) -> None:
    if not isinstance(source, dict):
        return
    for key in ("update_interval", "download_detour", "http_client"):
        if key in source:
            target[key] = source[key]


def _rule_set_tags(rule_set: Dict[str, Any]) -> set[str]:
    raw = rule_set.get("tag")
    if isinstance(raw, list):
        return {str(item) for item in raw if str(item).strip()}
    if raw is None:
        return set()
    text = str(raw).strip()
    return {text} if text else set()


def ensure_remote_rule_set(
    rule_sets: list[Any],
    *,
    tag: str,
    url: str,
    template: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Ensure a remote binary rule-set entry exists.

    Remote rule-sets are cached by ``experimental.cache_file`` (there is no
    ``path`` field on ``type: remote`` — that is local-only).  Keeping every
    entry remote preserves automatic ``update_interval`` refreshes.
    """

    existing = next(
        (
            rule_set
            for rule_set in rule_sets
            if isinstance(rule_set, dict) and tag in _rule_set_tags(rule_set)
        ),
        None,
    )
    if existing is not None:
        return existing
    rule_set: Dict[str, Any] = {
        "tag": tag,
        "type": "remote",
        "format": "binary",
        "url": url,
    }
    _clone_rule_set_transport(template, rule_set)
    rule_sets.append(rule_set)
    return rule_set


def configure_dns_servers(conf: Dict[str, Any]) -> None:
    """Prefer IP-literal DoH endpoints and a stable control-plane detour."""

    dns = conf.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    rewritten: list[Dict[str, Any]] = []
    seen_tags: set[str] = set()

    def append_server(server: Dict[str, Any]) -> None:
        tag = str(server.get("tag") or "").strip()
        if not tag or tag in seen_tags:
            return
        seen_tags.add(tag)
        rewritten.append(server)

    # Direct plain-UDP bootstrap for resolving proxy server hostnames without
    # depending on Available.  Must stay reachable on a censored uplink, so it
    # uses domestic UDP:53 rather than 1.1.1.1:443 DoH — the latter is commonly
    # blocked on TCP/443, which deadlocks proxy dialing (can't resolve the node
    # server address, so no outbound can ever connect).  Domestic resolvers
    # answer these overseas node hostnames correctly.  User-facing overseas
    # queries still go through google → Available for anti-pollution.
    append_server(
        {
            "type": "udp",
            "tag": "bootstrap",
            "server": "223.5.5.5",
            "server_port": 53,
        }
    )
    # Bootstrap Google DoH with an IP + SNI so resolving dns.google itself is not
    # required before the first clean query can complete.
    append_server(
        {
            "type": "https",
            "tag": "google",
            "server": "8.8.8.8",
            "server_port": 443,
            "path": "/dns-query",
            "tls": {"enabled": True, "server_name": "dns.google"},
            "detour": "Available",
        }
    )
    for server in servers:
        if not isinstance(server, dict):
            continue
        tag = str(server.get("tag") or "").strip()
        if tag in {"google", "cloudflare", "bootstrap"}:
            continue
        if tag in {"local", "local-backup"} or server.get("type") in {"udp", "local", "dhcp"}:
            cleaned = copy.deepcopy(server)
            cleaned.pop("detour", None)
            append_server(cleaned)
            continue
        cleaned = copy.deepcopy(server)
        if cleaned.get("detour") in {None, "", "DNS-Out"}:
            cleaned["detour"] = "Available"
        append_server(cleaned)
    if "local" not in seen_tags:
        append_server({"type": "udp", "tag": "local", "server": "223.5.5.5", "server_port": 53})
    if "local-backup" not in seen_tags:
        append_server({"type": "udp", "tag": "local-backup", "server": "119.29.29.29", "server_port": 53})
    dns["servers"] = rewritten
    dns.setdefault("strategy", "ipv4_only")
    dns.setdefault("cache_capacity", 32768)
    dns.setdefault("reverse_mapping", True)
    # Proxy outbound hostnames resolve via direct bootstrap DoH.
    conf.setdefault("route", {})["default_domain_resolver"] = "bootstrap"


def configure_proxy_domain_resolvers(conf: Dict[str, Any]) -> None:
    """Point every real proxy dial at the direct bootstrap resolver."""

    for outbound in conf.get("outbounds", []):
        if not isinstance(outbound, dict) or not is_proxy_outbound(outbound):
            continue
        if outbound.get("domain_resolver"):
            outbound["domain_resolver"] = "bootstrap"


def _scoped_urltest_members(node_tags: Sequence[str]) -> list[str]:
    """Prefer a calmer Auto pool: drop 0.1x tags when enough members remain."""

    unique = list(dict.fromkeys(str(tag) for tag in node_tags if str(tag).strip()))
    preferred = [tag for tag in unique if not AUTO_EXCLUDE_NAME_RE.search(tag)]
    if len(preferred) >= 2:
        return preferred
    return unique


def _append_scoped_urltest(conf: Dict[str, Any], tag: str, node_tags: Sequence[str]) -> str | None:
    members = _scoped_urltest_members(node_tags)
    if len(members) < 2:
        return None
    conf.setdefault("outbounds", []).append(
        build_urltest(
            tag,
            members,
            interval=SCOPED_URLTEST_INTERVAL,
            tolerance=SCOPED_URLTEST_TOLERANCE,
            idle_timeout=SCOPED_URLTEST_IDLE_TIMEOUT,
            interrupt_exist_connections=False,
        )
    )
    return tag


def configure_clean_split_policy(conf: Dict[str, Any]) -> None:
    """Install the China-direct policy and the AI/Emby overrides.

    Replacing the template rules, rather than appending to them, ensures old
    per-site exceptions cannot silently take precedence on a later rebuild.
    """

    configure_dns_servers(conf)

    route = conf.setdefault("route", {})
    rule_sets = route.setdefault("rule_set", [])
    cn_rule_set = ensure_remote_rule_set(rule_sets, tag="geosite-cn", url=GEOSITE_CN_URL)
    ensure_remote_rule_set(rule_sets, tag="geoip-cn", url=GEOIP_CN_URL, template=cn_rule_set)
    ensure_remote_rule_set(
        rule_sets,
        tag=GEOSITE_NON_CN_RULE_SET,
        url=GEOSITE_NON_CN_URL,
        template=cn_rule_set,
    )
    ensure_remote_rule_set(
        rule_sets,
        tag=GEOSITE_OPENAI_RULE_SET,
        url=GEOSITE_OPENAI_URL,
        template=cn_rule_set,
    )
    ensure_remote_rule_set(
        rule_sets,
        tag=GEOSITE_TELEGRAM_RULE_SET,
        url=GEOSITE_TELEGRAM_URL,
        template=cn_rule_set,
    )
    ensure_remote_rule_set(
        rule_sets,
        tag=GEOSITE_ADS_RULE_SET,
        url=GEOSITE_ADS_URL,
        template=cn_rule_set,
    )

    ai_domains = list(dict.fromkeys(AI_PROXY_DOMAINS))
    force_proxy_domains = list(dict.fromkeys(FORCE_PROXY_DOMAINS))
    route["rules"] = [
        {"action": "sniff", "timeout": "300ms"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "action": "route", "outbound": "direct"},
        {
            "ip_cidr": list(LOCAL_DNS_IP_CIDRS),
            "action": "route",
            "outbound": "direct",
        },
        {
            "domain_suffix": list(NTP_DOMAINS),
            "action": "route",
            "outbound": "direct",
        },
        {"protocol": ["bittorrent"], "action": "route", "outbound": "direct"},
        # Hard-reject a tiny known-bad ad list; the full ads category is routed
        # direct instead of reject to avoid breaking sites that share tracker hosts.
        {
            "domain_suffix": list(ADS_DOMAIN_SUFFIXES),
            "action": "reject",
        },
        {"rule_set": [GEOSITE_ADS_RULE_SET], "action": "route", "outbound": "direct"},
        # Global Clash mode overrides sit ABOVE the service-selection rules, so a
        # Direct/Proxy toggle is authoritative for Emby/AI/Telegram/GitHub/geo.
        # Games, private IPs, DNS-server IPs, BitTorrent and ad-blocking above
        # stay unconditional; the DNS rules mirror this ordering.
        {"clash_mode": "Direct", "action": "route", "outbound": "direct"},
        {"clash_mode": "Proxy", "action": "route", "outbound": "Available"},
        {
            "domain_suffix": list(dict.fromkeys(EMBY_DOMAINS)),
            "action": "route",
            "outbound": "Emby",
        },
        # OpenAI geosite + explicit AI extras (Cursor/x.ai/Claude/etc.).
        {"rule_set": [GEOSITE_OPENAI_RULE_SET], "action": "route", "outbound": "AI"},
        {
            "domain_suffix": ai_domains,
            "action": "route",
            "outbound": "AI",
        },
        {"rule_set": [GEOSITE_TELEGRAM_RULE_SET], "action": "route", "outbound": "Available"},
        {
            "ip_cidr": list(TELEGRAM_IP_CIDRS),
            "action": "route",
            "outbound": "Available",
        },
        {
            "domain_suffix": force_proxy_domains,
            "action": "route",
            "outbound": "Available",
        },
        # Prefer the proxy for every known overseas domain before geoip-cn gets
        # a chance to classify a CDN address as domestic.  DNS already uses the
        # same complementary rule-set, so route and resolver decisions stay in
        # sync for Google and other sites that are frequently misclassified.
        {"rule_set": [GEOSITE_NON_CN_RULE_SET], "action": "route", "outbound": "Available"},
        {"rule_set": ["geosite-cn"], "action": "route", "outbound": "direct"},
        {"rule_set": ["geoip-cn"], "action": "route", "outbound": "direct"},
    ]
    route["final"] = "Available"

    dns = conf.setdefault("dns", {})
    dns_server_tags = {
        str(server.get("tag"))
        for server in dns.get("servers", [])
        if isinstance(server, dict) and server.get("tag")
    }
    dns_rules: list[Dict[str, Any]] = []
    if "google" in dns_server_tags:
        if "local-backup" in dns_server_tags:
            dns_rules.append({"clash_mode": "Direct", "action": "route", "server": "local-backup"})
        dns_rules.append({"clash_mode": "Proxy", "action": "route", "server": "google"})
        dns_rules.extend(
            [
                {
                    "domain_suffix": list(dict.fromkeys(EMBY_DOMAINS)),
                    "action": "route",
                    "server": "google",
                },
                {
                    "domain_suffix": list(dict.fromkeys([*force_proxy_domains, *ai_domains])),
                    "action": "route",
                    "server": "google",
                },
                {"rule_set": [GEOSITE_OPENAI_RULE_SET], "action": "route", "server": "google"},
                {"rule_set": [GEOSITE_TELEGRAM_RULE_SET], "action": "route", "server": "google"},
                {"rule_set": [GEOSITE_NON_CN_RULE_SET], "action": "route", "server": "google"},
            ]
        )
    if "local" in dns_server_tags:
        dns_rules.append({"rule_set": ["geosite-cn"], "action": "route", "server": "local"})
    # Unknown domains must not fall back to the pollution-prone local resolver:
    # resolve them with clean proxied DoH, then let geoip-cn decide whether the
    # resulting destination can still travel directly.
    if "google" in dns_server_tags:
        dns["final"] = "google"
    elif "local" in dns_server_tags:
        dns["final"] = "local"
    dns["rules"] = dns_rules
    # Explicit optimistic window (1.14); bool True still works, object is clearer.
    if dns.get("optimistic") is True:
        dns["optimistic"] = {"enabled": True, "timeout": "3d"}


def organize_groups(
    conf: Dict[str, Any],
    subscriptions: Sequence[Dict[str, Any]],
    policy_aliases: Mapping[str, str],
) -> None:
    """Expose airport, Available, AI, and Emby selectors.

    Available is fully manual (pick an airport group or self-hosted node).
    Individual airports may opt into a scoped ``{group}/Auto`` urltest via the
    subscription ``urltest`` / ``auto_select`` flag; there is no global Auto.
    """

    outbounds = conf.setdefault("outbounds", [])
    # The generic builder supports legacy URLTest/control groups.  Strip them
    # before rebuilding the small public surface; provider-scoped Auto groups
    # are re-created below from the subscription manifest.
    removed_group_tags = {
        str(outbound.get("tag"))
        for outbound in outbounds
        if isinstance(outbound, dict)
        and (
            outbound.get("type") == "urltest"
            or (
                outbound.get("type") == "selector"
                and (
                    str(outbound.get("tag") or "") in {"DNS-Out", "Update-Out", "Control"}
                    or "auto" in str(outbound.get("tag") or "").lower()
                )
            )
        )
    }
    conf["outbounds"] = [
        outbound
        for outbound in outbounds
        if not isinstance(outbound, dict)
        or str(outbound.get("tag") or "") not in removed_group_tags
    ]
    outbounds = conf["outbounds"]
    proxy_outbounds = [
        outbound
        for outbound in outbounds
        if isinstance(outbound, dict) and is_proxy_outbound(outbound) and outbound.get("tag")
    ]
    proxy_tags = {str(outbound["tag"]) for outbound in proxy_outbounds}
    source_groups = {
        "self-hosted": [],
        "airport": [],
    }
    auto_group_tags: set[str] = set()
    for item in subscriptions:
        kind = str(item.get("_simple_group_kind") or "airport")
        if kind not in source_groups:
            continue
        source_tag = configured_group_tag(item, str(item["name"]))
        ai_include = str(item.get("ai_include", "")).strip().lower() in {"1", "true", "yes", "on"}
        source_groups[kind].append((source_tag, ai_include))
        if parse_bool(item.get("urltest", item.get("auto_select")), default=False):
            auto_group_tags.add(source_tag)

    selectors = {
        str(outbound.get("tag")): outbound
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("type") == "selector" and outbound.get("tag")
    }
    airport_groups: list[str] = []
    self_node_tags: list[str] = []
    ai_included_self_node_tags: list[str] = []
    for kind, groups in source_groups.items():
        for tag, ai_include in groups:
            selector = selectors.get(tag)
            if not selector:
                continue
            node_tags = [str(value) for value in selector.get("outbounds", []) if str(value) in proxy_tags]
            if kind == "airport":
                if node_tags:
                    auto_tag = f"{tag}/Auto"
                    if tag in auto_group_tags and _append_scoped_urltest(conf, auto_tag, node_tags):
                        selector["outbounds"] = [auto_tag, *node_tags]
                        selector["default"] = auto_tag
                        selector["interrupt_exist_connections"] = True
                    else:
                        selector["outbounds"] = node_tags
                        selector.pop("default", None)
                    airport_groups.append(tag)
            else:
                self_node_tags.extend(node_tags)
                if ai_include:
                    ai_included_self_node_tags.extend(node_tags)

    self_tags = {tag for tag, _ in source_groups["self-hosted"]}
    self_node_tags = list(dict.fromkeys(self_node_tags))
    manual_available = [*airport_groups, *self_node_tags]
    if not manual_available:
        raise RuntimeError("没有可放入 Available 的机场或自建节点")

    us_proxy_outbounds = [
        outbound
        for outbound in proxy_outbounds
        if detect_region(str(outbound["tag"])) == "US"
    ]
    # Available stays manual: pick an airport group or a self-hosted node.
    # Provider-scoped Auto (if any) lives inside that airport's selector.
    set_selector(conf, "Available", manual_available, default=manual_available[0])

    # AI: US nodes + opted-in self-hosted, kept manual.
    us_nodes = [str(outbound["tag"]) for outbound in us_proxy_outbounds]
    ai_choices = list(dict.fromkeys(us_nodes + ai_included_self_node_tags))
    if not ai_choices:
        raise RequiredRegionsError("订阅中缺少可用于 AI 的美国节点")
    set_selector(conf, "AI", ai_choices, default=ai_choices[0])
    # Streaming can consume substantially more traffic than normal browsing.
    # Keep it independently selectable while following Available by default;
    # self-hosted nodes are listed individually instead of behind a 自建 group.
    set_selector(
        conf,
        "Emby",
        ["Available", *manual_available, "direct"],
        default="Available",
    )

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

    # Self-hosted wrapper groups are redundant because their nodes are exposed
    # directly in each manual policy selector.
    remove_tags = self_tags | set(alias_replacements) | removed_group_tags
    conf["outbounds"] = [
        outbound
        for outbound in conf.get("outbounds", [])
        if not isinstance(outbound, dict) or str(outbound.get("tag") or "") not in remove_tags
    ]

    # Rule-set downloads go direct to avoid any first-start dependency on a
    # selected proxy.  A no-detour http_client already dials directly; sing-box
    # 1.14 rejects a detour to the bare `direct` outbound, so strip it rather
    # than set it (the clash_api UI download below still accepts detour:direct).
    for client in conf.get("http_clients", []):
        if isinstance(client, dict) and client.get("tag") == "rule-set-downloader":
            client.pop("detour", None)
    experimental = conf.get("experimental") if isinstance(conf.get("experimental"), dict) else {}
    clash_api = experimental.get("clash_api") if isinstance(experimental.get("clash_api"), dict) else {}
    if clash_api.get("external_ui_download_url"):
        clash_api["external_ui_download_detour"] = "direct"


def configure_android_google_play(conf: Dict[str, Any]) -> None:
    """Keep Play traffic on the proxy with clean DNS.

    Explicit package, domain, and DNS rules are needed even though the default
    policy is proxy-first for non-China traffic:
    ``dl.google.com`` (Play's main download CDN) is listed in geosite-cn, so
    without an override the trailing geosite-cn rule would force it to direct +
    domestic DNS, which is slow or unreachable in China and would defeat the
    point.  The route rule keeps Play on the proxy and the DNS rule keeps its
    names resolved through Google.
    """

    route = conf.setdefault("route", {})
    rules = route.setdefault("rules", [])
    play_package_rule = {
        "package_name": list(GOOGLE_PLAY_PACKAGES),
        "action": "route",
        "outbound": "Available",
    }
    play_domain_rule = {
        "domain_suffix": list(GOOGLE_PLAY_DOMAINS),
        "action": "route",
        "outbound": "Available",
    }
    # Keep sniffing and DNS hijacking first, then match Play before the
    # trailing geosite-cn rule can grab dl.google.com for direct routing.
    _insert_route_rules_after_bootstrap(rules, [play_package_rule, play_domain_rule])

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


def minimize_android_runtime(conf: Dict[str, Any]) -> None:
    """Drop desktop-only DNS controls and their unused fallback resolver."""

    route = conf.setdefault("route", {})
    route["rules"] = [
        rule
        for rule in route.get("rules", [])
        if not (isinstance(rule, dict) and "clash_mode" in rule)
    ]
    for rule in route["rules"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("ip_cidr"), list):
            continue
        rule["ip_cidr"] = [cidr for cidr in rule["ip_cidr"] if cidr != "119.29.29.29/32"]

    dns = conf.setdefault("dns", {})
    dns["rules"] = [
        rule
        for rule in dns.get("rules", [])
        if not (isinstance(rule, dict) and "clash_mode" in rule)
    ]
    dns["servers"] = [
        server
        for server in dns.get("servers", [])
        if not (isinstance(server, dict) and server.get("tag") == "local-backup")
    ]

def _insert_route_rules_after_bootstrap(rules: list[Any], new_rules: Sequence[Dict[str, Any]]) -> None:
    """Insert rules after sniff / hijack-dns so process and package matches stay early."""

    insert_at = 0
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("action") in {"sniff", "hijack-dns"} or rule.get("protocol") == "dns":
            insert_at = index + 1
            continue
        break
    for offset, rule in enumerate(new_rules):
        rules.insert(insert_at + offset, rule)


def configure_desktop_game_accelerators(conf: Dict[str, Any]) -> None:
    """Bypass TUN for known game accelerators on Windows."""

    route = conf.setdefault("route", {})
    rules = route.setdefault("rules", [])
    accelerator_names = set(GAME_ACCELERATOR_PROCESS_NAMES)
    if any(
        isinstance(rule, dict)
        and accelerator_names & set(normalized_string_list(rule.get("process_name")))
        for rule in rules
    ):
        return
    route["find_process"] = True
    _insert_route_rules_after_bootstrap(
        rules,
        [
            {
                "process_name": list(GAME_ACCELERATOR_PROCESS_NAMES),
                "action": "route",
                "outbound": "direct",
            }
        ],
    )


def configure_desktop_microsoft_store(conf: Dict[str, Any]) -> None:
    """Keep Microsoft Store catalog and CDN traffic on the selected proxy.

    The process rule covers CDN connections without a recoverable hostname;
    the domain and DNS rules cover catalog, license, and Xbox-backed downloads.
    All rules are inserted before the China rule-set tail.
    """

    route = conf.setdefault("route", {})
    rules = route.setdefault("rules", [])
    store_processes = set(MICROSOFT_STORE_PROCESS_NAMES)
    if not any(
        isinstance(rule, dict)
        and store_processes <= set(normalized_string_list(rule.get("process_name")))
        for rule in rules
    ):
        _insert_route_rules_after_bootstrap(
            rules,
            [
                {
                    "process_name": list(MICROSOFT_STORE_PROCESS_NAMES),
                    "action": "route",
                    "outbound": "Available",
                },
                {
                    "domain_suffix": list(MICROSOFT_STORE_DOMAINS),
                    "action": "route",
                    "outbound": "Available",
                },
            ],
        )
        route["find_process"] = True

    dns = conf.setdefault("dns", {})
    dns_rules = dns.setdefault("rules", [])
    dns_server_tags = {
        str(server.get("tag"))
        for server in dns.get("servers", [])
        if isinstance(server, dict) and server.get("tag")
    }
    if "google" in dns_server_tags and not any(
        isinstance(rule, dict)
        and set(MICROSOFT_STORE_DOMAINS) <= set(normalized_string_list(rule.get("domain_suffix")))
        and rule.get("server") == "google"
        for rule in dns_rules
    ):
        dns_rules.insert(
            0,
            {
                "domain_suffix": list(MICROSOFT_STORE_DOMAINS),
                "action": "route",
                "server": "google",
            },
        )


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
    # Keep the historical no-limit behavior unless a subscription explicitly
    # opts into Android limits in the local manifest.
    numeric_limit_keys = ("max_nodes_per_region", "max_other_nodes", "max_total_nodes")
    for subscription in subscriptions:
        apply_android_limits = target == "android" and subscription.pop("apply_android_limits", False) is True
        if apply_android_limits:
            continue
        subscription.pop("limits", None)
        for limit_key in numeric_limit_keys:
            subscription.pop(limit_key, None)
            subscription.pop(f"{limit_key}_desktop", None)
            subscription.pop(f"{limit_key}_android", None)
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
        # Keep every layer manual; organize_groups also strips legacy URLTests
        # emitted by older/general-purpose builder settings.
        available_urltest=False,
        profile=profile,
        offline=offline,
        policy_aliases=aliases,
        # Honour per-subscription region filters.  Numeric limits were removed
        # above, so subscriptions without a region filter retain every node.
        preserve_all_nodes=False,
        included_regions=set(ALL_REGIONS),
        unfiltered_roles=SELF_HOSTED_ROLES,
        skip_empty_groups=True,
        policy_alias_fallback="Available",
    )
    organize_groups(conf, subscriptions, aliases)
    configure_clean_split_policy(conf)
    configure_proxy_domain_resolvers(conf)
    if target == "android":
        configure_android_google_play(conf)
        minimize_android_runtime(conf)
    elif target == "desktop":
        # Insert order matters: later bootstrap inserts land closer to the top.
        # Put Microsoft Store first, then accelerators, so accelerators end up
        # above Store rules and above the China direct tail.
        configure_desktop_microsoft_store(conf)
        configure_desktop_game_accelerators(conf)
    require_valid_config(conf)
    region_counts = proxy_region_counts(conf)
    require_required_regions(region_counts)
    return conf, region_counts


def generate_configs(
    targets: Sequence[str],
    *,
    subscriptions_path: Path | str = LOCAL_CONFIG_DIR / "subscriptions.yaml",
    output_dir: Path | str = ROOT / "dist",
    fetch_proxy: str | None = None,
    offline: bool = False,
    cache_dir: Path | str | None = ROOT / "runtime" / "subscription-cache",
    policy_aliases_path: Path | str | None = LOCAL_CONFIG_DIR / "policy_aliases.yaml",
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
    parser.add_argument(
        "--subscriptions",
        default="config/local/subscriptions.yaml",
        help="订阅清单，默认 config/local/subscriptions.yaml",
    )
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

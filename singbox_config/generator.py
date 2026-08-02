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
from singbox_config.audit import is_insecure_outbound, is_proxy_outbound, require_valid_config
from singbox_config.io_utils import atomic_write_json
from singbox_config.profiles import apply_profile_to_template


ROOT = Path(__file__).resolve().parents[1]
LOCAL_CONFIG_DIR = ROOT / "config" / "local"
CORE_VERSION_DESKTOP = "1.14.0-beta.3"
# The user upgrades Android and Windows in lockstep; keep one version source
# so generated profiles cannot diverge.
CORE_VERSION_ANDROID = CORE_VERSION_DESKTOP
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
# Moved to config/rule-sets/google-play.json for easier maintenance
GOOGLE_PLAY_RULE_SET_TAG = "google-play"
GOOGLE_PLAY_RULE_SET_PATH = "config/rule-sets/google-play.json"
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
# Moved to config/rule-sets/microsoft-store.json for easier maintenance
MICROSOFT_STORE_RULE_SET_TAG = "microsoft-store"
MICROSOFT_STORE_RULE_SET_PATH = "config/rule-sets/microsoft-store.json"
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
# Direct-connect domestic DNS resolvers.  Keep them off the proxy so the UDP
# bootstrap and China-direct resolvers do not recurse through Available.
# Overseas public resolvers (8.8.8.8, 1.1.1.1, ...) are deliberately NOT here:
# app-issued plaintext DNS to them is captured by hijack-dns inside TUN, and
# app DoH to them on 443 must ride the proxy to work on a censored uplink.
LOCAL_DNS_IP_CIDRS = (
    "223.5.5.5/32",
    "119.29.29.29/32",
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
# Cold-start / rule-set-outage safety net for the biggest domestic services.
#
# Every China-direct decision below depends on ``geosite-cn`` / ``geoip-cn``
# being loaded, but those are remote rule-sets fetched from a CDN that is itself
# unreliable from inside China, and Android has no on-disk seed for them.  While
# they are missing, the whole China tail is inert: domestic traffic falls
# through to ``route.final`` (proxy) and ``dns.final`` (overseas DoH).  WeChat is
# the loudest victim — Tencent will not serve 公众号 article content to a request
# arriving from an overseas exit, so the page simply fails to load.
#
# These suffixes reproduce the load-bearing part of geosite-cn inline so the
# split keeps working with zero downloads.  Keep the list short and obvious;
# geosite-cn remains the authority once it arrives.
CHINA_DIRECT_DOMAINS = (
    # Tencent / WeChat — a 公众号 article pulls page, images and JS from all of these
    "qq.com",
    "wechat.com",
    "weixinbridge.com",
    "qpic.cn",
    "qlogo.cn",
    "gtimg.cn",
    "gtimg.com",
    "idqqimg.com",
    "tencent.com",
    "myqcloud.com",
    "qcloud.com",
    "tenpay.com",
    "weiyun.com",
    # Alibaba
    "taobao.com",
    "tmall.com",
    "alicdn.com",
    "alipay.com",
    "alipayobjects.com",
    "aliyun.com",
    "aliyuncs.com",
    "alibaba.com",
    "1688.com",
    "dingtalk.com",
    # Baidu
    "baidu.com",
    "bdstatic.com",
    "bdimg.com",
    "baidubce.com",
    # ByteDance
    "bytedance.com",
    "byteimg.com",
    "bytecdn.cn",
    "pstatp.com",
    "snssdk.com",
    "douyin.com",
    "douyinpic.com",
    "douyinstatic.com",
    "toutiao.com",
    "feishu.cn",
    # NetEase
    "163.com",
    "126.net",
    "127.net",
    "netease.com",
    "ydstatic.com",
    # Sina / Weibo
    "weibo.com",
    "weibocdn.com",
    "sinaimg.cn",
    "sina.com.cn",
    "sina.cn",
    # Bilibili
    "bilibili.com",
    "hdslb.com",
    "biliapi.net",
    "bilivideo.com",
    "bilivideo.cn",
    # Retail / delivery
    "jd.com",
    "360buyimg.com",
    "pinduoduo.com",
    "yangkeduo.com",
    "pddpic.com",
    "meituan.com",
    "meituan.net",
    "dianping.com",
    "sankuai.com",
    # Content
    "zhihu.com",
    "zhimg.com",
    "xiaohongshu.com",
    "xhscdn.com",
    "kuaishou.com",
    "kwimgs.com",
    "yximgs.com",
    "iqiyi.com",
    "iqiyipic.com",
    "qiyipic.com",
    "youku.com",
    "ykimg.com",
    # Handset vendors: OTA, push and account services must not leave the country
    "xiaomi.com",
    "mi.com",
    "miui.com",
    "xiaomi.net",
    "huawei.com",
    "hicloud.com",
    "dbankcdn.com",
    "oppomobile.com",
    "coloros.com",
    "vivo.com.cn",
    # Payments, travel, public services
    "unionpay.com",
    "95516.com",
    "ctrip.com",
    "12306.cn",
    "gov.cn",
    "edu.cn",
)
# Lightweight ad / tracker suffixes.  Prefer a small inline list over a remote
# category rule-set so first boot cannot hard-fail on a missing download.
# Everything here is an overseas ad network: a reject is safe because no
# domestic app treats these as functional endpoints.
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
            # Manual selectors only. DNS and rule-set updates use the dedicated
            # DNS-Out selector, whose default is a secure self-hosted IP node.
            "runtime": {"disable_provider_urltests": True},
            "control": {
                "enabled": False,
                "dns_detour": "Available",
                "update_detour": "DNS-Out",
            },
            "tuning": {
                "tun_stack": "system",
                "tun_mtu": 1400,
                "tun_dns_mode": "hijack",
                "dns_cache_capacity": 8192,
                "dns_optimistic": {"enabled": True, "timeout": "2h"},
                "dns_timeout": "8s",
                "cache_store_dns": True,
                # Keep mutable runtime state out of the repository root. The
                # parent runtime directory is created by setup before start.
                "cache_path": "runtime/sing-box-cache.db",
                "rule_set_initial_dir": "runtime/rule-set-cache",
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
                "external_ui_download_url": "https://github.com/Zephyruso/zashboard/releases/download/v3.16.0/dist.zip",
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
                # Android has no on-disk rule-set seed, and the jsDelivr mirror
                # is unreliable-to-blocked from a domestic uplink. Pull updates
                # through the proxy so a failed direct lookup cannot remove the
                # China tail; node hostnames resolve via direct `bootstrap`.
                "update_detour": "Available",
            },
            "tuning": {
                "tun_stack": "system",
                # Mobile networks and tunneled proxy transports can have a
                # substantially smaller path MTU than Ethernet.
                "tun_mtu": 1360,
                "tun_dns_mode": "hijack",
                "dns_cache_capacity": 4096,
                # WeChat, QQ and most domestic super-apps dial cached IP
                # literals rather than hostnames.  Reverse mapping is what lets
                # those connections still match the domain rules above the
                # geoip-cn tail, so keep it on despite the small memory cost.
                "dns_reverse_mapping": True,
                "dns_optimistic": {"enabled": True, "timeout": "45m"},
                "dns_timeout": "8s",
                "cache_store_dns": False,
                "udp_timeout": "1m",
                "endpoint_independent_nat": False,
                "rule_set_update_interval": "1d",
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
    for key in ("update_interval", "download_detour", "http_client", "initial_path"):
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


def configure_rule_set_initial_paths(conf: Dict[str, Any], initial_dir: str) -> None:
    """Attach 1.14 startup seeds after all generated rule-sets exist."""

    normalized_dir = str(initial_dir or "").strip().rstrip("/\\")
    if not normalized_dir:
        return
    for rule_set in conf.get("route", {}).get("rule_set", []):
        if not isinstance(rule_set, dict) or rule_set.get("type") != "remote":
            continue
        tag = rule_set.get("tag")
        if isinstance(tag, str) and tag.strip():
            rule_set["initial_path"] = f"{normalized_dir}/{tag.strip()}.srs"


def configure_dns_servers(conf: Dict[str, Any]) -> None:
    """Prefer IP-literal DoH endpoints and a stable control-plane detour."""

    dns = conf.setdefault("dns", {})
    outbound_tags = {
        str(outbound.get("tag"))
        for outbound in conf.get("outbounds", [])
        if isinstance(outbound, dict) and outbound.get("tag")
    }
    dns_detour = "DNS-Out" if "DNS-Out" in outbound_tags else "Available"
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
            "detour": dns_detour,
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
        if cleaned.get("detour") in {None, "", "Available", "DNS-Out"}:
            cleaned["detour"] = dns_detour
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
        # Reject both the high-confidence inline list and the maintained ad
        # category.  Keep these above Clash mode so Direct cannot bypass it.
        {
            "domain_suffix": list(ADS_DOMAIN_SUFFIXES),
            "action": "reject",
        },
        # ...but never reject a host that is also domestic infrastructure.
        # geosite-category-ads-all classifies Chinese apps' telemetry endpoints
        # as ads, and those endpoints are load-bearing: rejecting
        # badjs.weixinbridge.com / tcss.qq.com / log.tbs.qq.com / beacon.qq.com
        # stalls the X5 WebView that renders 微信公众号 articles, so the page
        # never finishes loading.  Blocking overseas ad networks is worth it;
        # blocking domestic ones is not, and this AND-NOT keeps that line
        # without an ever-growing hand-maintained exception list.
        {
            "type": "logical",
            "mode": "and",
            "rules": [
                {"rule_set": [GEOSITE_ADS_RULE_SET]},
                {"rule_set": ["geosite-cn"], "invert": True},
                {"domain_suffix": list(CHINA_DIRECT_DOMAINS), "invert": True},
            ],
            "action": "reject",
        },
        # Global Clash mode overrides sit ABOVE the service-selection rules, so a
        # Direct/Proxy toggle is authoritative for Emby/AI/Telegram/GitHub/geo.
        # Games, private IPs, DNS-server IPs, BitTorrent and ad-blocking above
        # stay unconditional; the DNS rules mirror this ordering.
        {"clash_mode": "Direct", "action": "route", "outbound": "direct"},
        {"clash_mode": "Proxy", "action": "route", "outbound": "Available"},
        {
            "clash_mode": "Rule",
            "domain_suffix": list(dict.fromkeys(EMBY_DOMAINS)),
            "action": "route",
            "outbound": "Emby",
        },
        # OpenAI geosite + explicit AI extras (Cursor/x.ai/Claude/etc.).
        {
            "clash_mode": "Rule",
            "rule_set": [GEOSITE_OPENAI_RULE_SET],
            "action": "route",
            "outbound": "AI",
        },
        {
            "clash_mode": "Rule",
            "domain_suffix": ai_domains,
            "action": "route",
            "outbound": "AI",
        },
        {
            "clash_mode": "Rule",
            "rule_set": [GEOSITE_TELEGRAM_RULE_SET],
            "action": "route",
            "outbound": "Available",
        },
        {
            "clash_mode": "Rule",
            "ip_cidr": list(TELEGRAM_IP_CIDRS),
            "action": "route",
            "outbound": "Available",
        },
        {
            "clash_mode": "Rule",
            "domain_suffix": force_proxy_domains,
            "action": "route",
            "outbound": "Available",
        },
        # Inline China tail.  Identical in intent to the geosite-cn rule below,
        # but it needs no download, so the split survives a rule-set outage
        # instead of dumping every domestic name onto the proxy.
        {
            "clash_mode": "Rule",
            "domain_suffix": list(CHINA_DIRECT_DOMAINS),
            "action": "route",
            "outbound": "direct",
        },
        # Prefer the proxy for every known overseas domain before geoip-cn gets
        # a chance to classify a CDN address as domestic.  DNS already uses the
        # same complementary rule-set, so route and resolver decisions stay in
        # sync for Google and other sites that are frequently misclassified.
        {
            "clash_mode": "Rule",
            "rule_set": [GEOSITE_NON_CN_RULE_SET],
            "action": "route",
            "outbound": "Available",
        },
        {
            "clash_mode": "Rule",
            "rule_set": ["geosite-cn"],
            "action": "route",
            "outbound": "direct",
        },
        {
            "clash_mode": "Rule",
            "rule_set": ["geoip-cn"],
            "action": "route",
            "outbound": "direct",
        },
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
                    "clash_mode": "Rule",
                    "domain_suffix": list(dict.fromkeys(EMBY_DOMAINS)),
                    "action": "route",
                    "server": "google",
                },
                {
                    "clash_mode": "Rule",
                    "domain_suffix": list(dict.fromkeys([*force_proxy_domains, *ai_domains])),
                    "action": "route",
                    "server": "google",
                },
                {
                    "clash_mode": "Rule",
                    "rule_set": [GEOSITE_OPENAI_RULE_SET],
                    "action": "route",
                    "server": "google",
                },
                {
                    "clash_mode": "Rule",
                    "rule_set": [GEOSITE_TELEGRAM_RULE_SET],
                    "action": "route",
                    "server": "google",
                },
            ]
        )
    if "local" in dns_server_tags:
        # Mirror the route-side inline China tail: resolve the big domestic
        # names domestically even while geosite-cn is still downloading, and
        # keep it above the geolocation-!cn rule for the same reason the route
        # rules do — otherwise a cold start sends every WeChat lookup to 8.8.8.8
        # over the proxy and Tencent answers with an overseas address.
        dns_rules.append(
            {
                "clash_mode": "Rule",
                "domain_suffix": list(CHINA_DIRECT_DOMAINS),
                "action": "route",
                "server": "local",
            }
        )
    if "google" in dns_server_tags:
        dns_rules.append(
            {
                "clash_mode": "Rule",
                "rule_set": [GEOSITE_NON_CN_RULE_SET],
                "action": "route",
                "server": "google",
            }
        )
    if "local" in dns_server_tags:
        dns_rules.append(
            {
                "clash_mode": "Rule",
                "rule_set": ["geosite-cn"],
                "action": "route",
                "server": "local",
            }
        )
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
        ai_exclude = parse_bool(item.get("ai_exclude"), default=False)
        source_groups[kind].append((source_tag, ai_exclude))
        if parse_bool(item.get("urltest", item.get("auto_select")), default=False):
            auto_group_tags.add(source_tag)

    selectors = {
        str(outbound.get("tag")): outbound
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("type") == "selector" and outbound.get("tag")
    }
    airport_groups: list[str] = []
    self_node_tags: list[str] = []
    ai_excluded_node_tags: set[str] = set()
    for kind, groups in source_groups.items():
        for tag, ai_exclude in groups:
            selector = selectors.get(tag)
            if not selector:
                continue
            node_tags = [str(value) for value in selector.get("outbounds", []) if str(value) in proxy_tags]
            if ai_exclude:
                ai_excluded_node_tags.update(node_tags)
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

    secure_self_tags = [
        tag
        for tag in self_node_tags
        if not is_insecure_outbound(next(outbound for outbound in proxy_outbounds if outbound["tag"] == tag))
    ]
    secure_self_tags.sort(key=lambda tag: ("vmiss" not in tag.lower(), self_node_tags.index(tag)))
    dns_choices = list(dict.fromkeys([*secure_self_tags, "Available", "direct"]))
    set_selector(conf, "DNS-Out", dns_choices, default=dns_choices[0])

    # AI is deliberately strict: secure US nodes only. Sources such as an
    # airport known to be unsuitable for AI can opt out via ``ai_exclude``.
    secure_proxy_tags = {
        str(outbound["tag"])
        for outbound in proxy_outbounds
        if not is_insecure_outbound(outbound)
    }
    us_nodes = [
        str(outbound["tag"])
        for outbound in us_proxy_outbounds
        if str(outbound["tag"]) in secure_proxy_tags
        and str(outbound["tag"]) not in ai_excluded_node_tags
    ]
    ai_choices = list(dict.fromkeys(us_nodes))
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
    remove_tags = self_tags | set(alias_replacements) | (removed_group_tags - {"DNS-Out"})
    conf["outbounds"] = [
        outbound
        for outbound in conf.get("outbounds", [])
        if not isinstance(outbound, dict) or str(outbound.get("tag") or "") not in remove_tags
    ]

    # sing-box 1.14 rejects an http_client whose detour points at the bare
    # `direct` outbound; a client with no detour already dials directly, so
    # normalize "direct" away.  A real proxy detour (Android pulls rule-sets
    # through Available because the CDN is not reachable directly from China)
    # must survive.
    for client in conf.get("http_clients", []):
        if isinstance(client, dict) and client.get("tag") == "rule-set-downloader":
            if client.get("detour") in {None, "", "direct"}:
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
    rule_sets = route.setdefault("rule_set", [])

    # Add the google-play rule-set if not already present
    if not any(
        isinstance(rs, dict) and rs.get("tag") == GOOGLE_PLAY_RULE_SET_TAG
        for rs in rule_sets
    ):
        rule_sets.append({
            "tag": GOOGLE_PLAY_RULE_SET_TAG,
            "type": "local",
            "format": "source",
            "path": GOOGLE_PLAY_RULE_SET_PATH,
        })

    play_package_rule = {
        "clash_mode": "Rule",
        "package_name": list(GOOGLE_PLAY_PACKAGES),
        "action": "route",
        "outbound": "Available",
    }
    play_domain_rule = {
        "clash_mode": "Rule",
        "rule_set": GOOGLE_PLAY_RULE_SET_TAG,
        "action": "route",
        "outbound": "Available",
    }
    # Below the unconditional prologue (private IPs, domestic DNS, NTP, ads) but
    # above the China tail, so dl.google.com cannot be claimed by geosite-cn
    # while Play Services' LAN discovery and clock sync still behave.
    _insert_rules_after_clash_mode(rules, [play_package_rule, play_domain_rule])

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
                "rule_set": GOOGLE_PLAY_RULE_SET_TAG,
                "action": "route",
                "server": "google",
            },
        )


def minimize_android_runtime(conf: Dict[str, Any]) -> None:
    """Drop desktop-only DNS controls and their unused fallback resolver."""

    route = conf.setdefault("route", {})
    route_rules: list[Any] = []
    for rule in route.get("rules", []):
        if not isinstance(rule, dict) or "clash_mode" not in rule:
            route_rules.append(rule)
            continue
        if rule.get("clash_mode") == "Rule":
            retained = copy.deepcopy(rule)
            retained.pop("clash_mode", None)
            route_rules.append(retained)
    route["rules"] = route_rules
    for rule in route["rules"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("ip_cidr"), list):
            continue
        rule["ip_cidr"] = [cidr for cidr in rule["ip_cidr"] if cidr != "119.29.29.29/32"]

    dns = conf.setdefault("dns", {})
    dns_rules: list[Any] = []
    for rule in dns.get("rules", []):
        if not isinstance(rule, dict) or "clash_mode" not in rule:
            dns_rules.append(rule)
            continue
        if rule.get("clash_mode") == "Rule":
            retained = copy.deepcopy(rule)
            retained.pop("clash_mode", None)
            dns_rules.append(retained)
    dns["rules"] = dns_rules
    dns["servers"] = [
        server
        for server in dns.get("servers", [])
        if not (isinstance(server, dict) and server.get("tag") == "local-backup")
    ]

def _insert_route_rules_after_bootstrap(rules: list[Any], new_rules: Sequence[Dict[str, Any]]) -> None:
    """Insert rules after sniff / hijack-dns / private IPs.

    Process and package matches must stay early, but never above
    ``ip_is_private``: Google Play Services does LAN discovery and the Microsoft
    Store uses Delivery Optimization peers on the local network.  Pinning either
    to ``Available`` above the private-IP rule would push that LAN traffic into
    the tunnel, where it cannot be answered.
    """

    insert_at = 0
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if (
            rule.get("action") in {"sniff", "hijack-dns"}
            or rule.get("protocol") == "dns"
            or rule.get("ip_is_private") is True
        ):
            insert_at = index + 1
            continue
        break
    for offset, rule in enumerate(new_rules):
        rules.insert(insert_at + offset, rule)


def _insert_rules_after_clash_mode(rules: list[Any], new_rules: Sequence[Dict[str, Any]]) -> None:
    """Insert rules just below the clash_mode overrides (route and DNS alike).

    Service-pinning rules (Microsoft Store, Google Play) must stay ABOVE the
    China rule-set tail but BELOW clash_mode, so the dashboard's Direct toggle
    remains authoritative over them.  Only the ``Direct``/``Proxy`` mode
    switches count as the boundary: most policy rules below them also carry
    ``clash_mode: "Rule"``, and anchoring to those would drop the new rules
    underneath the very China tail they need to outrank.  Falls back to the
    post-bootstrap slot when no mode switch exists (e.g. Android after
    minimization).
    """

    insert_at = None
    for index, rule in enumerate(rules):
        if isinstance(rule, dict) and rule.get("clash_mode") in {"Direct", "Proxy"}:
            insert_at = index + 1
    if insert_at is None:
        _insert_route_rules_after_bootstrap(rules, new_rules)
        return
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
    rule_sets = route.setdefault("rule_set", [])

    # Add the microsoft-store rule-set if not already present
    if not any(
        isinstance(rs, dict) and rs.get("tag") == MICROSOFT_STORE_RULE_SET_TAG
        for rs in rule_sets
    ):
        rule_sets.append({
            "tag": MICROSOFT_STORE_RULE_SET_TAG,
            "type": "local",
            "format": "source",
            "path": MICROSOFT_STORE_RULE_SET_PATH,
        })

    store_processes = set(MICROSOFT_STORE_PROCESS_NAMES)
    if not any(
        isinstance(rule, dict)
        and store_processes <= set(normalized_string_list(rule.get("process_name")))
        for rule in rules
    ):
        _insert_rules_after_clash_mode(
            rules,
            [
                {
                    "clash_mode": "Rule",
                    "process_name": list(MICROSOFT_STORE_PROCESS_NAMES),
                    "action": "route",
                    "outbound": "Available",
                },
                {
                    "clash_mode": "Rule",
                    "rule_set": MICROSOFT_STORE_RULE_SET_TAG,
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
        and rule.get("rule_set") == MICROSOFT_STORE_RULE_SET_TAG
        and rule.get("server") == "google"
        for rule in dns_rules
    ):
        dns_rules.insert(
            0,
            {
                "clash_mode": "Rule",
                "rule_set": MICROSOFT_STORE_RULE_SET_TAG,
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
    # The controller only listens on loopback, so keep the local dashboard
    # passwordless and avoid creating a persistent API secret.
    template = apply_profile_to_template(template, profile, clash_secret="")

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
    configure_rule_set_initial_paths(
        conf,
        str(profile.get("tuning", {}).get("rule_set_initial_dir") or ""),
    )
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

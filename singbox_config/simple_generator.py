#!/usr/bin/env python3
"""Small, declarative desktop/Android sing-box configuration generator."""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import requests
import yaml

from parsers import parse_subscription_text
from parsers.common import detect_region
from singbox_config.audit import (
    is_insecure_outbound,
    outbound_fingerprint,
    require_valid_config,
)
from singbox_config.io_utils import (
    atomic_write_json,
    atomic_write_text,
    parse_duration_seconds,
    parse_utc_timestamp,
    utc_now,
    utc_now_iso,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "policy.yaml"
DEFAULT_SUBSCRIPTIONS = ROOT / "config" / "local" / "subscriptions.yaml"
DEFAULT_CUSTOM_RULES = ROOT / "config" / "local" / "custom-rules.yaml"
DEFAULT_ROUTING_GROUPS = ROOT / "config" / "local" / "routing-groups.json"
DEFAULT_OUTPUT = ROOT / "dist"
DEFAULT_CACHE_DIR = ROOT / "runtime" / "subscription-cache"
NODE_ADDRESS_CACHE = ROOT / "runtime" / "node-address-cache.json"
PROFILE_PATHS = {
    "desktop": ROOT / "config" / "profiles" / "desktop.yaml",
    "android": ROOT / "config" / "profiles" / "android.yaml",
}

SUBSCRIPTION_KEYS = {
    "name",
    "enabled",
    "format",
    "source",
    "path",
    "user_agent",
    "group",
    "prefix_node_tags",
    "node_tag",
    "order",
    "urltest",
    "ai",
    "ai_include",
    "ai_exclude",
    "include",
    "exclude",
    "exclude_node_tags",
    "max_nodes",
    "deduplicate",
    "allow_unsupported",
    "allow_insecure",
}
PROCESS_RULE_KEYS = {"process_name", "process_path", "process_path_regex", "user", "user_id"}
PACKAGE_RULE_KEYS = {"package_name", "package_name_regex"}


@dataclass
class BuiltSource:
    name: str
    order: int
    entry_tag: str
    node_tags: list[str]
    nodes: list[dict[str, Any]]
    groups: list[dict[str, Any]]
    ai_node_tags: list[str]
    allows_duplicate_nodes: bool = False


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"配置文件不存在: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML 顶层必须是对象: {path}")
    return data


def deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def compile_patterns(values: Any, label: str) -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    for value in as_list(values):
        try:
            patterns.append(re.compile(str(value), re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"{label} 正则无效 {value!r}: {exc}") from exc
    return patterns


def matches_any(patterns: Iterable[re.Pattern[str]], value: str) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def cache_path_for(url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    return DEFAULT_CACHE_DIR / f"{digest}.txt"


def read_cache(url: str, max_age: str) -> str | None:
    path = cache_path_for(url)
    if not path.exists():
        return None
    meta_path = path.with_suffix(".json")
    timestamp = None
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(meta, dict):
                timestamp = parse_utc_timestamp(meta.get("validated_at") or meta.get("fetched_at"))
        except Exception:
            timestamp = None
    age = (utc_now() - timestamp).total_seconds() if timestamp else utc_now().timestamp() - path.stat().st_mtime
    if age > parse_duration_seconds(max_age):
        return None
    text = path.read_text(encoding="utf-8")
    return text if text.strip() else None


def write_cache(url: str, text: str) -> None:
    path = cache_path_for(url)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, text)
    atomic_write_json(
        path.with_suffix(".json"),
        {
            "schema_version": 3,
            "fetched_at": utc_now_iso(),
            "validated_at": utc_now_iso(),
            "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        },
    )


def download_text(
    url: str,
    timeout: int,
    proxy: str | None = None,
    user_agent: str | None = None,
) -> str:
    session = requests.Session()
    session.trust_env = False
    proxies = {"http": proxy, "https": proxy} if proxy else None
    response = session.get(
        url,
        timeout=(min(timeout, 10), timeout),
        proxies=proxies,
        headers={"User-Agent": user_agent or "sing-box-config/1.0"},
    )
    response.raise_for_status()
    payload = response.content
    if len(payload) > 32 * 1024 * 1024:
        raise ValueError("订阅下载结果超过 32 MiB 安全上限")
    text = payload.decode(response.encoding or "utf-8", errors="replace")
    if not text.strip():
        raise ValueError("订阅下载结果为空")
    if "<html" in text[:1024].lower():
        raise ValueError("订阅地址返回了 HTML 页面")
    return text


def load_subscription_text(
    item: Mapping[str, Any],
    manifest_dir: Path,
    policy: Mapping[str, Any],
    *,
    offline: bool = False,
    fetch_proxy: str | None = None,
) -> str:
    source = str(item.get("source") or "file").strip().lower()
    relative_path = str(item.get("path") or "").strip()
    if not relative_path:
        raise ValueError(f"{item.get('name')}: 缺少 path")
    path = (manifest_dir / relative_path).resolve()
    try:
        path.relative_to(manifest_dir.resolve())
    except ValueError as exc:
        raise ValueError(f"{item.get('name')}: path 超出 config/local: {relative_path}") from exc
    if source == "file":
        return path.read_text(encoding="utf-8")
    if source != "url_file":
        raise ValueError(f"{item.get('name')}: source 仅支持 file 或 url_file")
    url = path.read_text(encoding="utf-8").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"{item.get('name')}: URL 文件内容不是 HTTP(S) 地址")
    settings = policy.get("subscription", {})
    max_age = str(settings.get("cache_max_age") or "3d")
    cached = read_cache(url, max_age)
    if offline:
        if cached is None:
            raise RuntimeError(f"{item.get('name')}: 没有未过期的订阅缓存")
        return cached
    timeout = int(settings.get("timeout_seconds") or 20)
    user_agent = str(item.get("user_agent") or "").strip() or None
    errors: list[str] = []
    try:
        text = download_text(url, timeout, user_agent=user_agent)
        write_cache(url, text)
        return text
    except Exception as exc:
        errors.append(f"direct={type(exc).__name__}: {exc}")
    proxy = fetch_proxy or str(settings.get("retry_proxy") or "").strip() or None
    if proxy:
        try:
            text = download_text(url, timeout, proxy, user_agent=user_agent)
            write_cache(url, text)
            print(f"[订阅] {item.get('name')}: 直连失败，已通过本机代理更新。", file=sys.stderr)
            return text
        except Exception as exc:
            errors.append(f"proxy={type(exc).__name__}: {exc}")
    if cached is not None:
        print(f"[订阅] {item.get('name')}: 下载失败，使用未过期缓存。", file=sys.stderr)
        return cached
    raise RuntimeError(f"{item.get('name')}: 订阅获取失败；{' | '.join(errors)}")


def validate_manifest_item(item: Mapping[str, Any]) -> None:
    unknown = sorted(set(item) - SUBSCRIPTION_KEYS)
    if unknown:
        raise ValueError(f"{item.get('name') or '<unnamed>'}: 不支持的旧订阅字段: {', '.join(unknown)}")
    if not str(item.get("name") or "").strip():
        raise ValueError("订阅缺少 name")
    if not str(item.get("format") or "").strip():
        raise ValueError(f"{item.get('name')}: 缺少 format")


def strip_meta(node: Mapping[str, Any]) -> dict[str, Any]:
    cleaned = {key: copy.deepcopy(value) for key, value in node.items() if not key.startswith("_meta_")}
    # route.default_domain_resolver is authoritative for ordinary proxy dials.
    cleaned.pop("domain_resolver", None)
    return cleaned


def node_name(node: Mapping[str, Any]) -> str:
    return str(node.get("_meta_name") or node.get("tag") or "node").strip()


def is_placeholder_node(node: Mapping[str, Any]) -> bool:
    """Detect provider "info" entries that can never carry traffic.

    Airports often ship divider/quota lines as fake nodes pointing at
    127.0.0.1 or port 0.  Keeping them makes them the group default and the
    loopback address leaks into the TUN exclusion list.
    """
    server = str(node.get("server") or "").strip()
    try:
        port = int(node.get("server_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if port <= 1:
        return True
    if not server:
        return True
    try:
        ip = ipaddress.ip_address(server)
    except ValueError:
        return server.lower() in {"localhost", "localhost.localdomain"}
    return ip.is_loopback or ip.is_unspecified


def _is_ip_address(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def build_source(
    item: Mapping[str, Any],
    manifest_dir: Path,
    policy: Mapping[str, Any],
    used_tags: dict[str, str],
    used_fingerprints: dict[str, str],
    *,
    offline: bool,
    fetch_proxy: str | None,
) -> BuiltSource:
    validate_manifest_item(item)
    name = str(item["name"]).strip()
    text = load_subscription_text(item, manifest_dir, policy, offline=offline, fetch_proxy=fetch_proxy)
    nodes, _info, warnings = parse_subscription_text(str(item["format"]), text)
    if warnings and not bool_value(item.get("allow_unsupported")):
        raise ValueError(f"{name}: 订阅存在未接受的解析问题: {'; '.join(warnings)}")
    for warning in warnings:
        print(f"[订阅警告] {name}: {warning}", file=sys.stderr)

    include = compile_patterns(item.get("include"), f"{name}.include")
    exclude = compile_patterns(item.get("exclude"), f"{name}.exclude")
    exclude_node_tags = compile_patterns(item.get("exclude_node_tags"), f"{name}.exclude_node_tags")
    selected: list[dict[str, Any]] = []
    for node in nodes:
        original = node_name(node)
        if is_placeholder_node(node):
            print(f"[占位节点] {name}: {original} 指向 {node.get('server')}:{node.get('server_port')}，已忽略。", file=sys.stderr)
            continue
        if exclude_node_tags and matches_any(exclude_node_tags, original):
            continue
        if include and not matches_any(include, original):
            continue
        if exclude and matches_any(exclude, original):
            continue
        selected.append(node)
    max_nodes = int(item.get("max_nodes") or 0)
    if max_nodes > 0:
        selected = selected[:max_nodes]
    if not selected:
        raise ValueError(f"{name}: 筛选后没有可用节点")

    group_value = item.get("group")
    group_tag = str(group_value or name).strip()
    # ``group: false`` keeps multiple source nodes as independent outbounds.
    is_group = len(selected) > 1 and group_value is not False
    built_nodes: list[dict[str, Any]] = []
    node_tags: list[str] = []
    ai_tags: list[str] = []
    ai_mode = item.get("ai", "auto")
    ai_enabled = ai_mode is not False and str(ai_mode).strip().lower() not in {"false", "off", "disabled", "0"}
    ai_force = str(ai_mode).strip().lower() in {"true", "on", "enabled", "1"}
    allow_insecure = bool_value(item.get("allow_insecure"), False)
    ai_include = compile_patterns(item.get("ai_include"), f"{name}.ai_include")
    ai_exclude = compile_patterns(item.get("ai_exclude"), f"{name}.ai_exclude")
    deduplicate = bool_value(item.get("deduplicate"), True)

    for index, raw in enumerate(selected):
        original = node_name(raw)
        node = strip_meta(raw)
        if is_insecure_outbound(node) and not allow_insecure:
            raise ValueError(
                f"{name}: 节点 {original!r} 关闭了 TLS 证书校验；"
                "如确认必要，请在该订阅中显式设置 allow_insecure: true"
            )
        if len(selected) == 1 and item.get("node_tag"):
            tag = str(item["node_tag"]).strip()
        # Keep provider node names intact.  Groups already provide the
        # namespace users see in the selector, so adding a second prefix is
        # surprising and can make manual selection needlessly verbose.
        elif is_group and bool_value(item.get("prefix_node_tags"), True):
            tag = f"{group_tag}/{original}"
        else:
            tag = original
        node["tag"] = tag
        # 节点 server 为域名时，固定用直连解析器（policy.node_dns_resolver），
        # 避免走 dns.final（google → detour Available）依赖当前选中节点，
        # 导致节点域名解析超时、测速显示不出来或忽隐忽现。
        node_resolver = str(policy.get("node_dns_resolver") or "").strip()
        node_server = node.get("server")
        if node_resolver and node_server and not _is_ip_address(node_server):
            node["domain_resolver"] = node_resolver
        fingerprint = outbound_fingerprint(node, length=64)
        if deduplicate and fingerprint in used_fingerprints:
            print(f"[去重] {name}: {original} 与 {used_fingerprints[fingerprint]} 相同，已忽略。", file=sys.stderr)
            continue
        if tag in used_tags and used_tags[tag] != fingerprint:
            raise ValueError(f"节点 tag 冲突: {tag}；请在订阅中设置明确 node_tag 或 group")
        used_tags[tag] = fingerprint
        used_fingerprints.setdefault(fingerprint, tag)
        built_nodes.append(node)
        node_tags.append(tag)
        if ai_enabled and not is_insecure_outbound(node):
            allowed = ai_force or detect_region(tag) == "US" or matches_any(ai_include, original)
            if allowed and not matches_any(ai_exclude, original):
                ai_tags.append(tag)

    if not node_tags:
        raise ValueError(f"{name}: 节点全部与其他订阅重复")

    groups: list[dict[str, Any]] = []
    entry_tag = node_tags[0]
    if is_group:
        members = list(node_tags)
        default = members[0]
        # All subscription groups are intentionally manual selectors.  The
        # historical ``urltest`` option is accepted for manifest
        # compatibility, but never creates an implicit ``*/Auto`` group.
        groups.insert(
            0,
            {
                "type": "selector",
                "tag": group_tag,
                "outbounds": members,
                "default": default,
                "interrupt_exist_connections": True,
            },
        )
        entry_tag = group_tag
    return BuiltSource(
        name=name,
        order=int(item.get("order") or 100),
        entry_tag=entry_tag,
        node_tags=node_tags,
        nodes=built_nodes,
        groups=groups,
        ai_node_tags=ai_tags,
        allows_duplicate_nodes=not deduplicate,
    )


def load_sources(
    manifest_path: Path,
    policy: Mapping[str, Any],
    *,
    offline: bool,
    fetch_proxy: str | None,
) -> list[BuiltSource]:
    data = load_yaml(manifest_path)
    if int(data.get("schema_version") or 0) != 1:
        raise ValueError(f"订阅清单 schema_version 必须为 1: {manifest_path}")
    raw_items = data.get("subscriptions")
    if not isinstance(raw_items, list):
        raise ValueError("subscriptions 必须是数组")
    used_tags: dict[str, str] = {}
    used_fingerprints: dict[str, str] = {}
    sources: list[BuiltSource] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise ValueError("subscriptions 的每一项必须是对象")
        if not bool_value(raw.get("enabled"), True):
            continue
        sources.append(
            build_source(
                raw,
                manifest_path.parent,
                policy,
                used_tags,
                used_fingerprints,
                offline=offline,
                fetch_proxy=fetch_proxy,
            )
        )
    if not sources:
        raise ValueError("没有启用的订阅")
    return sorted(sources, key=lambda source: (source.order, source.name.casefold()))


def build_outbounds(
    sources: Sequence[BuiltSource],
    policy: Mapping[str, Any],
    profile: Mapping[str, Any],
    routing_groups: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    selectors = policy.get("selectors", {})
    interrupt = bool_value(selectors.get("interrupt_exist_connections"), True)
    nodes = [node for source in sources for node in source.nodes]
    region_groups: list[dict[str, Any]] = []
    region_group_tags: list[str] = []
    for raw_group in as_list(selectors.get("region_groups")):
        if not isinstance(raw_group, dict):
            raise ValueError("selectors.region_groups 的每一项必须是对象")
        tag = str(raw_group.get("tag") or "").strip()
        raw_regions = raw_group.get("regions", raw_group.get("region"))
        regions = [str(value).strip().upper() for value in as_list(raw_regions) if str(value).strip()]
        if not tag or not regions:
            raise ValueError("selectors.region_groups 必须同时设置 tag 和 regions")
        members = [
            str(node.get("tag"))
            for node in nodes
            if node.get("tag") and detect_region(str(node.get("tag"))) in regions
        ]
        if not members:
            raise ValueError(f"地区分组 {tag} 没有匹配到 {','.join(regions)} 节点")
        region_group_tags.append(tag)
        region_groups.append(
            {
                "type": "selector",
                "tag": tag,
                "outbounds": members,
                "default": members[0],
                "interrupt_exist_connections": interrupt,
            }
        )
    # Ungrouped multi-node sources expose every node to the top-level selector;
    # grouped sources continue to expose their selector entry only.
    source_entries = [
        tag
        for source in sources
        for tag in (source.node_tags if len(source.node_tags) > 1 and not source.groups else [source.entry_tag])
    ]
    # Keep the existing default entry stable; region groups are additional
    # manual choices exposed by the top-level selector.
    profile_available_entries = [
        str(tag).strip()
        for tag in as_list(profile.get("available_outbounds"))
        if str(tag).strip()
    ]
    available_entries = [*source_entries, *region_group_tags, *profile_available_entries]
    ai_entries = list(dict.fromkeys(tag for source in sources for tag in source.ai_node_tags))
    if not ai_entries:
        ai_entries = [str(selectors.get("available") or "Available")]
    # Keep the AI selector scoped to explicitly eligible nodes.  Adding the
    # general Available selector as a singleton fallback would allow an AI
    # rule to silently leave the intended region/policy boundary.
    direct_tag = str(selectors.get("direct") or "direct")
    available_tag = str(selectors.get("available") or "Available")
    ai_tag = str(selectors.get("ai") or "AI")
    emby_tag = str(selectors.get("emby") or "Emby")
    direct_outbound: dict[str, Any] = {"type": "direct", "tag": direct_tag}
    direct_interface = str(profile.get("direct_interface") or "").strip()
    if direct_interface:
        direct_outbound["bind_interface"] = direct_interface
    outbounds: list[dict[str, Any]] = [
        {
            "type": "selector",
            "tag": available_tag,
            "outbounds": available_entries,
            "default": available_entries[0],
            "interrupt_exist_connections": interrupt,
        },
        {
            "type": "selector",
            "tag": ai_tag,
            "outbounds": ai_entries,
            "default": ai_entries[0],
            "interrupt_exist_connections": interrupt,
        },
        direct_outbound,
        {
            "type": "selector",
            "tag": emby_tag,
            "outbounds": list(dict.fromkeys([available_tag, *available_entries, direct_tag])),
            "default": available_tag,
            "interrupt_exist_connections": interrupt,
        },
    ]
    outbounds.extend(region_groups)
    for source in sources:
        outbounds.extend(copy.deepcopy(source.groups))
    for source in sources:
        outbounds.extend(copy.deepcopy(source.nodes))
    outbounds.extend(copy.deepcopy(as_list(profile.get("static_outbounds"))))
    known_tags = {
        str(outbound.get("tag"))
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("tag")
    }
    unknown_profile_entries = [tag for tag in profile_available_entries if tag not in known_tags]
    if unknown_profile_entries:
        raise ValueError(
            "profile.available_outbounds 引用了不存在的出站: "
            + ", ".join(unknown_profile_entries)
        )
    managed_outbounds: list[dict[str, Any]] = []
    managed_tags: set[str] = set()
    for raw_group in as_list((routing_groups or {}).get("groups")):
        if not isinstance(raw_group, dict):
            raise ValueError("routing-groups.json groups 的每一项必须是对象")
        tag = str(raw_group.get("tag") or "").strip()
        members = [str(value).strip() for value in as_list(raw_group.get("outbounds")) if str(value).strip()]
        if not tag:
            raise ValueError("routing-groups.json 分组 tag 不能为空")
        # A routing-groups entry may only carry domains for an existing
        # outbound (a policy strategy selector such as Available/AI/Emby, or
        # a plain outbound such as direct).  The outbound is owned elsewhere
        # and must not be recreated here, so members must stay empty.
        if tag in known_tags:
            if members:
                raise ValueError(f"出站 {tag} 已存在，routing-groups.json 不应设置 outbounds")
            managed_tags.add(tag)
            continue
        if tag in known_tags or tag in managed_tags:
            raise ValueError(f"分组 tag 冲突: {tag}")
        if not members:
            raise ValueError(f"分组 {tag} 没有出站成员")
        unknown = [member for member in members if member not in known_tags]
        if unknown:
            raise ValueError(f"分组 {tag} 引用了不存在的出站: {', '.join(unknown)}")
        managed_tags.add(tag)
        managed_outbounds.append(
            {
                "type": "selector",
                "tag": tag,
                "outbounds": list(dict.fromkeys(members)),
                "default": members[0],
                "interrupt_exist_connections": interrupt,
            }
        )
    # Managed groups are deliberately not inserted into Available: their
    # members may include Available, and doing so would create a selector cycle.
    outbounds.extend(managed_outbounds)
    return outbounds


def filter_rule_for_platform(rule: Mapping[str, Any], platform: str) -> dict[str, Any] | None:
    if platform == "android" and any(key in rule for key in PROCESS_RULE_KEYS):
        return None
    if platform != "android" and any(key in rule for key in PACKAGE_RULE_KEYS):
        return None
    return copy.deepcopy(dict(rule))


def filtered_rules(values: Any, platform: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in as_list(values):
        if not isinstance(raw, dict):
            raise ValueError("规则必须是对象")
        rule = filter_rule_for_platform(raw, platform)
        if rule is not None:
            result.append(rule)
    return result


def load_inline_rules(path_text: str) -> list[dict[str, Any]]:
    path = (ROOT / path_text).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"inline_file 超出项目目录: {path_text}") from exc
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list):
        raise ValueError(f"inline_file 缺少 rules 数组: {path_text}")
    return copy.deepcopy(rules)


def rule_set_tags(item: Mapping[str, Any]) -> list[str]:
    return [str(value) for value in as_list(item.get("tag")) if str(value).strip()]


# Canonical route matchers stored in routing-groups.json.  Bare values keep
# the historical meaning of ``domain_suffix`` for backward compatibility.
MATCHER_ALIASES = {
    "suffix": "domain_suffix",
    "domain_suffix": "domain_suffix",
    "domain": "domain",
    "full": "domain",
    "keyword": "domain_keyword",
    "domain_keyword": "domain_keyword",
    "regexp": "domain_regex",
    "regex": "domain_regex",
    "domain_regex": "domain_regex",
    "ip": "ip_cidr",
    "cidr": "ip_cidr",
    "ip_cidr": "ip_cidr",
}
MATCHER_ORDER = ["domain_suffix", "domain", "domain_keyword", "domain_regex", "ip_cidr"]
_MATCHER_PREFIX = re.compile(r"^([A-Za-z_]+):(.*)$", re.DOTALL)


def normalize_ip_cidr(value: str) -> str:
    value = value.strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"无效的 IP/CIDR: {value}") from exc
    else:
        suffix = 32 if ip.version == 4 else 128
        net = ipaddress.ip_network(f"{ip}/{suffix}", strict=False)
    return str(net)


def parse_route_matcher(value: str) -> tuple[str, str]:
    value = value.strip()
    match = _MATCHER_PREFIX.match(value)
    if match and match.group(1).lower() in MATCHER_ALIASES:
        kind = MATCHER_ALIASES[match.group(1).lower()]
        payload = match.group(2).strip()
        if not payload:
            raise ValueError(f"分流规则 [{value}] 缺少匹配内容")
    else:
        kind, payload = "domain_suffix", value
    if kind == "ip_cidr":
        payload = normalize_ip_cidr(payload)
    elif kind == "domain_regex":
        try:
            re.compile(payload)
        except re.error as exc:
            raise ValueError(f"正则无效 {payload!r}: {exc}") from exc
    return kind, payload


def build_managed_rules(
    routing_groups: Mapping[str, Any] | None,
    direct_tag: str,
    dns_server_tags: Iterable[str] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Turn routing-groups domains into typed route + DNS rules.

    Each group yields one route rule per matcher kind; domains routed to the
    ``direct`` outbound also get a local-DNS rule so resolution cannot leak
    through the proxy DNS.  DNS rules are only emitted for servers that the
    policy actually declares, and never for IP matchers.  Empty groups produce
    nothing.
    """
    server_pool = {str(tag).strip() for tag in dns_server_tags if str(tag).strip()}
    local_server = "local" if "local" in server_pool else next(iter(server_pool), None)
    proxy_server = "google" if "google" in server_pool else ("local" if "local" in server_pool else next(iter(server_pool), None))
    route_rules: list[dict[str, Any]] = []
    dns_rules: list[dict[str, Any]] = []
    for raw_group in as_list((routing_groups or {}).get("groups")):
        if not isinstance(raw_group, dict):
            continue
        tag = str(raw_group.get("tag") or "").strip()
        if not tag:
            continue
        grouped: dict[str, list[str]] = {kind: [] for kind in MATCHER_ORDER}
        for value in as_list(raw_group.get("domains")):
            kind, payload = parse_route_matcher(str(value))
            grouped[kind].append(payload)
        for kind in MATCHER_ORDER:
            members = list(dict.fromkeys(grouped[kind]))
            if not members:
                continue
            route_rules.append({kind: members, "action": "route", "outbound": tag})
            if kind == "ip_cidr":
                continue
            server = local_server if tag == direct_tag else proxy_server
            if server:
                dns_rules.append({kind: members, "action": "route", "server": server})
    return route_rules, dns_rules


def build_rule_sets(
    policy: Mapping[str, Any],
    profile: Mapping[str, Any],
    custom: Mapping[str, Any],
) -> list[dict[str, Any]]:
    platform = str(profile.get("platform") or "")
    embed_local = bool_value(profile.get("embed_local_rule_sets"))
    strip_initial = bool_value(profile.get("strip_rule_set_initial_path"))
    result: list[dict[str, Any]] = []
    tags: set[str] = set()
    for raw in [*as_list(policy.get("rule_sets")), *as_list(profile.get("rule_sets")), *as_list(custom.get("rule_sets"))]:
        if not isinstance(raw, dict):
            raise ValueError("rule_sets 的每一项必须是对象")
        item = copy.deepcopy(raw)
        inline_file = item.pop("inline_file", None)
        if inline_file:
            item["rules"] = load_inline_rules(str(inline_file))
        elif (platform == "android" or embed_local) and item.get("type") == "local" and item.get("path"):
            # Remote profiles receive only config.json. Embed project-local
            # rule sets so SFA/SFW do not depend on the publisher's tree.
            item["type"] = "inline"
            item["rules"] = load_inline_rules(str(item.pop("path")))
            item.pop("format", None)
        if item.get("type") == "remote":
            item.setdefault("format", "binary")
            item.setdefault("update_interval", "1d")
            item.setdefault("http_client", "rule-set-downloader")
            if not strip_initial and "initial_path" not in item:
                tag_value = item.get("tag")
                placeholder = "{tag}" if isinstance(tag_value, list) else str(tag_value)
                item["initial_path"] = f"runtime/rule-set-cache/{placeholder}.srs"
        if strip_initial:
            item.pop("initial_path", None)
        current_tags = rule_set_tags(item)
        duplicate = sorted(set(current_tags) & tags)
        if duplicate:
            raise ValueError(f"重复规则集 tag: {', '.join(duplicate)}")
        tags.update(current_tags)
        result.append(item)
    return result


def read_node_address_cache() -> dict[str, list[str]]:
    try:
        data = json.loads(NODE_ADDRESS_CACHE.read_text(encoding="utf-8"))
        hosts = data.get("hosts") if isinstance(data, dict) else None
        return hosts if isinstance(hosts, dict) else {}
    except Exception:
        return {}


def node_route_exclusions(nodes: Sequence[Mapping[str, Any]]) -> list[str]:
    cached = read_node_address_cache()
    updated = copy.deepcopy(cached)
    addresses: list[str] = []
    for node in nodes:
        server = str(node.get("server") or "").strip()
        if not server:
            continue
        try:
            ip = ipaddress.ip_address(server)
            if ip.version == 4:
                addresses.append(f"{ip}/32")
            continue
        except ValueError:
            pass
        resolved: list[str] = []
        try:
            for item in socket.getaddrinfo(server, None, type=socket.SOCK_STREAM):
                ip = ipaddress.ip_address(item[4][0])
                if ip.version == 4:
                    resolved.append(f"{ip}/32")
        except OSError:
            resolved = [str(value) for value in cached.get(server, [])]
        resolved = list(dict.fromkeys(resolved))
        if not resolved:
            raise RuntimeError(f"节点域名无法解析且没有缓存: {server}")
        updated[server] = resolved
        addresses.extend(resolved)
    NODE_ADDRESS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(NODE_ADDRESS_CACHE, {"version": 1, "hosts": updated})
    unique = list(dict.fromkeys(addresses))
    return sorted(unique, key=lambda value: int(ipaddress.ip_network(value, strict=False).network_address))


def apply_route_exclusions(conf: dict[str, Any], nodes: Sequence[Mapping[str, Any]]) -> None:
    exclusions = node_route_exclusions(nodes)
    for inbound in conf.get("inbounds", []):
        if isinstance(inbound, dict) and inbound.get("type") == "tun":
            configured = [
                str(value).strip()
                for value in as_list(inbound.get("route_exclude_address"))
                if str(value).strip()
            ]
            inbound["route_exclude_address"] = list(dict.fromkeys([*configured, *exclusions]))
            return
    raise ValueError("桌面 profile 缺少 TUN inbound")


def assemble_rules(
    conf: dict[str, Any],
    policy: Mapping[str, Any],
    profile: Mapping[str, Any],
    custom: Mapping[str, Any],
    routing_groups: Mapping[str, Any] | None = None,
) -> None:
    platform = str(profile.get("platform") or "")
    route_policy = policy.get("route", {})
    dns_policy = policy.get("dns_rules", {})
    direct_tag = str(policy.get("selectors", {}).get("direct") or "direct")
    dns_server_tags = [
        str(server.get("tag")).strip()
        for server in as_list(policy.get("config", {}).get("dns", {}).get("servers"))
        if isinstance(server, dict) and str(server.get("tag") or "").strip()
    ]
    managed_rules, managed_dns_rules = build_managed_rules(routing_groups, direct_tag, dns_server_tags)
    conf.setdefault("route", {})["rules"] = [
        *filtered_rules(custom.get("route_rules_front"), platform),
        *filtered_rules(profile.get("route_rules_front"), platform),
        *filtered_rules(route_policy.get("pre_rules"), platform),
        *managed_rules,
        *filtered_rules(custom.get("route_rules"), platform),
        *filtered_rules(profile.get("route_rules"), platform),
        *filtered_rules(route_policy.get("business_rules"), platform),
        *filtered_rules(route_policy.get("domestic_rules"), platform),
    ]
    conf.setdefault("dns", {})["rules"] = [
        *filtered_rules(profile.get("dns_rules_front"), platform),
        *filtered_rules(dns_policy.get("pre_rules"), platform),
        *managed_dns_rules,
        *filtered_rules(custom.get("dns_rules"), platform),
        *filtered_rules(profile.get("dns_rules"), platform),
        *filtered_rules(dns_policy.get("business_rules"), platform),
        *filtered_rules(dns_policy.get("domestic_rules"), platform),
        # 兜底规则：只处理未命中上方任何规则的查询。当前用于 DNS 竞速
        #（evaluate + race），两者都不命中时才由 dns.final 兜底。
        *filtered_rules(dns_policy.get("final_rules"), platform),
    ]


def build_config(
    target: str,
    policy: Mapping[str, Any],
    profile: Mapping[str, Any],
    custom: Mapping[str, Any],
    sources: Sequence[BuiltSource],
    routing_groups: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    conf = deep_merge(policy.get("config", {}), profile.get("config", {}))
    conf["outbounds"] = build_outbounds(sources, policy, profile, routing_groups)
    conf.setdefault("route", {})["rule_set"] = build_rule_sets(policy, profile, custom)
    assemble_rules(conf, policy, profile, custom, routing_groups)
    nodes = [node for source in sources for node in source.nodes]
    if bool_value(profile.get("resolve_node_ipv4")):
        apply_route_exclusions(conf, nodes)
    require_valid_config(
        conf,
        {"allow_duplicate_nodes": any(source.allows_duplicate_nodes for source in sources)},
    )
    return conf


def target_names(value: str) -> tuple[str, ...]:
    if value == "all":
        return ("desktop", "android")
    if value == "desktop":
        return ("desktop",)
    if value == "android":
        return ("android",)
    if value not in PROFILE_PATHS:
        raise ValueError(f"未知目标: {value}")
    return (value,)


def generate(
    target: str,
    *,
    policy_path: Path = DEFAULT_POLICY,
    subscriptions_path: Path = DEFAULT_SUBSCRIPTIONS,
    custom_rules_path: Path = DEFAULT_CUSTOM_RULES,
    routing_groups_path: Path = DEFAULT_ROUTING_GROUPS,
    output_dir: Path = DEFAULT_OUTPUT,
    offline: bool = False,
    fetch_proxy: str | None = None,
) -> dict[str, Path]:
    policy = load_yaml(policy_path)
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError("config/policy.yaml schema_version 必须为 1")
    custom = load_yaml(custom_rules_path) if custom_rules_path.exists() else {"schema_version": 1}
    if int(custom.get("schema_version") or 0) != 1:
        raise ValueError("custom-rules.yaml schema_version 必须为 1")
    routing_groups = load_yaml(routing_groups_path) if routing_groups_path.exists() else {"schema_version": 1, "groups": []}
    if int(routing_groups.get("schema_version") or 0) != 1:
        raise ValueError("routing-groups.json schema_version 必须为 1")
    sources = load_sources(subscriptions_path, policy, offline=offline, fetch_proxy=fetch_proxy)
    results: dict[str, Path] = {}
    for name in target_names(target):
        profile = load_yaml(PROFILE_PATHS[name])
        if int(profile.get("schema_version") or 0) != 1:
            raise ValueError(f"{PROFILE_PATHS[name]} schema_version 必须为 1")
        conf = build_config(name, policy, profile, custom, sources, routing_groups)
        path = output_dir / name / "config.json"
        atomic_write_json(path, conf)
        atomic_write_json(
            path.with_name("config.validated.json"),
            {
                "schema_version": 1,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "validated_at": utc_now_iso(),
                "validator": "生成器内置结构校验",
            },
        )
        counts: dict[str, int] = {}
        for source in sources:
            for node in source.nodes:
                region = detect_region(str(node.get("tag") or ""))
                counts[region] = counts.get(region, 0) + 1
        summary = "、".join(f"{region} {count}" for region, count in sorted(counts.items()))
        print(f"{'桌面端' if name == 'desktop' else '安卓端'}配置已生成: {path}")
        print(f"  节点 {sum(counts.values())} 个；{summary}")
        results[name] = path
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=("all", "desktop", "android"), nargs="?", default="all")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--subscriptions", type=Path, default=DEFAULT_SUBSCRIPTIONS)
    parser.add_argument("--custom-rules", type=Path, default=DEFAULT_CUSTOM_RULES)
    parser.add_argument("--routing-groups", type=Path, default=DEFAULT_ROUTING_GROUPS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fetch-proxy")
    parser.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        generate(
            args.target,
            policy_path=args.policy,
            subscriptions_path=args.subscriptions,
            custom_rules_path=args.custom_rules,
            routing_groups_path=args.routing_groups,
            output_dir=args.output_dir,
            offline=args.offline,
            fetch_proxy=args.fetch_proxy,
        )
    except Exception as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Small, declarative desktop/Android sing-box configuration generator."""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import re
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
    "ai",
    "ai_include",
    "ai_exclude",
    "include",
    "exclude",
    "exclude_node_tags",
    "exclude_types",
    "max_nodes",
    "deduplicate",
    "allow_unsupported",
    "allow_insecure",
    "provider",
    # Apply the Clash subscription's hosts table to node dial names only.
    "use_hosts",
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
    provider: dict[str, Any] | None = None
    original_node_names: dict[str, str] | None = None
    allow_insecure: bool = False


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
    # Some providers encode subscription quota/help entries as ordinary
    # proxy nodes and use this sentinel hostname instead of loopback.
    if server.lower() == "dont.use.this.node":
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


def _hosts_target(value: Any) -> str:
    if isinstance(value, list):
        value = next((item for item in value if str(item).strip()), "")
    return str(value or "").strip().rstrip(".")


def clash_hosts_table(text: str) -> dict[str, str]:
    """Read a Clash ``hosts`` map. Values may be a domain, an IP, or a list."""
    data = yaml.safe_load(text)
    raw = data.get("hosts") if isinstance(data, dict) else None
    if not isinstance(raw, Mapping):
        return {}
    table: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key or "").strip().rstrip(".").lower()
        target = _hosts_target(value)
        if name and target:
            table[name] = target
    return table


def rewrite_server_with_hosts(server: str, hosts: Mapping[str, str]) -> str:
    current = server.strip().rstrip(".")
    seen: set[str] = set()
    while True:
        key = current.lower()
        if key in seen:
            return current
        target = hosts.get(key)
        if not target or target.lower() == key:
            return current
        seen.add(key)
        current = target


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
    native_provider = (
        str(item.get("source")) == "url_file"
        and bool_value((policy.get("providers") or {}).get("enabled"))
        and bool_value(item.get("provider"), True)
    )
    if native_provider and (item.get("exclude_types") or int(item.get("max_nodes") or 0) > 0):
        raise ValueError(
            f"{name}: 原生 Provider 不支持 exclude_types/max_nodes；"
            "请移除这些限制，或为该订阅设置 provider: false 使用静态生成"
        )
    text = load_subscription_text(item, manifest_dir, policy, offline=offline, fetch_proxy=fetch_proxy)
    nodes, _info, warnings = parse_subscription_text(str(item["format"]), text)
    hosts: dict[str, str] = {}
    if bool_value(item.get("use_hosts")):
        subscription_format = str(item.get("format") or "").strip().lower()
        if subscription_format not in {"clash", "clash-yaml"}:
            raise ValueError(f"{name}: use_hosts 只适用于 clash 订阅")
        hosts = clash_hosts_table(text)
        if not hosts:
            print(f"[订阅] {name}: 已设置 use_hosts，但订阅里没有 hosts。", file=sys.stderr)
    announced_rewrites: set[tuple[str, str]] = set()
    if warnings and not bool_value(item.get("allow_unsupported")):
        raise ValueError(f"{name}: 订阅存在未接受的解析问题: {'; '.join(warnings)}")
    for warning in warnings:
        print(f"[订阅警告] {name}: {warning}", file=sys.stderr)

    include = compile_patterns(item.get("include"), f"{name}.include")
    exclude = compile_patterns(item.get("exclude"), f"{name}.exclude")
    exclude_node_tags = compile_patterns(item.get("exclude_node_tags"), f"{name}.exclude_node_tags")
    # 上游订阅常混有本核心加载不了的 outbound 类型（例如 nodebuf 的
    # hysteria v1 用 up/down、wireguard 用旧 server 字段）。这些节点留在配置里
    # 会让 sing-box check 直接 FATAL、连带双端生成全部失败，所以按类型跳过。
    # 用类型而不是节点名：免费池的节点编号每轮都在换，按名字排除必然漏。
    exclude_types = {
        str(value).strip().lower() for value in as_list(item.get("exclude_types")) if str(value).strip()
    }
    dropped_types: dict[str, int] = {}
    placeholder_names: list[str] = []
    selected: list[dict[str, Any]] = []
    for node in nodes:
        original = node_name(node)
        node_type = str(node.get("type") or "").strip().lower()
        if node_type in exclude_types:
            dropped_types[node_type] = dropped_types.get(node_type, 0) + 1
            continue
        if is_placeholder_node(node):
            placeholder_names.append(original)
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
    if dropped_types:
        summary = "、".join(f"{kind} ×{count}" for kind, count in sorted(dropped_types.items()))
        print(f"[订阅] {name}: 已按 exclude_types 跳过 {summary}。", file=sys.stderr)
    if not selected:
        raise ValueError(f"{name}: 筛选后没有可用节点")

    group_value = item.get("group")
    group_tag = str(group_value or name).strip()
    # ``group: false`` keeps multiple source nodes as independent outbounds.
    is_group = (len(selected) > 1 or native_provider) and group_value is not False
    built_nodes: list[dict[str, Any]] = []
    node_tags: list[str] = []
    ai_tags: list[str] = []
    original_node_names: dict[str, str] = {}
    ai_mode = item.get("ai", "auto")
    ai_enabled = ai_mode is not False and str(ai_mode).strip().lower() not in {"false", "off", "disabled", "0"}
    ai_force = str(ai_mode).strip().lower() in {"true", "on", "enabled", "1"}
    allow_insecure = bool_value(item.get("allow_insecure"), False)
    ai_include = compile_patterns(item.get("ai_include"), f"{name}.ai_include")
    ai_exclude = compile_patterns(item.get("ai_exclude"), f"{name}.ai_exclude")
    deduplicate = bool_value(item.get("deduplicate"), True)
    # AI 分组的地区白名单来自 policy.selectors.ai_regions（缺省仅 US）。
    # HK/大陆与未识别地区永远不在名单内：Claude/ChatGPT 等服务拒绝这些出口。
    raw_selectors = policy.get("selectors")
    ai_regions = {
        str(value).strip().upper()
        for value in as_list(raw_selectors.get("ai_regions") if isinstance(raw_selectors, Mapping) else None)
        if str(value).strip()
    } or {"US"}

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
        # Clash「关闭 DNS 覆写」会留下订阅自己的 hosts。这里只改这一订阅的
        # 拨号域名（例如把没有解析的名字改到 hosts 指向的后端），SNI 不动，
        # 也不导入订阅里的 fake-ip。
        server_text = str(node.get("server") or "").strip()
        if hosts and server_text:
            rewritten = rewrite_server_with_hosts(server_text, hosts)
            if rewritten != server_text:
                node["server"] = rewritten
                pair = (server_text, rewritten)
                if pair not in announced_rewrites:
                    announced_rewrites.add(pair)
                    print(
                        f"[订阅] {name}: hosts 将节点域名 {server_text} 改写为 {rewritten}。",
                        file=sys.stderr,
                    )
        # 节点 server 为域名时，固定用直连解析器（policy.node_dns_resolver），
        # 避免走 dns.final（google → detour Available）依赖当前选中节点，
        # 导致节点域名解析超时、测速显示不出来或忽隐忽现。
        raw_node_resolver = policy.get("node_dns_resolver")
        if isinstance(raw_node_resolver, Mapping):
            resolver_server = str(raw_node_resolver.get("server") or "").strip()
            node_resolver: str | dict[str, Any] | None = (
                copy.deepcopy(dict(raw_node_resolver)) if resolver_server else None
            )
        else:
            resolver_text = str(raw_node_resolver or "").strip()
            node_resolver = resolver_text or None
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
        original_node_names[tag] = original
        # ``ai`` controls whether the subscription participates and whether
        # insecure TLS nodes may participate; membership still requires a
        # policy-allowed region match (selectors.ai_regions, default US) or an
        # explicit include pattern.
        if ai_enabled and (ai_force or not is_insecure_outbound(node)):
            allowed = detect_region(tag) in ai_regions or matches_any(ai_include, original)
            if allowed and not matches_any(ai_exclude, original):
                ai_tags.append(tag)

    if not node_tags:
        raise ValueError(f"{name}: 节点全部与其他订阅重复")

    provider: dict[str, Any] | None = None
    source = str(item.get("source") or "file").strip().lower()
    if source == "url_file" and bool_value(item.get("provider"), True):
        url_path = (manifest_dir / str(item.get("path") or "")).resolve()
        provider_url = url_path.read_text(encoding="utf-8").strip()
        if provider_url.startswith(("http://", "https://")):
            provider_tag = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-") or "provider"
            provider_suffix = hashlib.sha256(provider_url.encode("utf-8")).hexdigest()[:8]
            provider = {
                "type": "remote",
                "tag": f"provider-{provider_tag}-{provider_suffix}",
                "url": provider_url,
                "path": f"providers/{provider_tag}-{provider_suffix}.json",
                "update_interval": str(policy.get("providers", {}).get("update_interval") or "24h"),
                "http_client": {
                    "headers": {"User-Agent": str(item.get("user_agent") or "sing-box")},
                },
            }
            if node_resolver:
                provider["override_dialer"] = {"domain_resolver": copy.deepcopy(node_resolver)}
            if not allow_insecure:
                provider["override_tls"] = {"insecure": False}
            include = item.get("include")
            if include:
                provider["include"] = "|".join(str(value) for value in as_list(include))
            exclude_patterns = [
                str(value).strip()
                for value in [*as_list(item.get("exclude")), *as_list(item.get("exclude_node_tags"))]
                if str(value).strip()
            ]
            # Provider-level filters see ORIGINAL names, before the core adds
            # its namespace. Keep the exact placeholder names found by parsing,
            # including notices that do not contain the usual traffic keywords.
            exclude_patterns.extend(f"^{re.escape(value)}$" for value in placeholder_names)
            if exclude_patterns:
                provider["exclude"] = "|".join(f"(?:{pattern})" for pattern in exclude_patterns)
            health = policy.get("providers", {}).get("health_check")
            if isinstance(health, Mapping) and bool_value(health.get("enabled"), False):
                provider["health_check"] = {
                    "enabled": True,
                    "url": str(health.get("url") or "https://www.gstatic.com/generate_204"),
                    "interval": str(health.get("interval") or "10m"),
                    "timeout": str(health.get("timeout") or "3s"),
                }

    groups: list[dict[str, Any]] = []
    entry_tag = node_tags[0]
    if is_group:
        members = list(node_tags)
        default = members[0]
        # All subscription groups are intentionally manual selectors; there is
        # no implicit ``*/Auto`` urltest group (the legacy ``urltest`` manifest
        # option was removed and is rejected as an unknown field).
        groups.insert(
            0,
            {
                "type": "selector",
                "tag": group_tag,
                "outbounds": members,
                "default": default,
                "interrupt_exist_connections": True,
                **({"providers": [str(provider["tag"])]} if provider else {}),
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
        provider=provider,
        original_node_names=original_node_names,
        allow_insecure=allow_insecure,
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
    providers: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    selectors = policy.get("selectors", {})
    interrupt = bool_value(selectors.get("interrupt_exist_connections"), True)
    native = bool_value((policy.get("providers") or {}).get("enabled"), False)
    native_sources = [source for source in sources if native and source.provider]
    static_sources = [source for source in sources if not (native and source.provider)]
    bootstrap = provider_bootstrap(sources, policy) if native_sources else None

    def dynamic_tag(source: BuiltSource, tag: str) -> str:
        original = (source.original_node_names or {}).get(tag)
        if original is None:
            prefix = source.entry_tag + "/"
            original = tag[len(prefix):] if tag.startswith(prefix) else tag
        return f"{source.provider['tag']}/{original}"

    native_ai = [source for source in native_sources if source.ai_node_tags]
    for source in native_ai:
        if source.allow_insecure:
            raise ValueError(
                f"{source.name}: 允许 insecure 的动态订阅不能保证 AI 节点刷新后的 TLS 边界；"
                "请设置 ai: false、allow_insecure: false 或 provider: false"
            )
    # Ungrouped multi-node sources expose every node to the top-level selector;
    # grouped sources continue to expose their selector entry only.
    available_entries = [
        tag
        for source in sources
        if not (native and source.provider and not source.groups)
        for tag in (source.node_tags if len(source.node_tags) > 1 and not source.groups else [source.entry_tag])
    ]
    ai_entries = list(dict.fromkeys(tag for source in static_sources for tag in source.ai_node_tags))
    if native_ai and not ai_entries:
        raise ValueError("动态 AI 分组需要一个通过 AI 筛选的独立节点作为空 Provider 后备")
    if not ai_entries and not native_ai:
        ai_entries = [str(selectors.get("available") or "Available")]
    # selectors.ai_regions 的顺序即地区优先级：美国排最前并作为 AI 默认出口，
    # 其余白名单地区（JP/SG/TW）只作备用。组内相对顺序保持订阅原序。
    ai_region_order = [
        str(value).strip().upper()
        for value in as_list(selectors.get("ai_regions"))
        if str(value).strip()
    ] or ["US"]

    def ai_region_priority(tag: str) -> int:
        region = detect_region(tag)
        return ai_region_order.index(region) if region in ai_region_order else len(ai_region_order)

    ai_entries.sort(key=ai_region_priority)
    # Keep the AI selector scoped to explicitly eligible nodes.  Adding the
    # general Available selector as a singleton fallback would allow an AI
    # rule to silently leave the intended region/policy boundary.
    direct_tag = str(selectors.get("direct") or "direct")
    available_tag = str(selectors.get("available") or "Available")
    ai_tag = str(selectors.get("ai") or "AI")
    # Cold-region pool: unrecognised-region nodes are scattered across the
    # panel, so they are collected into one selector.  It is appended to
    # ``Available`` (so it stays reachable at all) and to ``AI`` after the
    # whitelist nodes, but deliberately NOT to the service groups: those follow
    # Available member-for-member, and every node in Other has an unrecognised
    # region, so listing it there would make a stray panel pick send YouTube or
    # Telegram traffic to an unaudited region.  Members come from the actual node
    # list, not available_entries — grouped sources expose entry tags there,
    # whose names say nothing about node regions.  Disabled when
    # selectors.other is empty or no Others node exists.
    other_tag = str(selectors.get("other") or "").strip()
    other_members = [
        tag
        for source in static_sources
        for tag in source.node_tags
        if other_tag and detect_region(tag) == "Others"
    ]
    other_members = list(dict.fromkeys(other_members))
    # Snapshot the service-group membership before Other joins the general list:
    # the groups below build their members from this, so Other reaches them only
    # indirectly, by being picked inside Available.
    service_entries = list(available_entries)
    if other_tag and other_members:
        available_entries = [*available_entries, other_tag]
        ai_entries = [*ai_entries, other_tag]
    direct_outbound: dict[str, Any] = {"type": "direct", "tag": direct_tag}
    # Provider refresh must not turn the user's global choice into URLTest.
    # Keep grouped subscriptions nested and allow explicit standalone choices.
    available: dict[str, Any] = {
        "type": "selector",
        "tag": available_tag,
        "outbounds": available_entries,
        "default": available_entries[0],
        "interrupt_exist_connections": interrupt,
    }
    if providers:
        available["providers"] = [str(item["tag"]) for item in providers]
    outbounds: list[dict[str, Any]] = [
        available,
        {
            "type": "selector",
            "tag": ai_tag,
            "outbounds": ai_entries,
            **({"default": ai_entries[0]} if ai_entries else {}),
            **({
                "providers": [str(source.provider["tag"]) for source in native_ai],
                # Restrict AI to names audited by the generator; new nodes join
                # the ordinary subscription selector immediately, and enter AI
                # only after the next generation checks region and TLS policy.
                "include": "^(?:" + "|".join(
                    re.escape(dynamic_tag(source, tag))
                    for source in native_ai for tag in source.ai_node_tags
                ) + ")$",
            } if native_ai else {}),
            "interrupt_exist_connections": interrupt,
        },
        direct_outbound,
    ]
    # Other sits next to the policy groups it can be picked from; its members
    # stay in subscription order.
    if other_tag and other_members:
        outbounds.append(
            {
                "type": "selector",
                "tag": other_tag,
                "outbounds": other_members,
                "default": other_members[0],
                "interrupt_exist_connections": interrupt,
            }
        )
    # Service groups expose Available plus its entries and follow Available by
    # default, so they only diverge once a node is pinned in the panel.
    for raw_group in as_list(selectors.get("groups")):
        if not isinstance(raw_group, Mapping) or not str(raw_group.get("tag") or "").strip():
            raise ValueError("selectors.groups 的每一项必须是带 tag 的对象")
        tag = str(raw_group["tag"]).strip()
        if bool_value(raw_group.get("when_referenced")) and not profile_references_outbound(profile, tag):
            continue
        direct_mode = str(raw_group.get("direct") or "").strip()
        if direct_mode not in {"", "last", "default"}:
            raise ValueError(f"selectors.groups[{tag}].direct 只能是 last 或 default")
        members = [available_tag, *service_entries]
        if direct_mode == "last":
            members.append(direct_tag)
        elif direct_mode == "default":
            members.insert(0, direct_tag)
        outbounds.append(
            {
                "type": "selector",
                "tag": tag,
                "outbounds": list(dict.fromkeys(members)),
                "default": members[0],
                "interrupt_exist_connections": interrupt,
            }
        )
    for source in sources:
        for group in copy.deepcopy(source.groups):
            if bool_value((policy.get("providers") or {}).get("enabled"), False) and source.provider:
                group["providers"] = [str(source.provider["tag"])]
                group["outbounds"] = [bootstrap]
                # Dynamic members do not exist at Selector.Start(). A default
                # pointing at a provider node would make the core fail startup.
                group.pop("default", None)
            elif not providers and "providers" in group:
                group.pop("providers", None)
            outbounds.append(group)
    for source in static_sources:
        outbounds.extend(copy.deepcopy(source.nodes))
    known_tags = {
        str(outbound.get("tag"))
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("tag")
    }
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


def provider_bootstrap(sources: Sequence[BuiltSource], policy: Mapping[str, Any]) -> str:
    """Use an independent secure node for startup and empty-provider fallback."""
    static_sources = [source for source in sources if source.provider is None]
    secure = {
        str(node["tag"]): node
        for source in static_sources for node in source.nodes
        if node.get("server") and not is_insecure_outbound(node)
    }
    preferred = str((policy.get("providers") or {}).get("bootstrap_outbound") or "").strip()
    if preferred:
        if preferred not in secure:
            raise ValueError("providers.bootstrap_outbound 必须指向独立的、启用 TLS 校验的静态代理节点")
        return preferred
    for source in static_sources:
        for tag in source.ai_node_tags:
            if tag in secure:
                return tag
    if secure:
        return next(iter(secure))
    raise ValueError("原生 Provider 需要一个独立代理节点用于下载自举及空分组后备；请添加单节点或设置 provider: false")


def profile_references_outbound(profile: Mapping[str, Any], tag: str) -> bool:
    """True when a profile route rule hands traffic to ``tag``.

    ``when_referenced`` groups (Google Play on Android) must only exist on the
    platforms whose rules reference them; emitting them everywhere would show
    an unused group in the other platform's panel.
    """
    for key in ("route_rules_front", "route_rules"):
        for rule in as_list(profile.get(key)):
            if isinstance(rule, dict) and str(rule.get("outbound") or "") == tag:
                return True
    return False


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


DNS_ACTION_FIELDS = {
    "action",
    "server",
    "race",
    "speculative",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "timeout",
    "client_subnet",
    "remove_client_subnet",
    "rcode",
    "answer",
    "ns",
    "extra",
}
# Query options that carry over from a ``route`` rule to its ``evaluate`` legs.
DNS_QUERY_OPTION_FIELDS = {
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "timeout",
    "client_subnet",
    "remove_client_subnet",
}
# Single-field matchers whose values are OR'd inside one rule, so rules that
# consist of exactly one such field can be merged by concatenating the lists.
DNS_MERGEABLE_MATCHER_FIELDS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "rule_set",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "package_name_regex",
}


def _dns_matcher(rule: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in rule.items() if key not in DNS_ACTION_FIELDS}


def _merge_dns_matchers(matchers: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Union several rule matchers into a single matcher.

    Rules made of one list-valued field are folded together per field; any
    other matcher (multi-field AND rules, inverted rules, logical rules) stays
    a separate branch.  More than one branch becomes a ``logical`` OR rule.
    An empty (catch-all) matcher absorbs every other branch.
    """
    if any(not matcher for matcher in matchers):
        return {}
    merged_lists: dict[str, list[Any]] = {}
    branches: list[dict[str, Any]] = []
    for matcher in matchers:
        keys = set(matcher)
        if len(keys) == 1:
            (key,) = keys
            if key in DNS_MERGEABLE_MATCHER_FIELDS:
                merged_lists.setdefault(key, []).extend(as_list(matcher[key]))
                continue
        branches.append(copy.deepcopy(dict(matcher)))
    folded = [
        {key: list(dict.fromkeys(values))}
        for key, values in merged_lists.items()
    ]
    branches = [*folded, *branches]
    if len(branches) == 1:
        return branches[0]
    return {"type": "logical", "mode": "or", "rules": branches}


def _network_prefixes(values: Any, label: str) -> list[str]:
    prefixes: list[str] = []
    for value in as_list(values):
        text = str(value).strip()
        if not text:
            continue
        try:
            prefixes.append(str(ipaddress.ip_network(text, strict=False)))
        except ValueError as exc:
            raise ValueError(f"{label} 无效: {text}") from exc
    return list(dict.fromkeys(prefixes))


# Answers outside this set may win a domestic race.  The set is one inverted
# IP rule so it AND-combines with ``response_rcode: NOERROR`` on a normal DNS
# rule.  A logical rule cannot ``respond`` to a tagged evaluate on this core.
DOMESTIC_ANSWER_RULE_SET = "domestic-dns-answers"


def _noerror_respond(response_tag: str, reject_prefixes: Sequence[str]) -> dict[str, Any]:
    """Return the first clean NOERROR, or skip a response whose answer is a sinkhole."""
    respond: dict[str, Any] = {
        "match_response": response_tag,
        "response_rcode": "NOERROR",
        "action": "respond",
        "race": True,
    }
    if reject_prefixes:
        respond["rule_set"] = [DOMESTIC_ANSWER_RULE_SET]
    return respond


def expand_dns_failover_rules(
    rules: Sequence[Mapping[str, Any]], settings: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    """Expand ordinary DNS routes into same-path resolver races.

    Cached responses remain fast.  On a cache miss, ``evaluate`` starts every
    upstream query in parallel and the first successful tagged response is
    returned by a ``respond`` race.  A final SERVFAIL bounds failure latency
    instead of falling through and querying the same servers again.

    Consecutive routes to the same server are merged into one block, so the
    matcher is written once per leg instead of once per rule.  Merging only
    happens for adjacent rules, which preserves the priority order between
    differently-resolved rules exactly.  ``respond`` rules carry no matcher:
    sing-box skips a ``match_response`` rule whose tag was never evaluated,
    so they can only fire for queries that matched this block's evaluates.

    Optional settings, keyed by the primary server tag of a race:

    - ``rewrite_ttl``: cap the TTL stored for that group (proxy CDN edges).
    - ``reject_answers``: prefixes that disqualify a NOERROR from winning.
    - ``remove_client_subnet``: strip EDNS Client Subnet on every raced query.
    """

    settings = settings if isinstance(settings, Mapping) else {}
    raw_groups = settings.get("servers")
    groups = raw_groups if isinstance(raw_groups, Mapping) else {}
    default_timeout = str(settings.get("timeout") or "2s").strip() or "2s"
    rewrite_ttl = settings.get("rewrite_ttl") if isinstance(settings.get("rewrite_ttl"), Mapping) else {}
    reject_answers = settings.get("reject_answers") if isinstance(settings.get("reject_answers"), Mapping) else {}
    remove_client_subnet = bool(settings.get("remove_client_subnet"))

    def alternatives_for(rule: Mapping[str, Any]) -> list[str]:
        if (
            (rule.get("action") or "route") != "route"
            or rule.get("match_response") is not None
            or rule.get("race")
        ):
            return []
        server = str(rule.get("server") or "").strip()
        alternatives = [str(value).strip() for value in as_list(groups.get(server)) if str(value).strip()]
        return alternatives if len(alternatives) >= 2 else []

    def block_key(rule: Mapping[str, Any]) -> tuple[Any, ...]:
        options = {key: rule[key] for key in DNS_QUERY_OPTION_FIELDS if key in rule}
        return (str(rule.get("server")), json.dumps(options, sort_keys=True, ensure_ascii=False))

    expanded: list[dict[str, Any]] = []
    block_index = 0
    index = 0
    while index < len(rules):
        rule = copy.deepcopy(dict(rules[index]))
        alternatives = alternatives_for(rule)
        if not alternatives:
            expanded.append(rule)
            index += 1
            continue
        key = block_key(rule)
        members = [rule]
        index += 1
        while index < len(rules):
            candidate = dict(rules[index])
            if not alternatives_for(candidate) or block_key(candidate) != key:
                break
            members.append(copy.deepcopy(candidate))
            index += 1
        block_index += 1
        matcher = _merge_dns_matchers([_dns_matcher(member) for member in members])
        query_options = {key: copy.deepcopy(rule[key]) for key in DNS_QUERY_OPTION_FIELDS if key in rule}
        query_options.setdefault("timeout", default_timeout)
        primary = str(rule.get("server") or "")
        if primary in rewrite_ttl and "rewrite_ttl" not in query_options:
            query_options["rewrite_ttl"] = rewrite_ttl[primary]
        if remove_client_subnet and "remove_client_subnet" not in query_options and "client_subnet" not in query_options:
            query_options["remove_client_subnet"] = True
        reject_prefixes = _network_prefixes(reject_answers.get(primary), "domestic_reject_answers")
        response_tags = [f"failover-{block_index}-{alternative}" for alternative in alternatives]
        for alternative, response_tag in zip(alternatives, response_tags):
            expanded.append(
                {
                    **copy.deepcopy(matcher),
                    "action": "evaluate",
                    "server": alternative,
                    "tag": response_tag,
                    **query_options,
                }
            )
        for response_tag in response_tags:
            expanded.append(_noerror_respond(response_tag, reject_prefixes))
        for response_tag in response_tags:
            expanded.append({
                "match_response": response_tag, "response_rcode": "NXDOMAIN", "action": "respond",
            })
        expanded.append({**copy.deepcopy(matcher), "action": "predefined", "rcode": "SERVFAIL"})
    return expanded


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


def build_managed_rules(routing_groups: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Turn routing-groups domains into one typed route rule per matcher kind.

    DNS rules are derived from these route rules like every other policy rule,
    so domains routed to ``direct`` resolve through the domestic resolver.
    """
    route_rules: list[dict[str, Any]] = []
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
    return route_rules


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


@dataclass
class DnsLayout:
    """DoH servers rendered from ``policy.dns_upstreams`` and their roles."""

    servers: list[dict[str, Any]]
    # Primary tag -> every server raced for it (see expand_dns_failover_rules).
    failover: dict[str, list[str]]
    # Outbound tag -> resolver whose detour matches that outbound.
    by_outbound: dict[str, str]
    proxy: str | None
    timeout: str


def build_dns_layout(
    policy: Mapping[str, Any], outbound_tags: set[str] | None = None
) -> DnsLayout:
    """Render DoH servers.

    ``outbound_tags`` limits ``proxy_detours`` to outbounds that actually
    exist. Groups marked ``when_referenced`` (Google Play on desktop) are
    skipped; any other missing target is a configuration error. Without
    ``outbound_tags`` every detour is rendered.
    """
    upstreams = policy.get("dns_upstreams")
    if not isinstance(upstreams, Mapping):
        return DnsLayout([], {}, {}, None, "2s")
    selectors = policy.get("selectors") or {}
    if not isinstance(selectors, Mapping):
        selectors = {}
    direct_tag = str(selectors.get("direct") or "direct")
    available_tag = str(selectors.get("available") or "Available")
    optional_tags = {
        str(group.get("tag") or "").strip()
        for group in as_list(selectors.get("groups"))
        if isinstance(group, Mapping) and bool_value(group.get("when_referenced"))
    }

    def render(entry: Any, suffix: str = "", detour: str | None = None) -> dict[str, Any]:
        if not isinstance(entry, Mapping) or not all(entry.get(key) for key in ("tag", "server", "server_name")):
            raise ValueError("dns_upstreams 的每一项必须包含 tag、server 和 server_name")
        server: dict[str, Any] = {
            "type": "https",
            "tag": f"{entry['tag']}-{suffix}" if suffix else str(entry["tag"]),
            "server": str(entry["server"]),
            "server_port": int(entry.get("server_port") or 443),
            "path": str(entry.get("path") or "/dns-query"),
            "tls": {"enabled": True, "server_name": str(entry["server_name"])},
        }
        if detour:
            server["detour"] = detour
        return server

    servers: list[dict[str, Any]] = []
    failover: dict[str, list[str]] = {}
    by_outbound: dict[str, str] = {}

    def add_race(outbound: str, legs: list[dict[str, Any]]) -> None:
        if not legs:
            return
        servers.extend(legs)
        failover[legs[0]["tag"]] = [leg["tag"] for leg in legs]
        by_outbound[outbound] = legs[0]["tag"]

    domestic_legs = [render(entry) for entry in as_list(upstreams.get("domestic"))]
    add_race(direct_tag, domestic_legs)
    node_resolver = policy.get("node_dns_resolver")
    if isinstance(node_resolver, Mapping) and domestic_legs:
        bootstrap_tag = str(node_resolver.get("server") or "").strip()
        if bootstrap_tag:
            if any(server.get("tag") == bootstrap_tag for server in servers):
                raise ValueError(f"node_dns_resolver.server 与 DNS server tag 冲突: {bootstrap_tag}")
            servers.append({
                "type": "group",
                "tag": bootstrap_tag,
                "servers": [server["tag"] for server in domestic_legs],
            })
    detours = upstreams.get("proxy_detours") or {}
    if not isinstance(detours, Mapping):
        raise ValueError("dns_upstreams.proxy_detours 必须是 出站: 后缀 的映射")
    for outbound, suffix in detours.items():
        tag = str(outbound).strip()
        if outbound_tags is not None and tag not in outbound_tags:
            if tag not in optional_tags:
                raise ValueError(f"dns_upstreams.proxy_detours 指向不存在的出站: {tag}")
            continue
        add_race(
            tag,
            [render(entry, str(suffix or "").strip(), tag) for entry in as_list(upstreams.get("proxy"))],
        )
    # Rendered tags must be unique: the resolver a dns rule names is decided by
    # which tag the core kept, so a collision silently resolves traffic through
    # a different exit than it connects through (far-away CDN edge, or a
    # domestic answer used behind a proxy).  Two proxy_detours entries sharing a
    # suffix is the easy way to hit this, so it is reported by name.
    seen_tags: set[str] = set()
    for server in servers:
        server_tag = str(server.get("tag"))
        if server_tag in seen_tags:
            raise ValueError(
                f"dns_upstreams 生成了重复的 DNS server tag: {server_tag}"
                "（检查 proxy_detours 的后缀是否重复）"
            )
        seen_tags.add(server_tag)
    return DnsLayout(
        servers=servers,
        failover=failover,
        by_outbound=by_outbound,
        proxy=by_outbound.get(available_tag),
        timeout=str(upstreams.get("timeout") or "2s"),
    )


ROUTE_ACTION_FIELDS = {"action", "outbound", "method", "no_drop", "dns"}
DNS_DOMAIN_FIELDS = {"domain", "domain_suffix", "domain_keyword", "domain_regex", "rule_set"}
DNS_MATCHER_FIELDS = DNS_DOMAIN_FIELDS | PROCESS_RULE_KEYS | PACKAGE_RULE_KEYS | {"invert", "type", "mode", "rules"}


def _matcher_fields(rule: Mapping[str, Any]) -> set[str]:
    fields = set(rule)
    for child in as_list(rule.get("rules")):
        if isinstance(child, Mapping):
            fields |= _matcher_fields(child)
    return fields


def derive_dns_rules(rules: Sequence[Mapping[str, Any]], layout: DnsLayout) -> list[dict[str, Any]]:
    """Pair every domain route rule with the DNS rule for the same egress.

    ``route`` resolves through the resolver detoured via the same outbound
    (direct -> domestic, AI -> google-ai, ...), falling back to the Available
    resolver; ``reject`` answers NXDOMAIN. Package and process rules are
    included, since they claim every connection from that app. A rule's
    ``dns`` key overrides the resolver, and ``dns: false`` opts out.
    """
    if not layout.servers:
        return []
    derived: list[dict[str, Any]] = []
    for rule in rules:
        override = rule.get("dns")
        if override is False:
            continue
        matcher = {key: copy.deepcopy(value) for key, value in rule.items() if key not in ROUTE_ACTION_FIELDS}
        fields = _matcher_fields(matcher)
        # Package and process rules carry no domain, but they still claim the
        # whole connection. Their DNS has to leave through the same outbound,
        # otherwise a pinned group resolves via Available and connects elsewhere.
        if override is None and not fields & (DNS_DOMAIN_FIELDS | PROCESS_RULE_KEYS | PACKAGE_RULE_KEYS):
            continue
        unsupported = sorted(fields - DNS_MATCHER_FIELDS)
        if unsupported:
            raise ValueError(f"路由规则含 DNS 不支持的匹配字段 {', '.join(unsupported)}，请设置 dns: false: {dict(rule)}")
        action = str(rule.get("action") or "route")
        if override is None and action == "reject":
            derived.append({**matcher, "action": "predefined", "rcode": "NXDOMAIN"})
            continue
        if override is None and action != "route":
            continue
        server = str(override).strip() if override is not None else (
            layout.by_outbound.get(str(rule.get("outbound") or "")) or layout.proxy
        )
        if server:
            derived.append({**matcher, "action": "route", "server": server})
    return derived


def _direct_dns_pins(layout: DnsLayout, direct_tag: str) -> list[dict[str, Any]]:
    """Route undetoured DoH server IPs straight out, before sniff can reclassify them.

    These servers have no ``detour``, so the connection is an ordinary route
    lookup.  Until ``geoip-cn`` is downloaded, ``route.final`` would send it
    through Available, and a domain node then waits on the resolver that is
    waiting on that node.  Matching the IP before sniff also keeps the TLS SNI
    (``dns.alidns.com`` / ``doh.pub``) from falling into a later domain rule.
    """
    by_port: dict[int, list[str]] = {}
    for server in layout.servers:
        if server.get("detour"):
            continue
        address = str(server.get("server") or "")
        if not _is_ip_address(address):
            continue
        port = int(server.get("server_port") or 443)
        by_port.setdefault(port, []).append(normalize_ip_cidr(address))
    return [
        {"port": port, "ip_cidr": list(dict.fromkeys(cidrs)), "action": "route", "outbound": direct_tag}
        for port, cidrs in by_port.items()
    ]


def _insert_direct_dns_pins(rules: list[dict[str, Any]], pins: Sequence[Mapping[str, Any]]) -> None:
    if not pins:
        return
    insert_at = 0
    for index, rule in enumerate(rules):
        if rule.get("action") == "hijack-dns" and rule.get("port") in (53, [53]):
            insert_at = index + 1
            break
        if rule.get("action") == "sniff":
            insert_at = index
            break
    rules[insert_at:insert_at] = [dict(pin) for pin in pins]


def _append_domestic_answer_rule_set(conf: dict[str, Any], prefixes: Sequence[str]) -> None:
    if not prefixes:
        return
    rule_sets = conf.setdefault("route", {}).setdefault("rule_set", [])
    if not isinstance(rule_sets, list):
        raise ValueError("route.rule_set 必须是数组")
    tags: set[str] = set()
    for item in rule_sets:
        if isinstance(item, dict):
            tags.update(rule_set_tags(item))
    if DOMESTIC_ANSWER_RULE_SET in tags:
        raise ValueError(f"规则集 tag 与 DNS 黑洞过滤冲突: {DOMESTIC_ANSWER_RULE_SET}")
    rule_sets.append({
        "type": "inline",
        "tag": DOMESTIC_ANSWER_RULE_SET,
        "rules": [{"ip_cidr": list(prefixes), "invert": True}],
    })


def _dns_race_settings(policy: Mapping[str, Any], layout: DnsLayout) -> dict[str, Any]:
    upstreams = policy.get("dns_upstreams")
    upstreams = upstreams if isinstance(upstreams, Mapping) else {}
    settings: dict[str, Any] = {
        "timeout": layout.timeout,
        "servers": layout.failover,
        # Client-supplied ECS would override the source address the resolver
        # actually sees: a Chinese prefix on a proxied query pulls a domestic
        # CDN edge, and a stale prefix on a direct query pulls the wrong city.
        "remove_client_subnet": True,
    }
    raw_ttl = upstreams.get("proxy_rewrite_ttl")
    if raw_ttl not in (None, "", False):
        try:
            ttl = int(raw_ttl)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"dns_upstreams.proxy_rewrite_ttl 必须是秒数: {raw_ttl}") from exc
        if ttl <= 0:
            raise ValueError(f"dns_upstreams.proxy_rewrite_ttl 必须是正数: {raw_ttl}")
        settings["rewrite_ttl"] = {
            str(server.get("tag")): ttl
            for server in layout.servers
            if server.get("detour") and server.get("tag") in layout.failover
        }
    reject_prefixes = _network_prefixes(upstreams.get("domestic_reject_answers"), "domestic_reject_answers")
    if reject_prefixes:
        settings["reject_answers"] = {
            str(server.get("tag")): reject_prefixes
            for server in layout.servers
            if not server.get("detour") and server.get("tag") in layout.failover
        }
    return settings


def assemble_rules(
    conf: dict[str, Any],
    policy: Mapping[str, Any],
    profile: Mapping[str, Any],
    custom: Mapping[str, Any],
    routing_groups: Mapping[str, Any] | None = None,
    layout: DnsLayout | None = None,
) -> None:
    platform = str(profile.get("platform") or "")
    for legacy in ("dns_rules", "dns_rules_front"):
        if legacy in profile:
            raise ValueError(f"profile 不再支持 {legacy}：DNS 规则由 route 规则自动推导，需要覆盖时在规则上写 dns")
    layout = layout or build_dns_layout(policy)
    route_policy = policy.get("route", {})
    profile_front = filtered_rules(profile.get("route_rules_front"), platform)
    pre_rules = filtered_rules(route_policy.get("pre_rules"), platform)
    managed_rules = build_managed_rules(routing_groups)
    profile_rules = filtered_rules(profile.get("route_rules"), platform)
    business_rules = filtered_rules(route_policy.get("business_rules"), platform)
    domestic_rules = filtered_rules(route_policy.get("domestic_rules"), platform)
    route_rules = [
        *filtered_rules(custom.get("route_rules_front"), platform),
        *profile_front,
        *pre_rules,
        *managed_rules,
        *filtered_rules(custom.get("route_rules"), platform),
        *profile_rules,
        *business_rules,
        *domestic_rules,
    ]
    route_out: list[dict[str, Any]] = [
        {key: value for key, value in rule.items() if key != "dns"} for rule in route_rules
    ]
    selectors = policy.get("selectors") if isinstance(policy.get("selectors"), Mapping) else {}
    direct_tag = str((selectors or {}).get("direct") or "direct")
    _insert_direct_dns_pins(route_out, _direct_dns_pins(layout, direct_tag))
    conf.setdefault("route", {})["rules"] = route_out
    dns_rules = [
        *derive_dns_rules(profile_front, layout),
        *derive_dns_rules(pre_rules, layout),
        *derive_dns_rules(managed_rules, layout),
        # custom-rules.yaml keeps its explicit DNS rules.
        *filtered_rules(custom.get("dns_rules"), platform),
        *derive_dns_rules(profile_rules, layout),
        *derive_dns_rules(business_rules, layout),
        *derive_dns_rules(domestic_rules, layout),
    ]
    # Unmatched queries race through dns.final's resolvers instead of falling
    # through to a single server.
    final = str(conf.get("dns", {}).get("final") or "")
    if final in layout.failover:
        dns_rules.append({"action": "route", "server": final})
    race_settings = _dns_race_settings(policy, layout)
    reject_answers = race_settings.get("reject_answers") if isinstance(race_settings.get("reject_answers"), Mapping) else {}
    reject_prefixes: list[str] = []
    for prefixes in reject_answers.values():
        reject_prefixes = list(prefixes)
        break
    _append_domestic_answer_rule_set(conf, reject_prefixes)
    conf.setdefault("dns", {})["rules"] = expand_dns_failover_rules(dns_rules, race_settings)


def build_config(
    target: str,
    policy: Mapping[str, Any],
    profile: Mapping[str, Any],
    custom: Mapping[str, Any],
    sources: Sequence[BuiltSource],
    routing_groups: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    conf = deep_merge(policy.get("config", {}), profile.get("config", {}))
    enabled_providers = bool_value((policy.get("providers") or {}).get("enabled"), False)
    # A grouped subscription already has a stable selector entry. Referencing
    # its Provider from Available would flatten every remote node into the
    # top-level list and defeat that grouping. Providers are therefore exposed
    # to Available only for sources whose nodes are standalone entries.
    providers = [source.provider for source in sources if source.provider] if enabled_providers else []
    providers = copy.deepcopy(providers)
    if providers:
        bootstrap = provider_bootstrap(sources, policy)
        for provider in providers:
            client = provider.setdefault("http_client", {})
            # Subscription downloads cannot use Available while its providers
            # are still loading. The standalone outbound has no such dependency.
            client["detour"] = bootstrap
    available_providers = [
        source.provider for source in sources
        if enabled_providers and source.provider and not source.groups
    ]
    conf["outbounds"] = build_outbounds(sources, policy, profile, routing_groups, available_providers)
    if providers:
        conf["providers"] = copy.deepcopy(providers)
    conf.setdefault("route", {})["rule_set"] = build_rule_sets(policy, profile, custom)
    outbound_tags = {
        str(outbound.get("tag"))
        for outbound in conf["outbounds"]
        if isinstance(outbound, dict) and outbound.get("tag")
    }
    layout = build_dns_layout(policy, outbound_tags)
    dns = conf.setdefault("dns", {})
    dns["servers"] = [*copy.deepcopy(layout.servers), *as_list(dns.get("servers"))]
    assemble_rules(conf, policy, profile, custom, routing_groups, layout)
    require_valid_config(
        conf,
        {
            "allow_duplicate_nodes": any(source.allows_duplicate_nodes for source in sources),
            "platform": target,
        },
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

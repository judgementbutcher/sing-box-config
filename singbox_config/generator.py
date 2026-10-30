#!/usr/bin/env python3
"""从 config/policy.yaml 和本机订阅生成桌面/安卓的 sing-box 配置。

policy.yaml 的 config 一节原样成为最终配置；这里只负责三件事：
按平台过滤带 only 的条目、用订阅生成 outbounds、补全引用到的规则集。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import requests
import yaml

from parsers import parse_subscription_text
from parsers.common import detect_region, is_info_node
from singbox_config.io_utils import atomic_write_json, atomic_write_text, parse_duration_seconds
from singbox_config.errors import InputError, OperationError, parse_error_summary, safe_error_message
from singbox_config.manifest import contained_path, read_manifest
from singbox_config import rule_sets as snapshot_rules


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "policy.yaml"
SUBSCRIPTIONS = ROOT / "config" / "local" / "subscriptions.yaml"
RULE_SETS = ROOT / "config" / "rule-sets"
CACHE_DIR = ROOT / "runtime" / "subscription-cache"
PLATFORMS = ("desktop", "android")
SUBSCRIPTION_KEYS = {
    "name", "path", "enabled", "user_agent", "exclude",
    "allow_insecure", "use_hosts", "ai", "ai_include", "ai_allow_insecure",
}


class SubscriptionRejected(Exception):
    """下载到了内容，但它不是一份订阅。"""


@dataclass
class Source:
    name: str
    nodes: list[dict[str, Any]]
    ai: list[str]  # 可以进 AI 分组的节点 tag
    info: list[str] = field(default_factory=list)  # "剩余流量""套餐到期"等信息条目


def log(message: str) -> None:
    print(message, file=sys.stderr)


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise InputError(f"{path.name}: {safe_error_message(exc)}") from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} 的顶层必须是对象")
    return data


# ---------------------------------------------------------------- 平台过滤

def for_platform(value: Any, platform: str) -> Any:
    """去掉不属于该平台的条目，并删掉 only 标记本身。"""
    if isinstance(value, dict):
        return {key: for_platform(item, platform) for key, item in value.items() if key != "only"}
    if isinstance(value, list):
        kept = []
        for item in value:
            only = item.get("only", platform) if isinstance(item, dict) else platform
            if only not in PLATFORMS:
                raise ValueError(f"only 只能是 {' / '.join(PLATFORMS)}，实际为 {only!r}")
            if only == platform:
                kept.append(for_platform(item, platform))
        return kept
    return value


# ---------------------------------------------------------------- 订阅读取

def download(url: str, timeout: int, user_agent: str, proxy: str | None = None) -> str:
    session = requests.Session()
    session.trust_env = False
    response = session.get(
        url,
        timeout=(min(timeout, 10), timeout),
        proxies={"http": proxy, "https": proxy} if proxy else None,
        headers={"User-Agent": user_agent},
    )
    response.raise_for_status()
    text = response.content.decode(response.encoding or "utf-8", errors="replace")
    if not text.strip():
        raise SubscriptionRejected("返回内容为空")
    if "<html" in text[:1024].lower():
        raise SubscriptionRejected("返回的是 HTML 页面")
    return text


_STAGED_CACHE: dict[Path, str] = {}
_FETCHED: dict[tuple[str, str], str] = {}


def subscription_cache_path(url: str, user_agent: str = "sing-box", *, cache_dir: Path | None = None) -> Path:
    """Cache identity includes the request representation, not just its URL."""
    identity = json.dumps([url, user_agent], ensure_ascii=False, separators=(",", ":"))
    return (CACHE_DIR if cache_dir is None else cache_dir) / (hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24] + ".txt")


def parse_subscription(text: str):
    try:
        return parse_subscription_text(detect_format(text), text)
    except Exception as exc:
        raise InputError(f"订阅内容解析失败（{parse_error_summary(exc)}）；原始内容未输出。") from None


def commit_staged_cache() -> None:
    """在所有生成与验证完成后调用，原子提交下载成功的订阅缓存。"""
    for cache_path, text in list(_STAGED_CACHE.items()):
        atomic_write_text(cache_path, text)
    _STAGED_CACHE.clear()


def stage_staged_cache(directory: Path) -> list[str]:
    """Write downloaded cache candidates to a build directory.

    The manager commits this directory only after every target configuration has
    passed the core check.  Keeping the candidate outside ``CACHE_DIR`` means a
    failed build cannot replace the last-good subscription input.
    """
    directory.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    for cache_path, text in list(_STAGED_CACHE.items()):
        target = directory / cache_path.name
        atomic_write_text(target, text)
        names.append(target.name)
    _STAGED_CACHE.clear()
    return names


def subscription_text(
    item: Mapping[str, Any], base: Path, settings: Mapping[str, Any], offline: bool
) -> str:
    """文件里只有一行 http(s) 地址就当作订阅链接下载，否则文件本身就是订阅内容。"""
    name = item["name"]
    text = contained_path(base, str(item["path"])).read_text(encoding="utf-8-sig")
    url = text.strip()
    if not re.fullmatch(r"https?://\S+", url):
        return text
    user_agent = str(item.get("user_agent") or "sing-box")
    cache = subscription_cache_path(url, user_agent)
    fetch_key = (url, user_agent)
    if fetch_key in _FETCHED:
        return _FETCHED[fetch_key]
    if not offline:
        timeout = int(settings.get("timeout_seconds") or 20)
        failures = []
        # 先直连，失败后经本机代理再试。
        for proxy in dict.fromkeys([None, settings.get("retry_proxy") or None]):
            try:
                text = download(url, timeout, user_agent, proxy)
            except (requests.RequestException, SubscriptionRejected) as exc:
                # 不打印异常原文：requests 的报错里带着完整订阅链接。
                if isinstance(exc, SubscriptionRejected):
                    reason = str(exc)
                elif isinstance(exc, requests.HTTPError):
                    reason = f"HTTP {exc.response.status_code}"
                else:
                    reason = type(exc).__name__
                failures.append(f"{'经代理' if proxy else '直连'} {reason}")
                continue
            try:
                test_nodes, _, _ = parse_subscription(text)
                if not test_nodes:
                    raise SubscriptionRejected("下载内容未解析出任何有效节点")
            except Exception as exc:
                failures.append(f"{'经代理' if proxy else '直连'} 内容无效（{parse_error_summary(exc)}）")
                continue
            # 先暂存到内存，不立刻覆写已有的持久化 last-good 缓存。
            _STAGED_CACHE[cache] = text
            _FETCHED[fetch_key] = text
            return text
        log(f"[订阅] {name}: 下载失败（{'，'.join(failures)}），尝试使用缓存。")
    max_age = settings.get("cache_max_age") or "3d"
    if cache.exists() and time.time() - cache.stat().st_mtime <= parse_duration_seconds(max_age):
        log(f"[订阅] {name}: 使用 {max_age} 以内的已缓存内容。")
        return cache.read_text(encoding="utf-8")
    legacy_cache = CACHE_DIR / (hashlib.sha256(url.encode("utf-8")).hexdigest()[:24] + ".txt")
    if not cache.exists() and legacy_cache.exists():
        raise OperationError(f"{name}: 旧缓存缺少 User-Agent 身份，不能安全复用；请先完成一次在线更新。")
    raise OperationError(f"{name}: 订阅下载失败，也没有 {max_age} 以内的缓存")


def detect_format(text: str) -> str:
    if text.lstrip().startswith("{") and '"outbounds"' in text:
        return "sing-box"
    if re.search(r"(?m)^\s*\"?proxies\"?\s*:", text):
        return "clash"
    return "uri"


def is_placeholder(node: Mapping[str, Any]) -> bool:
    """指向本机或端口无效的假节点（机场用来放"官网"之类的说明）。"""
    server = str(node.get("server") or "").strip().lower()
    has_ports = bool(node.get("server_ports"))
    try:
        port = int(node.get("server_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not has_ports and port <= 1:
        return True
    if not server or server in {"localhost", "dont.use.this.node"}:
        return True
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def is_insecure(node: Mapping[str, Any]) -> bool:
    tls = node.get("tls")
    return isinstance(tls, dict) and tls.get("insecure") is True


def fingerprint(node: Mapping[str, Any]) -> str:
    body = {key: value for key, value in node.items() if key != "tag"}
    payload = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def clash_hosts(text: str) -> dict[str, str]:
    """Clash 订阅自带的 hosts 表：域名 → 域名或 IP。"""
    data = yaml.safe_load(text)
    table = {}
    for key, value in ((data or {}).get("hosts") or {}).items():
        target = next((str(v) for v in (value if isinstance(value, list) else [value]) if v), "")
        if target:
            table[str(key).strip().rstrip(".").lower()] = target.strip().rstrip(".")
    return table


def apply_hosts(server: str, hosts: Mapping[str, str]) -> str:
    seen = set()
    while server.lower() in hosts and server.lower() not in seen:
        seen.add(server.lower())
        server = hosts[server.lower()]
    return server


def subscription_nodes(
    item: Mapping[str, Any], base: Path, settings: Mapping[str, Any], offline: bool
) -> tuple[list[dict[str, Any]], list[str]]:
    """读取一条订阅，返回清理过的节点（tag 为订阅里的原始名称）和信息条目的名称。"""
    name = item["name"]
    text = subscription_text(item, base, settings, offline)
    nodes, info, warnings = parse_subscription(text)
    if warnings:
        log(f"[订阅] {name}: {len(warnings)} 项无法解析或不受支持，已跳过；原始节点内容未输出。")
    try:
        hosts = clash_hosts(text) if item.get("use_hosts") else {}
    except Exception as exc:
        raise InputError(f"{name}: hosts 解析失败（{parse_error_summary(exc)}）；原始内容未输出。") from None
    exclude = [re.compile(str(pattern), re.IGNORECASE) for pattern in item.get("exclude") or []]
    result, notes = [], []
    for raw in [*nodes, *info]:
        original = str(raw.get("_meta_name") or raw.get("tag") or "").strip()
        if any(pattern.search(original) for pattern in exclude):
            continue
        # 流量、到期时间这类信息条目只留名字，在面板里显示，不当节点用。
        if is_info_node(original):
            notes.append(original)
            continue
        if is_placeholder(raw):
            continue
        # 订阅里的 domain_resolver 指向它自己的 DNS 服务器，这里没有；
        # 节点域名统一由 route.default_domain_resolver 解析。
        node = {
            key: value for key, value in raw.items()
            if not key.startswith("_meta_") and key != "domain_resolver"
        }
        node["tag"] = original
        if is_insecure(node) and not item.get("allow_insecure"):
            raise ValueError(
                f"{name}: 节点 {original!r} 关闭了 TLS 证书校验；"
                "确认要用的话，给这条订阅加上 allow_insecure: true"
            )
        if hosts:
            node["server"] = apply_hosts(str(node["server"]), hosts)
        result.append(node)
    if not result:
        raise ValueError(f"{name}: 订阅里没有可用节点")
    return result, notes


def unique_tag(tag: str, name: str, used: set[str]) -> str:
    candidate, count = tag, 1
    while candidate in used:
        candidate = f"{tag} [{name}]" if count == 1 else f"{tag} [{name} {count}]"
        count += 1
    return candidate


def load_sources(
    manifest_path: Path, policy: Mapping[str, Any], *, offline: bool = False
) -> list[Source]:
    """按清单顺序读取全部订阅：去重、保证 tag 唯一、挑出 AI 可用节点。"""
    _STAGED_CACHE.clear()
    _FETCHED.clear()
    items = [
        item for item in read_manifest(manifest_path, policy)["subscriptions"]
        if item.get("enabled", True)
    ]
    if not items:
        raise ValueError("没有启用的订阅")
    for item in items:
        unknown = sorted(set(item) - SUBSCRIPTION_KEYS)
        if unknown or not item.get("name") or not item.get("path"):
            raise ValueError(
                f"订阅 {item.get('name')!r} 的写法不对：必须有 name 和 path"
                + (f"，不认识的字段 {', '.join(unknown)}" if unknown else "")
            )
    names = [str(item["name"]) for item in items]
    if len(set(names)) != len(names):
        raise ValueError("订阅 name 不能重复")
    groups = policy.get("groups") or {}
    ai_regions = [str(region).upper() for region in groups.get("ai_regions") or []]
    used = {"Available", "AI", "Other", "direct", "block", *names}
    used.update(str(group["tag"]) for group in groups.get("services") or [])
    seen: dict[str, str] = {}
    sources = []
    for item, name in zip(items, names):
        ai_mode = item.get("ai", "auto")
        if ai_mode not in ("auto", True, False):
            raise ValueError(f"{name}: ai 只能是 auto / true / false")
        ai_include = [re.compile(str(p), re.IGNORECASE) for p in item.get("ai_include") or []]
        ai_allow_insecure = set(item.get("ai_allow_insecure") or [])
        nodes, notes = subscription_nodes(
            item, manifest_path.parent, policy.get("subscription") or {}, offline
        )
        source = Source(name, [], [])
        renames: dict[str, list[str]] = {}
        for node in nodes:
            original = node["tag"]
            digest = fingerprint(node)
            if digest in seen:
                renames.setdefault(original, []).append(seen[digest])
                log(f"[去重] {name}: {original} 与 {seen[digest]} 是同一个节点，已忽略。")
                continue
            # 只有一个节点、也没有信息条目的订阅不建分组，节点直接用订阅名。
            single = len(nodes) == 1 and not notes
            node["tag"] = name if single else unique_tag(original, name, used)
            used.add(node["tag"])
            seen[digest] = node["tag"]
            renames.setdefault(original, []).append(node["tag"])
            source.nodes.append(node)
            # 关闭校验的节点默认不进 AI；例外只匹配本来源的原始完整节点名。
            in_region = detect_region(node["tag"]) in ai_regions
            explicit_exception = original in ai_allow_insecure
            if ai_mode is not False and (in_region or explicit_exception or any(p.search(original) for p in ai_include)):
                if not is_insecure(node) or explicit_exception:
                    source.ai.append(node["tag"])
        for node in source.nodes:
            referenced = renames.get(node.get("detour"), [])
            if len(set(referenced)) > 1:
                raise ValueError(f"{name}: ambiguous detour reference")
            if referenced:
                node["detour"] = referenced[0]
        for note in dict.fromkeys(notes):
            source.info.append(unique_tag(note, name, used))
            used.add(source.info[-1])
        if source.nodes:
            sources.append(source)
    if not sources:
        raise ValueError("所有订阅都没有可用节点")
    return sources


# ---------------------------------------------------------------- 出站与分组

def selector(tag: str, members: Iterable[str]) -> dict[str, Any]:
    return {
        "type": "selector",
        "tag": tag,
        "outbounds": list(dict.fromkeys(members)),
        "interrupt_exist_connections": True,
    }


def transit_members(sources: Sequence[Source], candidates: Any) -> list[str]:
    """Select tested transit nodes by source and exact name, or by region."""
    if not isinstance(candidates, list):
        raise ValueError("前置 candidates 必须是列表")
    members = []
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) - {"source", "names", "regions"}:
            raise ValueError("前置候选只能包含 source / names / regions")
        if not isinstance(candidate.get("source"), str):
            raise ValueError("前置候选 source 必须是订阅名称")
        for key in ("names", "regions"):
            value = candidate.get(key, [])
            if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
                raise ValueError(f"前置候选 {key} 必须是字符串列表")
        names = set(candidate.get("names") or [])
        regions = {region.upper() for region in candidate.get("regions") or []}
        if not names and not regions:
            raise ValueError("前置候选必须指定 names 或 regions")
        for source in sources:
            if source.name != candidate["source"]:
                continue
            for node in source.nodes:
                if node["tag"] in names or detect_region(node["tag"]) in regions:
                    members.append(node["tag"])
    return list(dict.fromkeys(members))


def trusted_members(sources: Sequence[Source], candidates: Any, *, secure: bool = True) -> list[str]:
    """Resolve an explicit allowlist; never replace a missing trusted landing."""
    label = "受信" if secure else "指定"
    if not isinstance(candidates, list) or not candidates:
        raise ValueError(f"{label}候选必须是非空列表")
    members = []
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {"source", "names"}:
            raise ValueError(f"{label}候选必须只包含 source 和 names（完整节点名）")
        name, names = candidate["source"], candidate["names"]
        if (not isinstance(name, str) or not name.strip() or not isinstance(names, list)
                or not names or any(not isinstance(tag, str) or not tag.strip() for tag in names)):
            raise ValueError(f"{label}候选 source 必须是来源名称，names 必须是非空完整节点名列表")
        matching_sources = [source for source in sources if source.name == name]
        if len(matching_sources) != 1:
            raise ValueError(f"{label}来源缺失或不唯一: {name}")
        for tag in names:
            matches = [node for node in matching_sources[0].nodes if node["tag"] == tag]
            if len(matches) != 1:
                raise ValueError(f"{label}节点缺失或不唯一: {name} / {tag}；拒绝自动替换落地")
            node = matches[0]
            if (not node.get("server") or node.get("type") in {"direct", "block", "selector", "urltest"}
                    or (secure and is_insecure(node))):
                requirement = "证书校验正常的代理叶节点" if secure else "代理叶节点"
                raise ValueError(f"{label}节点必须是{requirement}: {tag}")
            members.append(tag)
    return list(dict.fromkeys(members))


def explicit_members(sources: Sequence[Source], members: Any) -> list[str]:
    """Ordered group references and exact source-scoped leaves; never expand airports."""
    if not isinstance(members, list) or not members:
        raise ValueError("显式 members 必须是非空列表")
    result = []
    for member in members:
        if isinstance(member, str) and member.strip():
            result.append(member)
        elif isinstance(member, dict):
            result.extend(trusted_members(sources, [member], secure=False))
        else:
            raise ValueError("members 只能包含分组名或 source/names 精确节点")
    return list(dict.fromkeys(result))


def validate_outbound_graph(outbounds: Sequence[Mapping[str, Any]]) -> None:
    lookup = {item["tag"]: item for item in outbounds}
    if len(lookup) != len(outbounds):
        raise ValueError("重复的出站 tag")
    done, visiting = set(), set()

    def visit(tag):
        if tag not in lookup:
            raise ValueError(f"出站引用不存在: {tag}")
        if tag in visiting:
            raise ValueError(f"出站 detour/分组循环: {tag}")
        if tag in done:
            return
        visiting.add(tag)
        node = lookup[tag]
        for dependency in [*node.get("outbounds", []), *([node["detour"]] if node.get("detour") else [])]:
            visit(dependency)
        visiting.remove(tag)
        done.add(tag)

    for tag in lookup:
        visit(tag)


def build_outbounds(sources: Sequence[Source], groups: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Available → 各订阅 → 节点；AI、Other 与业务分组挂在旁边。"""
    regions = [str(region).upper() for region in groups.get("ai_regions") or []]

    def region_priority(tag: str) -> int:
        region = detect_region(tag)
        return regions.index(region) if region in regions else len(regions)

    entries = [source.name for source in sources]
    nodes = [node for source in sources for node in source.nodes]
    # Other 收纳识别不出地区的节点，挂在 Available 下供手动选用。
    other = [node["tag"] for node in nodes if detect_region(node["tag"]) == "Others"]
    extra = ["Other"] if other else []
    ai = sorted((tag for source in sources for tag in source.ai), key=region_priority)
    if not ai:
        raise ValueError("AI 分组未筛选出任何可用节点，请检查订阅地区配置与证书有效性")

    outbounds = [
        selector("Available", entries + extra),
        selector("AI", ai),
        {"type": "direct", "tag": "direct"},
    ]
    if other:
        outbounds.append(selector("Other", other))
    for group in groups.get("services") or []:
        direct = group.get("direct")
        if direct not in (None, "first", "last"):
            raise ValueError(f"分组 {group['tag']} 的 direct 只能是 first 或 last")
        expand = group.get("expand")
        if expand not in (None, True, False):
            raise ValueError(f"分组 {group['tag']} 的 expand 只能是 true 或 false")
        filter_type = group.get("filter")
        include = group.get("include")

        if "members" in group:
            if (group.get("type", "selector") != "selector" or
                    {"filter", "outbounds", "include", "expand", "direct", "include_direct", "candidates"} & group.keys()):
                raise ValueError("显式 members 分组只能是手动选择器，不能混用其他成员来源")
            members = explicit_members(sources, group["members"])
        elif filter_type == "trusted":
            forbidden = {"outbounds", "include", "expand", "direct", "include_direct"} & group.keys()
            if group.get("type", "selector") != "selector" or forbidden:
                raise ValueError("受信分组必须是手动选择器，且不能混入其他成员或直连")
            members = trusted_members(sources, group.get("candidates"))
        elif "outbounds" in group:
            members = group["outbounds"]
            if (group.get("type", "selector") != "selector" or not isinstance(members, list)
                    or not members or any(not isinstance(member, str) or not member for member in members)):
                raise ValueError(f"分组 {group['tag']} 的 outbounds 必须是手动选择器的非空字符串列表")
            members = list(members)
        elif filter_type == "aether_transit" and "candidates" in group:
            if not isinstance(group.get("include_direct", False), bool):
                raise ValueError("前置 include_direct 必须是 true 或 false")
            members = transit_members(sources, group["candidates"])
            if not members:
                raise ValueError(f"前置分组 {group['tag']} 没有候选节点")
            if group.get("include_direct", False):
                members.append("direct")
        elif filter_type == "aether_transit":
            hk02 = []
            transit_others = []
            for node in nodes:
                t = node["tag"]
                if "Hong Kong | 02" in t:
                    hk02.append(t)
                elif any(k in t for k in ["Hong Kong", "Taiwan", "Japan"]):
                    transit_others.append(t)
            if not hk02 and not transit_others:
                for node in nodes:
                    t = node["tag"]
                    if detect_region(t) in ("HK", "TW", "JP"):
                        transit_others.append(t)
            members = list(dict.fromkeys(hk02 + transit_others + ["direct"]))
        elif include:
            members = [*include, "Available", *entries]
            if other:
                members.append("Other")
        elif expand:
            members = ["Available", *entries, *extra]
        else:
            members = ["Available", *entries]

        if direct == "first":
            members.insert(0, "direct")
        elif direct == "last":
            members.append("direct")
        kind = group.get("type", "selector")
        if "default" in group and (kind != "selector" or not isinstance(group["default"], str)
                                   or group["default"] not in members):
            raise ValueError(f"分组 {group['tag']} 的 default 必须是手动选择器的已有成员")
        if kind == "urltest" or filter_type == "aether_transit":
            lookup = {node["tag"]: node for node in nodes}
            for member in members:
                dependency, visited = member, set()
                while dependency in lookup:
                    if dependency in visited:
                        raise ValueError(f"前置候选 {member} 存在 detour 循环")
                    visited.add(dependency)
                    dependency = lookup[dependency].get("detour")
                    if dependency == group["tag"]:
                        raise ValueError(f"前置候选 {member} 依赖自身分组")
        if kind == "urltest":
            if not members:
                raise ValueError(f"自动分组 {group['tag']} 没有候选节点")
            interrupt = group.get("interrupt_exist_connections", False)
            if not isinstance(interrupt, bool):
                raise ValueError(f"自动分组 {group['tag']} 的 interrupt_exist_connections 必须是 true 或 false")
            outbounds.append({
                "type": "urltest", "tag": str(group["tag"]),
                "outbounds": list(dict.fromkeys(members)),
                "url": group.get("url", "https://www.gstatic.com/generate_204"),
                "interval": group.get("interval", "3m"),
                "tolerance": group.get("tolerance", 50),
                "idle_timeout": group.get("idle_timeout", "30m"),
                "interrupt_exist_connections": interrupt,
            })
        elif kind == "selector":
            selected = selector(str(group["tag"]), members)
            if "default" in group:
                selected["default"] = group["default"]
            outbounds.append(selected)
        else:
            raise ValueError(f"分组 {group['tag']} 的 type 只能是 selector 或 urltest")
    for source in sources:
        # 信息条目排在分组末尾：第一个成员是分组的默认值，必须是真节点。
        tags = [node["tag"] for node in source.nodes] + source.info
        if tags != [source.name]:
            outbounds.append(selector(source.name, tags))
    # 信息条目是 block 出站：只为在面板里看到名字，误选了也只是连不上。
    notes = [{"type": "block", "tag": tag} for source in sources for tag in source.info]
    has_block = any("block" in item.get("outbounds", []) for item in outbounds if item.get("type") == "selector")
    block_nodes = [{"type": "block", "tag": "block"}] if has_block and not any(item["tag"] == "block" for item in outbounds) else []
    return outbounds + nodes + notes + block_nodes


# ---------------------------------------------------------------- 规则集

def referenced_rule_sets(rules: Iterable[Mapping[str, Any]]) -> list[str]:
    tags: list[str] = []
    for rule in rules:
        value = rule.get("rule_set") or []
        tags.extend([value] if isinstance(value, str) else value)
        tags.extend(referenced_rule_sets(rule.get("rules") or []))
    return tags


def build_rule_sets(
    config: Mapping[str, Any], urls: Mapping[str, str], directory: Path = RULE_SETS
) -> list[dict[str, Any]]:
    """Collect local inline rules and remote definitions; generate() seals the latter."""
    rules = [*config["dns"].get("rules", []), *config["route"].get("rules", [])]
    rule_sets = []
    for tag in dict.fromkeys(referenced_rule_sets(rules)):
        path = directory / f"{tag}.txt"
        url = urls.get(tag.split("-", 1)[0])
        if path.exists():
            lines = (line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines())
            suffixes = [line for line in lines if line]
            if not suffixes:
                raise ValueError(f"{path} 是空名单")
            rule_sets.append({"type": "inline", "tag": tag, "rules": [{"domain_suffix": suffixes}]})
        elif url:
            rule_sets.append({"type": "remote", "tag": tag, "url": url.format(tag=tag)})
        else:
            raise ValueError(f"规则集 {tag}: 找不到 {path}，rule_set_urls 里也没有对应的地址")
    return rule_sets


# ---------------------------------------------------------------- 组装

def build_config(platform: str, policy: Mapping[str, Any], sources: Sequence[Source],
                 *, rule_sets: Path = RULE_SETS) -> dict[str, Any]:
    """Assemble definitions; generate() seals remote definitions before delivery."""
    scoped = for_platform(policy, platform)
    config = scoped["config"]
    config["outbounds"] = build_outbounds(sources, scoped.get("groups") or {})
    validate_outbound_graph(config["outbounds"])
    config["route"]["rule_set"] = build_rule_sets(config, scoped.get("rule_set_urls") or {}, rule_sets)
    return config


def generate(
    platforms: Sequence[str],
    *,
    policy_path: Path = POLICY,
    manifest_path: Path = SUBSCRIPTIONS,
    offline: bool = False,
    rule_sets: Path = RULE_SETS,
    core: Path | None = None,
    core_info: Mapping[str, str] | None = None,
    rule_snapshot_dir: Path | None = None,
    rule_snapshot_source: Path | None = None,
) -> dict[str, dict[str, Any]]:
    policy = load_yaml(policy_path)
    sources = load_sources(manifest_path, policy, offline=offline)
    configs = {platform: build_config(platform, policy, sources, rule_sets=rule_sets) for platform in platforms}
    options = dict(core=core, identity=core_info, offline=offline, previous=rule_snapshot_source,
                   proxy=policy.get("subscription", {}).get("retry_proxy"),
                   timeout=policy.get("subscription", {}).get("timeout_seconds", 20))
    if rule_snapshot_dir is not None:
        return snapshot_rules.materialize(configs, directory=rule_snapshot_dir, **options)
    if not snapshot_rules.remote_definitions(configs):
        return configs
    scratch = (ROOT / "runtime").resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="singbox-rule-snapshot-", dir=scratch) as folder:
        if Path(folder).resolve().parent != scratch:
            raise ValueError("Unexpected rule-set snapshot scratch location")
        return snapshot_rules.materialize(configs, directory=Path(folder) / "snapshot", **options)


def main(argv: Sequence[str] | None = None) -> int:
    global CACHE_DIR
    parser = argparse.ArgumentParser(description="生成 sing-box 配置")
    parser.add_argument("target", choices=[*PLATFORMS, "all"])
    parser.add_argument("--output-dir", type=Path, default=ROOT / "runtime" / "drafts")
    parser.add_argument("--offline", action="store_true", help="不下载订阅或规则，复用已校验的版本缓存")
    parser.add_argument("--core", type=Path, help="固定版本 CLI 核心，用于解析 SRS")
    parser.add_argument("--rule-snapshot-source", type=Path, help="离线时使用的已校验规则快照")
    parser.add_argument(
        "--cache-stage-dir",
        type=Path,
        help="将本次下载的订阅写入候选目录，等待外层校验成功后提交",
    )
    args = parser.parse_args(argv)
    platforms = PLATFORMS if args.target == "all" else (args.target,)
    try:
        previous = args.rule_snapshot_source
        from singbox_config.release_manager import active_release
        release = active_release(ROOT / "runtime")
        if release is not None:
            CACHE_DIR = release / "subscription-cache"
        if args.offline and previous is None:
            previous = release / "rule-set-snapshot" if release else None
        snapshot = args.output_dir / "rule-set-snapshots" / uuid.uuid4().hex
        configs = generate(platforms, offline=args.offline, core=args.core,
                           rule_snapshot_dir=snapshot, rule_snapshot_source=previous)
    except (OSError, ValueError, RuntimeError, KeyError, yaml.YAMLError) as exc:
        log(f"[错误] {safe_error_message(exc)}")
        return 1
    for platform, config in configs.items():
        atomic_write_text(args.output_dir / platform / "config.json",
                          json.dumps(config, ensure_ascii=False, separators=(",", ":")) + "\n")
        count = sum(1 for outbound in config["outbounds"] if "server" in outbound)
        print(f"[生成] {platform}: {count} 个节点")
    print(f"[规则快照] {snapshot}")
    if args.cache_stage_dir:
        stage_staged_cache(args.cache_stage_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

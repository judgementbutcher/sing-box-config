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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import requests
import yaml

from parsers import parse_subscription_text
from parsers.common import detect_region, is_info_node
from singbox_config.io_utils import atomic_write_json, atomic_write_text, parse_duration_seconds


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "policy.yaml"
SUBSCRIPTIONS = ROOT / "config" / "local" / "subscriptions.yaml"
RULE_SETS = ROOT / "config" / "rule-sets"
CACHE_DIR = ROOT / "runtime" / "subscription-cache"
PLATFORMS = ("desktop", "android")
SUBSCRIPTION_KEYS = {
    "name", "path", "enabled", "user_agent", "exclude",
    "allow_insecure", "use_hosts", "ai", "ai_include",
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
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
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


def subscription_text(
    item: Mapping[str, Any], base: Path, settings: Mapping[str, Any], offline: bool
) -> str:
    """文件里只有一行 http(s) 地址就当作订阅链接下载，否则文件本身就是订阅内容。"""
    name = item["name"]
    text = (base / str(item["path"])).read_text(encoding="utf-8-sig")
    url = text.strip()
    if not re.fullmatch(r"https?://\S+", url):
        return text
    cache = CACHE_DIR / (hashlib.sha256(url.encode("utf-8")).hexdigest()[:24] + ".txt")
    if not offline:
        timeout = int(settings.get("timeout_seconds") or 20)
        user_agent = str(item.get("user_agent") or "sing-box")
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
            atomic_write_text(cache, text)
            return text
        log(f"[订阅] {name}: 下载失败（{'，'.join(failures)}），尝试使用缓存。")
    max_age = settings.get("cache_max_age") or "3d"
    if cache.exists() and time.time() - cache.stat().st_mtime <= parse_duration_seconds(max_age):
        return cache.read_text(encoding="utf-8")
    raise RuntimeError(f"{name}: 订阅下载失败，也没有 {max_age} 以内的缓存")


def detect_format(text: str) -> str:
    if text.lstrip().startswith("{") and '"outbounds"' in text:
        return "sing-box"
    if re.search(r"(?m)^\s*\"?proxies\"?\s*:", text):
        return "clash"
    return "uri"


def is_placeholder(node: Mapping[str, Any]) -> bool:
    """指向本机或端口无效的假节点（机场用来放"官网"之类的说明）。"""
    server = str(node.get("server") or "").strip().lower()
    try:
        port = int(node.get("server_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if port <= 1 or not server or server in {"localhost", "dont.use.this.node"}:
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
    nodes, info, warnings = parse_subscription_text(detect_format(text), text)
    for warning in warnings:
        log(f"[订阅] {name}: {warning}")
    hosts = clash_hosts(text) if item.get("use_hosts") else {}
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
    items = [
        item for item in load_yaml(manifest_path).get("subscriptions") or []
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
    used = {"Available", "AI", "Other", "direct", *names}
    used.update(str(group["tag"]) for group in groups.get("services") or [])
    seen: dict[str, str] = {}
    sources = []
    for item, name in zip(items, names):
        ai_mode = item.get("ai", "auto")
        if ai_mode not in ("auto", True, False):
            raise ValueError(f"{name}: ai 只能是 auto / true / false")
        ai_include = [re.compile(str(p), re.IGNORECASE) for p in item.get("ai_include") or []]
        nodes, notes = subscription_nodes(
            item, manifest_path.parent, policy.get("subscription") or {}, offline
        )
        source = Source(name, [], [])
        for node in nodes:
            original = node["tag"]
            digest = fingerprint(node)
            if digest in seen:
                log(f"[去重] {name}: {original} 与 {seen[digest]} 是同一个节点，已忽略。")
                continue
            # 只有一个节点、也没有信息条目的订阅不建分组，节点直接用订阅名。
            single = len(nodes) == 1 and not notes
            node["tag"] = name if single else unique_tag(original, name, used)
            used.add(node["tag"])
            seen[digest] = node["tag"]
            source.nodes.append(node)
            # ai: auto 不收关闭了证书校验的节点，ai: true 才收；地区门槛两者相同。
            in_region = detect_region(node["tag"]) in ai_regions
            if ai_mode is not False and (in_region or any(p.search(original) for p in ai_include)):
                if ai_mode is True or not is_insecure(node):
                    source.ai.append(node["tag"])
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


def build_outbounds(sources: Sequence[Source], groups: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Available → 各订阅 → 节点；AI、Other 与业务分组挂在旁边。"""
    regions = [str(region).upper() for region in groups.get("ai_regions") or []]

    def region_priority(tag: str) -> int:
        region = detect_region(tag)
        return regions.index(region) if region in regions else len(regions)

    entries = [source.name for source in sources]
    nodes = [node for source in sources for node in source.nodes]
    # Other 收纳识别不出地区的节点，挂在 Available 和 AI 下供手动选用；
    # 不进业务分组，免得一次误选把 YouTube/Telegram 交给没核对过地区的出口。
    other = [node["tag"] for node in nodes if detect_region(node["tag"]) == "Others"]
    extra = ["Other"] if other else []
    ai = sorted((tag for source in sources for tag in source.ai), key=region_priority)

    outbounds = [
        selector("Available", entries + extra),
        selector("AI", ai + extra or ["Available"]),
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
        # 默认引用 Available 选择器本身（跟随 Available 的当前选择）；
        # expand: true 则把 Available 展开成它的成员（各订阅分组与 Other），
        # 让组里直接列出可选的出口，而不是套一层 Available。
        members = [*entries, *extra] if expand else ["Available", *entries]
        if direct == "first":
            members.insert(0, "direct")
        elif direct == "last":
            members.append("direct")
        outbounds.append(selector(str(group["tag"]), members))
    for source in sources:
        # 信息条目排在分组末尾：第一个成员是分组的默认值，必须是真节点。
        tags = [node["tag"] for node in source.nodes] + source.info
        if tags != [source.name]:
            outbounds.append(selector(source.name, tags))
    # 信息条目是 block 出站：只为在面板里看到名字，误选了也只是连不上。
    notes = [{"type": "block", "tag": tag} for source in sources for tag in source.info]
    return outbounds + nodes + notes


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
    """规则引用了哪些规则集就生成哪些：本地名单内嵌，geosite-/geoip- 远程下载。"""
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

def build_config(platform: str, policy: Mapping[str, Any], sources: Sequence[Source]) -> dict[str, Any]:
    scoped = for_platform(policy, platform)
    config = scoped["config"]
    config["outbounds"] = build_outbounds(sources, scoped.get("groups") or {})
    config["route"]["rule_set"] = build_rule_sets(config, scoped.get("rule_set_urls") or {})
    return config


def generate(
    platforms: Sequence[str],
    *,
    policy_path: Path = POLICY,
    manifest_path: Path = SUBSCRIPTIONS,
    offline: bool = False,
) -> dict[str, dict[str, Any]]:
    policy = load_yaml(policy_path)
    sources = load_sources(manifest_path, policy, offline=offline)
    return {platform: build_config(platform, policy, sources) for platform in platforms}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 sing-box 配置")
    parser.add_argument("target", choices=[*PLATFORMS, "all"])
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--offline", action="store_true", help="不下载订阅，只用缓存")
    args = parser.parse_args(argv)
    platforms = PLATFORMS if args.target == "all" else (args.target,)
    try:
        configs = generate(platforms, offline=args.offline)
    except (OSError, ValueError, RuntimeError, KeyError, yaml.YAMLError) as exc:
        log(f"[错误] {exc}")
        return 1
    for platform, config in configs.items():
        atomic_write_json(args.output_dir / platform / "config.json", config)
        count = sum(1 for outbound in config["outbounds"] if "server" in outbound)
        print(f"[生成] {platform}: {count} 个节点")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

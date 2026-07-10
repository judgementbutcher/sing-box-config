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
            "core": {"version": "1.14.0-alpha.41"},
            "runtime": {"disable_provider_urltests": True},
            "auto": {"enabled": False},
            "control": {
                "max_nodes": 0,
                "dns_detour": "Available",
                "update_detour": "Available",
            },
            "tuning": {"tun_stack": "system", "tun_mtu": 1500},
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
                "tun_mtu": 1420,
                "udp_timeout": "2m",
                "rule_set_update_interval": "7d",
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
    *,
    default: str,
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
        outbounds.append(build_selector(tag, list(choices), default=default))
        return
    selector["outbounds"] = list(dict.fromkeys(choices))
    selector["default"] = default


def add_region_groups(conf: Dict[str, Any]) -> Dict[str, str]:
    """Expose one simple, top-level selector for every retained country."""

    outbounds = conf.setdefault("outbounds", [])
    existing_tags = {
        str(outbound.get("tag"))
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("tag")
    }
    groups: Dict[str, str] = {}
    for region in REQUIRED_REGIONS:
        node_tags = [
            str(outbound["tag"])
            for outbound in outbounds
            if isinstance(outbound, dict)
            and is_proxy_outbound(outbound)
            and outbound.get("tag")
            and detect_region(str(outbound["tag"])) == region
        ]
        if not node_tags:
            continue
        group_tag = f"地区/{REGION_LABELS[region]}"
        if group_tag in existing_tags:
            raise RuntimeError(f"地区分组名称与现有 outbound 冲突: {group_tag}")
        outbounds.append(build_selector(group_tag, node_tags, default=node_tags[0]))
        existing_tags.add(group_tag)
        groups[region] = group_tag

    return groups


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
    for item in subscriptions:
        kind = str(item.get("_simple_group_kind") or "airport")
        if kind not in source_tags:
            continue
        source_tags[kind].append(configured_group_tag(item, str(item["name"])))

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
                    selector["default"] = node_tags[0]
                    airport_groups.append(tag)
            else:
                self_node_tags.extend(node_tags)

    self_group = "自建"
    if self_node_tags:
        if self_group in selectors and self_group not in source_tags["self-hosted"]:
            raise RuntimeError(f"自建分组名称与现有 outbound 冲突: {self_group}")
        set_selector(conf, self_group, list(dict.fromkeys(self_node_tags)), default=self_node_tags[0])

    self_tags = set(source_tags["self-hosted"])
    if self_node_tags:
        rewrite_references(conf, {tag: self_group for tag in self_tags})

    region_groups = add_region_groups(conf)
    available_choices = airport_groups + ([self_group] if self_node_tags else [])
    if not available_choices:
        raise RuntimeError("没有可放入 Available 的机场或自建分组")
    set_selector(conf, "Available", available_choices, default=available_choices[0])

    us_nodes = [
        str(outbound["tag"])
        for outbound in conf.get("outbounds", [])
        if isinstance(outbound, dict)
        and is_proxy_outbound(outbound)
        and outbound.get("tag")
        and detect_region(str(outbound["tag"])) == "US"
    ]
    if not us_nodes:
        raise RequiredRegionsError("订阅中缺少美国节点，无法生成仅包含美国节点的 AI 分组")
    set_selector(conf, "AI", us_nodes, default=us_nodes[0])

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
    if len(region_groups) != len(REQUIRED_REGIONS):
        missing = [REGION_LABELS[region] for region in REQUIRED_REGIONS if region not in region_groups]
        raise RequiredRegionsError(f"订阅中缺少必需地区：{'、'.join(missing)}")


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
    require_valid_config(conf)
    region_counts = proxy_region_counts(conf)
    require_required_regions(region_counts)
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

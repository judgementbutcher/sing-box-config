#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import requests
except ImportError:
    print("请先安装 requests: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("请先安装 pyyaml: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

from parsers import parse_subscription_text
from parsers.common import AI_PREFERRED_REGIONS, ALL_REGIONS, HOT_REGIONS, detect_region


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


configure_stdio()


DEFAULT_MAX_NODES_PER_REGION = 0
DEFAULT_MAX_OTHER_NODES = 0
DEFAULT_SUBSCRIPTION_CACHE_DIR = ".subscription-cache"
DEFAULT_KEEP_INFO_NODES = False
HOME_NODE_KEYWORDS = ["家宽", "home", "residential"]
COUNTRY_CODE_RE = re.compile(r"\b([A-Z]{2})\b")
NON_PROXY_OUTBOUND_TYPES = {"selector", "urltest", "direct", "block", "dns"}
SUBSCRIPTION_USERINFO_HEADER = "Subscription-Userinfo"
PROFILE_HEADER_MAP = {
    "profile_update_interval": "Profile-Update-Interval",
    "profile_web_page_url": "Profile-Web-Page-Url",
    "support_url": "Support-Url",
    "profile_title": "Profile-Title",
}


@dataclass
class SubscriptionContent:
    text: str
    userinfo: Dict[str, Any]
    from_cache: bool = False


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_yaml(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_header_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except Exception:
        pass
    try:
        return int(float(text))
    except Exception:
        return None


def format_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    amount = float(max(value, 0))
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    if unit == "B":
        return f"{int(amount)} {unit}"
    return f"{amount:.2f} {unit}"


def format_expire_timestamp(expire: int) -> Dict[str, Any]:
    if expire <= 0:
        return {}
    utc_dt = datetime.fromtimestamp(expire, timezone.utc)
    local_dt = utc_dt.astimezone()
    now = datetime.now(timezone.utc)
    return {
        "expires_at": local_dt.isoformat(timespec="seconds"),
        "expires_at_utc": utc_dt.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at_display": local_dt.strftime("%Y-%m-%d %H:%M:%S %z"),
        "days_remaining": round((utc_dt - now).total_seconds() / 86400, 2),
    }


def parse_subscription_userinfo(header_value: Optional[str]) -> Dict[str, Any]:
    raw_header = str(header_value or "").strip()
    if not raw_header:
        return {}

    raw_fields: Dict[str, str] = {}
    numeric_fields: Dict[str, int] = {}
    for part in raw_header.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if not key:
            continue
        raw_fields[key] = value
        parsed_value = parse_header_int(value)
        if parsed_value is not None:
            numeric_fields[key] = parsed_value

    info: Dict[str, Any] = {
        "raw": raw_header,
        "fields": raw_fields,
    }
    for key in ("upload", "download", "total", "expire"):
        if key in numeric_fields:
            info[key] = numeric_fields[key]

    upload = info.get("upload")
    download = info.get("download")
    if upload is not None or download is not None:
        used = int(upload or 0) + int(download or 0)
        info["used"] = used
        info["used_human"] = format_bytes(used)

    for key in ("upload", "download", "total"):
        if key in info:
            info[f"{key}_human"] = format_bytes(int(info[key]))

    total = info.get("total")
    used = info.get("used")
    if total is not None and used is not None:
        remaining = max(int(total) - int(used), 0)
        info["remaining"] = remaining
        info["remaining_human"] = format_bytes(remaining)
        if int(total) > 0:
            info["used_percent"] = round(int(used) * 100 / int(total), 2)

    expire = info.get("expire")
    if expire is not None:
        info.update(format_expire_timestamp(int(expire)))

    return info


def subscription_metadata_from_headers(headers: Any) -> Dict[str, Any]:
    info = parse_subscription_userinfo(headers.get(SUBSCRIPTION_USERINFO_HEADER))
    for field_name, header_name in PROFILE_HEADER_MAP.items():
        value = headers.get(header_name)
        if value is None or str(value).strip() == "":
            continue
        if field_name == "profile_update_interval":
            parsed_value = parse_header_int(value)
            info[field_name] = parsed_value if parsed_value is not None else str(value).strip()
        else:
            info[field_name] = str(value).strip()
    return info


def subscription_request_headers(user_agent: Optional[str] = None) -> Dict[str, str]:
    return {
        "Accept": "text/yaml,text/plain,application/x-yaml,application/octet-stream,*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
        "User-Agent": user_agent or "clash-verge/v2.4.7",
    }


def fetch_subscription_content(
    url: str,
    timeout: int = 30,
    user_agent: Optional[str] = None,
    fetch_proxy: Optional[str] = None,
) -> SubscriptionContent:
    headers = subscription_request_headers(user_agent)
    proxies = {"http": fetch_proxy, "https": fetch_proxy} if fetch_proxy else None
    r = requests.get(url, headers=headers, timeout=timeout, proxies=proxies)
    r.raise_for_status()
    return SubscriptionContent(
        text=r.text,
        userinfo=subscription_metadata_from_headers(r.headers),
        from_cache=False,
    )


def fetch_text(
    url: str,
    timeout: int = 30,
    user_agent: Optional[str] = None,
    fetch_proxy: Optional[str] = None,
) -> str:
    content = fetch_subscription_content(
        url,
        timeout=timeout,
        user_agent=user_agent,
        fetch_proxy=fetch_proxy,
    )
    return content.text


def subscription_cache_path(cache_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    return cache_dir / f"{digest}.txt"


def subscription_cache_meta_path(cache_path: Path) -> Path:
    return cache_path.with_suffix(".json")


def read_cached_subscription_userinfo(cache_path: Path) -> Dict[str, Any]:
    meta_path = subscription_cache_meta_path(cache_path)
    try:
        if not meta_path.exists() or not meta_path.is_file():
            return {}
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        userinfo = data.get("subscription_userinfo")
        return userinfo if isinstance(userinfo, dict) else {}
    except Exception as e:
        print(f"[WARN] 读取订阅缓存元数据失败 {meta_path}: {e}", file=sys.stderr)
    return {}


def read_cached_subscription(cache_path: Path) -> Optional[SubscriptionContent]:
    try:
        if cache_path.exists() and cache_path.is_file():
            text = cache_path.read_text(encoding="utf-8")
            if text.strip():
                return SubscriptionContent(
                    text=text,
                    userinfo=read_cached_subscription_userinfo(cache_path),
                    from_cache=True,
                )
    except Exception as e:
        print(f"[WARN] 读取订阅缓存失败 {cache_path}: {e}", file=sys.stderr)
    return None


def write_cached_subscription(cache_path: Path, content: SubscriptionContent) -> None:
    if not content.text.strip():
        return
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(content.text, encoding="utf-8")
        meta_path = subscription_cache_meta_path(cache_path)
        meta_path.write_text(
            json.dumps(
                {"subscription_userinfo": content.userinfo or {}},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception as e:
        print(f"[WARN] 写入订阅缓存失败 {cache_path}: {e}", file=sys.stderr)


def fetch_text_with_cache(
    url: str,
    cache_dir: Optional[Path],
    label: str,
    user_agent: Optional[str] = None,
    fetch_proxy: Optional[str] = None,
) -> SubscriptionContent:
    cache_path = subscription_cache_path(cache_dir, url) if cache_dir else None
    try:
        content = fetch_subscription_content(url, user_agent=user_agent, fetch_proxy=fetch_proxy)
        if not content.text.strip():
            raise ValueError("订阅下载结果为空")
    except Exception as e:
        if cache_path:
            cached = read_cached_subscription(cache_path)
            if cached is not None:
                print(f"[WARN] {label}: 订阅下载失败，已使用本地缓存。错误类型: {type(e).__name__}", file=sys.stderr)
                return cached
        raise

    if cache_path:
        write_cached_subscription(cache_path, content)
    return content


def read_text(path: Path) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_subscription_url(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"订阅文件不存在: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"订阅文件为空: {path}")
    return text


def resolve_path(path: str, base_dir: Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return base_dir / p


def make_unique_tag(base_tag: str, used: Set[str]) -> str:
    clean_base = str(base_tag).strip() or "node"
    tag = clean_base
    i = 2
    while tag in used:
        tag = f"{clean_base} #{i}"
        i += 1
    used.add(tag)
    return tag


def build_selector(tag: str, outbounds: List[str], default: Optional[str] = None) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "type": "selector",
        "tag": tag,
        "outbounds": outbounds,
        "interrupt_exist_connections": False,
    }
    if default:
        obj["default"] = default
    return obj


def build_urltest(
    tag: str,
    outbounds: List[str],
    url: str = "https://cp.cloudflare.com/generate_204",
    interval: str = "3m",
    tolerance: int = 50,
) -> Dict[str, Any]:
    return {
        "type": "urltest",
        "tag": tag,
        "outbounds": outbounds,
        "url": url,
        "interval": interval,
        "tolerance": tolerance,
        "interrupt_exist_connections": False,
    }


def strip_meta(outbounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cleaned = []
    for ob in outbounds:
        x = {}
        for k, v in ob.items():
            if not k.startswith("_meta_"):
                x[k] = v
        cleaned.append(x)
    return cleaned


def retag_outbound(outbound: Dict[str, Any], tag_prefix: str, used_tags: Set[str]) -> Dict[str, Any]:
    ob = copy.deepcopy(outbound)
    name = str(ob.get("_meta_name") or ob.get("tag") or "node").strip()
    ob["tag"] = make_unique_tag(f"{tag_prefix}/{name}", used_tags)
    return ob


def outbound_name(outbound: Dict[str, Any]) -> str:
    return str(outbound.get("_meta_name") or outbound.get("tag") or "").strip()


def build_info_outbound(name: str) -> Dict[str, Any]:
    return {
        "type": "block",
        "tag": name,
        "_meta_name": name,
        "_meta_info": True,
    }


def subscription_userinfo_summary(name: str, userinfo: Dict[str, Any]) -> str:
    parts = [f"{name} 订阅信息"]
    used_human = userinfo.get("used_human")
    total_human = userinfo.get("total_human")
    remaining_human = userinfo.get("remaining_human")

    if used_human and total_human:
        parts.append(f"流量 {used_human}/{total_human}")
    elif used_human:
        parts.append(f"已用 {used_human}")
    elif total_human:
        parts.append(f"总量 {total_human}")

    if remaining_human:
        parts.append(f"剩余 {remaining_human}")
    if userinfo.get("used_percent") is not None:
        parts.append(f"已用 {userinfo['used_percent']}%")
    if userinfo.get("expires_at_display"):
        parts.append(f"到期 {userinfo['expires_at_display']}")
    elif userinfo.get("expire") == 0:
        parts.append("到期 长期有效")

    return re.sub(r"\s+", " ", " | ".join(parts)).strip()


def build_subscription_userinfo_outbound(name: str, userinfo: Dict[str, Any]) -> Dict[str, Any]:
    outbound = build_info_outbound(subscription_userinfo_summary(name, userinfo))
    outbound["_meta_subscription_userinfo"] = userinfo
    return outbound


def is_home_node(outbound: Dict[str, Any]) -> bool:
    lowered = outbound_name(outbound).lower()
    return any(keyword.lower() in lowered for keyword in HOME_NODE_KEYWORDS)


def detect_other_country_key(outbound: Dict[str, Any]) -> str:
    name = outbound_name(outbound)
    regional_indicators = [
        chr(ord("A") + ord(ch) - 0x1F1E6)
        for ch in name
        if 0x1F1E6 <= ord(ch) <= 0x1F1FF
    ]
    if len(regional_indicators) >= 2:
        return "".join(regional_indicators[:2])

    matches = COUNTRY_CODE_RE.findall(name)
    if matches:
        return matches[-1]
    return "Others"


def append_unique_node(selected: List[Dict[str, Any]], seen: Set[int], node: Dict[str, Any]) -> bool:
    node_id = id(node)
    if node_id in seen:
        return False
    selected.append(node)
    seen.add(node_id)
    return True


def select_hot_region_nodes(nodes: List[Dict[str, Any]], max_nodes_per_region: int) -> List[Dict[str, Any]]:
    if max_nodes_per_region <= 0:
        return list(nodes)

    selected: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for node in nodes[:max_nodes_per_region]:
        append_unique_node(selected, seen, node)
    for node in nodes:
        if is_home_node(node):
            append_unique_node(selected, seen, node)
    return selected


def select_other_region_nodes(nodes: List[Dict[str, Any]], max_other_nodes: int) -> List[Dict[str, Any]]:
    if max_other_nodes <= 0:
        return list(nodes)

    selected: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    country_counts: Counter[str] = Counter()

    for node in nodes:
        if len(selected) >= max_other_nodes:
            break
        if is_home_node(node) and append_unique_node(selected, seen, node):
            country_counts[detect_other_country_key(node)] += 1

    for node in nodes:
        if len(selected) >= max_other_nodes:
            break
        country_key = detect_other_country_key(node)
        if country_counts[country_key] >= 2:
            continue
        if append_unique_node(selected, seen, node):
            country_counts[country_key] += 1

    return selected


def select_region_nodes(
    region: str,
    nodes: List[Dict[str, Any]],
    max_nodes_per_region: int,
    max_other_nodes: int,
) -> List[Dict[str, Any]]:
    if region == "Others":
        return select_other_region_nodes(nodes, max_other_nodes)
    return select_hot_region_nodes(nodes, max_nodes_per_region)


def parse_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return True
    lowered = str(value).strip().lower()
    return lowered not in {"0", "false", "no", "off", "disabled"}


def parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    lowered = str(value).strip().lower()
    if not lowered:
        return default
    return lowered in {"1", "true", "yes", "on", "enabled"}


def parse_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


def parse_region_filter(item: Dict[str, Any]) -> Set[str]:
    if parse_bool(item.get("hot_regions_only", item.get("hot_regions")), default=False):
        return set(HOT_REGIONS)

    regions = parse_string_list(item.get("regions", item.get("include_regions")))
    if not regions:
        return set(ALL_REGIONS)

    invalid = [region for region in regions if region not in ALL_REGIONS]
    if invalid:
        raise ValueError(f"{item['name']} 包含未知地区: {', '.join(invalid)}")
    return set(regions)


def parse_priority(value: Any, default: int = 100) -> int:
    if value is None or str(value).strip() == "":
        return default
    try:
        return int(value)
    except Exception as e:
        raise ValueError(f"priority 必须是整数: {value}") from e


def configured_group_tag(item: Dict[str, Any], default_name: str) -> str:
    tag = str(
        item.get("group_tag")
        or item.get("provider_tag")
        or item.get("tag")
        or f"Provider/{default_name}"
    ).strip()
    return tag or f"Provider/{default_name}"


def load_subscription_manifest(path: Path, default_subscription_file: str) -> List[Dict[str, Any]]:
    if not path.exists():
        return [
            {
                "name": "example-provider",
                "parser": "clash",
                "source": "url_file",
                "path": default_subscription_file,
                "enabled": True,
                "priority": 100,
                "role": "default",
            }
        ]

    data = load_yaml(str(path))
    if isinstance(data, list):
        subscriptions = data
    elif isinstance(data, dict):
        subscriptions = data.get("subscriptions")
    else:
        subscriptions = None

    if not isinstance(subscriptions, list) or not subscriptions:
        raise ValueError(f"订阅清单格式错误: {path}")

    normalized: List[Dict[str, Any]] = []
    seen_names: Set[str] = set()
    for index, item in enumerate(subscriptions):
        if not isinstance(item, dict):
            raise ValueError(f"订阅清单中存在非对象项: {path}")

        name = str(item.get("name", "")).strip()
        if not name:
            raise ValueError(f"订阅清单中存在空 name: {path}")
        enabled = parse_enabled(item.get("enabled", True))
        if not enabled:
            continue
        if name in seen_names:
            raise ValueError(f"订阅组名称重复: {name}")
        seen_names.add(name)

        parser_name = str(item.get("parser") or item.get("type") or "clash").strip()
        source = str(item.get("source") or "url").strip()
        priority = parse_priority(item.get("priority"), default=100)
        role = str(item.get("role") or "default").strip().lower() or "default"
        normalized.append(
            {
                **item,
                "name": name,
                "parser": parser_name,
                "source": source,
                "enabled": True,
                "priority": priority,
                "role": role,
                "_manifest_index": index,
            }
        )

    if not normalized:
        raise ValueError(f"订阅清单没有启用的订阅组: {path}")

    normalized.sort(key=lambda x: (int(x["priority"]), int(x["_manifest_index"])))
    return normalized


def make_single_subscription_from_args(args: argparse.Namespace) -> Optional[List[Dict[str, Any]]]:
    if args.sub_file:
        return [
            {
                "name": args.sub_name,
                "parser": args.sub_parser,
                "source": "file",
                "path": args.sub_file,
                "enabled": True,
                "priority": 100,
                "role": "default",
            }
        ]
    if args.sub_url:
        return [
            {
                "name": args.sub_name,
                "parser": args.sub_parser,
                "source": "url",
                "url": args.sub_url,
                "enabled": True,
                "priority": 100,
                "role": "default",
            }
        ]
    return None


def attach_subscription_content(item: Dict[str, Any], content: SubscriptionContent) -> str:
    if content.userinfo:
        item["_subscription_userinfo"] = {
            **content.userinfo,
            "fetched_from": "cache" if content.from_cache else "remote",
        }
    else:
        item.pop("_subscription_userinfo", None)
    return content.text


def load_source_text(
    item: Dict[str, Any],
    base_dir: Path,
    user_agent: str,
    cache_dir: Optional[Path],
    fetch_proxy: Optional[str],
) -> str:
    source = str(item.get("source") or "url").strip().lower()
    name = str(item.get("name") or "订阅")

    if source == "url":
        url = str(item.get("url") or "").strip()
        if not url:
            raise ValueError(f"订阅组 {item['name']} 缺少 url")
        content = fetch_text_with_cache(url, cache_dir, name, user_agent=user_agent, fetch_proxy=fetch_proxy)
        return attach_subscription_content(item, content)

    if source == "url_file":
        path = str(item.get("path") or "").strip()
        if not path:
            raise ValueError(f"订阅组 {item['name']} 缺少 path")
        url = read_subscription_url(resolve_path(path, base_dir))
        content = fetch_text_with_cache(url, cache_dir, name, user_agent=user_agent, fetch_proxy=fetch_proxy)
        return attach_subscription_content(item, content)

    if source == "file":
        path = str(item.get("path") or "").strip()
        if not path:
            raise ValueError(f"订阅组 {item['name']} 缺少 path")
        item.pop("_subscription_userinfo", None)
        return read_text(resolve_path(path, base_dir))

    raise ValueError(f"订阅组 {item['name']} 的 source 不支持: {source}")


def choose_default(candidates: List[str], preferred: List[str]) -> str:
    return next((tag for tag in preferred if tag in candidates), candidates[0])


def append_unique(values: List[str], value: str) -> None:
    if value not in values:
        values.append(value)


def outbound_region(outbound: Dict[str, Any]) -> str:
    region = str(outbound.get("_meta_region") or "Others")
    if region not in ALL_REGIONS:
        return "Others"
    return region


def apply_region_limits(
    grouped: Dict[str, List[Dict[str, Any]]],
    max_nodes_per_region: int,
    max_other_nodes: int,
) -> Dict[str, List[Dict[str, Any]]]:
    limited: Dict[str, List[Dict[str, Any]]] = {}
    for region in ALL_REGIONS:
        nodes = grouped.get(region, [])
        if region == "Others":
            limited[region] = select_other_region_nodes(nodes, max_other_nodes) if max_other_nodes > 0 else list(nodes)
        else:
            limited[region] = select_hot_region_nodes(nodes, max_nodes_per_region) if max_nodes_per_region > 0 else list(nodes)
    return limited


def build_provider_group(
    item: Dict[str, Any],
    node_outbounds: List[Dict[str, Any]],
    info_outbounds: List[Dict[str, Any]],
    used_tags: Set[str],
    max_nodes_per_region: int,
    max_other_nodes: int,
    keep_info_nodes: bool,
) -> Dict[str, Any]:
    name = str(item["name"])
    provider_tag = make_unique_tag(configured_group_tag(item, name), used_tags)
    priority = int(item.get("priority", 100))
    available_priority = parse_priority(
        item.get("available_priority", item.get("available_order")),
        default=priority,
    )
    include_in_available = parse_bool(item.get("include_in_available", item.get("available")), default=False)
    include_in_selectors = parse_string_list(item.get("include_in_selectors"))
    active_info_outbounds: List[Dict[str, Any]] = []
    if keep_info_nodes and info_outbounds:
        active_info_outbounds = [retag_outbound(ob, provider_tag, used_tags) for ob in info_outbounds]

    grouped: Dict[str, List[Dict[str, Any]]] = {region: [] for region in ALL_REGIONS}
    for ob in node_outbounds:
        grouped[outbound_region(ob)].append(ob)

    allowed_regions = parse_region_filter(item)
    for region in ALL_REGIONS:
        if region not in allowed_regions:
            grouped[region] = []

    grouped = apply_region_limits(grouped, max_nodes_per_region, max_other_nodes)

    if not any(grouped.values()):
        raise RuntimeError(f"订阅组 {name} 没有可用节点")

    selected_nodes: List[Dict[str, Any]] = []
    for region in ALL_REGIONS:
        for ob in grouped.get(region, []):
            node = retag_outbound(ob, provider_tag, used_tags)
            node["_meta_subscription"] = name
            node["_meta_role"] = str(item.get("role") or "default")
            node["_meta_priority"] = int(item.get("priority", 100))
            selected_nodes.append(node)

    region_selector_tags: Dict[str, str] = {}
    control_outbounds: List[Dict[str, Any]] = []
    if parse_bool(item.get("flat_group", item.get("flat")), default=False):
        node_tags = [node["tag"] for node in selected_nodes]
        if parse_bool(item.get("urltest", item.get("auto_select")), default=False):
            urltest_url = str(
                item.get("urltest_url")
                or item.get("test_url")
                or "https://cp.cloudflare.com/generate_204"
            ).strip()
            urltest_interval = str(item.get("urltest_interval") or "3m").strip()
            urltest_tolerance = parse_priority(item.get("urltest_tolerance"), default=50)
            control_outbounds.append(
                build_urltest(
                    provider_tag,
                    node_tags,
                    url=urltest_url,
                    interval=urltest_interval,
                    tolerance=urltest_tolerance,
                )
            )
        else:
            control_outbounds.append(build_selector(provider_tag, node_tags + ["direct"], default=node_tags[0]))
        return {
            "name": name,
            "role": str(item.get("role") or "default"),
            "priority": priority,
            "available_priority": available_priority,
            "provider_tag": provider_tag,
            "region_selector_tags": region_selector_tags,
            "control_outbounds": control_outbounds,
            "node_outbounds": selected_nodes,
            "info_outbounds": active_info_outbounds,
            "include_in_available": include_in_available,
            "include_in_selectors": include_in_selectors,
            "region_counts": {region: len(grouped.get(region, [])) for region in ALL_REGIONS},
        }

    for region in ALL_REGIONS:
        region_nodes = [node for node in selected_nodes if outbound_region(node) == region]
        if not region_nodes:
            continue

        region_tag = make_unique_tag(f"{provider_tag}/{region}", used_tags)
        region_selector_tags[region] = region_tag
        node_tags = [node["tag"] for node in region_nodes]
        control_outbounds.append(build_selector(region_tag, node_tags, default=node_tags[0]))

    provider_choices = [
        region_selector_tags[region]
        for region in ALL_REGIONS
        if region in region_selector_tags
    ] + ["direct"]
    provider_default = choose_default(
        provider_choices,
        [
            region_selector_tags[region]
            for region in ["HK", "TW", "JP", "SG", "US", "GB", "Others"]
            if region in region_selector_tags
        ] + ["direct"],
    )
    control_outbounds.insert(0, build_selector(provider_tag, provider_choices, default=provider_default))

    return {
        "name": name,
        "role": str(item.get("role") or "default"),
        "priority": priority,
        "available_priority": available_priority,
        "provider_tag": provider_tag,
        "region_selector_tags": region_selector_tags,
        "control_outbounds": control_outbounds,
        "node_outbounds": selected_nodes,
        "info_outbounds": active_info_outbounds,
        "include_in_available": include_in_available,
        "include_in_selectors": include_in_selectors,
        "region_counts": {region: len(grouped.get(region, [])) for region in ALL_REGIONS},
    }


def build_region_pool_groups(
    group_tag: str,
    nodes: List[Dict[str, Any]],
    used_tags: Set[str],
) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {region: [] for region in ALL_REGIONS}
    for node in nodes:
        grouped[outbound_region(node)].append(node)

    region_selector_tags: Dict[str, str] = {}
    control_outbounds: List[Dict[str, Any]] = []
    for region in ALL_REGIONS:
        region_nodes = grouped.get(region, [])
        if not region_nodes:
            continue

        region_tag = make_unique_tag(f"{group_tag}/{region}", used_tags)
        region_selector_tags[region] = region_tag
        node_tags = [node["tag"] for node in region_nodes]
        control_outbounds.append(build_selector(region_tag, node_tags, default=node_tags[0]))

    return region_selector_tags, control_outbounds


def choose_provider_default(built_groups: List[Dict[str, Any]]) -> str:
    preferred_roles = {"paid", "primary", "default"}
    for group in built_groups:
        if str(group.get("role") or "").lower() in preferred_roles:
            return str(group["provider_tag"])
    return str(built_groups[0]["provider_tag"])


def is_public_role(role: Any) -> bool:
    return str(role or "").strip().lower() in {"public", "free", "community", "backup-public", "公益"}


def build_config_from_subscriptions(
    subscriptions: List[Dict[str, Any]],
    template: Dict[str, Any],
    manifest_base_dir: Path,
    max_nodes_per_region: int = DEFAULT_MAX_NODES_PER_REGION,
    max_other_nodes: int = DEFAULT_MAX_OTHER_NODES,
    keep_info_nodes: bool = DEFAULT_KEEP_INFO_NODES,
    user_agent: str = "clash-verge/v2.4.7",
    cache_dir: Optional[Path] = Path(DEFAULT_SUBSCRIPTION_CACHE_DIR),
    fetch_proxy: Optional[str] = None,
) -> Dict[str, Any]:
    used_tags: Set[str] = {"Available", "AI", "Info", "Provider", "Public", "direct", "block"}
    built_groups: List[Dict[str, Any]] = []

    for item in subscriptions:
        name = str(item["name"])
        parser_name = str(item["parser"])
        text = load_source_text(item, manifest_base_dir, user_agent, cache_dir, fetch_proxy)
        try:
            node_outbounds, info_outbounds, warnings = parse_subscription_text(parser_name, text)
        except Exception as e:
            raise RuntimeError(f"订阅组 {name} 解析失败: {e}") from e

        for warning in warnings:
            print(f"[WARN] {name}: {warning}", file=sys.stderr)

        subscription_userinfo = item.get("_subscription_userinfo")
        if isinstance(subscription_userinfo, dict) and subscription_userinfo:
            info_outbounds.append(build_subscription_userinfo_outbound(name, subscription_userinfo))

        if not node_outbounds:
            raise RuntimeError(f"订阅组 {name} 没有解析出任何可用节点")

        built_groups.append(
            build_provider_group(
                item=item,
                node_outbounds=node_outbounds,
                info_outbounds=info_outbounds,
                used_tags=used_tags,
                max_nodes_per_region=max_nodes_per_region,
                max_other_nodes=max_other_nodes,
                keep_info_nodes=keep_info_nodes,
            )
        )

    if not built_groups:
        raise RuntimeError("没有可用订阅组")

    if not any(group["node_outbounds"] for group in built_groups):
        raise RuntimeError("没有可用节点")

    provider_groups = [str(group["provider_tag"]) for group in built_groups]
    provider_default = choose_provider_default(built_groups)
    provider_default_group = next(
        (group for group in built_groups if str(group["provider_tag"]) == provider_default),
        built_groups[0],
    )

    public_nodes = [
        node_ob
        for group in built_groups
        if is_public_role(group.get("role"))
        for node_ob in group["node_outbounds"]
    ]
    public_region_selector_tags: Dict[str, str] = {}
    public_control_outbounds: List[Dict[str, Any]] = []
    if public_nodes:
        public_region_selector_tags, public_control_outbounds = build_region_pool_groups(
            "Public",
            public_nodes,
            used_tags,
        )

    available_groups = sorted(
        [group for group in built_groups if group.get("include_in_available")],
        key=lambda group: (
            int(group.get("available_priority", group.get("priority", 100))),
            int(group.get("priority", 100)),
            str(group.get("provider_tag")),
        ),
    )
    available_choices: List[str] = [str(group["provider_tag"]) for group in available_groups]
    if not available_choices:
        available_choices = [provider_default]
    append_unique(available_choices, "direct")

    paid_ai_groups = []
    if not is_public_role(provider_default_group.get("role")):
        paid_ai_groups = [
            provider_default_group["region_selector_tags"][region]
            for region in AI_PREFERRED_REGIONS
            if region in provider_default_group["region_selector_tags"]
        ]
    ai_groups = paid_ai_groups
    if not ai_groups:
        ai_groups = [provider_default]
    for group in built_groups:
        for node_ob in group["node_outbounds"]:
            if outbound_region(node_ob) == "US":
                append_unique(ai_groups, str(node_ob["tag"]))

    info_tags = [
        info_ob["tag"]
        for group in built_groups
        for info_ob in group["info_outbounds"]
    ]

    outbounds: List[Dict[str, Any]] = []
    available_default = provider_default
    outbounds.append(build_selector("Available", available_choices, default=available_default))
    outbounds.append(build_selector("AI", ai_groups, default=ai_groups[0]))
    if public_nodes:
        public_choices = [
            public_region_selector_tags[region]
            for region in ALL_REGIONS
            if region in public_region_selector_tags
        ] + ["direct"]
        public_default = choose_default(
            public_choices,
            [
                public_region_selector_tags[region]
                for region in ["HK", "JP", "SG", "TW", "US", "GB", "Others"]
                if region in public_region_selector_tags
            ] + ["direct"],
        )
        outbounds.append(build_selector("Public", public_choices, default=public_default))
    outbounds.append(build_selector("Provider", provider_groups + ["direct"], default=provider_default))
    if info_tags:
        outbounds.append(build_selector("Info", info_tags, default=info_tags[0]))

    outbounds.extend(public_control_outbounds)
    for group in built_groups:
        outbounds.extend(group["control_outbounds"])

    selector_by_tag = {
        str(ob.get("tag")): ob
        for ob in outbounds
        if isinstance(ob, dict) and ob.get("type") == "selector" and ob.get("tag")
    }
    for group in built_groups:
        node_tags = [node["tag"] for node in group["node_outbounds"]]
        for selector_tag in group.get("include_in_selectors", []):
            selector = selector_by_tag.get(str(selector_tag))
            if not selector:
                print(f"[WARN] {group['name']}: 未找到要追加的分组 {selector_tag}", file=sys.stderr)
                continue
            selector_outbounds = selector.setdefault("outbounds", [])
            if not isinstance(selector_outbounds, list):
                print(f"[WARN] {group['name']}: 分组 {selector_tag} 的 outbounds 不是数组，已跳过", file=sys.stderr)
                continue
            for node_tag in node_tags:
                append_unique(selector_outbounds, node_tag)

    for group in built_groups:
        outbounds.extend(strip_meta(group["node_outbounds"]))
    for group in built_groups:
        outbounds.extend(strip_meta(group["info_outbounds"]))

    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})

    conf = copy.deepcopy(template)
    conf["outbounds"] = outbounds
    return conf


def write_nodes_report(
    conf: Dict[str, Any],
    report_path: Path,
    subscriptions: List[Dict[str, Any]],
) -> None:
    outbounds = conf.get("outbounds", [])
    if not isinstance(outbounds, list):
        outbounds = []

    proxy_nodes = [
        ob
        for ob in outbounds
        if isinstance(ob, dict) and str(ob.get("type")) not in NON_PROXY_OUTBOUND_TYPES
    ]
    selector_tags = [
        str(ob.get("tag"))
        for ob in outbounds
        if isinstance(ob, dict) and ob.get("type") == "selector" and ob.get("tag")
    ]

    subscription_reports: List[Dict[str, Any]] = []
    for item in subscriptions:
        name = str(item["name"])
        prefix = f"{configured_group_tag(item, name)}/"
        region_counts: Counter[str] = Counter()
        node_count = 0
        for node in proxy_nodes:
            tag = str(node.get("tag") or "")
            if not tag.startswith(prefix):
                continue
            node_count += 1
            # Re-detect from the visible node suffix so the report stays independent of stripped metadata.
            region_counts[detect_region(tag.removeprefix(prefix))] += 1

        subscription_report: Dict[str, Any] = {
            "name": name,
            "role": str(item.get("role") or "default"),
            "priority": int(item.get("priority", 100)),
            "nodes": node_count,
            "regions": {region: region_counts.get(region, 0) for region in ALL_REGIONS},
            "subscription_userinfo": None,
        }
        subscription_userinfo = item.get("_subscription_userinfo")
        if isinstance(subscription_userinfo, dict) and subscription_userinfo:
            subscription_report["subscription_userinfo"] = subscription_userinfo

        subscription_reports.append(subscription_report)

    report = {
        "subscriptions": subscription_reports,
        "totals": {
            "subscriptions": len(subscriptions),
            "proxy_nodes": len(proxy_nodes),
            "selectors": len(selector_tags),
            "urltests": sum(
                1
                for ob in outbounds
                if isinstance(ob, dict) and ob.get("type") == "urltest"
            ),
        },
        "main_selectors": [
            tag
            for tag in ["Available", "AI", "Public", "Provider", "Info"]
            if tag in selector_tags
        ],
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def get_clash_ui_url(conf: Dict[str, Any]) -> Optional[str]:
    clash_api = (
        conf.get("experimental", {})
        .get("clash_api", {})
    )
    controller = str(clash_api.get("external_controller") or "").strip()
    if not controller:
        return None
    if controller.startswith(("http://", "https://")):
        base_url = controller.rstrip("/")
    else:
        base_url = f"http://{controller.rstrip('/')}"
    return f"{base_url}/ui/"


def print_config_summary(
    conf: Dict[str, Any],
    template_path: Path,
    output_path: Path,
    subscriptions: List[Dict[str, Any]],
) -> None:
    outbounds = conf.get("outbounds", [])
    if not isinstance(outbounds, list):
        outbounds = []

    selector_tags = [
        str(ob.get("tag"))
        for ob in outbounds
        if isinstance(ob, dict) and ob.get("type") == "selector" and ob.get("tag")
    ]
    proxy_count = sum(
        1
        for ob in outbounds
        if isinstance(ob, dict) and str(ob.get("type")) not in NON_PROXY_OUTBOUND_TYPES
    )
    main_selectors = [tag for tag in ("Available", "AI", "Public", "Provider", "Info") if tag in selector_tags]
    ui_url = get_clash_ui_url(conf)

    print(f"完成: 已根据 {template_path} 生成 {output_path}")
    print(
        f"摘要: 订阅组 {len(subscriptions)} 个，代理节点 {proxy_count} 个，"
        f"手动分组 {len(selector_tags)} 个"
    )
    if main_selectors:
        print(f"主分组: {', '.join(main_selectors)}")
    if ui_url:
        print(f"面板: {ui_url}")
    print(f"下一步: .\\sing-box.exe check -c {output_path}，通过后运行 .\\singbox-service.exe restart")


def main() -> None:
    parser = argparse.ArgumentParser(description="生成 sing-box 配置，支持多订阅、地区分组和 AI 分流")
    parser.add_argument("--subscriptions", default="subscriptions.yaml", help="订阅组清单，默认 subscriptions.yaml")
    parser.add_argument("--sub-url", default=None, help="兼容旧用法：单个 Clash 订阅链接")
    parser.add_argument("--sub-file", default=None, help="兼容旧用法：本地 Clash YAML 文件")
    parser.add_argument("--sub-name", default="example-provider", help="兼容旧用法下的订阅组名称")
    parser.add_argument("--sub-parser", default="clash", help="兼容旧用法下的解析器，默认 clash")
    parser.add_argument("--subscription-file", default="subscriptions/example-provider.txt", help="默认订阅链接文件")
    parser.add_argument("--template", default="template.json", help="模板文件路径")
    parser.add_argument("--output", default="config.json", help="输出文件路径")
    parser.add_argument("--report", default="nodes-report.json", help="节点报告输出路径，默认 nodes-report.json")
    parser.add_argument("--no-report", action="store_true", help="不生成节点报告")
    parser.add_argument(
        "--max-nodes-per-region",
        type=int,
        default=DEFAULT_MAX_NODES_PER_REGION,
        help="每个地区最多保留几个节点，默认不限，0 表示不限",
    )
    parser.add_argument(
        "--max-other-nodes",
        type=int,
        default=DEFAULT_MAX_OTHER_NODES,
        help="Others 分组最多保留几个节点，默认不限，0 表示不限",
    )
    parser.add_argument("--clash-secret", default=None, help="覆盖模板里的 clash_api.secret")
    parser.add_argument("--user-agent", default="clash-verge/v2.4.7", help="自定义请求头 User-Agent")
    parser.add_argument(
        "--subscription-cache-dir",
        default=DEFAULT_SUBSCRIPTION_CACHE_DIR,
        help="订阅下载成功后的本地缓存目录，默认 .subscription-cache",
    )
    parser.add_argument(
        "--no-subscription-cache",
        action="store_true",
        help="禁用订阅下载缓存和失败回退",
    )
    parser.add_argument(
        "--fetch-proxy",
        default=None,
        help="下载订阅时使用的 HTTP/SOCKS 代理，例如 http://127.0.0.1:7890",
    )
    parser.add_argument("--keep-info-nodes", action="store_true", help="保留订阅信息节点（默认不保留）")
    parser.add_argument("--discard-info-nodes", action="store_true", help="兼容旧参数：不保留订阅信息节点")

    args = parser.parse_args()

    if args.max_nodes_per_region < 0:
        print("--max-nodes-per-region 必须 >= 0", file=sys.stderr)
        sys.exit(1)

    if args.max_other_nodes < 0:
        print("--max-other-nodes 必须 >= 0", file=sys.stderr)
        sys.exit(1)

    template_path = Path(args.template)
    if not template_path.exists():
        print(f"模板文件不存在: {template_path}", file=sys.stderr)
        sys.exit(1)

    try:
        template = load_json(str(template_path))
    except Exception as e:
        print(f"读取模板失败: {e}", file=sys.stderr)
        sys.exit(1)

    if args.clash_secret is not None:
        try:
            template["experimental"]["clash_api"]["secret"] = args.clash_secret
        except Exception:
            pass

    try:
        single_subscription = make_single_subscription_from_args(args)
        subscriptions_path = Path(args.subscriptions)
        subscriptions = single_subscription or load_subscription_manifest(subscriptions_path, args.subscription_file)
        manifest_base_dir = subscriptions_path.parent if subscriptions_path.parent != Path("") else Path(".")
        cache_dir = None if args.no_subscription_cache else Path(args.subscription_cache_dir)

        conf = build_config_from_subscriptions(
            subscriptions=subscriptions,
            template=template,
            manifest_base_dir=manifest_base_dir,
            max_nodes_per_region=args.max_nodes_per_region,
            max_other_nodes=args.max_other_nodes,
            keep_info_nodes=args.keep_info_nodes and not args.discard_info_nodes,
            user_agent=args.user_agent,
            cache_dir=cache_dir,
            fetch_proxy=args.fetch_proxy,
        )
        save_json(args.output, conf)
        if not args.no_report:
            write_nodes_report(conf, Path(args.report), subscriptions)
    except Exception as e:
        print(f"生成失败: {e}", file=sys.stderr)
        sys.exit(1)

    print_config_summary(conf, template_path, Path(args.output), subscriptions)


if __name__ == "__main__":
    main()

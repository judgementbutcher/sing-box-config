#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import copy
import hashlib
import json
import re
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from singbox_config.audit import (
    ConfigAuditError,
    is_insecure_outbound,
    outbound_fingerprint,
    require_valid_config,
)
from singbox_config.health import load_health_state, select_diverse_candidates
from singbox_config.io_utils import (
    atomic_write_json,
    atomic_write_text,
    parse_duration_seconds,
    parse_utc_timestamp,
    utc_now,
    utc_now_iso,
)
from singbox_config.profiles import apply_profile_to_template, load_profile


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


configure_stdio()


DEFAULT_MAX_NODES_PER_REGION = 0
DEFAULT_MAX_OTHER_NODES = 0
DEFAULT_SUBSCRIPTION_CACHE_DIR = "runtime/subscription-cache"
DEFAULT_TEMPLATE_DIR = "config/local/templates"
LEGACY_TEMPLATE_PATH = "config/local/templates/desktop-windows-sing-box-1.14.json"
EXAMPLE_TEMPLATE_PATH = "config/examples/templates/desktop-windows-sing-box-1.14.json"
DEFAULT_KEEP_INFO_NODES = False
DEFAULT_AVAILABLE_URLTEST_URL = "https://cp.cloudflare.com/generate_204"
DEFAULT_AVAILABLE_URLTEST_INTERVAL = "10m"
DEFAULT_AVAILABLE_URLTEST_TOLERANCE = 80
DEFAULT_AVAILABLE_URLTEST_IDLE_TIMEOUT = "30m"
DEFAULT_FETCH_WORKERS = 4
DEFAULT_FETCH_CONNECT_TIMEOUT = 5
DEFAULT_FETCH_READ_TIMEOUT = 20
DEFAULT_FETCH_RETRIES = 2
DEFAULT_CACHE_MAX_STALE = "7d"
DEFAULT_CACHE_RETENTION = "30d"
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
    cache_status: str = "remote"
    fetched_at: Optional[str] = None
    validated_at: Optional[str] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None


@dataclass
class LoadedSource:
    content: SubscriptionContent
    cache_path: Optional[Path] = None
    cached_fallback: Optional[SubscriptionContent] = None
    write_cache_after_parse: bool = False


@dataclass
class PreparedSubscription:
    item: Dict[str, Any]
    node_outbounds: List[Dict[str, Any]]
    info_outbounds: List[Dict[str, Any]]
    warnings: List[str]
    cache_status: str


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Dict[str, Any]) -> None:
    atomic_write_json(Path(path), data)


def load_yaml(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_policy_aliases(path: Optional[Path]) -> Dict[str, str]:
    if path is None or not path.exists():
        return {}
    data = load_yaml(str(path))
    aliases = data.get("aliases") if isinstance(data, dict) else None
    if not isinstance(aliases, dict):
        raise ValueError(f"策略别名文件格式错误: {path}")
    normalized: Dict[str, str] = {}
    for alias, target in aliases.items():
        alias_name = str(alias or "").strip()
        target_name = str(target or "").strip()
        if not alias_name or not target_name:
            raise ValueError(f"策略别名不能为空: {path}")
        if alias_name in {"Available", "AI", "DNS-Out", "Update-Out", "direct", "block"}:
            raise ValueError(f"策略别名使用了保留名称: {alias_name}")
        normalized[alias_name] = target_name
    return normalized


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
        "User-Agent": user_agent or "clash-verge/v2.5.1",
    }


def fetch_subscription_content(
    url: str,
    timeout: Optional[int] = None,
    user_agent: Optional[str] = None,
    fetch_proxy: Optional[str] = None,
    connect_timeout: int = DEFAULT_FETCH_CONNECT_TIMEOUT,
    read_timeout: int = DEFAULT_FETCH_READ_TIMEOUT,
    retries: int = DEFAULT_FETCH_RETRIES,
    cached: Optional[SubscriptionContent] = None,
) -> SubscriptionContent:
    headers = subscription_request_headers(user_agent)
    if cached and cached.etag:
        headers["If-None-Match"] = cached.etag
    if cached and cached.last_modified:
        headers["If-Modified-Since"] = cached.last_modified
    proxies = {"http": fetch_proxy, "https": fetch_proxy} if fetch_proxy else None
    if timeout is not None:
        connect_timeout = min(int(timeout), connect_timeout)
        read_timeout = int(timeout)

    retry_statuses = {429, 500, 502, 503, 504}
    last_error: Optional[Exception] = None
    for attempt in range(max(retries, 0) + 1):
        try:
            with requests.Session() as session:
                response = session.get(
                    url,
                    headers=headers,
                    timeout=(connect_timeout, read_timeout),
                    proxies=proxies,
                )
            if response.status_code == 304:
                if cached is None:
                    raise RuntimeError("服务器返回 304，但本地订阅缓存不存在")
                cached.from_cache = True
                cached.cache_status = "revalidated"
                cached.validated_at = utc_now_iso()
                return cached
            if response.status_code in retry_statuses:
                response.raise_for_status()
            response.raise_for_status()
            content = SubscriptionContent(
                text=response.text,
                userinfo=subscription_metadata_from_headers(response.headers),
                from_cache=False,
                cache_status="remote",
                fetched_at=utc_now_iso(),
                validated_at=utc_now_iso(),
                etag=response.headers.get("ETag"),
                last_modified=response.headers.get("Last-Modified"),
            )
            validate_subscription_payload(content.text)
            return content
        except Exception as exc:
            last_error = exc
            if attempt >= max(retries, 0):
                break
            time.sleep(min(0.5 * (2**attempt), 2.0))
    assert last_error is not None
    raise last_error


def validate_subscription_payload(text: str) -> None:
    stripped = text.lstrip()
    if not stripped:
        raise ValueError("订阅下载结果为空")
    prefix = stripped[:512].lower()
    if prefix.startswith("<!doctype html") or prefix.startswith("<html"):
        raise ValueError("订阅下载结果是 HTML 页面，不是代理配置")
    if len(text.encode("utf-8")) > 32 * 1024 * 1024:
        raise ValueError("订阅下载结果超过 32 MiB 安全上限")


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
    data = read_cached_subscription_meta(cache_path)
    userinfo = data.get("subscription_userinfo")
    return userinfo if isinstance(userinfo, dict) else {}


def read_cached_subscription_meta(cache_path: Path) -> Dict[str, Any]:
    meta_path = subscription_cache_meta_path(cache_path)
    try:
        if not meta_path.exists() or not meta_path.is_file():
            return {}
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[WARN] 读取订阅缓存元数据失败 {meta_path}: {e}", file=sys.stderr)
    return {}


def read_cached_subscription(cache_path: Path) -> Optional[SubscriptionContent]:
    try:
        if cache_path.exists() and cache_path.is_file():
            text = cache_path.read_text(encoding="utf-8")
            if text.strip():
                meta = read_cached_subscription_meta(cache_path)
                return SubscriptionContent(
                    text=text,
                    userinfo=meta.get("subscription_userinfo") if isinstance(meta.get("subscription_userinfo"), dict) else {},
                    from_cache=True,
                    cache_status="cache",
                    fetched_at=str(meta.get("fetched_at") or "") or None,
                    validated_at=str(meta.get("validated_at") or "") or None,
                    etag=str(meta.get("etag") or "") or None,
                    last_modified=str(meta.get("last_modified") or "") or None,
                )
    except Exception as e:
        print(f"[WARN] 读取订阅缓存失败 {cache_path}: {e}", file=sys.stderr)
    return None


def write_cached_subscription(cache_path: Path, content: SubscriptionContent) -> None:
    if not content.text.strip():
        return
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(cache_path, content.text)
        meta_path = subscription_cache_meta_path(cache_path)
        atomic_write_json(
            meta_path,
            {
                "schema_version": 2,
                "fetched_at": content.fetched_at or utc_now_iso(),
                "validated_at": content.validated_at or utc_now_iso(),
                "etag": content.etag,
                "last_modified": content.last_modified,
                "content_sha256": hashlib.sha256(content.text.encode("utf-8")).hexdigest(),
                "subscription_userinfo": content.userinfo or {},
            },
        )
    except Exception as e:
        print(f"[WARN] 写入订阅缓存失败 {cache_path}: {e}", file=sys.stderr)


def cached_subscription_age_seconds(cache_path: Path, content: SubscriptionContent) -> float:
    timestamp = parse_utc_timestamp(content.validated_at or content.fetched_at)
    if timestamp is not None:
        return max((utc_now() - timestamp).total_seconds(), 0.0)
    return max(utc_now().timestamp() - cache_path.stat().st_mtime, 0.0)


def fetch_source_with_cache(
    url: str,
    cache_dir: Optional[Path],
    label: str,
    user_agent: Optional[str] = None,
    fetch_proxy: Optional[str] = None,
    connect_timeout: int = DEFAULT_FETCH_CONNECT_TIMEOUT,
    read_timeout: int = DEFAULT_FETCH_READ_TIMEOUT,
    retries: int = DEFAULT_FETCH_RETRIES,
    cache_max_stale: str = DEFAULT_CACHE_MAX_STALE,
    offline: bool = False,
) -> LoadedSource:
    cache_path = subscription_cache_path(cache_dir, url) if cache_dir else None
    cached = read_cached_subscription(cache_path) if cache_path else None
    if offline:
        if cache_path is None or cached is None:
            raise RuntimeError(f"{label}: 离线模式下没有可用订阅缓存")
        age_seconds = cached_subscription_age_seconds(cache_path, cached)
        if age_seconds > parse_duration_seconds(cache_max_stale):
            raise RuntimeError(f"{label}: 离线缓存已超过最大陈旧时间 {cache_max_stale}")
        cached.cache_status = "offline-cache"
        return LoadedSource(content=cached, cache_path=cache_path)
    try:
        content = fetch_subscription_content(
            url,
            user_agent=user_agent,
            fetch_proxy=fetch_proxy,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=retries,
            cached=cached,
        )
    except Exception as e:
        if cache_path and cached is not None:
            max_stale_seconds = parse_duration_seconds(cache_max_stale)
            age_seconds = cached_subscription_age_seconds(cache_path, cached)
            if age_seconds <= max_stale_seconds:
                cached.cache_status = "stale-fallback"
                print(
                    f"[WARN] {label}: 订阅下载失败，已使用 {age_seconds / 86400:.1f} 天前的缓存。"
                    f"错误类型: {type(e).__name__}",
                    file=sys.stderr,
                )
                return LoadedSource(content=cached, cache_path=cache_path)
            raise RuntimeError(
                f"{label}: 订阅下载失败，缓存已超过最大陈旧时间 {cache_max_stale}"
            ) from e
        raise

    if content.cache_status == "revalidated":
        if cache_path:
            write_cached_subscription(cache_path, content)
        return LoadedSource(content=content, cache_path=cache_path)
    return LoadedSource(
        content=content,
        cache_path=cache_path,
        cached_fallback=cached,
        write_cache_after_parse=cache_path is not None,
    )


def fetch_text_with_cache(
    url: str,
    cache_dir: Optional[Path],
    label: str,
    user_agent: Optional[str] = None,
    fetch_proxy: Optional[str] = None,
) -> SubscriptionContent:
    """Compatibility wrapper used by external callers."""

    loaded = fetch_source_with_cache(
        url,
        cache_dir,
        label,
        user_agent=user_agent,
        fetch_proxy=fetch_proxy,
    )
    if loaded.write_cache_after_parse and loaded.cache_path:
        write_cached_subscription(loaded.cache_path, loaded.content)
    return loaded.content


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


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except Exception:
        return str(path)


def discover_templates(template_dir: Path) -> List[Path]:
    if not template_dir.exists() or not template_dir.is_dir():
        return []
    return sorted(
        [path for path in template_dir.glob("*.json") if path.is_file()],
        key=lambda path: path.name.lower(),
    )


def print_template_choices(templates: List[Path]) -> None:
    print("可用模板:")
    for index, template_path in enumerate(templates, start=1):
        print(f"  {index}. {display_path(template_path)}")


def choose_template_interactively(template_dir: Path) -> Path:
    templates = discover_templates(template_dir)
    if not templates:
        for fallback in (LEGACY_TEMPLATE_PATH, EXAMPLE_TEMPLATE_PATH):
            fallback_path = Path(fallback)
            if fallback_path.exists():
                print(
                    f"[WARN] 未找到 {display_path(template_dir)}/*.json，"
                    f"退回使用 {display_path(fallback_path)}"
                )
                return fallback_path
        raise FileNotFoundError(f"未找到模板文件。请在 {display_path(template_dir)} 放入 *.json 模板")

    print_template_choices(templates)
    if len(templates) == 1:
        print(f"只有 1 个模板，默认使用: {display_path(templates[0])}")
        return templates[0]

    default_index = 1
    while True:
        try:
            choice = input(f"请选择模板编号 [默认 {default_index}]: ").strip()
        except EOFError:
            print(f"\n[WARN] 未读取到输入，默认使用第 {default_index} 个模板。")
            return templates[default_index - 1]

        if not choice:
            return templates[default_index - 1]
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(templates):
                return templates[index - 1]
        print(f"无效选择: {choice}")


def make_unique_tag(base_tag: str, used: Set[str]) -> str:
    clean_base = str(base_tag).strip() or "node"
    tag = clean_base
    i = 2
    while tag in used:
        tag = f"{clean_base} #{i}"
        i += 1
    used.add(tag)
    return tag


def build_selector(
    tag: str,
    outbounds: List[str],
    default: Optional[str] = None,
    *,
    interrupt_exist_connections: bool = True,
) -> Dict[str, Any]:
    unique_outbounds = list(dict.fromkeys(str(value) for value in outbounds if str(value).strip()))
    if not unique_outbounds:
        raise ValueError(f"selector {tag} 没有候选 outbound")
    obj: Dict[str, Any] = {
        "type": "selector",
        "tag": tag,
        "outbounds": unique_outbounds,
        "interrupt_exist_connections": interrupt_exist_connections,
    }
    if default and default in unique_outbounds:
        obj["default"] = default
    return obj


def build_urltest(
    tag: str,
    outbounds: List[str],
    url: str = DEFAULT_AVAILABLE_URLTEST_URL,
    interval: str = DEFAULT_AVAILABLE_URLTEST_INTERVAL,
    tolerance: int = DEFAULT_AVAILABLE_URLTEST_TOLERANCE,
    idle_timeout: str = DEFAULT_AVAILABLE_URLTEST_IDLE_TIMEOUT,
    *,
    interrupt_exist_connections: bool = True,
) -> Dict[str, Any]:
    unique_outbounds = list(dict.fromkeys(str(value) for value in outbounds if str(value).strip()))
    if len(unique_outbounds) < 2:
        raise ValueError(f"URLTest {tag} 至少需要 2 个唯一节点")
    return {
        "type": "urltest",
        "tag": tag,
        "outbounds": unique_outbounds,
        "url": url,
        "interval": interval,
        "tolerance": tolerance,
        "idle_timeout": idle_timeout,
        "interrupt_exist_connections": interrupt_exist_connections,
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
    base_tag = f"{tag_prefix}/{name}"
    if base_tag not in used_tags:
        used_tags.add(base_tag)
        ob["tag"] = base_tag
        return ob
    fingerprint = str(ob.get("_meta_fingerprint") or outbound_fingerprint(ob))[:8]
    stable_tag = f"{base_tag} [{fingerprint}]"
    ob["tag"] = make_unique_tag(stable_tag, used_tags)
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
        or default_name
    ).strip()
    return tag or default_name


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
            "fetched_from": content.cache_status,
        }
    else:
        item.pop("_subscription_userinfo", None)
    item["_cache_status"] = content.cache_status
    return content.text


def load_source(
    item: Dict[str, Any],
    base_dir: Path,
    user_agent: str,
    cache_dir: Optional[Path],
    fetch_proxy: Optional[str],
    *,
    connect_timeout: int = DEFAULT_FETCH_CONNECT_TIMEOUT,
    read_timeout: int = DEFAULT_FETCH_READ_TIMEOUT,
    retries: int = DEFAULT_FETCH_RETRIES,
    cache_max_stale: str = DEFAULT_CACHE_MAX_STALE,
    offline: bool = False,
) -> LoadedSource:
    source = str(item.get("source") or "url").strip().lower()
    name = str(item.get("name") or "订阅")

    if source == "url":
        url = str(item.get("url") or "").strip()
        if not url:
            raise ValueError(f"订阅组 {item['name']} 缺少 url")
        return fetch_source_with_cache(
            url,
            cache_dir,
            name,
            user_agent=user_agent,
            fetch_proxy=fetch_proxy,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=retries,
            cache_max_stale=cache_max_stale,
            offline=offline,
        )

    if source == "url_file":
        path = str(item.get("path") or "").strip()
        if not path:
            raise ValueError(f"订阅组 {item['name']} 缺少 path")
        url = read_subscription_url(resolve_path(path, base_dir))
        return fetch_source_with_cache(
            url,
            cache_dir,
            name,
            user_agent=user_agent,
            fetch_proxy=fetch_proxy,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=retries,
            cache_max_stale=cache_max_stale,
            offline=offline,
        )

    if source == "file":
        path = str(item.get("path") or "").strip()
        if not path:
            raise ValueError(f"订阅组 {item['name']} 缺少 path")
        item.pop("_subscription_userinfo", None)
        return LoadedSource(
            content=SubscriptionContent(
                text=read_text(resolve_path(path, base_dir)),
                userinfo={},
                from_cache=False,
                cache_status="local-file",
                fetched_at=utc_now_iso(),
            )
        )

    raise ValueError(f"订阅组 {item['name']} 的 source 不支持: {source}")


def load_source_text(
    item: Dict[str, Any],
    base_dir: Path,
    user_agent: str,
    cache_dir: Optional[Path],
    fetch_proxy: Optional[str],
) -> str:
    loaded = load_source(item, base_dir, user_agent, cache_dir, fetch_proxy)
    return attach_subscription_content(item, loaded.content)


def compile_name_patterns(value: Any, label: str) -> List[re.Pattern[str]]:
    patterns: List[re.Pattern[str]] = []
    for pattern in parse_string_list(value):
        try:
            patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"{label} 包含无效正则 {pattern}: {exc}") from exc
    return patterns


def apply_node_filters(item: Dict[str, Any], nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    includes = compile_name_patterns(item.get("include_nodes", item.get("include")), f"{item['name']}.include")
    excludes = compile_name_patterns(item.get("exclude_nodes", item.get("exclude")), f"{item['name']}.exclude")
    overrides = item.get("region_overrides")
    compiled_overrides: List[Tuple[re.Pattern[str], str]] = []
    if isinstance(overrides, dict):
        overrides = [{"pattern": pattern, "region": region} for pattern, region in overrides.items()]
    if isinstance(overrides, list):
        for override in overrides:
            if not isinstance(override, dict):
                continue
            pattern = str(override.get("pattern") or "").strip()
            region = str(override.get("region") or "").strip()
            if not pattern or region not in ALL_REGIONS:
                raise ValueError(f"{item['name']}.region_overrides 格式错误")
            compiled_overrides.append((re.compile(pattern, re.IGNORECASE), region))

    selected: List[Dict[str, Any]] = []
    for node in nodes:
        name = outbound_name(node)
        if includes and not any(pattern.search(name) for pattern in includes):
            continue
        if excludes and any(pattern.search(name) for pattern in excludes):
            continue
        for pattern, region in compiled_overrides:
            if pattern.search(name):
                node["_meta_region"] = region
                break
        selected.append(node)
    return selected


def prepare_subscription(
    item: Dict[str, Any],
    *,
    manifest_base_dir: Path,
    user_agent: str,
    cache_dir: Optional[Path],
    fetch_proxy: Optional[str],
    connect_timeout: int,
    read_timeout: int,
    retries: int,
    cache_max_stale: str,
    offline: bool,
) -> PreparedSubscription:
    working_item = copy.deepcopy(item)
    name = str(working_item["name"])
    parser_name = str(working_item["parser"])
    loaded = load_source(
        working_item,
        manifest_base_dir,
        user_agent,
        cache_dir,
        fetch_proxy,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries=retries,
        cache_max_stale=cache_max_stale,
        offline=offline,
    )

    content = loaded.content
    fallback_warning: Optional[str] = None
    try:
        node_outbounds, info_outbounds, warnings = parse_subscription_text(parser_name, content.text)
    except Exception as remote_error:
        if loaded.cached_fallback is None:
            raise RuntimeError(f"订阅组 {name} 解析失败: {remote_error}") from remote_error
        try:
            node_outbounds, info_outbounds, warnings = parse_subscription_text(
                parser_name,
                loaded.cached_fallback.text,
            )
        except Exception:
            raise RuntimeError(f"订阅组 {name} 新内容及缓存均解析失败: {remote_error}") from remote_error
        content = loaded.cached_fallback
        content.cache_status = "parse-fallback"
        fallback_warning = "新下载内容解析失败，已回退到上次可解析缓存"

    node_outbounds = apply_node_filters(working_item, node_outbounds)
    if not node_outbounds:
        raise RuntimeError(f"订阅组 {name} 没有解析出任何可用节点")

    if content is loaded.content and loaded.write_cache_after_parse and loaded.cache_path:
        write_cached_subscription(loaded.cache_path, content)
    attach_subscription_content(working_item, content)
    if fallback_warning:
        warnings = [fallback_warning] + warnings
    return PreparedSubscription(
        item=working_item,
        node_outbounds=node_outbounds,
        info_outbounds=info_outbounds,
        warnings=warnings,
        cache_status=content.cache_status,
    )


def prepare_subscriptions(
    subscriptions: List[Dict[str, Any]],
    *,
    manifest_base_dir: Path,
    user_agent: str,
    cache_dir: Optional[Path],
    fetch_proxy: Optional[str],
    workers: int = DEFAULT_FETCH_WORKERS,
    connect_timeout: int = DEFAULT_FETCH_CONNECT_TIMEOUT,
    read_timeout: int = DEFAULT_FETCH_READ_TIMEOUT,
    retries: int = DEFAULT_FETCH_RETRIES,
    cache_max_stale: str = DEFAULT_CACHE_MAX_STALE,
    offline: bool = False,
) -> List[PreparedSubscription]:
    results: List[Optional[PreparedSubscription]] = [None] * len(subscriptions)
    max_workers = max(1, min(int(workers), len(subscriptions)))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="subscription") as executor:
        futures = {
            executor.submit(
                prepare_subscription,
                item,
                manifest_base_dir=manifest_base_dir,
                user_agent=user_agent,
                cache_dir=cache_dir,
                fetch_proxy=fetch_proxy,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                retries=retries,
                cache_max_stale=cache_max_stale,
                offline=offline,
            ): index
            for index, item in enumerate(subscriptions)
        }
        try:
            for future in as_completed(futures):
                results[futures[future]] = future.result()
        except Exception:
            for future in futures:
                future.cancel()
            raise
    return [result for result in results if result is not None]


def cleanup_subscription_cache(
    cache_dir: Optional[Path],
    active_urls: Set[str],
    *,
    retention: str = DEFAULT_CACHE_RETENTION,
) -> int:
    if cache_dir is None or not cache_dir.exists():
        return 0
    active_paths = {subscription_cache_path(cache_dir, url).resolve() for url in active_urls}
    cutoff = utc_now().timestamp() - parse_duration_seconds(retention)
    removed = 0
    for cache_path in cache_dir.glob("*.txt"):
        if cache_path.resolve() in active_paths or cache_path.stat().st_mtime >= cutoff:
            continue
        for path in (cache_path, subscription_cache_meta_path(cache_path)):
            try:
                if path.exists():
                    path.unlink()
                    removed += 1
            except OSError as exc:
                print(f"[WARN] 清理订阅缓存失败 {path}: {exc}", file=sys.stderr)
    return removed


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


def resolve_subscription_limit(
    item: Dict[str, Any],
    key: str,
    *,
    platform: str,
    runtime_profile: Dict[str, Any],
    fallback: int,
) -> int:
    limits = item.get("limits")
    if isinstance(limits, dict):
        platform_limits = limits.get(platform)
        if isinstance(platform_limits, dict) and platform_limits.get(key) is not None:
            return max(parse_priority(platform_limits.get(key), default=fallback), 0)
        if limits.get(key) is not None:
            return max(parse_priority(limits.get(key), default=fallback), 0)
    platform_key = f"{key}_{platform}"
    if item.get(platform_key) is not None:
        return max(parse_priority(item.get(platform_key), default=fallback), 0)
    if item.get(key) is not None:
        return max(parse_priority(item.get(key), default=fallback), 0)
    role = str(item.get("role") or "default").strip().lower()
    role_limits = runtime_profile.get("role_limits") if isinstance(runtime_profile.get("role_limits"), dict) else {}
    role_limit = role_limits.get(role) if isinstance(role_limits.get(role), dict) else {}
    if role_limit.get(key) is not None:
        return max(parse_priority(role_limit.get(key), default=fallback), 0)
    return max(int(fallback), 0)


def limit_grouped_total(
    grouped: Dict[str, List[Dict[str, Any]]],
    maximum: int,
) -> Dict[str, List[Dict[str, Any]]]:
    if maximum <= 0 or sum(len(nodes) for nodes in grouped.values()) <= maximum:
        return grouped
    limited: Dict[str, List[Dict[str, Any]]] = {region: [] for region in ALL_REGIONS}
    cursors = {region: 0 for region in ALL_REGIONS}
    while sum(len(nodes) for nodes in limited.values()) < maximum:
        added = False
        for region in ALL_REGIONS:
            cursor = cursors[region]
            nodes = grouped.get(region, [])
            if cursor >= len(nodes):
                continue
            limited[region].append(nodes[cursor])
            cursors[region] += 1
            added = True
            if sum(len(values) for values in limited.values()) >= maximum:
                break
        if not added:
            break
    return limited


def build_provider_group(
    item: Dict[str, Any],
    node_outbounds: List[Dict[str, Any]],
    info_outbounds: List[Dict[str, Any]],
    used_tags: Set[str],
    max_nodes_per_region: int,
    max_other_nodes: int,
    keep_info_nodes: bool,
    platform: str = "windows",
    runtime_profile: Optional[Dict[str, Any]] = None,
    preserve_all_nodes: bool = False,
) -> Dict[str, Any]:
    runtime_profile = runtime_profile or {}
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

    if not preserve_all_nodes:
        allowed_regions = parse_region_filter(item)
        for region in ALL_REGIONS:
            if region not in allowed_regions:
                grouped[region] = []

        effective_max_per_region = resolve_subscription_limit(
            item,
            "max_nodes_per_region",
            platform=platform,
            runtime_profile=runtime_profile,
            fallback=max_nodes_per_region,
        )
        effective_max_other = resolve_subscription_limit(
            item,
            "max_other_nodes",
            platform=platform,
            runtime_profile=runtime_profile,
            fallback=max_other_nodes,
        )
        effective_max_total = resolve_subscription_limit(
            item,
            "max_total_nodes",
            platform=platform,
            runtime_profile=runtime_profile,
            fallback=0,
        )
        grouped = apply_region_limits(grouped, effective_max_per_region, effective_max_other)
        grouped = limit_grouped_total(grouped, effective_max_total)

    if not any(grouped.values()):
        raise RuntimeError(f"订阅组 {name} 没有可用节点")

    selected_nodes: List[Dict[str, Any]] = []
    for region in ALL_REGIONS:
        for ob in grouped.get(region, []):
            node = retag_outbound(ob, provider_tag, used_tags)
            node["_meta_subscription"] = name
            node["_meta_role"] = str(item.get("role") or "default")
            node["_meta_priority"] = int(item.get("priority", 100))
            node["_meta_include_in_available"] = include_in_available
            selected_nodes.append(node)

    region_selector_tags: Dict[str, str] = {}
    control_outbounds: List[Dict[str, Any]] = []
    if parse_bool(item.get("flat_group", item.get("flat")), default=False):
        node_tags = [node["tag"] for node in selected_nodes]
        info_tags = [info["tag"] for info in active_info_outbounds]
        provider_urltest_enabled = parse_bool(item.get("urltest", item.get("auto_select")), default=False)
        if parse_bool(runtime_profile.get("disable_provider_urltests"), default=False):
            provider_urltest_enabled = False
        if provider_urltest_enabled and len(node_tags) >= 2:
            urltest_url = str(
                item.get("urltest_url")
                or item.get("test_url")
                or DEFAULT_AVAILABLE_URLTEST_URL
            ).strip()
            urltest_interval = str(item.get("urltest_interval") or DEFAULT_AVAILABLE_URLTEST_INTERVAL).strip()
            urltest_tolerance = parse_priority(
                item.get("urltest_tolerance"),
                default=DEFAULT_AVAILABLE_URLTEST_TOLERANCE,
            )
            urltest_idle_timeout = str(
                item.get("urltest_idle_timeout")
                or runtime_profile.get("urltest_idle_timeout")
                or DEFAULT_AVAILABLE_URLTEST_IDLE_TIMEOUT
            ).strip()
            if info_tags:
                auto_tag = make_unique_tag(f"{provider_tag}/Auto", used_tags)
                control_outbounds.append(
                    build_selector(provider_tag, info_tags + [auto_tag] + node_tags + ["direct"], default=auto_tag)
                )
                control_outbounds.append(
                    build_urltest(
                        auto_tag,
                        node_tags,
                        url=urltest_url,
                        interval=urltest_interval,
                        tolerance=urltest_tolerance,
                        idle_timeout=urltest_idle_timeout,
                    )
                )
            else:
                control_outbounds.append(
                    build_urltest(
                        provider_tag,
                        node_tags,
                        url=urltest_url,
                        interval=urltest_interval,
                        tolerance=urltest_tolerance,
                        idle_timeout=urltest_idle_timeout,
                    )
                )
        else:
            control_outbounds.append(build_selector(provider_tag, info_tags + node_tags + ["direct"], default=node_tags[0]))
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
    ]
    provider_choices = [info["tag"] for info in active_info_outbounds] + provider_choices + ["direct"]
    provider_default = choose_default(
        provider_choices,
        [
            region_selector_tags[region]
            for region in ["HK", "TW", "JP", "SG", "US", "FR", "GB", "Others"]
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
    user_agent: str = "clash-verge/v2.5.1",
    cache_dir: Optional[Path] = Path(DEFAULT_SUBSCRIPTION_CACHE_DIR),
    fetch_proxy: Optional[str] = None,
    available_urltest: bool = False,
    available_urltest_url: str = DEFAULT_AVAILABLE_URLTEST_URL,
    available_urltest_interval: str = DEFAULT_AVAILABLE_URLTEST_INTERVAL,
    available_urltest_tolerance: int = DEFAULT_AVAILABLE_URLTEST_TOLERANCE,
    available_urltest_idle_timeout: str = DEFAULT_AVAILABLE_URLTEST_IDLE_TIMEOUT,
    available_urltest_exclude_roles: Optional[Set[str]] = None,
    provider_default_tag: Optional[str] = None,
    profile: Optional[Dict[str, Any]] = None,
    fetch_workers: int = DEFAULT_FETCH_WORKERS,
    fetch_connect_timeout: int = DEFAULT_FETCH_CONNECT_TIMEOUT,
    fetch_read_timeout: int = DEFAULT_FETCH_READ_TIMEOUT,
    fetch_retries: int = DEFAULT_FETCH_RETRIES,
    cache_max_stale: str = DEFAULT_CACHE_MAX_STALE,
    health_state_path: Optional[Path] = None,
    generation_metadata: Optional[Dict[str, Any]] = None,
    offline: bool = False,
    policy_aliases: Optional[Dict[str, str]] = None,
    preserve_all_nodes: bool = False,
    included_regions: Optional[Set[str]] = None,
    unfiltered_roles: Optional[Set[str]] = None,
    skip_empty_groups: bool = False,
    policy_alias_fallback: Optional[str] = None,
) -> Dict[str, Any]:
    profile = profile or {}
    runtime_profile = profile.get("runtime") if isinstance(profile.get("runtime"), dict) else {}
    auto_profile = profile.get("auto") if isinstance(profile.get("auto"), dict) else {}
    control_profile = profile.get("control") if isinstance(profile.get("control"), dict) else {}
    platform = str(profile.get("platform") or "windows")
    policy_aliases = policy_aliases or {}
    if included_regions is not None:
        included_regions = {str(region).strip() for region in included_regions if str(region).strip()}
        invalid_regions = sorted(included_regions - set(ALL_REGIONS))
        if invalid_regions:
            raise ValueError(f"包含未知地区: {', '.join(invalid_regions)}")
    unfiltered_roles = {
        str(role).strip().lower()
        for role in (unfiltered_roles or set())
        if str(role).strip()
    }
    used_tags: Set[str] = {
        "Available",
        "Available/Auto",
        "AI",
        "AI/Auto",
        "DNS-Out",
        "Update-Out",
        "Control/Auto",
        "Info",
        "Public",
        "direct",
        "block",
    }
    used_tags.update(policy_aliases)
    built_groups: List[Dict[str, Any]] = []
    metadata = generation_metadata if generation_metadata is not None else {}
    metadata.clear()
    metadata.update(
        {
            "profile": str(profile.get("name") or "legacy"),
            "platform": platform,
            "deduplicated_nodes": 0,
            "preserve_all_nodes": preserve_all_nodes,
            "included_regions": sorted(included_regions) if included_regions is not None else None,
            "unfiltered_roles": sorted(unfiltered_roles),
            "cache_statuses": {},
            "pools": {},
        }
    )

    prepared = prepare_subscriptions(
        subscriptions,
        manifest_base_dir=manifest_base_dir,
        user_agent=user_agent,
        cache_dir=cache_dir,
        fetch_proxy=fetch_proxy,
        workers=fetch_workers,
        connect_timeout=fetch_connect_timeout,
        read_timeout=fetch_read_timeout,
        retries=fetch_retries,
        cache_max_stale=cache_max_stale,
        offline=offline,
    )
    subscriptions[:] = [entry.item for entry in prepared]

    seen_fingerprints: Dict[str, str] = {}
    for entry in prepared:
        item = entry.item
        name = str(item["name"])
        role = str(item.get("role") or "default").strip().lower()
        keep_all_regions = (
            role in unfiltered_roles
            or str(item.get("_simple_group_kind") or "").strip().lower() == "self-hosted"
        )
        unique_nodes: List[Dict[str, Any]] = []
        candidate_nodes = entry.node_outbounds
        if included_regions is not None and not keep_all_regions:
            candidate_nodes = [
                node for node in candidate_nodes if outbound_region(node) in included_regions
            ]
        for node in candidate_nodes:
            fingerprint = outbound_fingerprint(node)
            if fingerprint in seen_fingerprints:
                metadata["deduplicated_nodes"] += 1
                continue
            seen_fingerprints[fingerprint] = name
            node["_meta_fingerprint"] = fingerprint
            node["_meta_insecure"] = is_insecure_outbound(node)
            unique_nodes.append(node)

        for warning in entry.warnings:
            print(f"[WARN] {name}: {warning}", file=sys.stderr)
        metadata["cache_statuses"][name] = entry.cache_status

        info_outbounds = entry.info_outbounds
        subscription_userinfo = item.get("_subscription_userinfo")
        if isinstance(subscription_userinfo, dict) and subscription_userinfo:
            info_outbounds.append(build_subscription_userinfo_outbound(name, subscription_userinfo))

        if not unique_nodes:
            optional_roles = {
                str(value).strip().lower()
                for value in parse_string_list(runtime_profile.get("optional_roles"))
                if str(value).strip()
            }
            if included_regions is not None and not keep_all_regions and not candidate_nodes:
                reason = f"订阅组 {name} 没有指定地区节点"
            else:
                reason = f"订阅组 {name} 的节点全部与更高优先级订阅重复"
            if skip_empty_groups or str(item.get("role") or "default").strip().lower() in optional_roles:
                metadata.setdefault("skipped_subscriptions", []).append({"name": name, "reason": reason})
                print(f"[WARN] {reason}，该可选订阅组已跳过", file=sys.stderr)
                continue
            raise RuntimeError(reason)

        try:
            built_group = build_provider_group(
                item=item,
                node_outbounds=unique_nodes,
                info_outbounds=info_outbounds,
                used_tags=used_tags,
                max_nodes_per_region=max_nodes_per_region,
                max_other_nodes=max_other_nodes,
                keep_info_nodes=keep_info_nodes,
                platform=platform,
                runtime_profile=runtime_profile,
                preserve_all_nodes=preserve_all_nodes,
            )
        except RuntimeError as exc:
            optional_roles = {
                str(value).strip().lower()
                for value in parse_string_list(runtime_profile.get("optional_roles"))
                if str(value).strip()
            }
            if not skip_empty_groups and str(item.get("role") or "default").strip().lower() not in optional_roles:
                raise
            metadata.setdefault("skipped_subscriptions", []).append(
                {"name": name, "reason": str(exc)}
            )
            print(f"[WARN] {name}: {exc}，该可选订阅组已跳过", file=sys.stderr)
            continue
        built_groups.append(built_group)

    if not built_groups:
        raise RuntimeError("没有可用订阅组")

    if not any(group["node_outbounds"] for group in built_groups):
        raise RuntimeError("没有可用节点")

    provider_default = choose_provider_default(built_groups)
    provider_default_tag = str(provider_default_tag or "").strip()
    if provider_default_tag:
        if any(str(group["provider_tag"]) == provider_default_tag for group in built_groups):
            provider_default = provider_default_tag
        else:
            print(f"[WARN] 未找到指定默认订阅组: {provider_default_tag}", file=sys.stderr)
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

    all_proxy_nodes = [
        node_ob
        for group in built_groups
        for node_ob in group["node_outbounds"]
        if node_ob.get("tag")
    ]
    legacy_excluded_roles = {
        str(role).strip().lower()
        for role in (available_urltest_exclude_roles or set())
        if str(role).strip()
    }
    include_roles = {
        str(value).strip().lower()
        for value in parse_string_list(auto_profile.get("include_roles"))
        if str(value).strip()
    }
    fallback_roles = {
        str(value).strip().lower()
        for value in parse_string_list(auto_profile.get("fallback_roles"))
        if str(value).strip()
    }
    include_roles -= legacy_excluded_roles
    fallback_roles -= legacy_excluded_roles
    exclude_insecure = parse_bool(auto_profile.get("exclude_insecure"), default=False)
    health_state = load_health_state(health_state_path)

    def filter_pool_nodes(
        roles: Set[str],
        *,
        regions: Optional[Set[str]] = None,
        require_available: bool = False,
    ) -> List[Dict[str, Any]]:
        candidates = []
        for node in all_proxy_nodes:
            role = str(node.get("_meta_role") or "default").strip().lower()
            if roles and role not in roles:
                continue
            if regions and outbound_region(node) not in regions:
                continue
            if require_available and not bool(node.get("_meta_include_in_available")):
                continue
            if exclude_insecure and bool(node.get("_meta_insecure")):
                continue
            candidates.append(node)
        return candidates

    def candidates_with_fallback(
        *,
        regions: Optional[Set[str]] = None,
        require_available: bool = False,
    ) -> List[Dict[str, Any]]:
        primary = filter_pool_nodes(include_roles, regions=regions, require_available=require_available)
        fallback = filter_pool_nodes(fallback_roles, regions=regions, require_available=require_available)
        known = {str(node.get("_meta_fingerprint")) for node in primary}
        return primary + [node for node in fallback if str(node.get("_meta_fingerprint")) not in known]

    auto_enabled = available_urltest and parse_bool(auto_profile.get("enabled"), default=True)
    auto_url = str(auto_profile.get("url") or available_urltest_url)
    auto_interval = str(auto_profile.get("interval") or available_urltest_interval)
    auto_tolerance = parse_priority(auto_profile.get("tolerance"), default=available_urltest_tolerance)
    auto_idle_timeout = str(auto_profile.get("idle_timeout") or available_urltest_idle_timeout)

    control_include_roles = {
        str(value).strip().lower()
        for value in parse_string_list(control_profile.get("include_roles"))
        if str(value).strip()
    }
    control_fallback_roles = {
        str(value).strip().lower()
        for value in parse_string_list(control_profile.get("fallback_roles"))
        if str(value).strip()
    }
    control_exclude_insecure = parse_bool(control_profile.get("exclude_insecure"), default=True)
    control_candidates = []
    for roles in (control_include_roles, control_fallback_roles):
        for node in all_proxy_nodes:
            role = str(node.get("_meta_role") or "default").strip().lower()
            if roles and role not in roles:
                continue
            if control_exclude_insecure and bool(node.get("_meta_insecure")):
                continue
            if node not in control_candidates:
                control_candidates.append(node)
    control_max = parse_priority(control_profile.get("max_nodes"), default=0)
    control_nodes = select_diverse_candidates(
        control_candidates,
        maximum=control_max,
        health_state=health_state,
        preferred_regions=["Others", "HK", "JP", "SG", "US"],
    )
    reserved_fingerprints = {str(node.get("_meta_fingerprint")) for node in control_nodes}

    ai_regions = set(parse_string_list(auto_profile.get("ai_regions")) or AI_PREFERRED_REGIONS)
    ai_max = parse_priority(auto_profile.get("ai_max"), default=0)
    ai_nodes = (
        select_diverse_candidates(
            candidates_with_fallback(regions=ai_regions),
            maximum=ai_max,
            health_state=health_state,
            preferred_regions=parse_string_list(auto_profile.get("ai_regions")) or AI_PREFERRED_REGIONS,
            excluded_fingerprints=reserved_fingerprints,
        )
        if auto_enabled
        else []
    )
    reserved_fingerprints.update(str(node.get("_meta_fingerprint")) for node in ai_nodes)

    available_max = parse_priority(
        auto_profile.get("available_max"),
        default=len(all_proxy_nodes) if auto_enabled else 0,
    )
    available_nodes = (
        select_diverse_candidates(
            candidates_with_fallback(require_available=True),
            maximum=available_max,
            health_state=health_state,
            preferred_regions=parse_string_list(auto_profile.get("available_regions")) or HOT_REGIONS,
            excluded_fingerprints=reserved_fingerprints,
        )
        if auto_enabled
        else []
    )

    pool_outbounds: List[Dict[str, Any]] = []

    def create_pool(tag: str, nodes: List[Dict[str, Any]], *, interval: str, tolerance: int, idle_timeout: str) -> Optional[str]:
        node_tags = [str(node["tag"]) for node in nodes]
        if not node_tags:
            return None
        if len(node_tags) == 1:
            return node_tags[0]
        pool_outbounds.append(
            build_urltest(
                tag,
                node_tags,
                url=auto_url,
                interval=interval,
                tolerance=tolerance,
                idle_timeout=idle_timeout,
            )
        )
        return tag

    control_choice = create_pool(
        "Control/Auto",
        control_nodes,
        interval=str(control_profile.get("urltest_interval") or "1h"),
        tolerance=parse_priority(control_profile.get("tolerance"), default=150),
        idle_timeout=str(control_profile.get("idle_timeout") or "1h"),
    ) or ("direct" if control_max <= 0 else provider_default)
    ai_auto_choice = create_pool(
        "AI/Auto",
        ai_nodes,
        interval=auto_interval,
        tolerance=auto_tolerance,
        idle_timeout=auto_idle_timeout,
    )
    available_auto_choice = create_pool(
        "Available/Auto",
        available_nodes,
        interval=auto_interval,
        tolerance=auto_tolerance,
        idle_timeout=auto_idle_timeout,
    )
    if available_auto_choice:
        available_choices = [available_auto_choice] + [
            choice for choice in available_choices if choice != available_auto_choice
        ]

    paid_ai_groups: List[str] = []
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
        us_selector = group.get("region_selector_tags", {}).get("US")
        if us_selector:
            append_unique(ai_groups, str(us_selector))
    if ai_auto_choice:
        ai_groups = [ai_auto_choice] + [tag for tag in ai_groups if tag != ai_auto_choice]

    outbounds: List[Dict[str, Any]] = []
    outbounds.append(build_selector("Available", available_choices, default=available_auto_choice or provider_default))
    outbounds.append(build_selector("AI", ai_groups, default=ai_auto_choice or ai_groups[0]))
    outbounds.append(build_selector("DNS-Out", [control_choice, "direct"], default=control_choice))
    update_choices = [control_choice, "direct", available_auto_choice or provider_default]
    outbounds.append(build_selector("Update-Out", update_choices, default=control_choice))
    outbounds.extend(pool_outbounds)
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
                for region in ["HK", "JP", "SG", "TW", "US", "FR", "GB", "Others"]
                if region in public_region_selector_tags
            ] + ["direct"],
        )
        outbounds.append(build_selector("Public", public_choices, default=public_default))
    outbounds.extend(public_control_outbounds)
    for group in built_groups:
        outbounds.extend(group["control_outbounds"])

    resolved_aliases: Dict[str, str] = {}
    for alias, target in policy_aliases.items():
        matching_group = next(
            (
                group
                for group in built_groups
                if target in {str(group.get("name")), str(group.get("provider_tag"))}
            ),
            None,
        )
        if matching_group is None:
            fallback = str(policy_alias_fallback or "").strip()
            if not fallback:
                raise RuntimeError(f"策略别名 {alias} 的目标订阅组不存在: {target}")
            outbounds.append(build_selector(alias, [fallback], default=fallback))
            resolved_aliases[alias] = fallback
            metadata.setdefault("policy_alias_fallbacks", {})[alias] = {
                "target": target,
                "fallback": fallback,
            }
            print(
                f"[WARN] 策略别名 {alias} 的目标订阅组不存在，已回退到 {fallback}",
                file=sys.stderr,
            )
            continue
        resolved_target = str(matching_group["provider_tag"])
        outbounds.append(build_selector(alias, [resolved_target], default=resolved_target))
        resolved_aliases[alias] = resolved_target

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

    conf = copy.deepcopy(template)
    conf["outbounds"] = outbounds
    metadata["pools"] = {
        "control": len(control_nodes),
        "ai": len(ai_nodes),
        "available": len(available_nodes),
    }
    metadata["proxy_nodes_before_limits"] = len(seen_fingerprints)
    metadata["proxy_nodes_after_limits"] = sum(len(group["node_outbounds"]) for group in built_groups)
    metadata["policy_aliases"] = resolved_aliases
    return conf


def write_nodes_report(
    conf: Dict[str, Any],
    report_path: Path,
    subscriptions: List[Dict[str, Any]],
    *,
    generation_metadata: Optional[Dict[str, Any]] = None,
    audit_report: Optional[Dict[str, Any]] = None,
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
            subscription_report["subscription_userinfo"] = {
                key: value
                for key, value in subscription_userinfo.items()
                if key not in {"raw", "fields"}
            }

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
            for tag in ["Available", "AI", "DNS-Out", "Update-Out", "Public", "Info"]
            if tag in selector_tags
        ],
    }
    if generation_metadata:
        report["generation"] = generation_metadata
    if audit_report:
        report["audit"] = audit_report

    atomic_write_json(report_path, report)


def get_clash_ui_url(conf: Dict[str, Any]) -> Optional[str]:
    clash_api = (
        conf.get("experimental", {})
        .get("clash_api", {})
    )
    if not str(clash_api.get("external_ui") or "").strip():
        return None
    controller = str(clash_api.get("external_controller") or "").strip()
    if not controller:
        return None
    if controller.startswith(("http://", "https://")):
        base_url = controller.rstrip("/")
    else:
        base_url = f"http://{controller.rstrip('/')}"
    return f"{base_url}/"


def print_config_summary(
    conf: Dict[str, Any],
    template_path: Path,
    output_path: Path,
    subscriptions: List[Dict[str, Any]],
    *,
    platform: Optional[str] = None,
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
    main_selectors = [
        tag
        for tag in ("Available", "AI", "DNS-Out", "Update-Out", "Public", "Info")
        if tag in selector_tags
    ]
    urltest_members = sum(
        len(ob.get("outbounds", []))
        for ob in outbounds
        if isinstance(ob, dict) and ob.get("type") == "urltest"
    )
    ui_url = get_clash_ui_url(conf)

    print(f"完成: 已根据 {template_path} 生成 {output_path}")
    print(
        f"摘要: 订阅组 {len(subscriptions)} 个，代理节点 {proxy_count} 个，"
        f"手动分组 {len(selector_tags)} 个，测速成员 {urltest_members} 个"
    )
    if main_selectors:
        print(f"主分组: {', '.join(main_selectors)}")
    if ui_url:
        print(f"面板: {ui_url}")
    if str(platform or "").lower() == "android" or "android" in template_path.name.lower():
        print(f"下一步: 将 {output_path} 导入 Android sing-box；本机可用 runtime\\cores\\<版本>\\sing-box.exe check -c {output_path} 做基础校验")
    else:
        print(f"下一步: runtime\\cores\\<版本>\\sing-box.exe check -c {output_path}，通过后运行 runtime\\services\\singbox-service.exe restart")


def resolve_profile_file(profile: Dict[str, Any], value: Any) -> Optional[Path]:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text)
    if path.is_absolute():
        return path
    return Path(str(profile.get("_base_dir") or ".")) / path


def load_or_create_secret(path: Path, *, length: int = 32) -> str:
    if path.exists():
        secret = path.read_text(encoding="utf-8").strip()
        if secret:
            return secret
    secret = secrets.token_urlsafe(length)
    atomic_write_text(path, secret + "\n")
    return secret


def active_subscription_urls(subscriptions: List[Dict[str, Any]], base_dir: Path) -> Set[str]:
    urls: Set[str] = set()
    for item in subscriptions:
        source = str(item.get("source") or "url").strip().lower()
        if source == "url" and str(item.get("url") or "").strip():
            urls.add(str(item["url"]).strip())
        elif source == "url_file" and str(item.get("path") or "").strip():
            try:
                urls.add(read_subscription_url(resolve_path(str(item["path"]), base_dir)))
            except Exception:
                continue
    return urls


def main() -> None:
    parser = argparse.ArgumentParser(description="生成 sing-box 配置，支持多订阅、地区分组和 AI 分流")
    parser.add_argument("--profile", default=None, help="配置档位 YAML，例如 profiles/desktop-dev.yaml")
    parser.add_argument("--list-profiles", action="store_true", help="列出 profiles/*.yaml 后退出")
    parser.add_argument(
        "--subscriptions",
        default="config/local/subscriptions.yaml",
        help="订阅组清单，默认 config/local/subscriptions.yaml",
    )
    parser.add_argument("--sub-url", default=None, help="兼容旧用法：单个 Clash 订阅链接")
    parser.add_argument("--sub-file", default=None, help="兼容旧用法：本地 Clash YAML 文件")
    parser.add_argument("--sub-name", default="example-provider", help="兼容旧用法下的订阅组名称")
    parser.add_argument("--sub-parser", default="clash", help="兼容旧用法下的解析器，默认 clash")
    parser.add_argument("--subscription-file", default="config/local/subscriptions/example-provider.txt", help="默认订阅链接文件")
    parser.add_argument("--template", default=None, help="模板文件路径；未指定时从 config/local/templates/ 交互选择")
    parser.add_argument("--template-dir", default=DEFAULT_TEMPLATE_DIR, help="模板目录，默认 config/local/templates")
    parser.add_argument("--list-templates", action="store_true", help="列出可用模板后退出")
    parser.add_argument("--output", default=None, help="输出文件路径")
    parser.add_argument("--report", default=None, help="节点报告输出路径")
    parser.add_argument("--audit-output", default=None, help="配置审计 JSON 输出路径")
    parser.add_argument("--no-report", action="store_true", help="不生成节点报告")
    parser.add_argument(
        "--max-nodes-per-region",
        type=int,
        default=None,
        help="每个地区最多保留几个节点，默认不限，0 表示不限",
    )
    parser.add_argument(
        "--max-other-nodes",
        type=int,
        default=None,
        help="Others 分组最多保留几个节点，默认不限，0 表示不限",
    )
    parser.add_argument("--clash-secret", default=None, help="覆盖模板里的 clash_api.secret")
    parser.add_argument("--clash-secret-file", default=None, help="读取或创建 Clash API secret 文件")
    parser.add_argument("--user-agent", default="clash-verge/v2.5.1", help="自定义请求头 User-Agent")
    parser.add_argument(
        "--subscription-cache-dir",
        default=DEFAULT_SUBSCRIPTION_CACHE_DIR,
        help="订阅下载成功后的本地缓存目录，默认 runtime/subscription-cache",
    )
    parser.add_argument(
        "--no-subscription-cache",
        action="store_true",
        help="禁用订阅下载缓存和失败回退",
    )
    parser.add_argument("--offline", action="store_true", help="不访问网络，仅使用未过期订阅缓存")
    parser.add_argument(
        "--fetch-proxy",
        default=None,
        help="下载订阅时使用的 HTTP/SOCKS 代理，例如 http://127.0.0.1:7890",
    )
    parser.add_argument("--fetch-workers", type=int, default=None, help="订阅并发下载数")
    parser.add_argument("--fetch-connect-timeout", type=int, default=None, help="订阅连接超时秒数")
    parser.add_argument("--fetch-read-timeout", type=int, default=None, help="订阅读取超时秒数")
    parser.add_argument("--fetch-retries", type=int, default=None, help="订阅下载重试次数")
    parser.add_argument("--cache-max-stale", default=None, help="失败回退缓存最大陈旧时间，例如 7d")
    parser.add_argument("--cache-retention", default=None, help="未使用订阅缓存保留时间，例如 30d")
    parser.add_argument(
        "--available-urltest",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="为 Available/AI 增加经过限额的自动测速池",
    )
    parser.add_argument(
        "--available-urltest-url",
        default=None,
        help=f"自动测速地址，默认 {DEFAULT_AVAILABLE_URLTEST_URL}",
    )
    parser.add_argument(
        "--available-urltest-interval",
        default=None,
        help=f"自动测速间隔，默认 {DEFAULT_AVAILABLE_URLTEST_INTERVAL}",
    )
    parser.add_argument(
        "--available-urltest-tolerance",
        type=int,
        default=None,
        help=f"自动测速容差，默认 {DEFAULT_AVAILABLE_URLTEST_TOLERANCE}",
    )
    parser.add_argument("--available-urltest-idle-timeout", default=None, help="测速池空闲停止时间")
    parser.add_argument(
        "--available-urltest-exclude-roles",
        default="",
        help="自动测速组排除的订阅角色，逗号分隔，例如 primary",
    )
    parser.add_argument("--provider-default-tag", default=None, help="覆盖默认订阅组标签，例如 example-provider")
    parser.add_argument("--keep-info-nodes", action="store_true", help="保留订阅信息节点（默认不保留）")
    parser.add_argument("--discard-info-nodes", action="store_true", help="兼容旧参数：不保留订阅信息节点")

    args = parser.parse_args()

    if args.list_profiles:
        for profile_path in sorted(Path("profiles").glob("*.yaml")):
            if not profile_path.name.startswith("_"):
                print(profile_path)
        return

    profile: Dict[str, Any] = {}
    if args.profile:
        try:
            profile = load_profile(args.profile)
        except Exception as exc:
            print(f"读取配置档位失败: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.list_templates:
        templates = discover_templates(Path(args.template_dir))
        if templates:
            print_template_choices(templates)
        else:
            print(f"未找到模板文件: {Path(args.template_dir)}/*.json")
        return

    if args.max_nodes_per_region is not None and args.max_nodes_per_region < 0:
        print("--max-nodes-per-region 必须 >= 0", file=sys.stderr)
        sys.exit(1)

    if args.max_other_nodes is not None and args.max_other_nodes < 0:
        print("--max-other-nodes 必须 >= 0", file=sys.stderr)
        sys.exit(1)

    if args.available_urltest_tolerance is not None and args.available_urltest_tolerance < 0:
        print("--available-urltest-tolerance 必须 >= 0", file=sys.stderr)
        sys.exit(1)

    profile_template_path = resolve_profile_file(profile, profile.get("template")) if profile else None
    template_path = (
        Path(args.template)
        if args.template
        else profile_template_path
        if profile_template_path is not None
        else choose_template_interactively(Path(args.template_dir))
    )
    if not template_path.exists():
        print(f"模板文件不存在: {template_path}", file=sys.stderr)
        sys.exit(1)

    try:
        template = load_json(str(template_path))
    except Exception as e:
        print(f"读取模板失败: {e}", file=sys.stderr)
        sys.exit(1)

    clash_secret = args.clash_secret
    secret_path: Optional[Path] = None
    if clash_secret is None:
        requested_secret_file = args.clash_secret_file
        if requested_secret_file:
            secret_path = Path(requested_secret_file)
        elif profile:
            clash_profile = profile.get("clash_api") if isinstance(profile.get("clash_api"), dict) else {}
            secret_path = resolve_profile_file(profile, clash_profile.get("secret_file"))
        if secret_path is not None:
            clash_secret = load_or_create_secret(secret_path)
    if profile:
        try:
            template = apply_profile_to_template(template, profile, clash_secret=clash_secret)
        except Exception as exc:
            print(f"应用配置档位失败: {exc}", file=sys.stderr)
            sys.exit(1)
    elif clash_secret is not None:
        try:
            template["experimental"]["clash_api"]["secret"] = clash_secret
        except Exception:
            pass

    try:
        single_subscription = make_single_subscription_from_args(args)
        subscriptions_path = Path(args.subscriptions)
        subscriptions = single_subscription or load_subscription_manifest(subscriptions_path, args.subscription_file)
        manifest_base_dir = subscriptions_path.parent if subscriptions_path.parent != Path("") else Path(".")
        cache_dir = None if args.no_subscription_cache else Path(args.subscription_cache_dir)
        fetch_profile = profile.get("fetch") if isinstance(profile.get("fetch"), dict) else {}
        runtime_profile = profile.get("runtime") if isinstance(profile.get("runtime"), dict) else {}
        auto_profile = profile.get("auto") if isinstance(profile.get("auto"), dict) else {}

        output_path = Path(args.output) if args.output else resolve_profile_file(profile, profile.get("output")) if profile else Path("config.json")
        report_path = Path(args.report) if args.report else resolve_profile_file(profile, profile.get("report")) if profile else Path("nodes-report.json")
        if output_path is None:
            output_path = Path("config.json")
        if report_path is None:
            report_path = Path("nodes-report.json")

        max_nodes_per_region = (
            args.max_nodes_per_region
            if args.max_nodes_per_region is not None
            else DEFAULT_MAX_NODES_PER_REGION
        )
        max_other_nodes = args.max_other_nodes if args.max_other_nodes is not None else DEFAULT_MAX_OTHER_NODES
        keep_info_nodes = args.keep_info_nodes and not args.discard_info_nodes
        if not args.keep_info_nodes and profile:
            keep_info_nodes = parse_bool(runtime_profile.get("keep_info_nodes"), default=False)
        available_urltest = (
            args.available_urltest
            if args.available_urltest is not None
            else parse_bool(auto_profile.get("enabled"), default=False)
        )
        available_urltest_url = str(
            args.available_urltest_url or auto_profile.get("url") or DEFAULT_AVAILABLE_URLTEST_URL
        )
        available_urltest_interval = str(
            args.available_urltest_interval or auto_profile.get("interval") or DEFAULT_AVAILABLE_URLTEST_INTERVAL
        )
        available_urltest_tolerance = (
            args.available_urltest_tolerance
            if args.available_urltest_tolerance is not None
            else parse_priority(auto_profile.get("tolerance"), default=DEFAULT_AVAILABLE_URLTEST_TOLERANCE)
        )
        available_urltest_idle_timeout = str(
            args.available_urltest_idle_timeout
            or auto_profile.get("idle_timeout")
            or DEFAULT_AVAILABLE_URLTEST_IDLE_TIMEOUT
        )
        health_state_path = resolve_profile_file(profile, runtime_profile.get("health_state")) if profile else None
        policy_aliases_path = resolve_profile_file(profile, profile.get("policy_aliases_file")) if profile else None
        policy_aliases = load_policy_aliases(policy_aliases_path)
        generation_metadata: Dict[str, Any] = {}

        conf = build_config_from_subscriptions(
            subscriptions=subscriptions,
            template=template,
            manifest_base_dir=manifest_base_dir,
            max_nodes_per_region=max_nodes_per_region,
            max_other_nodes=max_other_nodes,
            keep_info_nodes=keep_info_nodes,
            user_agent=args.user_agent,
            cache_dir=cache_dir,
            fetch_proxy=args.fetch_proxy,
            available_urltest=available_urltest,
            available_urltest_url=available_urltest_url,
            available_urltest_interval=available_urltest_interval,
            available_urltest_tolerance=available_urltest_tolerance,
            available_urltest_idle_timeout=available_urltest_idle_timeout,
            available_urltest_exclude_roles=set(parse_string_list(args.available_urltest_exclude_roles)),
            provider_default_tag=args.provider_default_tag,
            profile=profile,
            fetch_workers=args.fetch_workers or int(fetch_profile.get("workers") or DEFAULT_FETCH_WORKERS),
            fetch_connect_timeout=args.fetch_connect_timeout
            or int(fetch_profile.get("connect_timeout") or DEFAULT_FETCH_CONNECT_TIMEOUT),
            fetch_read_timeout=args.fetch_read_timeout
            or int(fetch_profile.get("read_timeout") or DEFAULT_FETCH_READ_TIMEOUT),
            fetch_retries=args.fetch_retries
            if args.fetch_retries is not None
            else int(fetch_profile.get("retries") or DEFAULT_FETCH_RETRIES),
            cache_max_stale=str(args.cache_max_stale or fetch_profile.get("cache_max_stale") or DEFAULT_CACHE_MAX_STALE),
            health_state_path=health_state_path,
            generation_metadata=generation_metadata,
            offline=args.offline,
            policy_aliases=policy_aliases,
        )
        validation_limits = profile.get("validation") if isinstance(profile.get("validation"), dict) else {}
        audit_report = require_valid_config(conf, validation_limits)
        save_json(str(output_path), conf)
        audit_output_path = Path(args.audit_output) if args.audit_output else Path("validation") / f"{profile.get('name', 'legacy')}.json"
        atomic_write_json(audit_output_path, audit_report)
        if not args.no_report:
            write_nodes_report(
                conf,
                report_path,
                subscriptions,
                generation_metadata=generation_metadata,
                audit_report=audit_report,
            )
        retention = str(args.cache_retention or fetch_profile.get("cache_retention") or DEFAULT_CACHE_RETENTION)
        cleanup_subscription_cache(
            cache_dir,
            active_subscription_urls(subscriptions, manifest_base_dir),
            retention=retention,
        )
    except ConfigAuditError as e:
        for message in e.messages:
            print(f"[AUDIT] {message}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"生成失败: {e}", file=sys.stderr)
        sys.exit(1)

    print_config_summary(
        conf,
        template_path,
        output_path,
        subscriptions,
        platform=str(profile.get("platform") or "") if profile else None,
    )


if __name__ == "__main__":
    main()

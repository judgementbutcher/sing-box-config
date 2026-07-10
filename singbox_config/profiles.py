from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Dict, Iterable

import yaml


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if key == "extends":
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _load_profile_data(profile_path: Path, seen: set[Path]) -> Dict[str, Any]:
    resolved = profile_path.resolve()
    if resolved in seen:
        raise ValueError(f"配置档位 extends 存在循环: {profile_path}")
    seen.add(resolved)
    with profile_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"配置档位格式错误: {profile_path}")
    parent = data.get("extends")
    if not parent:
        return data
    parent_path = Path(str(parent))
    if not parent_path.is_absolute():
        parent_path = profile_path.parent / parent_path
    return _deep_merge(_load_profile_data(parent_path, seen), data)


def load_profile(path: Path | str) -> Dict[str, Any]:
    profile_path = Path(path)
    data = _load_profile_data(profile_path, set())
    name = str(data.get("name") or profile_path.stem).strip()
    platform = str(data.get("platform") or "").strip().lower()
    if platform not in {"windows", "android"}:
        raise ValueError(f"配置档位 platform 必须是 windows 或 android: {profile_path}")
    core = data.get("core")
    if not isinstance(core, dict) or not str(core.get("version") or "").strip():
        raise ValueError(f"配置档位缺少 core.version: {profile_path}")
    result = copy.deepcopy(data)
    result["name"] = name
    result["platform"] = platform
    result["_path"] = str(profile_path)
    result["_base_dir"] = str(profile_path.parent)
    return result


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        raise ValueError(f"无法识别 sing-box 版本: {value}")
    return tuple(int(part or 0) for part in match.groups())


def _find_tun_inbound(conf: Dict[str, Any]) -> Dict[str, Any] | None:
    for inbound in conf.get("inbounds", []):
        if isinstance(inbound, dict) and inbound.get("type") == "tun":
            return inbound
    return None


def _strip_tun_ipv6_addresses(tun: Dict[str, Any]) -> None:
    """Keep the virtual TUN interface IPv4-addressed on every platform."""

    addresses = tun.get("address")
    if addresses is None:
        return
    if not isinstance(addresses, list):
        raise ValueError("tun inbound 的 address 必须是数组")
    ipv4_addresses = [address for address in addresses if ":" not in str(address)]
    if not ipv4_addresses:
        raise ValueError("tun inbound 至少需要一个 IPv4 address")
    tun["address"] = ipv4_addresses


def _replace_detour(values: Iterable[Dict[str, Any]], old: str, new: str) -> None:
    for value in values:
        if isinstance(value, dict) and value.get("detour") == old:
            value["detour"] = new


def apply_profile_to_template(
    template: Dict[str, Any],
    profile: Dict[str, Any],
    *,
    clash_secret: str | None = None,
) -> Dict[str, Any]:
    """Apply platform and runtime tuning without duplicating the routing policy."""

    conf = copy.deepcopy(template)
    platform = str(profile["platform"])
    core_version = str(profile.get("core", {}).get("version"))
    tuning = profile.get("tuning") if isinstance(profile.get("tuning"), dict) else {}
    control = profile.get("control") if isinstance(profile.get("control"), dict) else {}
    clash = profile.get("clash_api") if isinstance(profile.get("clash_api"), dict) else {}
    logging = profile.get("logging") if isinstance(profile.get("logging"), dict) else {}

    log = conf.setdefault("log", {})
    if "disabled" in logging:
        log["disabled"] = bool(logging["disabled"])
    if logging.get("level"):
        log["level"] = str(logging["level"])
    log["timestamp"] = bool(logging.get("timestamp", True))

    dns = conf.setdefault("dns", {})
    if tuning.get("dns_strategy"):
        dns["strategy"] = str(tuning["dns_strategy"])
    if tuning.get("dns_cache_capacity") is not None:
        dns["cache_capacity"] = int(tuning["dns_cache_capacity"])
    if tuning.get("dns_reverse_mapping") is not None:
        dns["reverse_mapping"] = bool(tuning["dns_reverse_mapping"])
    if tuning.get("dns_final"):
        dns["final"] = str(tuning["dns_final"])
    if bool(tuning.get("force_local_dns")):
        dns["rules"] = []

    dns_detour = str(control.get("dns_detour") or "DNS-Out")
    update_detour = str(control.get("update_detour") or "Update-Out")
    _replace_detour(dns.get("servers", []), "Available", dns_detour)

    tun = _find_tun_inbound(conf)
    if tun is None:
        raise ValueError("模板缺少 tun inbound")
    for key, profile_key in (
        ("stack", "tun_stack"),
        ("mtu", "tun_mtu"),
        ("udp_timeout", "udp_timeout"),
        ("auto_route", "auto_route"),
        ("strict_route", "strict_route"),
        ("endpoint_independent_nat", "endpoint_independent_nat"),
    ):
        if tuning.get(profile_key) is not None:
            tun[key] = tuning[profile_key]
    _strip_tun_ipv6_addresses(tun)

    if platform == "android":
        conf["inbounds"] = [tun]
        tun.pop("route_address", None)
        tun.pop("route_exclude_address", None)
        app_settings = profile.get("android_apps") if isinstance(profile.get("android_apps"), dict) else {}
        app_file = str(app_settings.get("file") or "").strip()
        if app_file:
            app_path = Path(app_file)
            if not app_path.is_absolute():
                app_path = Path(str(profile.get("_base_dir") or ".")) / app_path
            if app_path.exists():
                with app_path.open("r", encoding="utf-8") as handle:
                    loaded_apps = yaml.safe_load(handle)
                if isinstance(loaded_apps, dict):
                    app_settings = _deep_merge(app_settings, loaded_apps)
        mode = str(app_settings.get("mode") or "").strip().lower()
        packages = [str(value).strip() for value in app_settings.get("packages", []) if str(value).strip()]
        tun.pop("include_package", None)
        tun.pop("exclude_package", None)
        if packages and mode == "include":
            tun["include_package"] = packages
        elif packages and mode == "exclude":
            tun["exclude_package"] = packages
        elif packages:
            raise ValueError("android_apps.mode 必须是 include 或 exclude")
    elif tuning.get("mixed_inbound") is False:
        conf["inbounds"] = [tun]

    route = conf.setdefault("route", {})
    if tuning.get("route_final"):
        route["final"] = str(tuning["route_final"])
    if bool(tuning.get("force_direct")):
        retained_actions = [
            rule
            for rule in route.get("rules", [])
            if isinstance(rule, dict) and rule.get("action") in {"sniff", "hijack-dns"}
        ]
        route["rules"] = retained_actions + [{"action": "route", "outbound": "direct"}]
        route["final"] = "direct"
    rule_set_interval = str(tuning.get("rule_set_update_interval") or "").strip()
    rule_sets = route.get("rule_set", [])
    if rule_set_interval:
        for rule_set in rule_sets:
            if isinstance(rule_set, dict) and rule_set.get("type") == "remote":
                rule_set["update_interval"] = rule_set_interval

    if _version_tuple(core_version) >= (1, 14, 0):
        client_tag = "rule-set-downloader"
        conf["http_clients"] = [{"tag": client_tag, "detour": update_detour}]
        route["default_http_client"] = client_tag
        for rule_set in rule_sets:
            if not isinstance(rule_set, dict) or rule_set.get("type") != "remote":
                continue
            rule_set.pop("download_detour", None)
            rule_set["http_client"] = client_tag
    else:
        conf.pop("http_clients", None)
        route.pop("default_http_client", None)
        for rule_set in rule_sets:
            if not isinstance(rule_set, dict) or rule_set.get("type") != "remote":
                continue
            rule_set.pop("http_client", None)
            rule_set["download_detour"] = update_detour

    experimental = conf.setdefault("experimental", {})
    cache_file = experimental.setdefault("cache_file", {})
    cache_file["enabled"] = bool(tuning.get("cache_enabled", True))
    if tuning.get("cache_path"):
        cache_file["path"] = str(tuning["cache_path"])

    if bool(clash.get("enabled", platform == "windows")):
        clash_api = experimental.setdefault("clash_api", {})
        clash_api["external_controller"] = str(clash.get("controller") or "127.0.0.1:9090")
        clash_api["secret"] = clash_secret if clash_secret is not None else str(clash_api.get("secret") or "")
        clash_api["default_mode"] = str(clash.get("default_mode") or "Rule")
        if bool(clash.get("external_ui", platform == "windows")):
            clash_api["external_ui"] = str(clash.get("external_ui_path") or "dashboard")
            if clash.get("external_ui_download_url"):
                clash_api["external_ui_download_url"] = str(clash["external_ui_download_url"])
                clash_api["external_ui_download_detour"] = update_detour
        else:
            clash_api.pop("external_ui", None)
            clash_api.pop("external_ui_download_url", None)
            clash_api.pop("external_ui_download_detour", None)
    else:
        experimental.pop("clash_api", None)

    return conf

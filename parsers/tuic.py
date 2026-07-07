# -*- coding: utf-8 -*-

from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from .common import detect_region, first_non_empty


def first_query_value(query: Dict[str, list[str]], *keys: str) -> Optional[str]:
    for key in keys:
        values = query.get(key)
        if not values:
            continue
        value = unquote(str(values[0])).strip()
        if value:
            return value
    return None


def truthy_query_value(query: Dict[str, list[str]], *keys: str) -> bool:
    for key in keys:
        if key not in query:
            continue
        values = query.get(key) or [""]
        value = unquote(str(values[0])).strip().lower()
        return value in {"", "1", "true", "yes", "on", "enabled"}
    return False


def parse_uri(uri: str) -> Dict[str, Any]:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "tuic":
        raise ValueError("不是 tuic:// URI")
    if not parsed.hostname or not parsed.port:
        raise ValueError("缺少 server 或 port")
    if not parsed.username:
        raise ValueError("缺少 uuid")

    query = parse_qs(parsed.query, keep_blank_values=True)
    uuid = unquote(parsed.username).strip()
    password = unquote(parsed.password or "").strip()
    if not password:
        raise ValueError("缺少 password")

    name = unquote(parsed.fragment).strip() or f"{parsed.hostname}:{parsed.port}"
    tls_obj: Dict[str, Any] = {
        "enabled": True,
        "server_name": first_non_empty(
            first_query_value(query, "sni", "servername", "serverName"),
            parsed.hostname,
        ),
    }

    if truthy_query_value(query, "allowInsecure", "insecure"):
        tls_obj["insecure"] = True

    alpn = first_query_value(query, "alpn")
    if alpn:
        tls_obj["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    outbound: Dict[str, Any] = {
        "type": "tuic",
        "tag": name,
        "server": parsed.hostname,
        "server_port": int(parsed.port),
        "uuid": uuid,
        "password": password,
        "domain_resolver": "local",
        "tls": tls_obj,
        "_meta_name": name,
        "_meta_region": detect_region(name),
    }

    congestion_control = first_query_value(query, "congestion_control", "congestion-control", "cc")
    if congestion_control:
        outbound["congestion_control"] = congestion_control

    udp_relay_mode = first_query_value(query, "udp_relay_mode", "udp-relay-mode")
    if udp_relay_mode:
        outbound["udp_relay_mode"] = udp_relay_mode

    return outbound

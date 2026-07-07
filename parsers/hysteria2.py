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
    if parsed.scheme.lower() not in {"hy2", "hysteria2"}:
        raise ValueError("不是 hy2:// 或 hysteria2:// URI")
    if not parsed.hostname or not parsed.port:
        raise ValueError("缺少 server 或 port")
    if not parsed.username:
        raise ValueError("缺少 password")

    query = parse_qs(parsed.query, keep_blank_values=True)
    password = unquote(parsed.username)
    name = unquote(parsed.fragment).strip() or f"{parsed.hostname}:{parsed.port}"

    tls_obj: Dict[str, Any] = {
        "enabled": True,
        "server_name": first_non_empty(
            first_query_value(query, "sni", "peer", "servername", "serverName"),
            parsed.hostname,
        ),
    }
    if truthy_query_value(query, "allowInsecure", "insecure"):
        tls_obj["insecure"] = True

    alpn = first_query_value(query, "alpn")
    if alpn:
        tls_obj["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    outbound: Dict[str, Any] = {
        "type": "hysteria2",
        "tag": name,
        "server": parsed.hostname,
        "server_port": int(parsed.port),
        "password": password,
        "domain_resolver": "local",
        "tls": tls_obj,
        "_meta_name": name,
        "_meta_region": detect_region(name),
    }

    obfs_type = first_query_value(query, "obfs", "obfs-type", "obfs_type")
    obfs_password = first_query_value(query, "obfs-password", "obfs_password")
    if obfs_type or obfs_password:
        outbound["obfs"] = {
            "type": obfs_type or "salamander",
            "password": obfs_password or "",
        }

    return outbound

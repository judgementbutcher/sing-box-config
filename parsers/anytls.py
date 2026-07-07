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
    if parsed.scheme.lower() != "anytls":
        raise ValueError("不是 anytls:// URI")
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
            first_query_value(query, "sni", "servername", "serverName"),
            parsed.hostname,
        ),
    }

    if truthy_query_value(query, "allowInsecure", "insecure"):
        tls_obj["insecure"] = True

    fingerprint = first_query_value(query, "fp", "fingerprint", "client-fingerprint")
    if fingerprint:
        tls_obj["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint,
        }

    alpn = first_query_value(query, "alpn")
    if alpn:
        tls_obj["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    return {
        "type": "anytls",
        "tag": name,
        "server": parsed.hostname,
        "server_port": int(parsed.port),
        "password": password,
        "domain_resolver": "local",
        "tls": tls_obj,
        "_meta_name": name,
        "_meta_region": detect_region(name),
    }

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


def build_tls(parsed_host: str, query: Dict[str, list[str]], security: str) -> Dict[str, Any]:
    tls_obj: Dict[str, Any] = {
        "enabled": True,
        "server_name": first_non_empty(
            first_query_value(query, "sni", "servername", "serverName"),
            parsed_host,
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

    if security == "reality":
        public_key = first_query_value(query, "pbk", "publicKey", "public_key")
        if not public_key:
            raise ValueError("Reality 缺少 public key")
        tls_obj["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": first_query_value(query, "sid", "shortId", "short_id") or "",
        }

    return tls_obj


def parse_uri(uri: str) -> Dict[str, Any]:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "trojan":
        raise ValueError("不是 trojan:// URI")
    if not parsed.hostname or not parsed.port:
        raise ValueError("缺少 server 或 port")
    if not parsed.username:
        raise ValueError("缺少 password")

    query = parse_qs(parsed.query, keep_blank_values=True)
    password = unquote(parsed.username)
    name = unquote(parsed.fragment).strip() or f"{parsed.hostname}:{parsed.port}"

    outbound: Dict[str, Any] = {
        "type": "trojan",
        "tag": name,
        "server": parsed.hostname,
        "server_port": int(parsed.port),
        "password": password,
        "domain_resolver": "local",
    }

    security = (first_query_value(query, "security") or "tls").lower()
    if security in {"tls", "reality"}:
        outbound["tls"] = build_tls(parsed.hostname, query, security)
    elif security != "none":
        raise ValueError(f"暂不支持 Trojan security={security}")

    network = (first_query_value(query, "type", "network") or "tcp").lower()
    if network == "ws":
        transport: Dict[str, Any] = {
            "type": "ws",
            "path": first_query_value(query, "path") or "/",
        }
        host = first_query_value(query, "host")
        if host:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    elif network == "grpc":
        transport = {"type": "grpc"}
        service_name = first_query_value(query, "serviceName", "service_name")
        if service_name:
            transport["service_name"] = service_name
        outbound["transport"] = transport
    elif network != "tcp":
        raise ValueError(f"暂不支持 Trojan type={network}")

    outbound["_meta_name"] = name
    outbound["_meta_region"] = detect_region(name)
    return outbound

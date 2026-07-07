# -*- coding: utf-8 -*-

from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from .common import detect_region, first_non_empty


SUPPORTED_PACKET_ENCODINGS = {"packetaddr", "xudp"}


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


def normalize_vless_flow(value: Optional[str]) -> Optional[str]:
    flow = str(value or "").strip()
    if not flow:
        return None
    if flow == "xtls-rprx-vision" or flow.startswith("xtls-rprx-vision-"):
        return "xtls-rprx-vision"
    raise ValueError(f"暂不支持 VLESS flow={flow}")


def normalize_packet_encoding(value: Optional[str]) -> Optional[str]:
    packet_encoding = str(value or "").strip().lower()
    if not packet_encoding or packet_encoding in {"none", "off", "false"}:
        return None
    if packet_encoding not in SUPPORTED_PACKET_ENCODINGS:
        raise ValueError(f"暂不支持 VLESS packet_encoding={packet_encoding}")
    return packet_encoding


def split_csv(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def build_tls(parsed_host: str, query: Dict[str, list[str]], security: str) -> Dict[str, Any]:
    tls_obj: Dict[str, Any] = {
        "enabled": True,
        "server_name": first_non_empty(
            first_query_value(query, "sni", "servername", "serverName"),
            parsed_host,
        ),
    }

    if truthy_query_value(query, "allowInsecure", "insecure", "skip-cert-verify"):
        tls_obj["insecure"] = True

    fingerprint = first_query_value(query, "fp", "fingerprint", "client-fingerprint")
    if fingerprint:
        tls_obj["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint,
        }

    alpn = split_csv(first_query_value(query, "alpn"))
    if alpn:
        tls_obj["alpn"] = alpn

    if security == "reality":
        public_key = first_query_value(query, "pbk", "publicKey", "public_key", "public-key")
        if not public_key:
            raise ValueError("Reality 缺少 public key")
        tls_obj["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": first_query_value(query, "sid", "shortId", "short_id", "short-id") or "",
        }

    return tls_obj


def build_transport(query: Dict[str, list[str]], network: str) -> Optional[Dict[str, Any]]:
    if network in {"tcp", "raw"}:
        return None
    if network in {"ws", "websocket"}:
        transport: Dict[str, Any] = {
            "type": "ws",
            "path": first_query_value(query, "path") or "/",
        }
        host = first_query_value(query, "host")
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if network == "grpc":
        transport = {"type": "grpc"}
        service_name = first_query_value(query, "serviceName", "service_name")
        if service_name:
            transport["service_name"] = service_name
        return transport
    raise ValueError(f"暂不支持 VLESS type={network}")


def parse_uri(uri: str) -> Dict[str, Any]:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "vless":
        raise ValueError("不是 vless:// URI")
    if not parsed.hostname or not parsed.port:
        raise ValueError("缺少 server 或 port")
    if not parsed.username:
        raise ValueError("缺少 uuid")

    query = parse_qs(parsed.query, keep_blank_values=True)
    uuid = unquote(parsed.username).strip()
    name = unquote(parsed.fragment).strip() or f"{parsed.hostname}:{parsed.port}"

    encryption = first_query_value(query, "encryption")
    if encryption and encryption.lower() != "none":
        raise ValueError(f"暂不支持 VLESS encryption={encryption}")

    outbound: Dict[str, Any] = {
        "type": "vless",
        "tag": name,
        "server": parsed.hostname,
        "server_port": int(parsed.port),
        "uuid": uuid,
        "domain_resolver": "local",
    }

    flow = normalize_vless_flow(first_query_value(query, "flow"))
    if flow:
        outbound["flow"] = flow

    packet_encoding = normalize_packet_encoding(first_query_value(query, "packetEncoding", "packet_encoding"))
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding

    security = (first_query_value(query, "security") or "").lower()
    if security in {"tls", "reality"}:
        outbound["tls"] = build_tls(parsed.hostname, query, security)
    elif security and security != "none":
        raise ValueError(f"暂不支持 VLESS security={security}")

    network = (first_query_value(query, "type", "network") or "tcp").lower()
    if network == "udp":
        outbound["network"] = "udp"
    else:
        transport = build_transport(query, network)
        outbound["transport"] = transport
        if transport is None:
            outbound.pop("transport")

    outbound["_meta_name"] = name
    outbound["_meta_region"] = detect_region(name)
    return outbound

# -*- coding: utf-8 -*-

import base64
import json
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlsplit

from .common import detect_region, first_non_empty


def decode_base64(value: str) -> str:
    normalized = unquote(value).replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized).decode("utf-8")


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def split_csv(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    return [x.strip() for x in text.split(",") if x.strip()]


def parse_vmess_payload(uri: str) -> Dict[str, Any]:
    payload = uri[len("vmess://") :].strip()
    if not payload:
        raise ValueError("VMess payload 为空")
    data = json.loads(decode_base64(payload))
    if not isinstance(data, dict):
        raise ValueError("VMess payload 不是 JSON 对象")
    return data


def parse_uri(uri: str) -> Dict[str, Any]:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "vmess":
        raise ValueError("不是 vmess:// URI")

    data = parse_vmess_payload(uri)
    server = str(data.get("add") or data.get("server") or "").strip()
    port = parse_int(data.get("port"))
    uuid = str(data.get("id") or data.get("uuid") or "").strip()
    if not server or not port:
        raise ValueError("缺少 server 或 port")
    if not uuid:
        raise ValueError("缺少 uuid")

    name = str(data.get("ps") or data.get("name") or f"{server}:{port}").strip()
    outbound: Dict[str, Any] = {
        "type": "vmess",
        "tag": name,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": str(data.get("scy") or data.get("security") or "auto").strip() or "auto",
        "alter_id": parse_int(data.get("aid") or data.get("alterId")),
        "domain_resolver": "local",
    }

    if parse_bool(data.get("tls")):
        tls_obj: Dict[str, Any] = {
            "enabled": True,
            "server_name": first_non_empty(
                data.get("sni"),
                data.get("serverName"),
                data.get("host"),
                server,
            ),
        }
        if parse_bool(data.get("allowInsecure")) or parse_bool(data.get("skip-cert-verify")):
            tls_obj["insecure"] = True
        alpn = split_csv(data.get("alpn"))
        if alpn:
            tls_obj["alpn"] = alpn
        outbound["tls"] = tls_obj

    network = str(data.get("net") or data.get("network") or "tcp").strip().lower()
    if network == "ws":
        transport: Dict[str, Any] = {
            "type": "ws",
            "path": str(data.get("path") or "/"),
        }
        host = str(data.get("host") or "").strip()
        if host:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    elif network == "grpc":
        transport = {"type": "grpc"}
        service_name = str(data.get("path") or data.get("serviceName") or "").strip()
        if service_name:
            transport["service_name"] = service_name
        outbound["transport"] = transport
    elif network != "tcp":
        raise ValueError(f"暂不支持 VMess net={network}")

    outbound["_meta_name"] = name
    outbound["_meta_region"] = detect_region(name)
    return outbound

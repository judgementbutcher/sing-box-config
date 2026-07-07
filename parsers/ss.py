# -*- coding: utf-8 -*-

import base64
from typing import Any, Dict, Tuple
from urllib.parse import unquote, urlsplit

from .common import detect_region


def decode_base64(value: str) -> str:
    normalized = unquote(value).replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized).decode("utf-8")


def split_method_password(value: str) -> Tuple[str, str]:
    if ":" not in value:
        raise ValueError("缺少 method:password")
    method, password = value.split(":", 1)
    method = unquote(method).strip()
    password = unquote(password)
    if not method or not password:
        raise ValueError("method 或 password 为空")
    return method, password


def parse_decoded_full_uri(decoded: str) -> Tuple[str, str, str, int]:
    parsed = urlsplit(f"//{decoded}")
    if not parsed.hostname or not parsed.port:
        raise ValueError("缺少 server 或 port")
    if parsed.username is None or parsed.password is None:
        raise ValueError("缺少 method 或 password")
    return (
        unquote(parsed.username),
        unquote(parsed.password),
        parsed.hostname,
        int(parsed.port),
    )


def parse_uri(uri: str) -> Dict[str, Any]:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "ss":
        raise ValueError("不是 ss:// URI")
    if parsed.query:
        raise ValueError("暂不支持带 query/plugin 的 Shadowsocks URI")

    name = unquote(parsed.fragment).strip()
    method = ""
    password = ""
    server = parsed.hostname
    port = parsed.port

    if server and port:
        if parsed.username is None:
            raise ValueError("缺少 Shadowsocks 用户信息")

        if parsed.password is not None:
            method = unquote(parsed.username).strip()
            password = unquote(parsed.password)
        else:
            method, password = split_method_password(decode_base64(parsed.username))
    else:
        payload = uri[len("ss://") :]
        payload = payload.split("#", 1)[0].split("?", 1)[0]
        method, password, server, port = parse_decoded_full_uri(decode_base64(payload))

    if not name:
        name = f"{server}:{port}"

    return {
        "type": "shadowsocks",
        "tag": name,
        "server": server,
        "server_port": int(port),
        "method": method,
        "password": password,
        "domain_resolver": "local",
        "_meta_name": name,
        "_meta_region": detect_region(name),
    }

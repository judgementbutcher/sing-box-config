# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional, Tuple

import yaml

from .common import detect_region, first_non_empty, is_info_node


SUPPORTED_PACKET_ENCODINGS = {"packetaddr", "xudp"}


def parse_yaml(text: str) -> Dict[str, Any]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("YAML 顶层不是对象")
    return data


def normalize_vless_flow(value: Any) -> Optional[str]:
    flow = str(value or "").strip()
    if not flow:
        return None
    if flow == "xtls-rprx-vision" or flow.startswith("xtls-rprx-vision-"):
        return "xtls-rprx-vision"
    raise ValueError(f"暂不支持 VLESS flow={flow}")


def normalize_packet_encoding(value: Any) -> Optional[str]:
    packet_encoding = str(value or "").strip().lower()
    if not packet_encoding or packet_encoding in {"none", "off", "false"}:
        return None
    if packet_encoding not in SUPPORTED_PACKET_ENCODINGS:
        raise ValueError(f"暂不支持 VLESS packet_encoding={packet_encoding}")
    return packet_encoding


def parse_alpn(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    return [x.strip() for x in text.split(",") if x.strip()]


def first_mapping_value(mapping: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def clash_vless_to_singbox(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if node.get("type") != "vless":
        return None

    name = str(node.get("name", "")).strip()
    if not name or is_info_node(name):
        return None

    server = node.get("server")
    port = node.get("port")
    uuid = node.get("uuid")

    if not server or not port or not uuid:
        return None

    outbound: Dict[str, Any] = {
        "type": "vless",
        "tag": name,
        "server": server,
        "server_port": int(port),
        "uuid": str(uuid),
        "domain_resolver": "local",
    }

    flow = normalize_vless_flow(node.get("flow"))
    if flow:
        outbound["flow"] = flow

    packet_encoding = normalize_packet_encoding(
        first_non_empty(
            node.get("packet-encoding"),
            node.get("packet_encoding"),
            node.get("packetEncoding"),
        )
    )
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding

    mux_opts = node.get("smux") or node.get("multiplex")
    if isinstance(mux_opts, dict) and mux_opts.get("enabled") is not False:
        mux_obj: Dict[str, Any] = {"enabled": True}
        for k in (
            "protocol",
            "max_connections",
            "min_streams",
            "max_streams",
            "padding",
            "brutal",
        ):
            if k in mux_opts:
                mux_obj[k] = mux_opts[k]
        outbound["multiplex"] = mux_obj

    reality_opts = node.get("reality-opts") or node.get("reality_opts") or {}
    if not isinstance(reality_opts, dict):
        reality_opts = {}
    has_reality = bool(first_mapping_value(reality_opts, "public-key", "public_key", "publicKey"))

    if node.get("tls") or has_reality:
        tls_obj: Dict[str, Any] = {
            "enabled": True,
            "server_name": first_non_empty(node.get("servername"), node.get("sni"), str(server)),
        }

        if node.get("skip-cert-verify") is True:
            tls_obj["insecure"] = True

        fp = node.get("client-fingerprint")
        if fp:
            tls_obj["utls"] = {
                "enabled": True,
                "fingerprint": str(fp),
            }

        alpn = parse_alpn(node.get("alpn"))
        if alpn:
            tls_obj["alpn"] = alpn

        public_key = first_mapping_value(reality_opts, "public-key", "public_key", "publicKey")
        short_id = first_mapping_value(reality_opts, "short-id", "short_id", "shortId")
        if public_key:
            tls_obj["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": short_id or "",
            }

        outbound["tls"] = tls_obj

    network = str(node.get("network", "") or "").strip().lower()
    if network == "ws":
        ws_opts = node.get("ws-opts") or {}
        headers = ws_opts.get("headers") or {}
        transport: Dict[str, Any] = {
            "type": "ws",
            "path": str(ws_opts.get("path") or "/"),
        }
        host = headers.get("Host") or headers.get("host")
        if host:
            transport["headers"] = {"Host": str(host)}
        outbound["transport"] = transport
    elif network == "grpc":
        grpc_opts = node.get("grpc-opts") or {}
        service_name = grpc_opts.get("grpc-service-name")
        transport = {"type": "grpc"}
        if service_name:
            transport["service_name"] = str(service_name)
        outbound["transport"] = transport
    elif network and network not in {"tcp", "raw"}:
        raise ValueError(f"暂不支持 VLESS network={network}")

    outbound["_meta_name"] = name
    outbound["_meta_region"] = detect_region(name)
    return outbound


def build_shadowsocks_plugin(node: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    plugin = str(node.get("plugin") or "").strip()
    if not plugin:
        return None, None

    plugin_opts = node.get("plugin-opts") or node.get("plugin_opts") or {}
    plugin_key = plugin.lower()
    if plugin_key in ("obfs", "simple-obfs", "obfs-local"):
        opts: List[str] = []
        if isinstance(plugin_opts, dict):
            mode = first_non_empty(plugin_opts.get("mode"), plugin_opts.get("obfs"))
            host = first_non_empty(plugin_opts.get("host"), plugin_opts.get("obfs-host"))
            if mode:
                opts.append(f"obfs={mode}")
            if host:
                opts.append(f"obfs-host={host}")
        elif plugin_opts:
            opts.append(str(plugin_opts))
        return "obfs-local", ";".join(opts)

    if plugin_key == "v2ray-plugin":
        if isinstance(plugin_opts, dict):
            opts = [f"{key}={value}" for key, value in plugin_opts.items() if value is not None]
            return "v2ray-plugin", ";".join(opts)
        return "v2ray-plugin", str(plugin_opts or "")

    raise ValueError(f"暂不支持 Shadowsocks 插件: {plugin}")


def clash_shadowsocks_to_singbox(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if node.get("type") != "ss":
        return None

    name = str(node.get("name", "")).strip()
    if not name or is_info_node(name):
        return None

    server = node.get("server")
    port = node.get("port")
    method = node.get("cipher") or node.get("method")
    password = node.get("password")

    if not server or not port or not method or password is None:
        return None

    outbound: Dict[str, Any] = {
        "type": "shadowsocks",
        "tag": name,
        "server": server,
        "server_port": int(port),
        "method": str(method),
        "password": str(password),
        "domain_resolver": "local",
    }

    if node.get("udp") is False:
        outbound["network"] = "tcp"

    plugin, plugin_opts = build_shadowsocks_plugin(node)
    if plugin:
        outbound["plugin"] = plugin
    if plugin_opts:
        outbound["plugin_opts"] = plugin_opts

    outbound["_meta_name"] = name
    outbound["_meta_region"] = detect_region(name)
    return outbound


def clash_anytls_to_singbox(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if node.get("type") != "anytls":
        return None

    name = str(node.get("name", "")).strip()
    if not name or is_info_node(name):
        return None

    server = node.get("server")
    port = node.get("port")
    password = node.get("password")

    if not server or not port or password is None:
        return None

    tls_obj: Dict[str, Any] = {
        "enabled": True,
        "server_name": first_non_empty(node.get("sni"), node.get("servername"), str(server)),
    }

    if node.get("skip-cert-verify") is True:
        tls_obj["insecure"] = True

    fp = node.get("client-fingerprint")
    if fp:
        tls_obj["utls"] = {
            "enabled": True,
            "fingerprint": str(fp),
        }

    alpn = node.get("alpn")
    if isinstance(alpn, list) and alpn:
        tls_obj["alpn"] = [str(x) for x in alpn]
    elif isinstance(alpn, str) and alpn.strip():
        tls_obj["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    outbound = {
        "type": "anytls",
        "tag": name,
        "server": server,
        "server_port": int(port),
        "password": str(password),
        "domain_resolver": "local",
        "tls": tls_obj,
        "_meta_name": name,
        "_meta_region": detect_region(name),
    }
    return outbound


def clash_hysteria2_to_singbox(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if node.get("type") not in {"hysteria2", "hy2"}:
        return None

    name = str(node.get("name", "")).strip()
    if not name or is_info_node(name):
        return None

    server = node.get("server")
    port = node.get("port")
    password = node.get("password")
    if not server or not port or password is None:
        return None

    tls_obj: Dict[str, Any] = {
        "enabled": True,
        "server_name": first_non_empty(node.get("sni"), node.get("servername"), str(server)),
    }
    if node.get("skip-cert-verify") is True:
        tls_obj["insecure"] = True

    alpn = parse_alpn(node.get("alpn"))
    if alpn:
        tls_obj["alpn"] = alpn

    outbound: Dict[str, Any] = {
        "type": "hysteria2",
        "tag": name,
        "server": server,
        "server_port": int(port),
        "password": str(password),
        "domain_resolver": "local",
        "tls": tls_obj,
        "_meta_name": name,
        "_meta_region": detect_region(name),
    }

    obfs_type = first_non_empty(node.get("obfs"), node.get("obfs-type"), node.get("obfs_type"))
    obfs_password = first_non_empty(node.get("obfs-password"), node.get("obfs_password"))
    if obfs_type or obfs_password:
        outbound["obfs"] = {"type": obfs_type or "salamander", "password": obfs_password or ""}

    return outbound


def clash_node_to_singbox(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return (
        clash_vless_to_singbox(node)
        or clash_shadowsocks_to_singbox(node)
        or clash_anytls_to_singbox(node)
        or clash_hysteria2_to_singbox(node)
    )


def build_info_outbound(name: str) -> Dict[str, Any]:
    return {
        "type": "block",
        "tag": name,
        "_meta_name": name,
        "_meta_info": True,
    }


def parse(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    data = parse_yaml(text)
    proxies = data.get("proxies", [])
    if not isinstance(proxies, list):
        raise ValueError("Clash 订阅中 proxies 不是数组")

    nodes: List[Dict[str, Any]] = []
    info_nodes: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for index, node in enumerate(proxies, 1):
        if not isinstance(node, dict):
            continue

        name = str(node.get("name", "")).strip()
        if name and is_info_node(name):
            info_nodes.append(build_info_outbound(name))
            continue

        try:
            outbound = clash_node_to_singbox(node)
        except Exception as e:
            warnings.append(f"第 {index} 个节点解析失败: {e}")
            continue

        if outbound is not None:
            nodes.append(outbound)

    return nodes, info_nodes, warnings

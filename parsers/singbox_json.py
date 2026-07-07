# -*- coding: utf-8 -*-

import copy
import json
from typing import Any, Dict, List, Tuple

from .common import detect_region, is_info_node


NON_PROXY_OUTBOUND_TYPES = {"selector", "urltest", "direct", "block", "dns"}


def build_info_outbound(name: str) -> Dict[str, Any]:
    return {
        "type": "block",
        "tag": name,
        "_meta_name": name,
        "_meta_info": True,
    }


def parse(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("sing-box JSON 顶层不是对象")

    outbounds = data.get("outbounds", [])
    if not isinstance(outbounds, list):
        raise ValueError("sing-box JSON 中 outbounds 不是数组")

    nodes: List[Dict[str, Any]] = []
    info_nodes: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for index, outbound in enumerate(outbounds, 1):
        if not isinstance(outbound, dict):
            continue

        outbound_type = str(outbound.get("type") or "").strip()
        tag = str(outbound.get("tag") or "").strip()
        if not outbound_type:
            warnings.append(f"第 {index} 个 outbound 缺少 type，已跳过")
            continue
        if not tag:
            warnings.append(f"第 {index} 个 outbound 缺少 tag，已跳过")
            continue

        if outbound_type in NON_PROXY_OUTBOUND_TYPES:
            if is_info_node(tag):
                info_nodes.append(build_info_outbound(tag))
            continue

        node = copy.deepcopy(outbound)
        node["_meta_name"] = tag
        node["_meta_region"] = detect_region(tag)
        nodes.append(node)

    return nodes, info_nodes, warnings

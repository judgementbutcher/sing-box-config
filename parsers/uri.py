# -*- coding: utf-8 -*-

from typing import Any, Callable, Dict, List, Tuple

from . import anytls, hysteria2, ss, trojan, tuic, vless, vmess


LineParser = Callable[[str], Dict[str, Any]]

LINE_PARSERS: Dict[str, LineParser] = {
    "anytls": anytls.parse_uri,
    "hy2": hysteria2.parse_uri,
    "hysteria2": hysteria2.parse_uri,
    "ss": ss.parse_uri,
    "trojan": trojan.parse_uri,
    "tuic": tuic.parse_uri,
    "vless": vless.parse_uri,
    "vmess": vmess.parse_uri,
}


def parse(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    nodes: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("```"):
            continue
        if "://" not in line:
            continue

        scheme = line.split("://", 1)[0].strip().lower()
        parser = LINE_PARSERS.get(scheme)
        if parser is None:
            warnings.append(f"第 {line_no} 行协议暂不支持: {scheme}")
            continue

        try:
            nodes.append(parser(line))
        except Exception as e:
            warnings.append(f"第 {line_no} 行解析失败: {e}")

    return nodes, [], warnings

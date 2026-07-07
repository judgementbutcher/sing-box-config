# -*- coding: utf-8 -*-

from typing import Any, Callable, Dict, List, Tuple

from . import clash, singbox_json, uri


ParseOutput = Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]
ParserFunc = Callable[[str], ParseOutput]

PARSERS: Dict[str, ParserFunc] = {
    "clash": clash.parse,
    "clash-yaml": clash.parse,
    "json": singbox_json.parse,
    "sing-box": singbox_json.parse,
    "sing-box-json": singbox_json.parse,
    "singbox": singbox_json.parse,
    "singbox-json": singbox_json.parse,
    "uri": uri.parse,
    "uri-list": uri.parse,
    "v2ray": uri.parse,
    "v2ray-uri": uri.parse,
    "v2rayn": uri.parse,
}


def parse_subscription_text(parser_name: str, text: str) -> ParseOutput:
    key = parser_name.strip().lower()
    parser = PARSERS.get(key)
    if parser is None:
        supported = ", ".join(sorted(PARSERS))
        raise ValueError(f"不支持的解析器: {parser_name}，可用: {supported}")
    return parser(text)

# -*- coding: utf-8 -*-

import re
from typing import List, Optional, Tuple


REGION_MAP: List[Tuple[str, List[str]]] = [
    ("HK", ["🇭🇰", "香港", "hong kong", "hongkong"]),
    ("TW", ["🇹🇼", "台湾", "臺灣", "taiwan"]),
    ("JP", ["🇯🇵", "日本", "japan", "tokyo", "osaka"]),
    ("SG", ["🇸🇬", "新加坡", "singapore"]),
    ("US", ["🇺🇸", "美国", "美國", "united states", "america", "chicago", "los angeles", "san jose", "chatgpt专用"]),
    ("FR", ["🇫🇷", "法国", "法國", "france", "paris"]),
    ("GB", ["🇬🇧", "英国", "英國", "united kingdom", "britain", "london"]),
]

REGION_CODES = {
    # HKS: airport/proxy 命名常见的香港写法（如 Panstar-HKS），按词边界匹配避免误伤。
    "HK": {"HK", "HKG", "HKS"},
    "TW": {"TW", "TWN"},
    "JP": {"JP", "JPN"},
    "SG": {"SG", "SGP"},
    # LAX: 洛杉矶机场代码，机场节点常用（如 VMISS-LAX-DC1），与 USA 一样按词边界匹配。
    "US": {"US", "USA", "LAX"},
    "FR": {"FR", "FRA"},
    "GB": {"GB", "GBR", "UK"},
}

INFO_NODE_KEYWORDS = [
    "剩余流量",
    "下次重置",
    "套餐到期",
    "上次更新",
    "流量",
    "到期",
    "订阅",
]


def is_info_node(name: str) -> bool:
    lowered = name.strip().lower()
    return any(keyword.lower() in lowered for keyword in INFO_NODE_KEYWORDS)


def detect_region(name: str) -> str:
    lowered = name.strip().lower()
    for region, keywords in REGION_MAP:
        for kw in keywords:
            if kw.lower() in lowered:
                return region
    upper = name.upper()
    for region, codes in REGION_CODES.items():
        for code in codes:
            if re.search(rf"(?<![A-Z0-9]){re.escape(code)}(?![A-Z0-9])", upper):
                return region
    return "Others"


def first_non_empty(*values: Optional[str]) -> Optional[str]:
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return None

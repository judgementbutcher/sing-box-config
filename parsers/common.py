# -*- coding: utf-8 -*-

from typing import List, Optional, Tuple


REGION_MAP: List[Tuple[str, List[str]]] = [
    ("HK", ["香港", "hk"]),
    ("TW", ["台湾", "tw"]),
    ("JP", ["日本", "jp"]),
    ("SG", ["新加坡", "sg"]),
    ("US", ["美国", "us", "chicago", "chatgpt专用"]),
    ("GB", ["英国", "gb"]),
]

INFO_NODE_KEYWORDS = [
    "剩余流量",
    "下次重置",
    "套餐到期",
    "上次更新",
    "流量",
    "到期",
    "订阅",
]

HOT_REGIONS = ["HK", "TW", "JP", "SG", "US", "GB"]
ALL_REGIONS = HOT_REGIONS + ["Others"]
AI_PREFERRED_REGIONS = ["US", "SG", "JP", "HK", "TW", "GB"]


def is_info_node(name: str) -> bool:
    lowered = name.strip().lower()
    return any(keyword.lower() in lowered for keyword in INFO_NODE_KEYWORDS)


def detect_region(name: str) -> str:
    lowered = name.strip().lower()
    for region, keywords in REGION_MAP:
        for kw in keywords:
            if kw.lower() in lowered:
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

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .io_utils import atomic_write_json, parse_utc_timestamp, utc_now_iso


def load_health_state(path: Path | str | None) -> Dict[str, Dict[str, Any]]:
    if not path:
        return {}
    state_path = Path(path)
    if not state_path.exists():
        return {}
    import json

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    nodes = data.get("nodes") if isinstance(data, dict) else None
    return nodes if isinstance(nodes, dict) else {}


def save_health_state(path: Path | str, nodes: Dict[str, Dict[str, Any]]) -> None:
    atomic_write_json(
        path,
        {
            "schema_version": 1,
            "updated_at": utc_now_iso(),
            "nodes": nodes,
        },
    )


def merge_health_sample(
    state: Dict[str, Dict[str, Any]],
    fingerprint: str,
    *,
    delay_ms: int | None,
    successful: bool,
    alpha: float = 0.35,
) -> None:
    entry = dict(state.get(fingerprint) or {})
    successes = int(entry.get("successes") or 0)
    failures = int(entry.get("failures") or 0)
    if successful:
        successes += 1
        if delay_ms is not None and delay_ms > 0:
            previous = entry.get("ewma_delay_ms")
            entry["ewma_delay_ms"] = round(
                float(delay_ms) if previous is None else alpha * float(delay_ms) + (1 - alpha) * float(previous),
                2,
            )
    else:
        failures += 1
    entry["successes"] = successes
    entry["failures"] = failures
    total = successes + failures
    entry["success_rate"] = round(successes / total, 4) if total else None
    entry["updated_at"] = utc_now_iso()
    state[fingerprint] = entry


def health_score(entry: Dict[str, Any] | None) -> float:
    if not entry:
        return 650.0
    delay = float(entry.get("ewma_delay_ms") or 600.0)
    success_rate = entry.get("success_rate")
    success_penalty = 250.0 if success_rate is None else (1.0 - float(success_rate)) * 2000.0
    updated = parse_utc_timestamp(entry.get("updated_at"))
    stale_penalty = 0.0
    if updated is not None:
        age_days = max((datetime.now(timezone.utc) - updated).total_seconds() / 86400, 0.0)
        stale_penalty = min(age_days * 20.0, 300.0)
    return delay + success_penalty + stale_penalty


def select_diverse_candidates(
    nodes: Iterable[Dict[str, Any]],
    *,
    maximum: int,
    health_state: Dict[str, Dict[str, Any]] | None = None,
    preferred_regions: Iterable[str] | None = None,
    excluded_fingerprints: set[str] | None = None,
) -> List[Dict[str, Any]]:
    """Pick healthy candidates while avoiding a pool dominated by one region/provider."""

    if maximum <= 0:
        return []
    health_state = health_state or {}
    excluded_fingerprints = excluded_fingerprints or set()
    preferred = list(preferred_regions or [])
    region_rank = {region: index for index, region in enumerate(preferred)}

    eligible = []
    for node in nodes:
        fingerprint = str(node.get("_meta_fingerprint") or "")
        if not fingerprint or fingerprint in excluded_fingerprints:
            continue
        eligible.append(node)

    def sort_key(node: Dict[str, Any]) -> tuple[float, int, int, str]:
        fingerprint = str(node.get("_meta_fingerprint") or "")
        role = str(node.get("_meta_role") or "default").lower()
        role_penalty = {
            "primary": 0,
            "paid": 0,
            "default": 50,
            "backup": 250,
            "public": 500,
            "free": 500,
        }.get(role, 150)
        insecure_penalty = 5000 if bool(node.get("_meta_insecure")) else 0
        region = str(node.get("_meta_region") or "Others")
        return (
            health_score(health_state.get(fingerprint)) + role_penalty + insecure_penalty,
            region_rank.get(region, len(region_rank) + 1),
            int(node.get("_meta_priority") or 100),
            fingerprint,
        )

    eligible.sort(key=sort_key)
    buckets: Dict[tuple[str, str], List[Dict[str, Any]]] = {}
    for node in eligible:
        key = (
            str(node.get("_meta_subscription") or "unknown"),
            str(node.get("_meta_region") or "Others"),
        )
        buckets.setdefault(key, []).append(node)

    bucket_keys = sorted(
        buckets,
        key=lambda key: (
            region_rank.get(key[1], len(region_rank) + 1),
            sort_key(buckets[key][0]),
            key,
        ),
    )
    selected: List[Dict[str, Any]] = []
    while bucket_keys and len(selected) < maximum:
        next_round: List[tuple[str, str]] = []
        for key in bucket_keys:
            bucket = buckets[key]
            if bucket and len(selected) < maximum:
                selected.append(bucket.pop(0))
            if bucket:
                next_round.append(key)
        bucket_keys = next_round
    return selected

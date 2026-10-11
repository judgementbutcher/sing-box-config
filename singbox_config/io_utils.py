from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$", re.IGNORECASE)
DURATION_FACTORS = {
    "ms": 0.001,
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}


def parse_duration_seconds(value: Any, *, default_unit: str = "s") -> float:
    """Parse a compact duration such as ``30m`` or ``7d`` into seconds."""

    if isinstance(value, (int, float)):
        return float(value)
    match = DURATION_RE.match(str(value or ""))
    if not match:
        raise ValueError(f"无效时间长度: {value}")
    amount = float(match.group(1))
    unit = (match.group(2) or default_unit).lower()
    return amount * DURATION_FACTORS[unit]


def atomic_write_text(path: Path | str, text: str, *, encoding: str = "utf-8") -> None:
    """Write a text file using an atomic replace in the destination directory."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            newline="",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def atomic_write_json(path: Path | str, data: Any) -> None:
    atomic_write_text(Path(path), json.dumps(data, ensure_ascii=False, indent=2) + "\n")

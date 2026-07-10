import json

import pytest

from singbox_config.io_utils import atomic_write_json, parse_duration_seconds


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("500ms", 0.5),
        ("30s", 30),
        ("10m", 600),
        ("2h", 7200),
        ("7d", 604800),
        ("1w", 604800),
    ],
)
def test_parse_duration_seconds(value, expected):
    assert parse_duration_seconds(value) == expected


def test_parse_duration_rejects_invalid_value():
    with pytest.raises(ValueError):
        parse_duration_seconds("tomorrow")


def test_atomic_write_json_replaces_existing_file(tmp_path):
    target = tmp_path / "data.json"
    target.write_text('{"old": true}', encoding="utf-8")
    atomic_write_json(target, {"new": True})
    assert json.loads(target.read_text(encoding="utf-8")) == {"new": True}
    assert not list(tmp_path.glob("*.tmp"))

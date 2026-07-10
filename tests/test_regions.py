import pytest

from parsers.common import detect_region


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("🇭🇰 Premium 01", "HK"),
        ("Tokyo JP-02", "JP"),
        ("Singapore SGP 3", "SG"),
        ("Los Angeles USA", "US"),
        ("Paris France FR", "FR"),
        ("London UK", "GB"),
        ("Taiwan TW", "TW"),
        ("Russia Moscow", "Others"),
        ("news-service", "Others"),
    ],
)
def test_detect_region_uses_flags_names_and_bounded_codes(name, expected):
    assert detect_region(name) == expected

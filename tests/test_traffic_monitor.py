from datetime import datetime

from singbox_config.traffic_monitor import (
    UNKNOWN,
    TrafficStore,
    connection_dimensions,
    site_key,
    source_group_from_chain,
)


def _connection(upload=100, download=500):
    return {
        "id": "connection-1",
        "upload": upload,
        "download": download,
        "metadata": {
            "host": "link00.okemby.org",
            "destinationIP": "203.0.113.10",
            "network": "tcp",
            "processPath": r"C:\Program Files\Browser\browser.exe",
        },
        "rule": "domain_suffix=okemby.org => route(Emby)",
        "chains": ["香港 01", "机场 A", "Available", "Emby"],
    }


def test_connection_dimensions_and_site_grouping():
    dimensions = connection_dimensions(_connection())
    assert dimensions["destination"] == "link00.okemby.org"
    assert dimensions["process"] == "browser.exe"
    assert dimensions["outbound"] == "香港 01"
    assert dimensions["chain"] == "香港 01 → 机场 A → Available → Emby"
    assert source_group_from_chain(dimensions["chain"]) == "机场 A"
    assert site_key(dimensions["destination"]) == "okemby.org"
    assert site_key("www.example.com.cn") == "example.com.cn"


def test_source_group_identifies_self_hosted_and_direct_routes():
    assert source_group_from_chain("瓦工自建/合租_gamer1_idc → AI") == "自建"
    assert source_group_from_chain("Lumina机场/香港A02 → Available") == "Lumina机场"
    assert source_group_from_chain("良心云/新加坡高速03 → Emby") == "良心云"
    assert source_group_from_chain("direct") == "直连"


def test_snapshot_deltas_and_unknown_gap_are_persisted(tmp_path):
    store = TrafficStore(tmp_path / "traffic.db")
    # Seed at a fixed far-past date so today/yesterday/7d/30d are always empty
    # while the "all" period still captures it — keeps the period assertions
    # deterministic no matter when the suite runs.
    captured = datetime.fromisoformat("2020-01-02T08:00:00+08:00")
    try:
        first = store.record_snapshot(
            {"uploadTotal": 1000, "downloadTotal": 2000, "connections": [_connection()]},
            captured,
        )
        assert first == {
            "upload": 1000,
            "download": 2000,
            "unknownUpload": 900,
            "unknownDownload": 1500,
        }

        second = store.record_snapshot(
            {"uploadTotal": 1100, "downloadTotal": 2300, "connections": [_connection(150, 700)]},
            captured,
        )
        assert second == {
            "upload": 100,
            "download": 300,
            "unknownUpload": 50,
            "unknownDownload": 100,
        }

        summary = store.summary("all", "site")
        assert summary["upload"] == 1100
        assert summary["download"] == 2300
        assert summary["known"] == 850
        assert summary["rows"][0]["label"] == UNKNOWN
        known_row = next(row for row in summary["rows"] if row["label"] == "okemby.org")
        assert known_row["upload"] == 150
        assert known_row["download"] == 700
        assert known_row["sourceGroups"] == [{
            "label": "机场 A",
            "upload": 150,
            "download": 700,
            "total": 850,
        }]

        proxy = store.summary("all", "site", scope="proxy")
        assert proxy["total"] == 850
        assert proxy["rows"][0]["label"] == "okemby.org"
        assert store.summary("yesterday", "site")["total"] == 0
    finally:
        store.close()

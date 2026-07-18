from datetime import datetime

from traffic_monitor import UNKNOWN, TrafficStore, connection_dimensions, site_key


def _connection(upload=100, download=500):
    return {
        "id": "connection-1",
        "upload": upload,
        "download": download,
        "metadata": {
            "host": "r3---sn.example.googlevideo.com",
            "destinationIP": "203.0.113.10",
            "network": "tcp",
            "processPath": r"C:\Program Files\Browser\browser.exe",
        },
        "rule": "domain_suffix=googlevideo.com => route(YouTube)",
        "chains": ["香港 01", "机场 A", "Available", "YouTube"],
    }


def test_connection_dimensions_and_site_grouping():
    dimensions = connection_dimensions(_connection())
    assert dimensions["destination"] == "r3---sn.example.googlevideo.com"
    assert dimensions["process"] == "browser.exe"
    assert dimensions["outbound"] == "香港 01"
    assert dimensions["chain"] == "香港 01 → 机场 A → Available → YouTube"
    assert site_key(dimensions["destination"]) == "googlevideo.com"
    assert site_key("www.example.com.cn") == "example.com.cn"


def test_snapshot_deltas_and_unknown_gap_are_persisted(tmp_path):
    store = TrafficStore(tmp_path / "traffic.db")
    captured = datetime.fromisoformat("2026-07-18T08:00:00+08:00")
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
        known_row = next(row for row in summary["rows"] if row["label"] == "googlevideo.com")
        assert known_row["upload"] == 150
        assert known_row["download"] == 700

        proxy = store.summary("all", "site", scope="proxy")
        assert proxy["total"] == 850
        assert proxy["rows"][0]["label"] == "googlevideo.com"
        assert store.summary("yesterday", "site")["total"] == 0
    finally:
        store.close()

import base64
import hashlib
import json
import threading
import subprocess
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

from singbox_config.publisher import (
    PublisherServer,
    load_or_create_credentials,
    publication_urls,
    validated_config,
    windows_default_route_ip,
)


def write_validated_config(directory, name):
    config = directory / f"{name}.json"
    stamp = directory / f"{name}.validated.json"
    config.write_text('{"log":{"disabled":true}}\n', encoding="utf-8")
    stamp.write_text(json.dumps({"sha256": hashlib.sha256(config.read_bytes()).hexdigest()}), encoding="utf-8")
    return config, stamp


def test_credentials_persist_until_explicit_rotation(tmp_path):
    path = tmp_path / "publisher.json"
    first = load_or_create_credentials(path)
    assert load_or_create_credentials(path) == first
    rotated = load_or_create_credentials(path, rotate=True)
    assert rotated["username"] == "sfa"
    assert rotated["password"] != first["password"]


def test_publication_urls_embed_credentials_only_where_required():
    credentials = {"username": "sfa", "password": "tok/en+with=specials"}
    assert publication_urls("192.0.2.10", 18080, credentials) == {
        "桌面/SFW（本机首选）": "http://127.0.0.1:18080/desktop/config.json",
        "桌面/SFW（局域网）": "http://192.0.2.10:18080/desktop/config.json",
        "安卓/SFA": "http://sfa:tok%2Fen%2Bwith%3Dspecials@192.0.2.10:18080/android/config.json",
    }
    assert publication_urls("192.0.2.10", 18080) == {
        "桌面/SFW（本机首选）": "http://127.0.0.1:18080/desktop/config.json",
        "桌面/SFW（局域网）": "http://192.0.2.10:18080/desktop/config.json",
        "安卓/SFA": "http://192.0.2.10:18080/android/config.json",
    }


def test_embedded_credentials_authenticate_against_live_publisher(tmp_path):
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop, desktop_stamp = write_validated_config(tmp_path, "desktop")
    credentials = {"username": "sfa", "password": "tok/en+with=specials"}
    server = PublisherServer(
        ("127.0.0.1", 0),
        android,
        android_stamp,
        desktop,
        desktop_stamp,
        credentials,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        link = publication_urls("127.0.0.1", server.server_port, credentials)["安卓/SFA"]
        parts = urlsplit(link)
        assert parts.hostname == "127.0.0.1"
        assert parts.port == server.server_port
        assert parts.path == "/android/config.json"
        # The client is expected to base64 the userinfo it parsed out of the link,
        # so this proves the printed string carries usable credentials.
        # ``urlopen`` itself cannot consume a userinfo URL, hence the manual header.
        secret = f"{unquote(parts.username)}:{unquote(parts.password)}"
        token = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        plain = f"http://{parts.hostname}:{parts.port}{parts.path}"
        response = urlopen(Request(plain, headers={"Authorization": f"Basic {token}"}), timeout=2)
        assert response.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_publisher_requires_auth_and_validated_hash(tmp_path):
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop, desktop_stamp = write_validated_config(tmp_path, "desktop")
    assert validated_config(android, android_stamp) == (True, "")
    server = PublisherServer(
        ("127.0.0.1", 0),
        android,
        android_stamp,
        desktop,
        desktop_stamp,
        {"username": "sfa", "password": "secret"},
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for target in ("android",):
            url = f"http://127.0.0.1:{server.server_port}/{target}/config.json"
            try:
                urlopen(url, timeout=2)
                raise AssertionError("unauthenticated request unexpectedly succeeded")
            except HTTPError as exc:
                assert exc.code == 401
            token = base64.b64encode(b"sfa:secret").decode("ascii")
            response = urlopen(Request(url, headers={"Authorization": f"Basic {token}"}), timeout=2)
            assert response.status == 200
            assert response.headers["Cache-Control"] == "no-store"
        desktop_url = f"http://127.0.0.1:{server.server_port}/desktop/config.json"
        response = urlopen(desktop_url, timeout=2)
        assert response.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_publisher_returns_utf8_validation_error_without_breaking_status_line(tmp_path):
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop = tmp_path / "desktop.json"
    desktop.write_text('{"log":{"disabled":true}}\n', encoding="utf-8")
    desktop_stamp = tmp_path / "desktop.validated.json"
    server = PublisherServer(
        ("127.0.0.1", 0),
        android,
        android_stamp,
        desktop,
        desktop_stamp,
        {"username": "sfa", "password": "secret"},
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/desktop/config.json"
    try:
        try:
            urlopen(url, timeout=2)
            raise AssertionError("unvalidated config unexpectedly succeeded")
        except HTTPError as exc:
            assert exc.code == 503
            assert exc.reason == "Service Unavailable"
            assert exc.headers.get_content_charset() == "utf-8"
            assert exc.read().decode("utf-8") == f"配置缺少验证标记: {desktop_stamp}\n"

        request = Request(url, method="HEAD")
        try:
            urlopen(request, timeout=2)
            raise AssertionError("unvalidated config unexpectedly succeeded")
        except HTTPError as exc:
            assert exc.code == 503
            assert exc.read() == b""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_windows_route_probe_timeout_is_non_fatal(monkeypatch):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("route", 0.25)

    monkeypatch.setattr("singbox_config.publisher.subprocess.run", timeout)
    assert windows_default_route_ip() is None

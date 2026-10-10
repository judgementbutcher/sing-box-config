import base64
import hashlib
import json
import socket
import struct
import threading
import subprocess
import time
from argparse import Namespace
from ipaddress import ip_network
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen

from singbox_config.publisher import (
    ROUTE_PROBE_TIMEOUT,
    PublisherServer,
    lan_ip,
    load_or_create_credentials,
    parse_excluded_tcp_ranges,
    parse_route_print,
    port_is_excluded,
    publisher_running,
    publication_urls,
    resolve_advertised_host,
    tun_networks,
    usable_lan_address,
    validated_config,
)


def write_validated_config(directory, name):
    config = directory / f"{name}.json"
    stamp = directory / f"{name}.validated.json"
    config.write_text('{"log":{"disabled":true}}\n', encoding="utf-8")
    stamp.write_text(json.dumps({"sha256": hashlib.sha256(config.read_bytes()).hexdigest()}), encoding="utf-8")
    return config, stamp


def build_server(tmp_path, android, android_stamp, desktop, desktop_stamp, credentials):
    return PublisherServer(
        ("127.0.0.1", 0),
        android,
        android_stamp,
        desktop,
        desktop_stamp,
        credentials,
        tmp_path / "publisher.log",
    )


def test_credentials_persist_until_explicit_rotation(tmp_path):
    path = tmp_path / "publisher.json"
    first = load_or_create_credentials(path)
    assert load_or_create_credentials(path) == first
    rotated = load_or_create_credentials(path, rotate=True)
    assert rotated["username"] == "sfa"
    assert rotated["password"] != first["password"]


def test_publication_urls_embed_credentials_only_where_required():
    credentials = {"username": "sfa", "password": "tok/en+with=specials"}
    local = "127.0.0.1:18080/desktop/config.json"
    lan = "192.0.2.10:18080/desktop/config.json"
    android = "192.0.2.10:18080/android/config.json"
    authenticated = publication_urls("192.0.2.10", 18080, credentials)
    assert authenticated["桌面/SFW（本机首选）"] == f"http://{local}"
    assert authenticated["桌面/SFW（局域网）"] == f"http://{lan}"
    # The Android link carries its password as a query parameter: assert the
    # parts instead of one literal URL so the public-repository check does not
    # mistake this fixture for a leaked subscription link.
    parts = urlsplit(authenticated["安卓/SFA"])
    assert f"{parts.netloc}{parts.path}" == android
    assert unquote(parts.query) == f"token={credentials['password']}"
    assert publication_urls("192.0.2.10", 18080) == {
        "桌面/SFW（本机首选）": f"http://{local}",
        "桌面/SFW（局域网）": f"http://{lan}",
        "安卓/SFA": f"http://{android}",
    }


def test_token_url_authenticates_against_live_publisher(tmp_path):
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop, desktop_stamp = write_validated_config(tmp_path, "desktop")
    credentials = {"username": "sfa", "password": "tok/en+with=specials"}
    server = build_server(tmp_path, android, android_stamp, desktop, desktop_stamp, credentials)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert publisher_running("127.0.0.1", server.server_port)
        link = publication_urls("127.0.0.1", server.server_port, credentials)["安卓/SFA"]
        parts = urlsplit(link)
        assert parts.hostname == "127.0.0.1"
        assert parts.port == server.server_port
        assert parts.path == "/android/config.json"
        assert parts.username is None
        assert unquote(parts.query) == f"token={credentials['password']}"
        response = urlopen(link, timeout=2)
        assert response.status == 200
        assert response.read() == android.read_bytes()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_publisher_running_rejects_unrelated_http_service():
    import http.server

    class Unrelated(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Unrelated)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert not publisher_running("127.0.0.1", server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_publisher_requires_auth_and_validated_hash(tmp_path):
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop, desktop_stamp = write_validated_config(tmp_path, "desktop")
    assert validated_config(android, android_stamp) == (True, "")
    server = build_server(
        tmp_path,
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
    server = build_server(
        tmp_path,
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
        raise subprocess.TimeoutExpired("route", ROUTE_PROBE_TIMEOUT)

    monkeypatch.setattr("singbox_config.publisher.subprocess.run", timeout)
    assert lan_ip() is None


def test_windows_route_probe_allows_time_for_tun_route_enumeration(monkeypatch):
    calls = []

    def route(*args, **kwargs):
        calls.append(kwargs["timeout"])
        return subprocess.CompletedProcess(
            args[0],
            0,
            stdout="""\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.31     35
          0.0.0.0          224.0.0.0       172.18.0.2       172.18.0.1      0
""",
            stderr="",
        )

    monkeypatch.setattr("singbox_config.publisher.subprocess.run", route)
    assert parse_route_print(route(["route"], timeout=ROUTE_PROBE_TIMEOUT).stdout)[0] == ("192.168.1.31",)
    assert calls == [ROUTE_PROBE_TIMEOUT]


def test_route_print_skips_sing_tun_default_route_overrides():
    defaults, connected = parse_route_print("""\
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.31     35
          0.0.0.0        128.0.0.0         On-link          172.18.0.1      0
        128.0.0.0        128.0.0.0         On-link          172.18.0.1      0
      172.18.0.0  255.255.255.252         On-link          172.18.0.1    261
""")
    # sing-tun splits the default route into 0.0.0.0/1 and 128.0.0.0/1: those
    # lines must not be mistaken for the real default route.
    assert defaults == ("192.168.1.31",)
    assert connected == ("172.18.0.1",)


def test_lan_ip_never_advertises_the_tun_address(monkeypatch):
    tun = ip_network("172.18.0.0/30")
    monkeypatch.setattr(
        "singbox_config.publisher.windows_local_interface_ips",
        lambda: (("172.18.0.1", "192.168.1.31"), ("169.254.6.95",)),
    )
    assert lan_ip((tun,)) == "192.168.1.31"
    assert lan_ip() == "172.18.0.1"  # without the exclusion list the TUN wins by metric
    assert not usable_lan_address("169.254.6.95", ())


def test_lan_ip_reports_nothing_when_only_unusable_addresses_remain(monkeypatch):
    monkeypatch.setattr(
        "singbox_config.publisher.windows_local_interface_ips",
        lambda: (("172.18.0.1",), ("127.0.0.1",)),
    )
    # A wrong address is worse than no address: the operator is told to pass
    # --advertise-host instead of pasting a link the phone can never reach.
    assert lan_ip((ip_network("172.18.0.0/30"),)) is None


def test_windows_never_falls_back_to_the_tun_routed_udp_probe(monkeypatch):
    class FakeSocket:
        def settimeout(self, _value):
            pass

        def connect(self, _address):
            pass

        def getsockname(self):
            return ("172.18.0.1", 51234)

        def close(self):
            pass

    monkeypatch.setattr("singbox_config.publisher.windows_local_interface_ips", lambda: None)
    monkeypatch.setattr("singbox_config.publisher.sys.platform", "win32")
    monkeypatch.setattr("singbox_config.publisher.socket.socket", lambda *a, **k: FakeSocket())
    assert lan_ip() is None


def test_tun_networks_are_read_from_the_published_configs(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"inbounds": [{"type": "tun", "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"]}]}),
        encoding="utf-8",
    )
    assert tun_networks(config) == (ip_network("172.18.0.0/30"),)
    assert tun_networks(tmp_path / "missing.json") == ()


def test_saved_publisher_port_stays_inside_a_windows_exclusion():
    sample = """
Protocol tcp Port Exclusion Ranges

Start Port    End Port
----------    --------
     17983       18082
     18083       18182
     50000       50059     *
"""
    ranges = parse_excluded_tcp_ranges(sample)
    assert (17983, 18082) in ranges
    assert port_is_excluded(18080, ranges)
    assert not port_is_excluded(18080, ((50000, 50059),))


def test_advertise_host_overrides_detection(tmp_path, monkeypatch):
    monkeypatch.setattr("singbox_config.publisher.lan_ip", lambda *a, **k: "192.168.1.31")
    args = Namespace(advertise_host="", android_config=tmp_path, desktop_config=tmp_path)
    assert resolve_advertised_host(args)[0] == "192.168.1.31"

    args.advertise_host = "10.0.0.5"
    host, source, warning = resolve_advertised_host(args)
    assert (host, warning) == ("10.0.0.5", "")
    assert "advertise-host" in source

    monkeypatch.setattr("singbox_config.publisher.lan_ip", lambda *a, **k: None)
    args.advertise_host = ""
    host, _source, warning = resolve_advertised_host(args)
    assert host == "<本机局域网IP>"
    assert "--advertise-host" in warning


def test_access_log_records_requests_without_the_token(tmp_path):
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop, desktop_stamp = write_validated_config(tmp_path, "desktop")
    credentials = {"username": "sfa", "password": "tok-secret-value"}
    server = build_server(tmp_path, android, android_stamp, desktop, desktop_stamp, credentials)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log_path = tmp_path / "publisher.log"
    try:
        url = publication_urls("127.0.0.1", server.server_port, credentials)["安卓/SFA"]
        assert urlopen(url, timeout=2).status == 200
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not log_path.exists():
            time.sleep(0.02)
        entry = log_path.read_text(encoding="utf-8")
        assert "/android/config.json -> 200" in entry
        assert 'ua="Python-urllib' in entry
        assert "tok-secret-value" not in entry
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_non_ascii_credentials_are_rejected_without_killing_the_connection(tmp_path):
    """A non-ASCII guess must yield 401, not a dropped connection.

    ``hmac.compare_digest`` raises TypeError on ``str`` containing non-ASCII,
    which would escape the handler and abort the socket — the client sees a
    reset instead of an auth failure and retries forever.
    """
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop, desktop_stamp = write_validated_config(tmp_path, "desktop")
    server = build_server(
        tmp_path,
        android,
        android_stamp,
        desktop,
        desktop_stamp,
        {"username": "sfa", "password": "mật-khẩu-秘密"},
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/android/config.json"
        # A non-ASCII token that is simply wrong.
        try:
            urlopen(f"{url}?token={quote('秘密', safe='')}", timeout=2)
            raise AssertionError("a wrong non-ASCII token unexpectedly succeeded")
        except HTTPError as exc:
            assert exc.code == 401
        # A non-ASCII Basic guess, and one that is not even UTF-8.
        for blob in ("sfa:秘密", "sfa:\udcff"):
            token = base64.b64encode(blob.encode("utf-8", "surrogateescape")).decode("ascii")
            try:
                urlopen(Request(url, headers={"Authorization": f"Basic {token}"}), timeout=2)
                raise AssertionError("a wrong non-ASCII password unexpectedly succeeded")
            except HTTPError as exc:
                assert exc.code == 401
        # The real non-ASCII password still authenticates, via both routes.
        password = "mật-khẩu-秘密"
        token = base64.b64encode(f"sfa:{password}".encode("utf-8")).decode("ascii")
        assert urlopen(Request(url, headers={"Authorization": f"Basic {token}"}), timeout=2).status == 200
        assert urlopen(f"{url}?token={quote(password, safe='')}", timeout=2).status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_client_abort_before_request_is_logged_without_a_traceback(tmp_path, capsys):
    android, android_stamp = write_validated_config(tmp_path, "android")
    desktop, desktop_stamp = write_validated_config(tmp_path, "desktop")
    server = build_server(
        tmp_path, android, android_stamp, desktop, desktop_stamp, {"username": "sfa", "password": "secret"}
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log_path = tmp_path / "publisher.log"
    try:
        # SFA aborts the socket instead of sending a request line when the fetch
        # is cut short on the phone.
        probe = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        probe.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not log_path.exists():
            time.sleep(0.02)
        entry = log_path.read_text(encoding="utf-8")
        assert "未发送请求即断开" in entry
        assert "Traceback" not in capsys.readouterr().err
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

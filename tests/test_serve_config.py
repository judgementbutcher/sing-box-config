from __future__ import annotations

import io
import os
from pathlib import Path
from types import SimpleNamespace

from scripts.serve import serve_config
from scripts.serve.serve_config import ConfigRequestHandler


def _handler(config_path: Path, path: str) -> tuple[ConfigRequestHandler, list[tuple[object, ...]]]:
    handler = object.__new__(ConfigRequestHandler)
    calls: list[tuple[object, ...]] = []
    handler.path = path
    handler.server = SimpleNamespace(
        config_path=config_path,
        config_url="http://192.168.1.2:8080/android/config.json",
    )
    handler.wfile = io.BytesIO()
    handler.send_response = lambda code: calls.append(("response", code))
    handler.send_header = lambda name, value: calls.append(("header", name, value))
    handler.end_headers = lambda: calls.append(("end_headers",))
    handler.send_error = lambda code, message: calls.append(("error", code, message))
    return handler, calls


def test_publisher_serves_only_android_config(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text('{"outbounds": []}', encoding="utf-8")

    handler, calls = _handler(config_path, "/android/config.json")
    handler._serve_config(include_body=True)

    assert ("response", 200) in calls
    assert ("header", "X-Sing-Box-Config-Publisher", "1") in calls
    assert any(call[:2] == ("header", "X-Sing-Box-Config-Pid") for call in calls)
    assert handler.wfile.getvalue() == b'{"outbounds": []}'

    rejected, calls = _handler(config_path, "/desktop/config.json")
    rejected._serve_config(include_body=True)

    assert calls == [("error", 404, "Only /android/config.json is published")]


def test_publisher_uses_stable_default_port(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "dist" / "android" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}", encoding="utf-8")
    ready_file = tmp_path / "publisher.ready"
    pid_file = tmp_path / "publisher.pid"
    attempts: list[int] = []

    class FakeServer:
        def __init__(self, address, _config_path, _config_url) -> None:
            attempts.append(address[1])
            self.server_address = address
            self.config_url = ""

        def serve_forever(self) -> None:
            assert ready_file.read_text(encoding="utf-8") == (
                f"http://192.168.1.2:{serve_config.DEFAULT_PORT}/android/config.json"
            )
            assert pid_file.read_text(encoding="ascii") == str(os.getpid())
            raise KeyboardInterrupt

        def server_close(self) -> None:
            pass

    monkeypatch.setattr(serve_config, "ConfigHTTPServer", FakeServer)
    monkeypatch.setattr(serve_config, "lan_ip", lambda: "192.168.1.2")

    assert (
        serve_config.main(
            [
                "--dir",
                str(tmp_path / "dist"),
                "--ready-file",
                str(ready_file),
                "--pid-file",
                str(pid_file),
            ]
        )
        == 0
    )
    assert attempts == [serve_config.DEFAULT_PORT]
    assert not ready_file.exists()
    assert not pid_file.exists()


def test_windows_lan_ip_uses_real_default_route_not_tun(monkeypatch) -> None:
    route_table = """
    0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.31     35
    0.0.0.0        248.0.0.0       172.18.0.2       172.18.0.1      0
    """
    monkeypatch.setattr(serve_config.sys, "platform", "win32")
    monkeypatch.setattr(
        serve_config.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=route_table),
    )
    monkeypatch.setattr(serve_config.socket, "socket", lambda *_args: None)

    assert serve_config.lan_ip() == "192.168.1.31"

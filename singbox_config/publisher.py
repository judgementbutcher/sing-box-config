"""Authenticated local publisher for validated sing-box configurations."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ANDROID_CONFIG = ROOT / "dist" / "android" / "config.json"
DEFAULT_ANDROID_STAMP = ROOT / "dist" / "android" / "config.validated.json"
DEFAULT_DESKTOP_CONFIG = ROOT / "dist" / "desktop" / "config.json"
DEFAULT_DESKTOP_STAMP = ROOT / "dist" / "desktop" / "config.validated.json"
DEFAULT_CREDENTIALS = ROOT / ".secrets" / "android-publisher.json"


def windows_default_route_ip() -> str | None:
    if sys.platform != "win32":
        return None
    try:
        result = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            # ``route print`` can hang when a VPN/TUN adapter is reconfiguring;
            # publishing must remain responsive even then.
            timeout=0.25,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    candidates: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[:2] != ["0.0.0.0", "0.0.0.0"]:
            continue
        try:
            address = IPv4Address(fields[3])
            metric = int(fields[4])
        except ValueError:
            continue
        if not address.is_loopback and not address.is_unspecified:
            candidates.append((metric, str(address)))
    return min(candidates, default=(0, None))[1]


def lan_ip() -> str:
    route_ip = windows_default_route_ip()
    if route_ip:
        return route_ip
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        sock.connect(("223.5.5.5", 80))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def load_or_create_credentials(path: Path, rotate: bool = False) -> dict[str, str]:
    if path.is_file() and not rotate:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("username") and data.get("password"):
            return {"username": str(data["username"]), "password": str(data["password"])}
        raise ValueError(f"发布凭据格式无效: {path}")
    credentials = {
        "username": "sfa",
        "password": secrets.token_urlsafe(24),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(credentials, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return credentials


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validated_config(path: Path, stamp_path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"配置尚未生成: {path}"
    if not stamp_path.is_file():
        return False, f"配置缺少验证标记: {stamp_path}"
    try:
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, f"配置验证标记无效: {stamp_path}"
    expected = str(stamp.get("sha256") or "") if isinstance(stamp, dict) else ""
    if not expected or not hmac.compare_digest(expected.lower(), sha256_file(path).lower()):
        return False, f"配置已改动但尚未通过验证: {path}"
    return True, ""


@dataclass(frozen=True)
class _ValidatedSnapshot:
    config_signature: tuple[int, int, int] | None
    stamp_signature: tuple[int, int, int] | None
    ok: bool
    message: str
    body: bytes = b""
    sha256: str = ""


def _signature(path: Path) -> tuple[int, int, int] | None:
    try:
        info = path.stat()
    except OSError:
        return None
    return (info.st_mtime_ns, info.st_size, getattr(info, "st_ino", 0))


class ValidatedConfigStore:
    """Cache validated bytes until the manager atomically publishes a new file."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[tuple[Path, Path], _ValidatedSnapshot] = {}

    def snapshot(self, path: Path, stamp_path: Path) -> _ValidatedSnapshot:
        key = (path, stamp_path)
        with self._lock:
            config_sig = _signature(path)
            stamp_sig = _signature(stamp_path)
            cached = self._entries.get(key)
            if cached and cached.config_signature == config_sig and cached.stamp_signature == stamp_sig:
                return cached
            if config_sig is None:
                result = _ValidatedSnapshot(config_sig, stamp_sig, False, f"配置尚未生成: {path}")
            elif stamp_sig is None:
                result = _ValidatedSnapshot(config_sig, stamp_sig, False, f"配置缺少验证标记: {stamp_path}")
            else:
                result = self._read_and_validate(path, stamp_path, config_sig, stamp_sig)
            self._entries[key] = result
            return result

    @staticmethod
    def _read_and_validate(path: Path, stamp_path: Path, config_sig, stamp_sig) -> _ValidatedSnapshot:
        try:
            stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _ValidatedSnapshot(config_sig, stamp_sig, False, f"配置验证标记无效: {stamp_path}")
        expected = str(stamp.get("sha256") or "") if isinstance(stamp, dict) else ""
        try:
            body = path.read_bytes()
        except OSError:
            return _ValidatedSnapshot(config_sig, stamp_sig, False, f"配置尚未生成: {path}")
        actual = hashlib.sha256(body).hexdigest()
        if not expected or not hmac.compare_digest(expected.lower(), actual.lower()):
            return _ValidatedSnapshot(config_sig, stamp_sig, False, f"配置已改动但尚未通过验证: {path}")
        return _ValidatedSnapshot(config_sig, stamp_sig, True, "", body, actual)


def publication_urls(host: str, port: int) -> dict[str, str]:
    return {
        "桌面/SFW（本机首选）": f"http://127.0.0.1:{port}/desktop/config.json",
        "桌面/SFW（局域网）": f"http://{host}:{port}/desktop/config.json",
        "安卓/SFA": f"http://{host}:{port}/android/config.json",
    }


def print_publication_info(host: str, port: int, credentials: Mapping[str, str]) -> None:
    print("\n配置发布已启动，请保存以下信息：", flush=True)
    for name, url in publication_urls(host, port).items():
        print(f"  {name}: {url}", flush=True)
    print(f"  用户名: {credentials['username']}", flush=True)
    print(f"  密码:   {credentials['password']}", flush=True)
    print("按 Ctrl+C 停止发布。\n", flush=True)


class PublisherHandler(BaseHTTPRequestHandler):
    server_version = "SingBoxConfigPublisher/1.0"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> "PublisherServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: Any) -> None:
        # Console writes are surprisingly expensive on Windows and every SFA
        # refresh can issue several requests.  Keep diagnostics available, but
        # make them opt-in for normal publishing.
        if os.environ.get("SINGBOX_PUBLISHER_VERBOSE"):
            print(f"publisher {self.address_string()} - {format % args}", flush=True)

    def authenticated(self) -> bool:
        value = self.headers.get("Authorization", "")
        if not value.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(username, self.app.username) and hmac.compare_digest(
            password, self.app.password
        )

    def challenge(self) -> None:
        body = b"Authentication required\n"
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="sing-box config", charset="UTF-8"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text_error(self, status: HTTPStatus, message: str, include_body: bool) -> None:
        """Return a UTF-8 diagnostic without putting it in the HTTP status line."""
        body = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def serve(self, include_body: bool) -> None:
        request_path = urlsplit(self.path).path
        if request_path == "/healthz":
            results = {
                path: self.app.store.snapshot(config_path, stamp_path).ok
                for path, (config_path, stamp_path) in self.app.paths.items()
            }
            body = json.dumps({"ok": all(results.values()), "configs": results}).encode("utf-8")
            status = HTTPStatus.OK if all(results.values()) else HTTPStatus.SERVICE_UNAVAILABLE
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if include_body:
                self.wfile.write(body)
            return
        item = self.app.paths.get(request_path)
        if item is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        # SFW's remote-config updater does not send HTTP Basic Auth headers.
        # Keep Android protected, but allow the desktop endpoint so published
        # configs can be refreshed directly from SFW.
        if request_path != "/desktop/config.json" and not self.authenticated():
            self.challenge()
            return
        config_path, stamp_path = item
        snapshot = self.app.store.snapshot(config_path, stamp_path)
        if not snapshot.ok:
            self.send_text_error(HTTPStatus.SERVICE_UNAVAILABLE, snapshot.message, include_body)
            return
        body = snapshot.body
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Sing-Box-Config-SHA256", snapshot.sha256)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self.serve(True)

    def do_HEAD(self) -> None:  # noqa: N802
        self.serve(False)


class PublisherServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(
        self,
        address: tuple[str, int],
        android_config: Path,
        android_stamp: Path,
        desktop_config: Path,
        desktop_stamp: Path,
        credentials: Mapping[str, str],
    ):
        super().__init__(address, PublisherHandler)
        self.paths = {
            "/android/config.json": (android_config, android_stamp),
            "/desktop/config.json": (desktop_config, desktop_stamp),
        }
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.store = ValidatedConfigStore()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="发布已校验的 sing-box 配置")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--android-config", type=Path, default=DEFAULT_ANDROID_CONFIG)
    parser.add_argument("--android-stamp", type=Path, default=DEFAULT_ANDROID_STAMP)
    parser.add_argument("--desktop-config", type=Path, default=DEFAULT_DESKTOP_CONFIG)
    parser.add_argument("--desktop-stamp", type=Path, default=DEFAULT_DESKTOP_STAMP)
    parser.add_argument("--credentials", type=Path, default=DEFAULT_CREDENTIALS)
    parser.add_argument("--rotate-credentials", action="store_true")
    parser.add_argument("--show-info", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    credentials = load_or_create_credentials(args.credentials.resolve(), rotate=args.rotate_credentials)
    address_host = lan_ip()
    if args.rotate_credentials or args.show_info:
        print_publication_info(address_host, args.port, credentials)
        return 0

    server = PublisherServer(
        (args.host, args.port),
        args.android_config.resolve(),
        args.android_stamp.resolve(),
        args.desktop_config.resolve(),
        args.desktop_stamp.resolve(),
        credentials,
    )
    print_publication_info(address_host, server.server_port, credentials)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
import time
from contextlib import closing
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address, IPv4Network, ip_network
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qs, quote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ANDROID_CONFIG = ROOT / "dist" / "android" / "config.json"
DEFAULT_ANDROID_STAMP = ROOT / "dist" / "android" / "config.validated.json"
DEFAULT_DESKTOP_CONFIG = ROOT / "dist" / "desktop" / "config.json"
DEFAULT_DESKTOP_STAMP = ROOT / "dist" / "desktop" / "config.validated.json"
DEFAULT_CREDENTIALS = ROOT / ".secrets" / "android-publisher.json"
DEFAULT_ACCESS_LOG = ROOT / "runtime" / "publisher.log"
ACCESS_LOG_LIMIT = 1024 * 1024
# ``route print`` needs about 1.5s on a machine with a TUN adapter and several
# virtual switches: a tighter bound silently produced a fallback address that
# the phone can never reach.
ROUTE_PROBE_TIMEOUT = 5


def parse_route_print(output: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (default-route interface IPs by metric, other local interface IPs).

    ``route print -4`` lists one line per route with five whitespace-separated
    fields.  The interface column holds the local address that route belongs to,
    so the default routes name the adapters that can actually reach other hosts
    while the remaining lines enumerate every other local IPv4 address.
    """
    defaults: list[tuple[int, str]] = []
    connected: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 5:
            continue
        destination, mask, _gateway, interface, metric = fields
        try:
            address = IPv4Address(interface)
            metric_value = int(metric)
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            continue
        if destination == "0.0.0.0" and mask == "0.0.0.0":
            defaults.append((metric_value, str(address)))
        elif destination != "0.0.0.0":
            connected.append(str(address))
    defaults.sort(key=lambda item: item[0])
    return tuple(address for _metric, address in defaults), tuple(dict.fromkeys(connected))


def windows_local_interface_ips() -> tuple[tuple[str, ...], tuple[str, ...]] | None:
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
            timeout=ROUTE_PROBE_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return parse_route_print(result.stdout)


def tun_networks(*config_paths: Path) -> tuple[IPv4Network, ...]:
    """Collect the TUN address ranges of the configurations being published.

    The publisher's own TUN address looks like any other private address, but it
    belongs to the client's TUN as well: advertising it hands the phone an URL
    pointing at its own virtual interface, which fails with a transport error
    instead of reaching this machine.
    """
    networks: list[IPv4Network] = []
    for path in config_paths:
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        inbounds = config.get("inbounds") if isinstance(config, dict) else None
        if not isinstance(inbounds, Iterable):
            continue
        for inbound in inbounds:
            if not isinstance(inbound, Mapping) or inbound.get("type") != "tun":
                continue
            addresses = inbound.get("address")
            if isinstance(addresses, str):
                addresses = [addresses]
            if not isinstance(addresses, Iterable):
                continue
            for value in addresses:
                try:
                    network = ip_network(str(value), strict=False)
                except ValueError:
                    continue
                if network.version == 4:
                    networks.append(network)
    return tuple(dict.fromkeys(networks))


def usable_lan_address(value: str, exclude: Sequence[IPv4Network] = ()) -> bool:
    try:
        address = IPv4Address(value)
    except ValueError:
        return False
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        return False
    return not any(address in network for network in exclude)


def lan_ip(exclude: Sequence[IPv4Network] = ()) -> str | None:
    """Pick the address other devices on the network should use.

    Never falls back to a routed guess on Windows: when the UDP trick below is
    used on a machine running sing-box TUN with ``auto_route``, the probe packet
    is routed into the tunnel and reports the TUN address itself.  Returning
    ``None`` keeps the broken link out of the console and lets the operator set
    ``--advertise-host`` explicitly.
    """
    probe = windows_local_interface_ips()
    if probe is not None:
        defaults, connected = probe
        for candidate in (*defaults, *connected):
            if usable_lan_address(candidate, exclude):
                return candidate
        return None
    if sys.platform == "win32":
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        sock.connect(("223.5.5.5", 80))
        address = str(sock.getsockname()[0])
    except OSError:
        return None
    finally:
        sock.close()
    return address if usable_lan_address(address, exclude) else None


def log_event(message: str, log_path: Path | None = None) -> None:
    """Append one diagnostic line, never let logging break publishing."""
    path = log_path if log_path is not None else DEFAULT_ACCESS_LOG
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file() and path.stat().st_size > ACCESS_LOG_LIMIT:
            path.unlink()
        with path.open("a", encoding="utf-8") as sink:
            sink.write(line)
    except OSError:
        pass


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


def publication_urls(host: str, port: int, credentials: Mapping[str, str] | None = None) -> dict[str, str]:
    android = f"http://{host}:{port}/android/config.json"
    if credentials:
        android = f"{android}?token={quote(str(credentials['password']), safe='')}"
    return {
        "桌面/SFW（本机首选）": f"http://127.0.0.1:{port}/desktop/config.json",
        "桌面/SFW（局域网）": f"http://{host}:{port}/desktop/config.json",
        "安卓/SFA": android,
    }


def print_publication_info(
    host: str,
    port: int,
    credentials: Mapping[str, str],
    *,
    source: str = "",
    warning: str = "",
) -> None:
    print("\n配置发布地址与凭据：", flush=True)
    for name, url in publication_urls(host, port, credentials).items():
        print(f"  {name}: {url}", flush=True)
    print(f"  用户名: {credentials['username']}", flush=True)
    print(f"  密码:   {credentials['password']}", flush=True)
    if source:
        print(f"  地址来源: {source}", flush=True)
    if warning:
        print(f"  警告: {warning}", flush=True)
    print("  安卓链接已附带访问令牌，可直接粘贴；客户端若分开填写，请用上面的用户名和密码。", flush=True)
    print("  桌面链接不需要认证。", flush=True)
    print("  手机与电脑必须在同一局域网（同一 Wi-Fi/热点），且地址不是 TUN/虚拟网卡地址。", flush=True)
    print("  若 SFA 报 EOF 或连接被重置：先在 SFA 内断开 VPN 再导入/刷新；", flush=True)
    print("  也可把 dist\\android\\config.json 传到手机作为本地配置导入（一次性）。", flush=True)
    print(f"  拉取记录与中断原因: {DEFAULT_ACCESS_LOG}", flush=True)


def publisher_running(host: str, port: int) -> bool:
    try:
        with closing(socket.create_connection((host, port), timeout=1)) as connection:
            connection.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            response = connection.recv(256)
        return response.startswith(b"HTTP/1.1 200 ") or response.startswith(b"HTTP/1.1 503 ")
    except OSError:
        return False


class PublisherHandler(BaseHTTPRequestHandler):
    server_version = "SingBoxConfigPublisher/1.0"
    protocol_version = "HTTP/1.1"
    # A phone that opens a socket and never sends a request would otherwise pin
    # a handler thread forever.
    timeout = 30

    @property
    def app(self) -> "PublisherServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: Any) -> None:
        # Console writes are surprisingly expensive on Windows and every SFA
        # refresh can issue several requests.  Keep diagnostics available, but
        # make them opt-in for normal publishing.
        if os.environ.get("SINGBOX_PUBLISHER_VERBOSE"):
            # Request lines can contain the access token. Never log the URL.
            status = args[1] if len(args) > 1 and str(args[1]).isdigit() else "request"
            print(f"publisher {self.address_string()} - HTTP {status}", flush=True)

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        super().log_request(code, size)
        # Only the path is recorded: the Android link carries its token in the
        # query string, which must never reach a log file.
        try:
            path = urlsplit(self.path).path
        except ValueError:
            path = "-"
        # SFA and the phone's browser reach this port over the same address, so
        # the client identity is what tells the two apart during a pull failure.
        agent = " ".join(str(self.headers.get("User-Agent") or "").split())[:60] if self.headers else ""
        agent = agent.replace('"', "'") or "-"
        log_event(
            f'{self.client_address[0]} {self.command or "-"} {path} -> {code} ua="{agent}"',
            self.app.access_log,
        )

    def authenticated(self) -> bool:
        token = parse_qs(urlsplit(self.path).query).get("token", [])
        if len(token) == 1 and hmac.compare_digest(token[0], self.app.password):
            return True
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
        access_log: Path | None = None,
    ):
        super().__init__(address, PublisherHandler)
        self.paths = {
            "/android/config.json": (android_config, android_stamp),
            "/desktop/config.json": (desktop_config, desktop_stamp),
        }
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.store = ValidatedConfigStore()
        self.access_log = access_log if access_log is not None else DEFAULT_ACCESS_LOG

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Log a phone aborting its own fetch in one line instead of a traceback."""
        error = sys.exc_info()[1]
        address = client_address[0] if client_address else "-"
        if isinstance(error, ConnectionError | TimeoutError):
            # SFA (or the TUN in front of it) frequently drops the connection
            # before sending a request line; that is a client-side event, and a
            # traceback in the publishing console hides the real problem.
            log_event(f"{address} 未发送请求即断开 ({type(error).__name__})", self.access_log)
            return
        log_event(f"{address} 请求处理异常: {type(error).__name__}: {error}", self.access_log)
        super().handle_error(request, client_address)


def resolve_advertised_host(args: argparse.Namespace) -> tuple[str, str, str]:
    """Return (host, source description, warning) for the printed links."""
    requested = str(args.advertise_host or "").strip()
    if requested:
        if usable_lan_address(requested):
            return requested, "由 --advertise-host 指定", ""
        return requested, "由 --advertise-host 指定", "该地址是环回或自动分配地址，手机无法访问。"
    exclude = tun_networks(args.desktop_config.resolve(), args.android_config.resolve())
    detected = lan_ip(exclude)
    if detected:
        return detected, "自动探测（默认路由所在网卡）", ""
    ranges = "、".join(str(network) for network in exclude) or "TUN 地址段"
    return (
        "<本机局域网IP>",
        "自动探测失败",
        f"无法确定局域网地址（已排除虚拟网卡与 {ranges}）；请用 --advertise-host 指定，例如 --advertise-host 192.168.1.31。",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="发布已校验的 sing-box 配置")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument(
        "--advertise-host",
        default="",
        help="发布链接中使用的本机局域网地址；默认按默认路由自动探测，探测到 TUN/虚拟网卡时会拒绝使用",
    )
    parser.add_argument("--android-config", type=Path, default=DEFAULT_ANDROID_CONFIG)
    parser.add_argument("--android-stamp", type=Path, default=DEFAULT_ANDROID_STAMP)
    parser.add_argument("--desktop-config", type=Path, default=DEFAULT_DESKTOP_CONFIG)
    parser.add_argument("--desktop-stamp", type=Path, default=DEFAULT_DESKTOP_STAMP)
    parser.add_argument("--credentials", type=Path, default=DEFAULT_CREDENTIALS)
    parser.add_argument("--access-log", type=Path, default=DEFAULT_ACCESS_LOG)
    parser.add_argument("--rotate-credentials", action="store_true")
    parser.add_argument("--show-info", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    credentials = load_or_create_credentials(args.credentials.resolve(), rotate=args.rotate_credentials)
    address_host, source, warning = resolve_advertised_host(args)
    if args.rotate_credentials or args.show_info:
        print_publication_info(address_host, args.port, credentials, source=source, warning=warning)
        if publisher_running("127.0.0.1", args.port):
            print("状态: 发布服务正在监听；请确认手机与电脑处于可互访的网络。", flush=True)
        else:
            print("状态: 发布服务未运行。请先在管理菜单中选择“启动发布”，并保持该窗口运行。", flush=True)
        return 0

    if publisher_running("127.0.0.1", args.port):
        print(
            f"状态: 端口 {args.port} 上已经有一个发布器在监听（多半是上次没关掉的窗口）。"
            "请先关闭它再启动，或改用 --port；两个进程同时占用同一端口时，请求和日志会分叉，"
            "排查会变得不可信。",
            flush=True,
        )
        return 1

    server = PublisherServer(
        (args.host, args.port),
        args.android_config.resolve(),
        args.android_stamp.resolve(),
        args.desktop_config.resolve(),
        args.desktop_stamp.resolve(),
        credentials,
        args.access_log.resolve(),
    )
    print_publication_info(address_host, server.server_port, credentials, source=source, warning=warning)
    print("状态: 发布服务正在监听。按 Ctrl+C 停止发布。\n", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

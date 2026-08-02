#!/usr/bin/env python3
"""Publish the generated configs over LAN HTTP for sing-box for Android (SFA).

SFA can subscribe to a *remote profile* — a URL it re-fetches on demand or on a
timer — which removes the need to copy ``config.json`` onto the phone by hand.
This starts a tiny read-only HTTP server that exposes only the Android profile
and prints the exact URL to paste into SFA (New Profile -> Type: Remote).
After that, a daily refresh is: regenerate the Android config on the desktop,
then tap "update" on the phone.

Only run this on a trusted LAN: the served files contain your real node
credentials.  Nothing leaves the local network unless you forward the port
yourself.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PORT = 8888


class ConfigRequestHandler(BaseHTTPRequestHandler):
    """Expose only the Android profile, never the rest of ``dist``."""

    server: "ConfigHTTPServer"

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._serve_config(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._serve_config(include_body=False)

    def _serve_config(self, include_body: bool) -> None:
        if urlsplit(self.path).path != "/android/config.json":
            self.send_error(404, "Only /android/config.json is published")
            return
        try:
            with self.server.config_path.open("rb") as config_file:
                size = os.fstat(config_file.fileno()).st_size
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(size))
                # SFA should always pull the freshest config, never a cached copy.
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Sing-Box-Config-Publisher", "1")
                self.send_header("X-Sing-Box-Config-Url", self.server.config_url)
                self.send_header("X-Sing-Box-Config-Pid", str(os.getpid()))
                self.end_headers()
                if include_body:
                    self.wfile.write(config_file.read())
        except OSError as exc:
            self.send_error(503, f"Unable to read Android config: {exc}")

    def log_message(self, format: str, *args) -> None:
        # Show who fetched what; confirms the phone actually pulled.
        print(f"  {self.address_string()} - {format % args}", flush=True)


class ConfigHTTPServer(ThreadingHTTPServer):
    """HTTP server carrying the one profile it is allowed to publish."""

    def __init__(self, address: tuple[str, int], config_path: Path, config_url: str) -> None:
        super().__init__(address, ConfigRequestHandler)
        self.config_path = config_path
        self.config_url = config_url


def windows_default_route_ip() -> str | None:
    """Return the address bound to Windows' real default route, if available.

    A sing-box TUN adapter may hijack a UDP probe to the Internet, even though
    the computer's physical Wi-Fi default gateway is still the address a phone
    on the local network needs.  ``route print`` exposes that physical route
    without relying on localized adapter names.
    """

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
        )
    except OSError:
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
    """Best-effort physical LAN IPv4 address (no packets are actually sent)."""

    windows_ip = windows_default_route_ip()
    if windows_ip:
        return windows_ip

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 80))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="局域网发布 sing-box 配置，供手机 sing-box for Android 远程订阅"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"监听端口，默认 {DEFAULT_PORT}（固定端口可让手机长期复用同一 URL）",
    )
    parser.add_argument("--dir", default=str(ROOT / "dist"), help="发布目录，默认 dist")
    parser.add_argument("--ready-file", help="监听成功后写入远程配置 URL，供管理脚本确认启动")
    parser.add_argument("--pid-file", help="监听成功后写入服务进程 ID，供管理脚本停止发布")
    args = parser.parse_args(argv)

    serve_dir = Path(args.dir)
    android_config = serve_dir / "android" / "config.json"
    if not android_config.exists():
        print(
            f"[错误] 找不到 {android_config}。\n"
            f"       请先生成安卓配置：python scripts/config/generate_config.py android",
            flush=True,
        )
        return 1

    requested_port = args.port
    try:
        server = ConfigHTTPServer(("0.0.0.0", requested_port), android_config, "")
        selected_port = int(server.server_address[1])
    except OSError as exc:
        print(
            f"[错误] 无法监听端口 {requested_port}：{exc}\n"
            "       可手工指定端口：scripts/serve/serve_android.bat --port 8888",
            flush=True,
        )
        return 1

    url = f"http://{lan_ip()}:{selected_port}/android/config.json"
    server.config_url = url

    if args.ready_file:
        ready_file = Path(args.ready_file)
        try:
            ready_file.parent.mkdir(parents=True, exist_ok=True)
            ready_file.write_text(url, encoding="utf-8")
        except OSError as exc:
            server.server_close()
            print(f"[错误] 发布器已监听，但无法写入启动确认文件：{exc}", flush=True)
            return 1
    if args.pid_file:
        pid_file = Path(args.pid_file)
        try:
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(str(os.getpid()), encoding="ascii")
        except OSError as exc:
            server.server_close()
            print(f"[错误] 发布器已监听，但无法写入进程状态文件：{exc}", flush=True)
            return 1
    banner = "=" * 64
    print(banner)
    print("局域网配置发布中（仅在可信网络使用；文件含真实节点凭据）")
    print(f"  安卓远程配置 URL：{url}")
    print("")
    print("首次在手机 SFA 里：新建配置 → 类型选「远程」→ 名称随意 →")
    print("  地址粘贴上面的 URL → 保存。（可在配置里打开自动更新）")
    print("以后刷新：桌面重新生成安卓配置后，在 SFA 点该配置的「更新」即可。")
    print("")
    print("手机打不开？① 确认手机和电脑连同一 WiFi；")
    print("           ② 首次可能弹出 Windows 防火墙提示，勾选「专用网络」允许访问。")
    print("按 Ctrl+C 停止发布。")
    print(banner)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止局域网发布。")
    finally:
        server.server_close()
        if args.ready_file:
            try:
                ready_file = Path(args.ready_file)
                if ready_file.exists() and ready_file.read_text(encoding="utf-8").strip() == url:
                    ready_file.unlink()
            except OSError:
                pass
        if args.pid_file:
            try:
                pid_file = Path(args.pid_file)
                if pid_file.exists() and pid_file.read_text(encoding="ascii").strip() == str(os.getpid()):
                    pid_file.unlink()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Publish the generated configs over LAN HTTP for sing-box for Android (SFA).

SFA can subscribe to a *remote profile* — a URL it re-fetches on demand or on a
timer — which removes the need to copy ``config.json`` onto the phone by hand.
This starts a tiny read-only HTTP server rooted at ``dist/`` and prints the
exact URL to paste into SFA (New Profile -> Type: Remote).  After that, a daily
refresh is: regenerate the Android config on the desktop, then tap "update" on
the phone.

Only run this on a trusted LAN: the served files contain your real node
credentials.  Nothing leaves the local network unless you forward the port
yourself.
"""

from __future__ import annotations

import argparse
import socket
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent
DEFAULT_PORT = 8080


class ConfigRequestHandler(SimpleHTTPRequestHandler):
    """Serve files read-only, always fresh, with a JSON content type."""

    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, ".json": "application/json"}

    def end_headers(self) -> None:
        # SFA should always pull the freshest config, never a cached copy.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        # Show who fetched what; confirms the phone actually pulled.
        print(f"  {self.address_string()} - {format % args}")


def lan_ip() -> str:
    """Best-effort primary LAN IPv4 address (no packets are actually sent)."""

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
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"监听端口，默认 {DEFAULT_PORT}")
    parser.add_argument("--dir", default=str(ROOT / "dist"), help="发布目录，默认 dist")
    args = parser.parse_args(argv)

    serve_dir = Path(args.dir)
    android_config = serve_dir / "android" / "config.json"
    if not android_config.exists():
        print(
            f"[错误] 找不到 {android_config}。\n"
            f"       请先生成安卓配置：python generate_config.py android",
            flush=True,
        )
        return 1

    handler = partial(ConfigRequestHandler, directory=str(serve_dir))
    try:
        server = ThreadingHTTPServer(("0.0.0.0", args.port), handler)
    except OSError as exc:
        print(f"[错误] 无法监听 0.0.0.0:{args.port}：{exc}\n       换个端口：serve_android.bat --port 8888", flush=True)
        return 1

    url = f"http://{lan_ip()}:{args.port}/android/config.json"
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

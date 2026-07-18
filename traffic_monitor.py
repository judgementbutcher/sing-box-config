"""Persistent, local-only traffic attribution for sing-box's Clash API.

The Clash API exposes byte counters for active connections, but it does not
retain historical per-destination totals.  This process samples those counters,
stores their deltas in SQLite, and serves a small dashboard on localhost.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import ntpath
import signal
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import date, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "runtime" / "traffic-monitor.db"
DEFAULT_UI = BASE_DIR / "traffic_dashboard"
UNKNOWN = "未识别（采样间隙/已关闭连接）"
GROUPS = {"site", "destination", "process", "rule", "outbound", "chain", "network"}
SCOPES = {"all", "proxy", "direct"}
COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac.cn", "com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn",
    "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au",
    "com.br", "com.hk", "com.sg", "com.tw", "co.nz",
}


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _text(value: Any, fallback: str) -> str:
    result = str(value or "").strip()
    return result or fallback


def site_key(destination: str) -> str:
    """Return a useful site-level key without requiring a public suffix DB."""

    host = destination.lower().strip().rstrip(".")
    if host == UNKNOWN or not host or ":" in host:
        return host or "未知目的地"
    parts = host.split(".")
    if len(parts) < 2 or all(part.isdigit() for part in parts):
        return host
    suffix2 = ".".join(parts[-2:])
    if suffix2 in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix2


def connection_dimensions(connection: dict[str, Any]) -> dict[str, str]:
    metadata = connection.get("metadata") if isinstance(connection.get("metadata"), dict) else {}
    host = _text(metadata.get("host"), "")
    destination_ip = _text(metadata.get("destinationIP"), "")
    destination = (host or destination_ip or "未知目的地").lower().rstrip(".")

    process = _text(metadata.get("process"), "")
    process_path = _text(metadata.get("processPath"), "")
    if not process and process_path:
        process = ntpath.basename(process_path)
    process = process or "未知应用"

    chains = connection.get("chains") if isinstance(connection.get("chains"), list) else []
    chain_values = [str(item).strip() for item in chains if str(item).strip()]
    chain = " → ".join(chain_values) or "未知出口"
    outbound = chain_values[0] if chain_values else "未知出口"

    return {
        "destination": destination,
        "process": process,
        "rule": _text(connection.get("rule"), "未标注规则"),
        "outbound": outbound,
        "chain": chain,
        "network": _text(metadata.get("network"), "未知协议").upper(),
    }


class TrafficStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=10000")
        self._create_schema()

    def _create_schema(self) -> None:
        with self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS usage (
                    day TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    process TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    outbound TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    network TEXT NOT NULL,
                    upload INTEGER NOT NULL DEFAULT 0,
                    download INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (day, destination, process, rule, outbound, chain, network)
                );
                CREATE INDEX IF NOT EXISTS idx_usage_day ON usage(day);
                CREATE TABLE IF NOT EXISTS connection_state (
                    id TEXT PRIMARY KEY,
                    upload INTEGER NOT NULL,
                    download INTEGER NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monitor_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def _get_state(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM monitor_state WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def _set_state(self, key: str, value: Any) -> None:
        self._db.execute(
            "INSERT INTO monitor_state(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    @staticmethod
    def _counter_delta(current: int, previous: int | None) -> int:
        if previous is None or current < previous:
            return current
        return current - previous

    def record_snapshot(self, snapshot: dict[str, Any], captured_at: datetime | None = None) -> dict[str, int]:
        captured_at = captured_at or datetime.now().astimezone()
        timestamp = captured_at.isoformat(timespec="seconds")
        day = captured_at.date().isoformat()
        connections = snapshot.get("connections") if isinstance(snapshot.get("connections"), list) else []
        increments: dict[tuple[str, ...], list[int]] = defaultdict(lambda: [0, 0])
        attributed_up = 0
        attributed_down = 0

        with self._lock, self._db:
            for connection in connections:
                if not isinstance(connection, dict):
                    continue
                connection_id = _text(connection.get("id"), "")
                if not connection_id:
                    continue
                upload = _safe_int(connection.get("upload"))
                download = _safe_int(connection.get("download"))
                previous = self._db.execute(
                    "SELECT upload, download FROM connection_state WHERE id = ?", (connection_id,)
                ).fetchone()
                up_delta = self._counter_delta(upload, int(previous["upload"]) if previous else None)
                down_delta = self._counter_delta(download, int(previous["download"]) if previous else None)
                dimensions = connection_dimensions(connection)
                key = tuple(dimensions[name] for name in ("destination", "process", "rule", "outbound", "chain", "network"))
                increments[key][0] += up_delta
                increments[key][1] += down_delta
                attributed_up += up_delta
                attributed_down += down_delta
                self._db.execute(
                    "INSERT INTO connection_state(id, upload, download, last_seen) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET upload = excluded.upload, "
                    "download = excluded.download, last_seen = excluded.last_seen",
                    (connection_id, upload, download, timestamp),
                )

            total_up = _safe_int(snapshot.get("uploadTotal"))
            total_down = _safe_int(snapshot.get("downloadTotal"))
            previous_up_text = self._get_state("api_upload_total")
            previous_down_text = self._get_state("api_download_total")
            global_up = self._counter_delta(total_up, int(previous_up_text) if previous_up_text is not None else 0)
            global_down = self._counter_delta(total_down, int(previous_down_text) if previous_down_text is not None else 0)
            if previous_up_text is None:
                global_up = total_up
            if previous_down_text is None:
                global_down = total_down

            unknown_up = max(0, global_up - attributed_up)
            unknown_down = max(0, global_down - attributed_down)
            if unknown_up or unknown_down:
                unknown_key = (UNKNOWN, "未知应用", "未标注规则", "未知出口", "未知出口", "未知协议")
                increments[unknown_key][0] += unknown_up
                increments[unknown_key][1] += unknown_down

            for key, (upload, download) in increments.items():
                if not upload and not download:
                    continue
                self._db.execute(
                    """
                    INSERT INTO usage(
                        day, destination, process, rule, outbound, chain, network,
                        upload, download, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(day, destination, process, rule, outbound, chain, network)
                    DO UPDATE SET upload = upload + excluded.upload,
                                  download = download + excluded.download,
                                  last_seen = excluded.last_seen
                    """,
                    (day, *key, upload, download, timestamp, timestamp),
                )

            self._set_state("api_upload_total", total_up)
            self._set_state("api_download_total", total_down)
            self._set_state("last_success", timestamp)
            self._set_state("live_connections", len(connections))
            self._set_state("last_error", "")
            cutoff = (captured_at - timedelta(days=2)).isoformat(timespec="seconds")
            self._db.execute("DELETE FROM connection_state WHERE last_seen < ?", (cutoff,))

        return {
            "upload": attributed_up + unknown_up,
            "download": attributed_down + unknown_down,
            "unknownUpload": unknown_up,
            "unknownDownload": unknown_down,
        }

    def record_error(self, message: str) -> None:
        with self._lock, self._db:
            self._set_state("last_error", message[:500])

    @staticmethod
    def _date_range(period: str) -> tuple[str | None, str | None]:
        today = date.today()
        if period == "today":
            value = today.isoformat()
            return value, value
        if period == "yesterday":
            value = (today - timedelta(days=1)).isoformat()
            return value, value
        if period == "7d":
            return (today - timedelta(days=6)).isoformat(), today.isoformat()
        if period == "30d":
            return (today - timedelta(days=29)).isoformat(), today.isoformat()
        return None, None

    def summary(self, period: str, group: str, limit: int = 50, scope: str = "all") -> dict[str, Any]:
        if group not in GROUPS:
            raise ValueError(f"unsupported group: {group}")
        if scope not in SCOPES:
            raise ValueError(f"unsupported scope: {scope}")
        start_day, end_day = self._date_range(period)
        clauses: list[str] = []
        params_list: list[Any] = []
        if start_day:
            clauses.append("day >= ?")
            params_list.append(start_day)
        if end_day:
            clauses.append("day <= ?")
            params_list.append(end_day)
        if scope == "proxy":
            clauses.extend(["outbound <> 'direct'", "destination <> ?"])
            params_list.append(UNKNOWN)
        elif scope == "direct":
            clauses.append("outbound = 'direct'")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        params = tuple(params_list)
        with self._lock:
            totals = self._db.execute(
                f"SELECT COALESCE(SUM(upload), 0) upload, COALESCE(SUM(download), 0) download "
                f"FROM usage {where}",
                params,
            ).fetchone()
            known = self._db.execute(
                f"SELECT COALESCE(SUM(upload + download), 0) bytes FROM usage {where} "
                + ("AND destination <> ?" if where else "WHERE destination <> ?"),
                (*params, UNKNOWN),
            ).fetchone()
            source_group = "destination" if group == "site" else group
            rows = self._db.execute(
                f"SELECT {source_group} label, SUM(upload) upload, SUM(download) download, "
                f"MAX(last_seen) last_seen FROM usage {where} GROUP BY {source_group}",
                params,
            ).fetchall()

        combined: dict[str, dict[str, Any]] = {}
        for row in rows:
            label = site_key(str(row["label"])) if group == "site" else str(row["label"])
            item = combined.setdefault(label, {"label": label, "upload": 0, "download": 0, "lastSeen": ""})
            item["upload"] += int(row["upload"])
            item["download"] += int(row["download"])
            item["lastSeen"] = max(item["lastSeen"], str(row["last_seen"] or ""))
        ordered = sorted(combined.values(), key=lambda item: item["upload"] + item["download"], reverse=True)
        for item in ordered:
            item["total"] = item["upload"] + item["download"]
        total_up = int(totals["upload"])
        total_down = int(totals["download"])
        return {
            "period": period,
            "group": group,
            "scope": scope,
            "upload": total_up,
            "download": total_down,
            "total": total_up + total_down,
            "known": int(known["bytes"]),
            "rows": ordered[: max(1, min(limit, 500))],
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = {
                row["key"]: row["value"]
                for row in self._db.execute("SELECT key, value FROM monitor_state").fetchall()
            }
            size = self.path.stat().st_size if self.path.exists() else 0
        return {
            "lastSuccess": state.get("last_success", ""),
            "lastError": state.get("last_error", ""),
            "liveConnections": _safe_int(state.get("live_connections")),
            "databaseBytes": size,
        }

    def close(self) -> None:
        with self._lock:
            self._db.close()


class ClashClient:
    def __init__(self, controller: str, secret: str = "", timeout: float = 5.0):
        self.url = controller.rstrip("/") + "/connections"
        self.secret = secret
        self.timeout = timeout

    def snapshot(self) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
        request = Request(self.url, headers=headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except HTTPError as exc:
            raise RuntimeError(f"Clash API HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"Clash API 暂不可用：{exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Clash API 返回了无效数据")
        return payload


class Collector(threading.Thread):
    def __init__(self, client: ClashClient, store: TrafficStore, interval: float):
        super().__init__(name="traffic-collector", daemon=True)
        self.client = client
        self.store = store
        self.interval = max(0.5, interval)
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self.store.record_snapshot(self.client.snapshot())
            except Exception as exc:  # Keep the dashboard alive while sing-box restarts.
                self.store.record_error(str(exc))
            remaining = max(0.1, self.interval - (time.monotonic() - started))
            self.stop_event.wait(remaining)

    def stop(self) -> None:
        self.stop_event.set()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SingBoxTrafficMonitor/1.0"

    @property
    def app(self) -> "DashboardServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _headers(self, status: HTTPStatus, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'",
        )
        self.end_headers()

    def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _file(self, filename: str, content_type: str) -> None:
        path = (self.app.ui_dir / filename).resolve()
        if path.parent != self.app.ui_dir.resolve() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        self._headers(HTTPStatus.OK, content_type, len(body))
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path == "/api/status":
                self._json(self.app.store.status())
            elif parsed.path == "/api/summary":
                period = query.get("period", ["today"])[0]
                group = query.get("group", ["site"])[0]
                scope = query.get("scope", ["all"])[0]
                limit = _safe_int(query.get("limit", [50])[0]) or 50
                self._json(self.app.store.summary(period, group, limit, scope))
            elif parsed.path == "/api/export.csv":
                period = query.get("period", ["today"])[0]
                group = query.get("group", ["site"])[0]
                scope = query.get("scope", ["all"])[0]
                summary = self.app.store.summary(period, group, 500, scope)
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["排名", "分类", "上传字节", "下载字节", "总字节", "最后活动"])
                for index, row in enumerate(summary["rows"], 1):
                    writer.writerow([index, row["label"], row["upload"], row["download"], row["total"], row["lastSeen"]])
                body = ("\ufeff" + output.getvalue()).encode("utf-8")
                self._headers(HTTPStatus.OK, "text/csv; charset=utf-8", len(body))
                self.wfile.write(body)
            elif parsed.path in {"/", "/index.html"}:
                self._file("index.html", "text/html; charset=utf-8")
            elif parsed.path == "/app.js":
                self._file("app.js", "text/javascript; charset=utf-8")
            elif parsed.path == "/styles.css":
                self._file("styles.css", "text/css; charset=utf-8")
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], store: TrafficStore, ui_dir: Path):
        super().__init__(address, DashboardHandler)
        self.store = store
        self.ui_dir = ui_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="sing-box 流量去向统计面板")
    parser.add_argument("--controller", default="http://127.0.0.1:9090")
    parser.add_argument("--secret", default="")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9091)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument("--ui-dir", type=Path, default=DEFAULT_UI)
    parser.add_argument("--once", action="store_true", help="采样一次后退出")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    store = TrafficStore(args.database.resolve())
    client = ClashClient(args.controller, args.secret)
    if args.once:
        try:
            result = store.record_snapshot(client.snapshot())
            print(json.dumps(result, ensure_ascii=False))
            return 0
        finally:
            store.close()

    if not args.ui_dir.is_dir():
        raise SystemExit(f"找不到面板资源目录：{args.ui_dir}")
    collector = Collector(client, store, args.interval)
    server = DashboardServer((args.host, args.port), store, args.ui_dir.resolve())
    stopping = threading.Event()

    def stop(_signum: int, _frame: Any) -> None:
        if stopping.is_set():
            return
        stopping.set()
        collector.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    collector.start()
    print(f"Traffic attribution dashboard: http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        collector.stop()
        collector.join(timeout=5)
        server.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

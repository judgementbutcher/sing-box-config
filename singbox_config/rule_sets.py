"""Download once per build and seal remote SRS rules into self-contained configs."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

import requests

from .io_utils import atomic_write_json

CORE_LINE = "sing-box version 1.15.0-alpha.11-reF1nd"
MAX_DOWNLOAD = 16 * 1024 * 1024
MAX_SOURCE = 64 * 1024 * 1024


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _tag(tag: Any) -> str:
    if (not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_!.\-]{0,159}", tag)
            or tag.endswith(".") or tag.split(".")[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}):
        raise ValueError("Invalid rule-set tag")
    return tag


def _source(body: bytes, tag: str) -> dict[str, Any]:
    if len(body) > MAX_SOURCE:
        raise ValueError(f"Rule-set source too large: {tag}")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"Invalid rule-set source: {tag}") from exc
    if (not isinstance(data, dict) or data.get("version") not in (1, 2, 3, 4)
            or not isinstance(data.get("rules"), list) or not data["rules"]
            or any(not isinstance(rule, dict) or not rule for rule in data["rules"])):
        raise ValueError(f"Invalid or empty rule-set source: {tag}")
    return data


def core_identity(core: Path | None = None) -> tuple[Path, dict[str, str]]:
    if core is None:
        configured = os.environ.get("SING_BOX_CORE")
        if configured:
            core = Path(configured)
        else:
            folder = Path(__file__).resolve().parents[1] / "runtime/cores/1.15.0-alpha.11-reF1nd"
            core = next(folder.rglob("sing-box.exe"), None)
    if core is None or not core.is_file():
        raise ValueError("Required rule-set parsing core is missing")
    core = core.resolve()
    try:
        result = subprocess.run([str(core), "version"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Unable to identify rule-set parsing core") from exc
    lines = result.stdout.decode("utf-8", errors="replace").splitlines()
    if result.returncode or not lines or lines[0].strip() != CORE_LINE:
        raise ValueError("Rule-set parsing core version mismatch")
    return core, {"validator": CORE_LINE, "core_sha256": digest(core.read_bytes())}


def _download(url: str, tag: str, *, proxy: str | None, timeout: float) -> bytes:
    # Never print upstream exceptions: URLs or proxy URLs can contain credentials.
    for via in dict.fromkeys((None, proxy)):
        try:
            with requests.Session() as session:
                session.trust_env = False
                proxies = {"http": via, "https": via} if via else None
                with session.get(url, timeout=(min(timeout, 10), timeout), proxies=proxies, stream=True) as response:
                    response.raise_for_status()
                    parts, size, started = [], 0, time.monotonic()
                    for chunk in response.iter_content(65536):
                        size += len(chunk)
                        if size > MAX_DOWNLOAD or time.monotonic() - started > timeout * 2:
                            raise ValueError(f"Rule-set download exceeded limit: {tag}")
                        parts.append(chunk)
                    body = b"".join(parts)
                    if not body.startswith(b"SRS"):
                        raise ValueError(f"Invalid SRS download: {tag}")
                    return body
        except (requests.RequestException, ValueError):
            continue
    raise ValueError(f"Rule-set download failed: {tag}; active release preserved")


def _decompile(core: Path, raw: bytes, tag: str, *, workdir: Path | None = None) -> bytes:
    scratch = (workdir or Path(__file__).resolve().parents[1] / "runtime").resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="singbox-rules-", dir=scratch) as directory:
        path = Path(directory)
        if path.resolve().parent != scratch:
            raise ValueError("Unexpected rule-set scratch location")
        binary, source = path / "input.srs", path / "output.json"
        binary.write_bytes(raw)
        try:
            result = subprocess.run([str(core), "rule-set", "decompile", str(binary), "-o", str(source)],
                                    capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Rule-set parsing failed: {tag}") from exc
        if result.returncode or not source.is_file() or source.stat().st_size > MAX_SOURCE:
            raise ValueError(f"Rule-set parsing failed: {tag}")
        body = source.read_bytes()
        _source(body, tag)
        return body


def load_snapshot(directory: Path) -> tuple[dict[str, Any], dict[str, tuple[bytes, bytes]]]:
    """Validate every attachment before selecting a subset for an offline build."""
    try:
        if directory.is_symlink():
            raise ValueError("Rule-set snapshot links are not allowed")
        metadata = json.loads((directory / "snapshot.json").read_text(encoding="utf-8"))
        if (not isinstance(metadata, dict) or metadata.get("schema_version") != 1
                or not isinstance(metadata.get("entries"), dict) or not isinstance(metadata.get("core"), dict)
                or metadata["core"].get("validator") != CORE_LINE
                or not re.fullmatch(r"[0-9a-f]{64}", str(metadata["core"].get("core_sha256", "")))):
            raise ValueError("Invalid rule-set snapshot metadata")
        expected, bodies = {"snapshot.json"}, {}
        for name, entry in metadata["entries"].items():
            tag = _tag(name)
            if (not isinstance(entry, dict) or not isinstance(entry.get("url"), str)
                    or not entry["url"].startswith(("http://", "https://"))
                    or not isinstance(entry.get("downloaded_at"), str)):
                raise ValueError(f"Invalid rule-set snapshot entry: {tag}")
            binary, source = directory / f"{tag}.srs", directory / f"{tag}.json"
            expected.update((binary.name, source.name))
            if binary.is_symlink() or source.is_symlink() or binary.stat().st_size > MAX_DOWNLOAD or source.stat().st_size > MAX_SOURCE:
                raise ValueError(f"Invalid rule-set snapshot files: {tag}")
            raw, text = binary.read_bytes(), source.read_bytes()
            if not raw.startswith(b"SRS") or digest(raw) != entry.get("sha256") or digest(text) != entry.get("source_sha256"):
                raise ValueError(f"Rule-set snapshot hash mismatch: {tag}")
            _source(text, tag)
            bodies[tag] = (raw, text)
        actual = {p.name for p in directory.iterdir()}
        if actual != expected:
            raise ValueError("Rule-set snapshot file set mismatch")
        return metadata, bodies
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Rule-set snapshot missing or invalid; run an online update first") from exc


def remote_definitions(configs: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    definitions = {}
    for config in configs.values():
        for item in config["route"].get("rule_set", []):
            if item["type"] != "remote":
                continue
            tag, url = _tag(item["tag"]), item["url"]
            if not isinstance(url, str) or not url.startswith(("https://", "http://")):
                raise ValueError(f"Invalid rule-set URL: {tag}")
            if tag in definitions and definitions[tag] != url:
                raise ValueError(f"Rule-set URL differs across platforms: {tag}")
            definitions[tag] = url
    return definitions


def materialize(configs: Mapping[str, dict[str, Any]], *, directory: Path,
                core: Path | None = None, identity: Mapping[str, str] | None = None,
                offline: bool = False, previous: Path | None = None,
                proxy: str | None = None, timeout: float = 20) -> dict[str, dict[str, Any]]:
    """Seal a complete immutable snapshot, then return configs with inline rules."""
    definitions = remote_definitions(configs)
    if directory.exists():
        raise ValueError("Rule-set snapshot destination already exists")
    if definitions and not offline:
        core, actual_identity = core_identity(core)
        if identity is not None and dict(identity) != actual_identity:
            raise ValueError("Rule-set parsing core changed during build")
        identity = actual_identity
    elif identity is None:
        if definitions:
            core, identity = core_identity(core)
        else:
            identity = {"validator": CORE_LINE, "core_sha256": "0" * 64}
    entries, bodies = {}, {}
    if definitions and offline:
        if previous is None:
            raise ValueError("No validated rule-set snapshot; run an online update first")
        stored, stored_bodies = load_snapshot(previous)
        if stored["core"] != dict(identity):
            raise ValueError("Offline rule-set snapshot parsing core mismatch")
        for tag, url in definitions.items():
            entry = stored["entries"].get(tag)
            if entry is None or entry["url"] != url:
                raise ValueError(f"Offline rule-set missing or source changed: {tag}; run an online update")
            entries[tag], bodies[tag] = entry, stored_bodies[tag]
    elif definitions:
        for tag, url in definitions.items():
            raw = _download(url, tag, proxy=proxy, timeout=timeout)
            source = _decompile(core, raw, tag, workdir=directory.parent)
            entries[tag] = {"url": url, "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "sha256": digest(raw), "source_sha256": digest(source)}
            bodies[tag] = (raw, source)
        if digest(core.read_bytes()) != identity["core_sha256"]:
            raise ValueError("Rule-set parsing core changed during build")
    sealed = copy.deepcopy(configs)
    for config in sealed.values():
        for index, item in enumerate(config["route"].get("rule_set", [])):
            if item["type"] == "remote":
                tag = item["tag"]
                config["route"]["rule_set"][index] = {
                    "type": "inline", "tag": tag, "rules": _source(bodies[tag][1], tag)["rules"]}
    directory.mkdir(parents=True, exist_ok=False)
    for tag, (raw, source) in bodies.items():
        (directory / f"{tag}.srs").write_bytes(raw)
        (directory / f"{tag}.json").write_bytes(source)
    atomic_write_json(directory / "snapshot.json", {"schema_version": 1, "core": dict(identity), "entries": entries})
    validate_embedded(sealed, directory, definitions=definitions)
    return sealed


def validate_embedded(configs: Mapping[str, dict[str, Any]], directory: Path,
                      *, definitions: Mapping[str, str] | None = None) -> None:
    metadata, bodies = load_snapshot(directory)
    if definitions is not None and dict(definitions) != {tag: entry["url"] for tag, entry in metadata["entries"].items()}:
        raise ValueError("Configuration rule-set references differ from snapshot")
    seen = set()
    for config in configs.values():
        for item in config["route"].get("rule_set", []):
            if item["type"] != "inline":
                raise ValueError("Sealed configuration contains external rule-set")
            tag = item["tag"]
            if tag in bodies:
                if item["rules"] != _source(bodies[tag][1], tag)["rules"]:
                    raise ValueError(f"Embedded rule-set differs from snapshot: {tag}")
                seen.add(tag)
    if seen != set(bodies):
        raise ValueError("Rule-set snapshot contains unreferenced content")

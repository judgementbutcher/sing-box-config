"""Immutable releases; only active-release.json is authoritative.

Exports and the editable subscription manifest are recoverable projections, not
commit points. A crash before the pointer switch leaves the old release active;
a crash after it is recovered from projection-journal.json on the next command.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Sequence

import yaml

from . import generator, rule_sets
from .manifest import contained_path, read_manifest, validate_manifest
from .errors import OperationError, safe_error_message

PLATFORMS = ("desktop", "android")
CORE_VERSION = "sing-box version 1.15.0-alpha.11-reF1nd"
POINTER_NAME = "active-release.json"
LOCK_NAME = "publish.lock"
JOURNAL_NAME = "projection-journal.json"
PENDING_EXIT_CODE = 10
ROOT = Path(__file__).resolve().parents[1]


class ReleaseError(OperationError):
    pass


def progress(message: str) -> None:
    print(f"[进度] {message}", file=sys.stderr, flush=True)


def committed_projection_pending(runtime_root: Path) -> bool:
    """A journal written before the pointer switch is not a committed release."""
    try:
        journal = _json(runtime_root / JOURNAL_NAME)
        pointer = _json(runtime_root / POINTER_NAME)
        return (isinstance(journal, dict) and isinstance(pointer, dict)
                and bool(journal.get("build_id")) and journal.get("build_id") == pointer.get("build_id"))
    except (OSError, ValueError, RuntimeError, TypeError):
        return False


class FileLock:
    """Kernel-owned lock: process exit releases it, the lock file stays put."""
    def __init__(self, path: Path):
        self.path = path
        self.file = None

    def __enter__(self):
        no_links(self.path, recursive=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a+b")
        if self.path.stat().st_size == 0:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.file.close()
            raise ReleaseError("Another configuration operation is running") from exc
        return self

    def __exit__(self, *_args):
        self.file.close()


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12]


def safe_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", value):
        raise ReleaseError("Invalid snapshot/build id")
    return value


def no_links(root: Path, *, recursive: bool = True) -> None:
    for path in (root, *root.parents):
        if path.is_symlink() or (path.exists() and getattr(path.stat(), "st_file_attributes", 0) & 0x400):
            raise ReleaseError("Reparse points/symlinks are not allowed")
    if recursive and root.is_dir():
        for path in root.rglob("*"):
            if path.is_symlink() or getattr(path.stat(), "st_file_attributes", 0) & 0x400:
                raise ReleaseError("Reparse points/symlinks are not allowed")


def _write_bytes(path: Path, body: bytes, *, expected_hashes: tuple[str, ...] | None = None) -> None:
    no_links(path, recursive=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as target:
            target.write(body)
            target.flush()
            os.fsync(target.fileno())
        if expected_hashes is not None:
            no_links(path, recursive=False)
            current = sha256_file(path) if path.exists() else "missing"
            if current not in expected_hashes:
                raise ReleaseError("Working manifest changed externally; inspect pending transaction before retrying")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, data: Any) -> None:
    _write_bytes(path, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def _write_config(path: Path, data: Any) -> None:
    _write_bytes(path, (json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))


def _json(path: Path) -> Any:
    no_links(path, recursive=False)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def core_identity(core: Path) -> dict[str, str]:
    if not core.is_file():
        raise ReleaseError("Required validation core is missing")
    result = subprocess.run([str(core), "version"], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=30)
    if result.returncode or not result.stdout.splitlines() or result.stdout.splitlines()[0].strip() != CORE_VERSION:
        raise ReleaseError("Validation core version mismatch")
    return {"validator": CORE_VERSION, "core_sha256": sha256_file(core)}


def _run_core(core: Path, config: Path) -> None:
    result = subprocess.run([str(core), "check", "-c", str(config)], cwd=config.parent,
                            capture_output=True, timeout=90)
    if result.returncode:
        # Core diagnostics may contain node passwords/URLs: do not print them.
        raise ReleaseError(f"Core check failed: {config.parent.name}")


def _files(root: Path) -> dict[str, dict[str, Any]]:
    no_links(root)
    return {p.relative_to(root).as_posix(): {"sha256": sha256_file(p), "size": p.stat().st_size}
            for p in sorted(root.rglob("*")) if p.is_file() and p != root / "manifest.json"}


def validate_release(root: Path, identity: dict[str, str] | None = None) -> dict[str, Any]:
    no_links(root)
    metadata = _json(root / "release.json")
    if not isinstance(metadata, dict) or metadata.get("schema_version") != 1 or metadata.get("build_id") != root.name:
        raise ReleaseError("Invalid release metadata")
    if metadata.get("platforms") != list(PLATFORMS) or metadata.get("validator") != CORE_VERSION:
        raise ReleaseError("Invalid release platforms/validator")
    if not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("core_sha256", ""))):
        raise ReleaseError("Invalid core digest")
    if identity and any(metadata.get(key) != value for key, value in identity.items()):
        raise ReleaseError("Snapshot validation core differs from installed core")
    listed = _json(root / "manifest.json")
    if not isinstance(listed, dict) or listed != _files(root):
        raise ReleaseError("Release file set/hash mismatch (missing, extra or changed files)")
    for platform in PLATFORMS:
        config = root / platform / "config.json"
        stamp = _json(root / platform / "config.validated.json")
        if not isinstance(stamp, dict) or stamp.get("build_id") != root.name or stamp.get("sha256") != sha256_file(config):
            raise ReleaseError("Invalid configuration validation stamp")
        if any(stamp.get(key) != metadata[key] for key in ("validator", "core_sha256")):
            raise ReleaseError("Configuration validator mismatch")
        data = _json(config)
        if data.get("providers"):
            raise ReleaseError("Provider experiments cannot be activated")
    if not (root / "subscription-cache").is_dir() or not (root / "inputs" / "config" / "policy.yaml").is_file():
        raise ReleaseError("Release input/cache attachments are missing")
    if metadata.get("rule_set_snapshot") is not None:
        if metadata["rule_set_snapshot"] != 1:
            raise ReleaseError("Unsupported rule-set snapshot version")
        configs = {p: _json(root / p / "config.json") for p in PLATFORMS}
        policy = generator.load_yaml(root / "inputs/config/policy.yaml")
        definitions = {p: {"route": {"rule_set": generator.build_rule_sets(
            data, policy.get("rule_set_urls", {}), root / "inputs/config/rule-sets")}}
            for p, data in configs.items()}
        rule_sets.validate_embedded(configs, root / "rule-set-snapshot",
                                    definitions=rule_sets.remote_definitions(definitions))
        snapshot, _ = rule_sets.load_snapshot(root / "rule-set-snapshot")
        if snapshot["core"] != {key: metadata[key] for key in ("validator", "core_sha256")}:
            raise ReleaseError("Rule-set snapshot core differs from configuration validator")
    return metadata


def active_release(runtime_root: Path, *, validate: bool = True) -> Path | None:
    pointer = runtime_root / POINTER_NAME
    if not pointer.exists():
        return None
    no_links(pointer)
    data = _json(pointer)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ReleaseError("Invalid active pointer")
    build_id = safe_id(data.get("build_id", ""))
    if data.get("release") != f"releases/{build_id}":
        raise ReleaseError("Invalid active pointer path")
    release = contained_path(runtime_root, data["release"])
    no_links(release)
    if validate:
        validate_release(release)
    return release


def _copy(source: Path, target: Path) -> None:
    no_links(source)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def _new(runtime_root: Path) -> Path:
    no_links(runtime_root / "releases", recursive=False)
    candidate = runtime_root / "releases" / _id()
    candidate.mkdir(parents=True, exist_ok=False)
    return candidate


def _capture_inputs(candidate: Path, config_root: Path) -> None:
    _copy(config_root, candidate / "inputs" / "config")
    for directory in ("parsers", "singbox_config", "scripts"):
        _copy(ROOT / directory, candidate / "inputs" / "source" / directory)
    for name in ("pyproject.toml", "requirements.lock"):
        shutil.copy2(ROOT / name, candidate / "inputs" / "source" / name)


def _finish(candidate: Path, core: Path, identity: dict[str, str], *, origin: str) -> None:
    for platform in PLATFORMS:
        progress(f"核心校验：{'桌面' if platform == 'desktop' else '安卓'}配置")
        config = candidate / platform / "config.json"
        _run_core(core, config)
        _write_json(candidate / platform / "config.validated.json", {
            "schema_version": 2, "build_id": candidate.name,
            "sha256": sha256_file(config), **identity,
            "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    if sha256_file(core) != identity["core_sha256"]:
        raise ReleaseError("Validation core changed during build")
    _write_json(candidate / "release.json", {
        "schema_version": 1, "build_id": candidate.name, **identity,
        "platforms": list(PLATFORMS), "origin": origin,
        "input_provenance": "working-copy-not-historical" if origin.startswith("legacy-") else "captured-inputs",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": sys.version.split()[0],
        "dependencies": {name: importlib.metadata.version(name) for name in ("requests", "PyYAML")},
        **({"rule_set_snapshot": 1} if (candidate / "rule-set-snapshot").is_dir() else {}),
    })
    _write_json(candidate / "manifest.json", _files(candidate))
    validate_release(candidate, identity)


def _export(release: Path, output_root: Path) -> None:
    # Deliberately leave client databases and old experimental files untouched.
    # A per-platform stamp is written last; the server never reads this export.
    no_links(output_root, recursive=False)
    for platform in PLATFORMS:
        for name in ("config.json", "config.validated.json"):
            _write_bytes(output_root / platform / name, (release / platform / name).read_bytes())


def _subscription_files(config_root: Path) -> dict[Path, Path]:
    manifest = config_root / "local" / "subscriptions.yaml"
    data = read_manifest(manifest, generator.load_yaml(config_root / "policy.yaml"))
    paths = [contained_path(manifest.parent, item["path"]) for item in data["subscriptions"]]
    return {path.relative_to(manifest.parent): path for path in paths}


def _check_projection(release: Path, config_root: Path, manifest_before: str,
                      inputs_before: dict[str, str] | None, *, committed: bool) -> list[tuple[Path, Path]]:
    """Check every precondition before writing any working input or manifest."""
    target = config_root / "local" / "subscriptions.yaml"
    expected = release / "inputs" / "config" / "local" / "subscriptions.yaml"
    current = sha256_file(target) if target.exists() else "missing"
    allowed = (manifest_before, sha256_file(expected)) if committed else (manifest_before,)
    if current not in allowed:
        raise ReleaseError("Working manifest changed externally; inspect pending transaction before retrying")
    before = {Path(name): digest for name, digest in inputs_before.items()} if inputs_before is not None else None
    additions = []
    for relative, source in _subscription_files(release / "inputs" / "config").items():
        destination = contained_path(target.parent, relative.as_posix())
        expected_hash = sha256_file(source) if source.is_file() else "missing"
        # Old journals cannot establish which missing files were new. Refuse
        # to recreate them, while allowing already-complete projections.
        if before is not None and relative not in before:
            raise ReleaseError("Subscription input baseline is missing; inspect journal before retrying")
        original = before[relative] if before is not None else expected_hash
        actual = sha256_file(destination) if destination.exists() else "missing"
        allowed = {original}
        if committed and original == "missing" and before is not None:
            allowed.add(expected_hash)  # A previous recovery may have created this new file.
        if actual not in allowed or (before is None and actual != expected_hash):
            raise ReleaseError("Subscription input changed externally; inspect pending transaction before retrying")
        if actual == "missing" and expected_hash != "missing":
            if before is None or original != "missing":
                raise ReleaseError("Cannot recreate an input without evidence it was added by this transaction")
            additions.append((source, destination))
    return additions


def recover(runtime_root: Path, output_root: Path, config_root: Path) -> None:
    journal_path = runtime_root / JOURNAL_NAME
    if not journal_path.exists():
        return
    journal = _json(journal_path)
    if journal.get("config_root") != str(config_root.resolve()) or journal.get("output_root") != str(output_root.resolve()):
        raise ReleaseError("Recovery roots differ from the pending transaction")
    release = active_release(runtime_root)
    if release is not None and release.name == journal["build_id"]:
        if journal.get("manifest_before") is not None:
            target = config_root / "local" / "subscriptions.yaml"
            expected = release / "inputs" / "config" / "local" / "subscriptions.yaml"
            additions = _check_projection(release, config_root, journal["manifest_before"],
                                          journal.get("inputs_before"), committed=True)
            for source, destination in additions:
                no_links(destination, recursive=False)
                destination.parent.mkdir(parents=True, exist_ok=True)
                body = source.read_bytes()
                # Never replace an input created by an external editor after
                # the preflight. Partial I/O remains a conflict for inspection.
                with destination.open("xb") as sink:
                    sink.write(body)
                    sink.flush()
                    os.fsync(sink.fileno())
            _check_projection(release, config_root, journal["manifest_before"],
                              journal.get("inputs_before"), committed=True)
            _write_bytes(target, expected.read_bytes(),
                         expected_hashes=(journal["manifest_before"], sha256_file(expected)))
        _export(release, output_root)
    journal_path.unlink()


def _activate(candidate: Path, runtime_root: Path, output_root: Path, config_root: Path,
              *, manifest_before: str | None = None, inputs_before: dict[str, str] | None = None) -> str:
    previous = active_release(runtime_root, validate=False)
    journal = {"schema_version": 2, "build_id": candidate.name,
               "manifest_before": manifest_before, "inputs_before": inputs_before,
               "config_root": str(config_root.resolve()),
               "output_root": str(output_root.resolve())}
    if manifest_before is not None:
        _check_projection(candidate, config_root, manifest_before, inputs_before, committed=False)
    _write_json(runtime_root / JOURNAL_NAME, journal)
    _write_json(runtime_root / POINTER_NAME, {
        "schema_version": 1, "build_id": candidate.name, "release": f"releases/{candidate.name}",
        "previous_build_id": previous.name if previous else None,
        "committed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    print(f"[COMMITTED] build_id={candidate.name}；活动版本已切换，正在同步导出。", flush=True)
    try:
        recover(runtime_root, output_root, config_root)
    except ReleaseError:
        print("[WARNING] 已提交，但工作文件存在冲突；请保留事务记录，解决冲突后执行 recover，暂勿导入 dist。", flush=True)
        raise
    except OSError:
        print("[WARNING] 已提交，导出或清单同步未完成；请先执行 recover，暂勿导入 dist。", flush=True)
    else:
        print(f"[OK] build_id={candidate.name}；两端配置已提交且导出同步完成。客户端仍需刷新配置。", flush=True)
    return candidate.name


def _bootstrap(runtime_root: Path, output_root: Path, config_root: Path, core: Path,
               identity: dict[str, str]) -> None:
    if active_release(runtime_root, validate=False) is not None:
        return
    if not all((output_root / p / "config.json").is_file() for p in PLATFORMS):
        return
    _legacy_check(output_root)
    candidate = _new(runtime_root)
    _capture_inputs(candidate, config_root)
    cache = runtime_root / "subscription-cache"
    if cache.exists():
        _copy(cache, candidate / "subscription-cache")
    else:
        (candidate / "subscription-cache").mkdir()
    for platform in PLATFORMS:
        (candidate / platform).mkdir()
        shutil.copy2(output_root / platform / "config.json", candidate / platform / "config.json")
    _finish(candidate, core, identity, origin="legacy-dist-import")
    _activate(candidate, runtime_root, output_root, config_root)


def build(*, runtime_root: Path, output_root: Path, config_root: Path, core: Path,
          offline: bool = False, mode: str = "all", name: str = "", link: str = "") -> str:
    with FileLock(runtime_root / LOCK_NAME):
        progress("1/5 检查固定核心和待恢复事务")
        identity = core_identity(core)
        recover(runtime_root, output_root, config_root)
        previous = active_release(runtime_root)
        candidate = _new(runtime_root)
        progress("2/5 捕获工作输入和上次缓存；正式版本尚未改变")
        _capture_inputs(candidate, config_root)
        cache = previous / "subscription-cache" if previous else runtime_root / "subscription-cache"
        if cache.exists():
            _copy(cache, candidate / "subscription-cache")
        else:
            (candidate / "subscription-cache").mkdir()
        manifest_path = candidate / "inputs" / "config" / "local" / "subscriptions.yaml"
        before = None
        inputs_before = None
        if mode != "all":
            # The baseline must describe the bytes actually copied, never a
            # newer working copy saved while source/cache attachments copied.
            before = sha256_file(manifest_path) if manifest_path.exists() else "missing"
            local_before = {p.relative_to(manifest_path.parent): sha256_file(p)
                            for p in manifest_path.parent.rglob("*") if p.is_file()}
            _edit_manifest(manifest_path, mode, name, link)
            inputs_before = {relative.as_posix(): local_before.get(relative, "missing")
                             for relative in _subscription_files(candidate / "inputs" / "config")}
        old_cache = generator.CACHE_DIR
        try:
            generator.CACHE_DIR = candidate / "subscription-cache"
            config = candidate / "inputs" / "config"
            progress(f"3/5 {'离线复用' if offline else '下载并解析'}订阅与规则，生成桌面和安卓配置")
            configs = generator.generate(PLATFORMS, policy_path=config / "policy.yaml",
                                         manifest_path=manifest_path, rule_sets=config / "rule-sets", offline=offline,
                                         core=core, core_info=identity,
                                         rule_snapshot_dir=candidate / "rule-set-snapshot",
                                         rule_snapshot_source=previous / "rule-set-snapshot" if previous else None)
            generator.stage_staged_cache(candidate / "subscription-cache")
            for platform, data in configs.items():
                _write_config(candidate / platform / "config.json", data)
            progress("4/5 校验两端配置并封存候选版本")
            _finish(candidate, core, identity, origin=mode)
            _bootstrap(runtime_root, output_root, config_root, core, identity)
            progress("5/5 提交活动版本并同步兼容导出")
            return _activate(candidate, runtime_root, output_root, config_root,
                             manifest_before=before, inputs_before=inputs_before)
        finally:
            generator.CACHE_DIR = old_cache
            generator._STAGED_CACHE.clear()
            generator._FETCHED.clear()


def _edit_manifest(path: Path, mode: str, name: str, link: str) -> None:
    policy = generator.load_yaml(path.parents[1] / "policy.yaml")
    data = read_manifest(path, policy) if path.exists() else {"subscriptions": []}
    items = data["subscriptions"]
    matches = [e for e in items if e["name"] == name]
    if mode == "add":
        if matches or not name.strip():
            raise ReleaseError("Subscription name is empty or already exists")
        if not re.fullmatch(r"(?i)(?:https?|anytls|hy2|hysteria2|ss|trojan|tuic|vless|vmess)://\S+", link):
            raise ReleaseError("Expected subscription URL or supported node URI")
        suffix = ".url.txt" if link.lower().startswith(("http://", "https://")) else ".txt"
        relative = "subscriptions/source-" + uuid.uuid4().hex + suffix
        target = contained_path(path.parent, relative)
        _write_bytes(target, (link + "\n").encode("utf-8"))
        items.append({"name": name, "path": relative})
    elif len(matches) != 1:
        raise ReleaseError("Subscription not found")
    elif mode == "remove":
        items.remove(matches[0])
        # Shared input files are deliberately retained. Deletion is never part
        # of configuration rollback; unused private inputs can be reviewed later.
    else:
        matches[0]["enabled"] = mode == "enable"
    validate_manifest(data, policy, path.parent)
    _write_bytes(path, yaml.safe_dump(data, allow_unicode=True, sort_keys=False).encode("utf-8"))


def _legacy_check(source: Path) -> None:
    no_links(source)
    for platform in PLATFORMS:
        config = source / platform / "config.json"
        stamp = _json(source / platform / "config.validated.json")
        if not isinstance(stamp, dict) or stamp.get("sha256") != sha256_file(config) or stamp.get("validator") != CORE_VERSION:
            raise ReleaseError("Legacy snapshot hash/validator mismatch; refusing restore")
        if _json(config).get("providers"):
            raise ReleaseError("Legacy Provider snapshots are diagnostic-only")


def restore(build_id: str, *, runtime_root: Path, output_root: Path, config_root: Path,
            core: Path, legacy: bool = False) -> str:
    safe_id(build_id)
    with FileLock(runtime_root / LOCK_NAME):
        progress("检查固定核心、恢复事务和历史版本完整性")
        identity = core_identity(core)
        recover(runtime_root, output_root, config_root)
        source = contained_path(runtime_root / ("backups" if legacy else "releases"), build_id)
        if legacy:
            source = source / "dist" if (source / "dist").is_dir() else source
            _legacy_check(source)
        else:
            validate_release(source, identity)
        candidate = _new(runtime_root)
        progress("复制历史配置到新候选；不覆盖工作配置或客户端选择")
        if legacy:
            _capture_inputs(candidate, config_root)
            (candidate / "subscription-cache").mkdir()
        else:
            _copy(source / "inputs", candidate / "inputs")
            _copy(source / "subscription-cache", candidate / "subscription-cache")
            if (source / "rule-set-snapshot").is_dir():
                _copy(source / "rule-set-snapshot", candidate / "rule-set-snapshot")
        for platform in PLATFORMS:
            (candidate / platform).mkdir()
            shutil.copy2(source / platform / "config.json", candidate / platform / "config.json")
        _finish(candidate, core, identity, origin=f"{'legacy-restore' if legacy else 'restore'}:{build_id}")
        _bootstrap(runtime_root, output_root, config_root, core, identity)
        return _activate(candidate, runtime_root, output_root, config_root)


def verify(*, runtime_root: Path, output_root: Path, config_root: Path, core: Path) -> None:
    with FileLock(runtime_root / LOCK_NAME):
        identity = core_identity(core)
        recover(runtime_root, output_root, config_root)
        release = active_release(runtime_root)
        if release is None:
            _legacy_check(output_root)
            release = output_root
        else:
            validate_release(release, identity)
        for platform in PLATFORMS:
            _run_core(core, release / platform / "config.json")
            for name in ("config.json", "config.validated.json"):
                if sha256_file(output_root / platform / name) != sha256_file(release / platform / name):
                    raise ReleaseError("Compatibility export is stale; run recover")
        print(f"[OK] {release.name}: both platforms checked")
        inputs = release / "inputs" / "config"
        if inputs.exists() and _files(config_root) != _files(inputs):
            print("[NOTE] Working config differs from active input snapshot; next update uses the working config")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("all", "check", "rollback", "add", "remove", "disable", "enable", "list", "sources", "recover"))
    parser.add_argument("--runtime-root", type=Path, default=ROOT / "runtime")
    parser.add_argument("--output-root", type=Path, default=ROOT / "dist")
    parser.add_argument("--config-root", type=Path, default=ROOT / "config")
    parser.add_argument("--core", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--name", default="")
    parser.add_argument("--link", default="")
    parser.add_argument("--build-id", default="")
    parser.add_argument("--legacy", action="store_true")
    args = parser.parse_args(argv)
    try:
        for path in (args.runtime_root, args.output_root, args.config_root):
            no_links(path, recursive=False)
        common = dict(runtime_root=args.runtime_root.resolve(), output_root=args.output_root.resolve(),
                      config_root=args.config_root.resolve())
        if args.command == "list":
            active = active_release(args.runtime_root, validate=False)
            for label in ("releases", "backups"):
                base = args.runtime_root / label
                for path in sorted(base.iterdir(), reverse=True) if base.exists() else []:
                    if path.is_dir():
                        try:
                            if label == "releases":
                                validate_release(path)
                            else:
                                _legacy_check(path / "dist" if (path / "dist").is_dir() else path)
                            state = "valid"
                            if path == active:
                                state += ", active"
                        except (OSError, ValueError, ReleaseError, KeyError, TypeError):
                            state = "invalid/incomplete"
                        print(f"{label}: {path.name} [{state}]")
        elif args.command == "sources":
            data = read_manifest(args.config_root / "local" / "subscriptions.yaml", generator.load_yaml(args.config_root / "policy.yaml"))
            for item in data["subscriptions"]:
                print(f"{item['name']} [{'enabled' if item.get('enabled', True) else 'disabled'}]")
        elif args.command == "recover":
            with FileLock(args.runtime_root / LOCK_NAME):
                recover(**common)
                release = active_release(args.runtime_root)
                if release:
                    _export(release, args.output_root)
            print("[OK] 兼容导出与清单同步完成；客户端状态未修改。")
        else:
            if args.core is None:
                raise ReleaseError("--core is required")
            if args.command == "check":
                verify(**common, core=args.core.resolve())
            elif args.command == "rollback":
                restore(args.build_id, **common, core=args.core.resolve(), legacy=args.legacy)
            else:
                build(**common, core=args.core.resolve(), offline=args.offline,
                      mode=args.command, name=args.name, link=args.link)
            if (args.runtime_root / JOURNAL_NAME).exists():
                return PENDING_EXIT_CODE if committed_projection_pending(args.runtime_root) else 1
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, yaml.YAMLError, subprocess.SubprocessError) as exc:
        print(f"[ERROR] {safe_error_message(exc)}", file=sys.stderr)
        if committed_projection_pending(args.runtime_root):
            print("[待同步] 活动版本已经提交。请保留事务记录并执行 recover；暂勿导入 dist。", file=sys.stderr)
            return PENDING_EXIT_CODE
        print("[提示] 操作未完成；请先查看活动版本状态，再按错误提示重试。", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

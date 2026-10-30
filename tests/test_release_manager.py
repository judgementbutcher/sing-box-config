import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from singbox_config import generator, release_manager as rm


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    config = tmp_path / "config"
    policy = {"groups": {"ai_regions": ["US"]}, "config": {"dns": {"servers": [], "rules": []},
              "route": {"rules": []}}, "subscription": {"cache_max_age": "3d"}}
    write(config / "policy.yaml", policy)
    (config / "rule-sets").mkdir()
    nodes = [{"type": "vless", "tag": "US 01", "server": "node.example.com", "server_port": 443,
              "uuid": "00000000-0000-4000-8000-000000000000", "tls": {"enabled": True}}]
    write(config / "local" / "input.json", {"outbounds": nodes})
    write(config / "local" / "subscriptions.yaml", {"subscriptions": [{"name": "US source", "path": "input.json"}]})
    core = tmp_path / "core"
    core.write_bytes(b"test core")
    identity = {"validator": rm.CORE_VERSION, "core_sha256": rm.sha256_file(core)}
    monkeypatch.setattr(rm, "core_identity", lambda _core: identity)
    monkeypatch.setattr(rm, "_run_core", lambda _core, path: json.loads(path.read_text(encoding="utf-8")))
    return dict(runtime_root=tmp_path / "runtime", output_root=tmp_path / "dist", config_root=config, core=core)


def tree_hash(path):
    return {p.relative_to(path).as_posix(): rm.sha256_file(p) for p in path.rglob("*") if p.is_file()}


def cli_args(workspace, command="all"):
    return [command, "--runtime-root", str(workspace["runtime_root"]),
            "--output-root", str(workspace["output_root"]),
            "--config-root", str(workspace["config_root"]), "--core", str(workspace["core"])]


def test_cli_runtime_failure_is_friendly_and_redacts_urls(workspace, monkeypatch, capsys):
    monkeypatch.setattr(rm, "build", lambda **_kwargs: (_ for _ in ()).throw(
        RuntimeError("download failed: https://subscription.example.invalid/PRIVATE-MARKER")))
    assert rm.main(cli_args(workspace)) == 1
    output = capsys.readouterr().err
    assert "[ERROR]" in output
    assert "PRIVATE-MARKER" not in output
    assert "Traceback" not in output


def test_cli_yaml_failure_never_echoes_raw_manifest(workspace, capsys):
    (workspace["config_root"] / "local/subscriptions.yaml").write_text(
        "subscriptions:\n - name: PRIVATE-MARKER: invalid\n", encoding="utf-8")
    assert rm.main(cli_args(workspace)) == 1
    output = capsys.readouterr().err
    assert "line 2" in output
    assert "PRIVATE-MARKER" not in output
    assert "Traceback" not in output


def test_cli_uses_distinct_pending_exit_and_successful_recovery(workspace, monkeypatch, capsys):
    rm.build(**workspace)
    export = rm._export
    monkeypatch.setattr(rm, "_export", lambda *_args: (_ for _ in ()).throw(OSError("injected")))
    assert rm.main(cli_args(workspace)) == rm.PENDING_EXIT_CODE == 10
    output = capsys.readouterr()
    assert "[COMMITTED]" in output.out
    assert "[WARNING]" in output.out
    assert "[进度] 5/5" in output.err
    assert rm.main(cli_args(workspace, "recover")) == 10
    monkeypatch.setattr(rm, "_export", export)
    assert rm.main(cli_args(workspace, "recover")) == 0
    assert not (workspace["runtime_root"] / rm.JOURNAL_NAME).exists()


def test_cli_precommit_journal_is_not_reported_as_committed(workspace, monkeypatch, capsys):
    rm.build(**workspace)
    pointer = (workspace["runtime_root"] / rm.POINTER_NAME).read_bytes()
    write_json = rm._write_json

    def fail_pointer(path, data):
        if path.name == rm.POINTER_NAME:
            raise OSError("injected pointer failure")
        return write_json(path, data)

    monkeypatch.setattr(rm, "_write_json", fail_pointer)
    capsys.readouterr()
    assert rm.main(cli_args(workspace)) == 1
    output = capsys.readouterr()
    assert "[COMMITTED]" not in output.out
    assert "[待同步]" not in output.err
    assert (workspace["runtime_root"] / rm.POINTER_NAME).read_bytes() == pointer


def test_cli_argument_errors_keep_exit_two():
    with pytest.raises(SystemExit) as caught:
        rm.main(["all", "--unknown-audit-option"])
    assert caught.value.code == 2


def remote_policy(workspace, monkeypatch):
    from singbox_config import rule_sets
    path = workspace["config_root"] / "policy.yaml"
    policy = generator.load_yaml(path)
    policy["rule_set_urls"] = {"geosite": "https://rules.example/{tag}.srs"}
    policy["config"]["route"]["rules"] = [{"rule_set": "geosite-cn", "outbound": "direct"}]
    write(path, policy)
    identity = rm.core_identity(workspace["core"])
    monkeypatch.setattr(rule_sets, "core_identity", lambda core: (core, identity))
    monkeypatch.setattr(rule_sets, "_download", lambda url, tag, **kwargs: b"SRS" + tag.encode())
    monkeypatch.setattr(rule_sets, "_decompile", lambda core, raw, tag, **kwargs:
                        json.dumps({"version": 1, "rules": [{"domain_suffix": ["example.cn"]}]}).encode())
    return rule_sets


def test_rule_snapshot_is_sealed_reused_offline_and_restored(workspace, monkeypatch):
    rules = remote_policy(workspace, monkeypatch)
    first = rm.build(**workspace)
    release = rm.active_release(workspace["runtime_root"])
    before = tree_hash(release / "rule-set-snapshot")
    assert rm.validate_release(release)["rule_set_snapshot"] == 1
    body = (release / "desktop/config.json").read_text(encoding="utf-8")
    assert "\n  " not in body and json.loads(body)["route"]["rule_set"][0]["type"] == "inline"
    monkeypatch.setattr(rules, "_download", lambda *_a, **_k: pytest.fail("offline attempted network"))
    rm.build(**workspace, offline=True)
    assert tree_hash(rm.active_release(workspace["runtime_root"]) / "rule-set-snapshot") == before
    rm.restore(first, **workspace)
    assert tree_hash(rm.active_release(workspace["runtime_root"]) / "rule-set-snapshot") == before


def test_rule_download_failure_and_first_offline_migration_preserve_active(workspace, monkeypatch):
    rm.build(**workspace)
    runtime = workspace["runtime_root"]
    pointer = (runtime / rm.POINTER_NAME).read_bytes()
    original = tree_hash(rm.active_release(runtime))
    exported = tree_hash(workspace["output_root"])
    rules = remote_policy(workspace, monkeypatch)
    monkeypatch.setattr(rules, "_download", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("rule download failed")))
    for offline in (False, True):
        with pytest.raises(ValueError):
            rm.build(**workspace, offline=offline)
        assert (runtime / rm.POINTER_NAME).read_bytes() == pointer
        assert tree_hash(rm.active_release(runtime)) == original
        assert tree_hash(workspace["output_root"]) == exported


def test_release_rejects_embedded_rule_change_even_with_updated_stamps(workspace, monkeypatch):
    remote_policy(workspace, monkeypatch)
    rm.build(**workspace)
    release = rm.active_release(workspace["runtime_root"])
    path = release / "android/config.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["route"]["rule_set"][0]["rules"] = [{"domain_suffix": ["changed.example"]}]
    write(path, data)
    stamp = release / "android/config.validated.json"
    value = json.loads(stamp.read_text())
    value["sha256"] = rm.sha256_file(path)
    write(stamp, value)
    write(release / "manifest.json", rm._files(release))
    with pytest.raises(ValueError, match="differs"):
        rm.validate_release(release)


def test_release_is_complete_and_cache_survives_new_process(workspace, monkeypatch):
    config = workspace["config_root"]
    url = "https://subscription.example.invalid/private-test"
    (config / "local" / "input.json").write_text(url, encoding="utf-8")
    body = json.dumps({"outbounds": [{"type": "vless", "tag": "US new", "server": "new.example.com",
                                     "server_port": 443, "uuid": "00000000-0000-4000-8000-000000000000"}]})
    calls = []
    monkeypatch.setattr(generator, "download", lambda *args: calls.append(args) or body)
    build_id = rm.build(**workspace)
    assert len(calls) == 1
    release = rm.active_release(workspace["runtime_root"])
    assert release.name == build_id
    assert rm.validate_release(release)["validator"] == rm.CORE_VERSION
    cache = generator.subscription_cache_path(url, cache_dir=release / "subscription-cache")
    assert cache.read_text(encoding="utf-8") == body
    code = """
import sys
from pathlib import Path
from singbox_config import generator
from singbox_config.release_manager import active_release
r = active_release(Path(sys.argv[1]))
generator.CACHE_DIR = r / 'subscription-cache'
c = r / 'inputs' / 'config'
result = generator.generate(('desktop', 'android'), policy_path=c/'policy.yaml', manifest_path=c/'local'/'subscriptions.yaml', rule_sets=c/'rule-sets', offline=True)
assert any(n['tag'] == 'direct' for n in result['desktop']['outbounds'])
assert any(n.get('server') == 'new.example.com' for n in result['android']['outbounds'])
"""
    result = subprocess.run([sys.executable, "-c", code, str(workspace["runtime_root"])], capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert not (workspace["runtime_root"] / "subscription-cache").exists()
    assert cache.exists()  # Never moved out of the immutable version.


@pytest.mark.parametrize("failure", ["android-check", "manifest", "journal", "pointer"])
def test_failure_before_commit_preserves_active_cache_and_working_inputs(workspace, monkeypatch, failure):
    manifest = workspace["config_root"] / "local" / "subscriptions.yaml"
    write(manifest, {"subscriptions": [{"name": "US source", "path": "input.json"},
                                      {"name": "Backup", "path": "input.json", "enabled": False}]})
    rm.build(**workspace)
    runtime = workspace["runtime_root"]
    pointer = (runtime / rm.POINTER_NAME).read_bytes()
    original = tree_hash(rm.active_release(runtime))
    working = tree_hash(workspace["config_root"])
    output = tree_hash(workspace["output_root"])
    real_write = rm._write_json
    real_check = rm._run_core

    def write_failure(path, data):
        if path.name == {"manifest": "manifest.json", "journal": rm.JOURNAL_NAME, "pointer": rm.POINTER_NAME}.get(failure):
            raise OSError("injected I/O failure")
        return real_write(path, data)

    def check_failure(core, path):
        if failure == "android-check" and path.parent.name == "android":
            raise rm.ReleaseError("injected second platform failure")
        return real_check(core, path)

    monkeypatch.setattr(rm, "_write_json", write_failure)
    monkeypatch.setattr(rm, "_run_core", check_failure)
    with pytest.raises((OSError, rm.ReleaseError)):
        rm.build(**workspace, mode="enable", name="Backup")
    assert (runtime / rm.POINTER_NAME).read_bytes() == pointer
    assert tree_hash(rm.active_release(runtime)) == original
    assert tree_hash(workspace["config_root"]) == working
    assert tree_hash(workspace["output_root"]) == output


def test_projection_failure_is_explicit_and_recoverable(workspace, monkeypatch, capsys):
    rm.build(**workspace)
    original_export = rm._export
    monkeypatch.setattr(rm, "_export", lambda *_a: (_ for _ in ()).throw(OSError("projection failure")))
    build_id = rm.build(**workspace)
    runtime = workspace["runtime_root"]
    assert rm.active_release(runtime).name == build_id
    assert (runtime / rm.JOURNAL_NAME).exists()
    assert "[WARNING]" in capsys.readouterr().out
    monkeypatch.setattr(rm, "_export", original_export)
    rm.recover(runtime, workspace["output_root"], workspace["config_root"])
    assert not (runtime / rm.JOURNAL_NAME).exists()
    rm.verify(**workspace)


def test_interrupt_after_pointer_switch_recovers_add_input_and_manifest(workspace, monkeypatch):
    rm.build(**workspace)
    old = (workspace["config_root"] / "local" / "subscriptions.yaml").read_bytes()
    original_recover = rm.recover
    calls = 0

    def interrupt(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt()
        return original_recover(*args)

    monkeypatch.setattr(rm, "recover", interrupt)
    link = "https://subscription.example.invalid/new"
    body = (workspace["config_root"] / "local" / "input.json").read_text(encoding="utf-8")
    monkeypatch.setattr(generator, "download", lambda *_a: body.replace("node.example.com", "second.example.com"))
    with pytest.raises(KeyboardInterrupt):
        rm.build(**workspace, mode="add", name="Second", link=link)
    assert (workspace["config_root"] / "local" / "subscriptions.yaml").read_bytes() == old
    original_recover(workspace["runtime_root"], workspace["output_root"], workspace["config_root"])
    entries = yaml.safe_load((workspace["config_root"] / "local" / "subscriptions.yaml").read_text(encoding="utf-8"))["subscriptions"]
    new = entries[-1]
    assert new["name"] == "Second"
    assert (workspace["config_root"] / "local" / new["path"]).read_text(encoding="utf-8").strip() == link


def test_shared_input_removal_preserves_file_and_yaml_field_order(workspace):
    path = workspace["config_root"] / "local" / "subscriptions.yaml"
    path.write_text('subscriptions:\n - path: "input.json"\n   name: "US source"\n - path: input.json\n   enabled: false\n   name: Backup\n', encoding="utf-8")
    rm.build(**workspace, mode="remove", name="Backup")
    assert (path.parent / "input.json").exists()
    assert [e["name"] for e in yaml.safe_load(path.read_text(encoding="utf-8"))["subscriptions"]] == ["US source"]
    rm.build(**workspace, offline=True)


def test_manifest_edit_during_capture_is_preserved_and_activation_refused(workspace, monkeypatch):
    rm.build(**workspace)
    runtime, config = workspace["runtime_root"], workspace["config_root"]
    pointer = (runtime / rm.POINTER_NAME).read_bytes()
    output = tree_hash(workspace["output_root"])
    manifest = config / "local/subscriptions.yaml"
    capture = rm._capture_inputs
    edited = None

    def capture_then_edit(candidate, config_root):
        nonlocal edited
        capture(candidate, config_root)
        data = json.loads(manifest.read_text())
        data["subscriptions"].append({"name": "External addition", "path": "input.json", "enabled": False})
        write(manifest, data)
        edited = manifest.read_bytes()

    monkeypatch.setattr(rm, "_capture_inputs", capture_then_edit)
    with pytest.raises(rm.ReleaseError, match="manifest changed externally"):
        rm.build(**workspace, mode="enable", name="US source")
    assert manifest.read_bytes() == edited
    assert (runtime / rm.POINTER_NAME).read_bytes() == pointer
    assert not (runtime / rm.JOURNAL_NAME).exists()
    assert tree_hash(workspace["output_root"]) == output


@pytest.mark.parametrize("change", ["modify", "delete"])
def test_manifest_change_while_temporary_file_is_flushed_is_preserved(tmp_path, monkeypatch, change):
    manifest = tmp_path / "subscriptions.yaml"
    manifest.write_bytes(b"original")
    before = rm.sha256_file(manifest)
    fsync = os.fsync

    def flush_then_edit(fd):
        fsync(fd)
        if change == "modify":
            manifest.write_bytes(b"external edit")
        else:
            manifest.unlink()

    monkeypatch.setattr(os, "fsync", flush_then_edit)
    with pytest.raises(rm.ReleaseError, match="manifest changed externally"):
        rm._write_bytes(manifest, b"candidate", expected_hashes=(before,))
    if change == "modify":
        assert manifest.read_bytes() == b"external edit"
    else:
        assert not manifest.exists()
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("change", ["delete", "modify"])
def test_existing_input_change_before_commit_refuses_maintenance(workspace, monkeypatch, change):
    rm.build(**workspace)
    runtime, config = workspace["runtime_root"], workspace["config_root"]
    pointer = (runtime / rm.POINTER_NAME).read_bytes()
    output = tree_hash(workspace["output_root"])
    manifest = (config / "local/subscriptions.yaml").read_bytes()
    source = config / "local/input.json"
    finish = rm._finish

    def finish_then_edit(*args, **kwargs):
        finish(*args, **kwargs)
        if change == "delete":
            source.unlink()
        else:
            source.write_bytes(b"external edit")

    monkeypatch.setattr(rm, "_finish", finish_then_edit)
    with pytest.raises(rm.ReleaseError, match="input changed externally"):
        rm.build(**workspace, mode="enable", name="US source")
    assert not source.exists() if change == "delete" else source.read_bytes() == b"external edit"
    assert (config / "local/subscriptions.yaml").read_bytes() == manifest
    assert (runtime / rm.POINTER_NAME).read_bytes() == pointer
    assert not (runtime / rm.JOURNAL_NAME).exists()
    assert tree_hash(workspace["output_root"]) == output


@pytest.mark.parametrize("legacy_journal", [False, True])
@pytest.mark.parametrize("change", ["delete", "modify", "manifest"])
def test_recovery_preflights_all_inputs_and_preserves_external_changes(workspace, monkeypatch, change, legacy_journal):
    rm.build(**workspace)
    runtime, config, output = (workspace[key] for key in ("runtime_root", "config_root", "output_root"))
    source = config / "local/input.json"
    original_input = source.read_bytes()
    manifest = config / "local/subscriptions.yaml"
    original_manifest = manifest.read_bytes()
    original_output = tree_hash(output)
    original_recover = rm.recover
    calls = 0

    def interrupt(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt()
        return original_recover(*args)

    monkeypatch.setattr(rm, "recover", interrupt)
    monkeypatch.setattr(generator, "download", lambda *_a: original_input.decode().replace("node.example.com", "new.example.com"))
    with pytest.raises(KeyboardInterrupt):
        rm.build(**workspace, mode="add", name="New", link="https://subscription.example.invalid/new")
    release = rm.active_release(runtime)
    entries = yaml.safe_load((release / "inputs/config/local/subscriptions.yaml").read_text(encoding="utf-8"))["subscriptions"]
    added = config / "local" / entries[-1]["path"]
    if legacy_journal:
        journal = json.loads((runtime / rm.JOURNAL_NAME).read_text())
        journal.pop("inputs_before")
        journal["schema_version"] = 1
        write(runtime / rm.JOURNAL_NAME, journal)
    journal_bytes = (runtime / rm.JOURNAL_NAME).read_bytes()
    if change == "delete":
        source.unlink()
    elif change == "modify":
        source.write_bytes(b"external edit")
    else:
        manifest.write_bytes(original_manifest + b"\n# external edit\n")
    for _ in range(2):
        with pytest.raises(rm.ReleaseError, match="changed externally"):
            original_recover(runtime, output, config)
        assert not added.exists()  # Preflight completes before any new input is created.
        assert tree_hash(output) == original_output
        assert (runtime / rm.JOURNAL_NAME).read_bytes() == journal_bytes
        assert rm.active_release(runtime).name == release.name
    assert not source.exists() if change == "delete" else source.read_bytes() == (b"external edit" if change == "modify" else original_input)
    assert manifest.read_bytes() == (original_manifest + b"\n# external edit\n" if change == "manifest" else original_manifest)
    source.write_bytes(original_input)
    manifest.write_bytes(original_manifest)
    if legacy_journal:
        with pytest.raises(rm.ReleaseError):
            original_recover(runtime, output, config)
        assert not added.exists()  # An old journal cannot prove this missing input was newly added.
    else:
        original_recover(runtime, output, config)
        assert added.is_file()
        assert not (runtime / rm.JOURNAL_NAME).exists()
        rm.verify(**workspace)


def test_recovery_reuses_new_input_after_manifest_write_failure(workspace, monkeypatch):
    rm.build(**workspace)
    config, runtime = workspace["config_root"], workspace["runtime_root"]
    manifest = config / "local/subscriptions.yaml"
    original_manifest = manifest.read_bytes()
    body = (config / "local/input.json").read_text()
    monkeypatch.setattr(generator, "download", lambda *_a: body.replace("node.example.com", "new.example.com"))
    write_bytes = rm._write_bytes

    def fail_manifest(path, contents, **kwargs):
        if path == manifest:
            raise OSError("injected manifest write failure after new input creation")
        return write_bytes(path, contents, **kwargs)

    monkeypatch.setattr(rm, "_write_bytes", fail_manifest)
    rm.build(**workspace, mode="add", name="New", link="https://subscription.example.invalid/new")
    release = rm.active_release(runtime)
    entries = yaml.safe_load((release / "inputs/config/local/subscriptions.yaml").read_text(encoding="utf-8"))["subscriptions"]
    added = config / "local" / entries[-1]["path"]
    assert added.is_file()
    created = added.stat().st_mtime_ns
    assert manifest.read_bytes() == original_manifest
    assert (runtime / rm.JOURNAL_NAME).exists()
    monkeypatch.setattr(rm, "_write_bytes", write_bytes)
    rm.recover(runtime, workspace["output_root"], config)
    assert added.stat().st_mtime_ns == created  # Already-created inputs are checked, not rewritten.
    assert not (runtime / rm.JOURNAL_NAME).exists()
    rm.verify(**workspace)


def test_restore_twice_does_not_modify_source_or_clients(workspace):
    original_id = rm.build(**workspace)
    original = workspace["runtime_root"] / "releases" / original_id
    hashes = tree_hash(original)
    database = workspace["output_root"] / "desktop" / "cache.db"
    database.write_bytes(b"client selections")
    for _ in range(2):
        new_id = rm.restore(original_id, **workspace)
        assert new_id != original_id
        assert tree_hash(original) == hashes
        rm.verify(**workspace)
    assert database.read_bytes() == b"client selections"


def test_good_snapshot_can_replace_a_corrupted_active_release(workspace):
    good = rm.build(**workspace)
    current = rm.build(**workspace)
    broken = workspace["runtime_root"] / "releases" / current / "desktop/config.json"
    broken.write_text("{}")
    with pytest.raises(rm.ReleaseError):
        rm.active_release(workspace["runtime_root"])
    restored = rm.restore(good, **workspace)
    assert rm.active_release(workspace["runtime_root"]).name == restored
    assert broken.read_text() == "{}"  # Preserve the damaged version as evidence.


@pytest.mark.parametrize("mutation", ["extra", "missing", "changed", "stamp", "core"])
def test_bad_snapshot_refused_before_active_state_changes(workspace, mutation):
    build_id = rm.build(**workspace)
    source = workspace["runtime_root"] / "releases" / build_id
    rm.build(**workspace)
    before = (workspace["runtime_root"] / rm.POINTER_NAME).read_bytes()
    if mutation == "extra":
        (source / "extra.txt").write_text("unexpected")
    elif mutation == "missing":
        (source / "subscription-cache").rmdir()
    elif mutation == "changed":
        (source / "inputs" / "config" / "policy.yaml").write_text("{}")
    elif mutation == "stamp":
        (source / "desktop" / "config.validated.json").write_text("{}")
    else:
        (source / "release.json").write_text("{}")
    with pytest.raises((rm.ReleaseError, OSError)):
        rm.restore(build_id, **workspace)
    assert (workspace["runtime_root"] / rm.POINTER_NAME).read_bytes() == before


@pytest.mark.parametrize("value", ["..", "../x", "C:\\other", "/tmp/x", "", "a/b", "a.b"])
def test_restore_rejects_uncontained_ids(workspace, value):
    with pytest.raises(rm.ReleaseError):
        rm.restore(value, **workspace)
    assert not (workspace["runtime_root"] / rm.POINTER_NAME).exists()


def test_kernel_lock_rejects_concurrency_and_recovers_after_process_exit(tmp_path):
    path = tmp_path / "lock"
    code = "from pathlib import Path; import sys, os; from singbox_config.release_manager import FileLock; lock=FileLock(Path(sys.argv[1])); lock.__enter__(); print('ready', flush=True); sys.stdin.read(1); os._exit(23)"
    process = subprocess.Popen([sys.executable, "-c", code, str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert process.stdout.readline().strip() == b"ready"
        with pytest.raises(rm.ReleaseError):
            with rm.FileLock(path):
                pass
    finally:
        process.stdin.write(b"x")
        process.stdin.flush()
        process.wait(timeout=5)
    with rm.FileLock(path):
        pass


def test_symlink_snapshot_rejected(workspace, tmp_path):
    link = workspace["runtime_root"] / "releases" / "escape"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks requires Windows developer mode")
    with pytest.raises((rm.ReleaseError, ValueError)):
        rm.restore("escape", **workspace)


def test_internal_reparse_point_cannot_be_hidden_by_resolve(workspace):
    build_id = rm.build(**workspace)
    releases = workspace["runtime_root"] / "releases"
    try:
        (releases / "alias").symlink_to(releases / build_id, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks requires Windows developer mode")
    with pytest.raises((rm.ReleaseError, ValueError)):
        rm.restore("alias", **workspace)


def test_missing_or_wrong_core_refused(tmp_path):
    with pytest.raises(rm.ReleaseError):
        rm.core_identity(tmp_path / "missing")
    # Python is executable, but is not a sing-box CLI, despite a zero exit stub.
    with pytest.raises(rm.ReleaseError):
        rm.core_identity(Path(sys.executable))


@pytest.mark.parametrize("commit", [False, True])
def test_real_process_crash_at_pointer_boundary(workspace, commit):
    rm.build(**workspace)
    runtime = workspace["runtime_root"]
    before = (runtime / rm.POINTER_NAME).read_bytes()
    code = """
import os, sys
from pathlib import Path
from singbox_config import release_manager as rm
root, config, output, core = map(Path, sys.argv[1:5])
identity = {'validator': rm.CORE_VERSION, 'core_sha256': rm.sha256_file(core)}
rm.core_identity = lambda _: identity
rm._run_core = lambda *_: None
write = rm._write_json
def crash(path, data):
    if path.name == rm.POINTER_NAME:
        if sys.argv[5] == 'yes':
            write(path, data)
        os._exit(29)
    return write(path, data)
rm._write_json = crash
rm.build(runtime_root=root, config_root=config, output_root=output, core=core, offline=True)
"""
    result = subprocess.run([sys.executable, "-c", code, str(runtime), str(workspace["config_root"]),
                             str(workspace["output_root"]), str(workspace["core"]), "yes" if commit else "no"], capture_output=True)
    assert result.returncode == 29
    assert ((runtime / rm.POINTER_NAME).read_bytes() != before) is commit
    with rm.FileLock(runtime / rm.LOCK_NAME):
        rm.recover(runtime, workspace["output_root"], workspace["config_root"])
    rm.verify(**workspace)


def test_publisher_uses_active_release_even_when_export_failed(workspace, monkeypatch):
    import threading
    from urllib.error import HTTPError
    from urllib.request import urlopen
    from singbox_config.publisher import PublisherServer, PublisherHandler

    rm.build(**workspace)
    output, runtime = workspace["output_root"], workspace["runtime_root"]
    server = PublisherServer(("127.0.0.1", 0), output / "android/config.json", output / "android/config.validated.json",
                             output / "desktop/config.json", output / "desktop/config.validated.json",
                             {"username": "sfa", "password": "test-secret"}, runtime / "test.log", runtime)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/desktop/config.json"
    try:
        first = urlopen(url, timeout=3)
        old = first.read()
        old_id = first.headers["X-Sing-Box-Build-ID"]
        node_input = workspace["config_root"] / "local/input.json"
        node_input.write_text(node_input.read_text().replace("node.example.com", "changed.example.com"))
        monkeypatch.setattr(rm, "_export", lambda *_a: (_ for _ in ()).throw(OSError("export failure")))
        new_id = rm.build(**workspace)
        assert new_id != old_id
        assert (output / "desktop/config.json").read_bytes() == old
        response = urlopen(url, timeout=3)
        body = response.read()
        assert response.headers["X-Sing-Box-Build-ID"] == new_id
        assert response.headers["X-Sing-Box-Config-SHA256"] == hashlib.sha256(body).hexdigest()
        assert b"changed.example.com" in body
        # Simulate a LAN origin, including a spoofed X-Forwarded-For header:
        # exemption depends on the socket peer, never forwarded headers.
        monkeypatch.setattr(PublisherHandler, "desktop_loopback_exemption", staticmethod(lambda *_a: False))
        with pytest.raises(HTTPError) as error:
            urlopen(url, timeout=3)
        assert error.value.code == 401
        assert urlopen(url + "?token=test-secret", timeout=3).status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

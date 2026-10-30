import copy
import hashlib
import json
from pathlib import Path

import pytest

from singbox_config import rule_sets as rs


@pytest.fixture
def parser(tmp_path, monkeypatch):
    core = tmp_path / "core"
    core.write_bytes(b"fixed parsing core")
    identity = {"validator": rs.CORE_LINE, "core_sha256": rs.digest(core.read_bytes())}
    calls = []
    monkeypatch.setattr(rs, "core_identity", lambda path: (core, identity))

    def download(url, tag, **options):
        calls.append((url, tag))
        return b"SRS" + tag.encode()

    def decompile(core, raw, tag, **options):
        return json.dumps({"version": 1, "rules": [{"domain_suffix": [tag + ".example"]}]}).encode()

    monkeypatch.setattr(rs, "_download", download)
    monkeypatch.setattr(rs, "_decompile", decompile)
    return core, identity, calls


def configs(*tags):
    config = {"route": {"rule_set": [{"type": "remote", "tag": tag, "url": f"https://rules.example/{tag}.srs"} for tag in tags]}}
    return {"desktop": copy.deepcopy(config), "android": copy.deepcopy(config)}


def test_online_downloads_union_once_and_seals_every_platform(tmp_path, parser):
    core, identity, calls = parser
    source = configs("geosite-google", "geosite-cn")
    destination = tmp_path / "snapshot"
    result = rs.materialize(source, directory=destination, core=core, identity=identity)
    assert len(calls) == 2
    assert source["desktop"]["route"]["rule_set"][0]["type"] == "remote"
    assert all(r["type"] == "inline" and "url" not in r for c in result.values() for r in c["route"]["rule_set"])
    rs.validate_embedded(result, destination, definitions=rs.remote_definitions(source))
    assert (destination / "geosite-google.srs").read_bytes() == b"SRSgeosite-google"


def test_offline_reuses_original_bytes_and_download_time(tmp_path, parser, monkeypatch):
    core, identity, _ = parser
    source = configs("geosite-google", "geosite-cn")
    first = tmp_path / "first"
    rs.materialize(source, directory=first, core=core, identity=identity)
    monkeypatch.setattr(rs, "_download", lambda *_a, **_k: pytest.fail("offline attempted network"))
    second = tmp_path / "second"
    result = rs.materialize(configs("geosite-google"), directory=second, offline=True, identity=identity, previous=first)
    old, _ = rs.load_snapshot(first)
    new, _ = rs.load_snapshot(second)
    assert new["entries"] == {"geosite-google": old["entries"]["geosite-google"]}
    assert (first / "geosite-google.json").read_bytes() == (second / "geosite-google.json").read_bytes()
    rs.validate_embedded(result, second)


@pytest.mark.parametrize("failure", ["no-snapshot", "missing-tag", "url-change", "raw-change", "json-change", "extra", "missing", "core-change"])
def test_offline_refuses_incomplete_or_changed_snapshot(tmp_path, parser, failure):
    core, identity, _ = parser
    first = tmp_path / "first"
    rs.materialize(configs("geosite-cn"), directory=first, core=core, identity=identity)
    source = configs("geosite-cn")
    previous = first
    if failure == "no-snapshot":
        previous = None
    elif failure == "missing-tag":
        source = configs("geosite-google")
    elif failure == "url-change":
        source["desktop"]["route"]["rule_set"][0]["url"] = "https://other.example/geosite-cn.srs"
        source["android"] = copy.deepcopy(source["desktop"])
    elif failure in ("raw-change", "json-change"):
        (first / ("geosite-cn.srs" if failure == "raw-change" else "geosite-cn.json")).write_bytes(b"changed")
    elif failure == "extra":
        (first / "unexpected.txt").write_text("extra")
    elif failure == "missing":
        (first / "geosite-cn.srs").unlink()
    elif failure == "core-change":
        identity = {**identity, "core_sha256": "a" * 64}
    with pytest.raises(ValueError):
        rs.materialize(source, directory=tmp_path / "next", identity=identity, offline=True, previous=previous)
    assert not (tmp_path / "next").exists()


def test_failed_second_rule_never_writes_partial_snapshot(tmp_path, parser, monkeypatch):
    core, identity, _ = parser

    def download(url, tag, **options):
        if tag == "second":
            raise ValueError("download failed")
        return b"SRSfirst"

    monkeypatch.setattr(rs, "_download", download)
    destination = tmp_path / "snapshot"
    with pytest.raises(ValueError, match="download failed"):
        rs.materialize(configs("first", "second"), directory=destination, core=core, identity=identity)
    assert not destination.exists()


def test_embedded_content_must_match_snapshot(tmp_path, parser):
    core, identity, _ = parser
    snapshot = tmp_path / "snapshot"
    result = rs.materialize(configs("geosite-google"), directory=snapshot, core=core, identity=identity)
    result["android"]["route"]["rule_set"][0]["rules"] = [{"domain_suffix": ["wrong.example"]}]
    with pytest.raises(ValueError, match="differs"):
        rs.validate_embedded(result, snapshot)


@pytest.mark.parametrize("name", ["../escape", "bad/name", "CON", "NUL.json", "bad."])
def test_tag_cannot_escape_snapshot_directory(tmp_path, parser, name):
    core, identity, calls = parser
    with pytest.raises(ValueError, match="tag"):
        rs.materialize(configs(name), directory=tmp_path / "snapshot", core=core, identity=identity)
    assert not calls


def test_invalid_srs_never_becomes_an_empty_allowlist(tmp_path):
    from singbox_config.generator import ROOT
    cores = list((ROOT / "runtime/cores/1.15.0-alpha.11-reF1nd").rglob("sing-box.exe"))
    if not cores:
        pytest.skip("optional local core unavailable")
    with pytest.raises(ValueError, match="parsing"):
        rs._decompile(cores[0], b"SRS\x00invalid", "invalid")


def test_hung_parser_fails_with_a_bounded_safe_error(tmp_path, monkeypatch):
    import subprocess

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("private-command-details", 60)

    monkeypatch.setattr(rs.subprocess, "run", timeout)
    with pytest.raises(ValueError, match="Rule-set parsing failed: sample"):
        rs._decompile(tmp_path / "core", b"SRSinvalid", "sample", workdir=tmp_path)


def test_unavailable_core_version_command_is_reported_cleanly(tmp_path, monkeypatch):
    import subprocess
    core = tmp_path / "core"
    core.write_bytes(b"core")
    monkeypatch.setattr(rs.subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(subprocess.TimeoutExpired("version", 30)))
    with pytest.raises(ValueError, match="Unable to identify"):
        rs.core_identity(core)

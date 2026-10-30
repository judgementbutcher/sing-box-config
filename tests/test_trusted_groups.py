"""Trusted landing selection must fail instead of widening or shrinking its allowlist."""

import copy

import pytest

from singbox_config.generator import Source, build_outbounds


def landing(tag, **extra):
    return {"type": "vless", "tag": tag, "server": "vps.example.invalid", "server_port": 443,
            "uuid": "00000000-0000-4000-8000-000000000000", "tls": {"enabled": True},
            "detour": "Aether-前置", **extra}


@pytest.fixture
def trusted_setup():
    sources = [Source("Home", [landing("US Home v6"), landing("US Home v4")], ["US Home v6"]),
               Source("Airport", [landing("US Other")], ["US Other"])]
    group = {"tag": "Claude", "filter": "trusted", "default": "US Home v6",
             "candidates": [{"source": "Home", "names": ["US Home v6", "US Home v4"]}]}
    return sources, group


def build(sources, group):
    return {item["tag"]: item for item in build_outbounds(sources, {"services": [group]})}


def test_trusted_landings_are_explicit_manual_and_can_include_future_ipv4(trusted_setup):
    sources, group = trusted_setup
    original = copy.deepcopy(sources)
    out = build(sources, group)
    assert out["Claude"] == {"type": "selector", "tag": "Claude",
                             "outbounds": ["US Home v6", "US Home v4"],
                             "default": "US Home v6", "interrupt_exist_connections": True}
    assert sources == original  # The shared detour and node parameters are preserved.
    assert out["AI"]["outbounds"] == ["US Home v6", "US Other"]
    assert not any(tag.startswith("Claude-") for tag in out)


@pytest.mark.parametrize("missing", ["source", "first", "second"])
def test_missing_trusted_member_fails_even_when_other_ai_nodes_exist(trusted_setup, missing):
    sources, group = trusted_setup
    if missing == "source":
        sources = sources[1:]
    else:
        sources[0].nodes.pop(0 if missing == "first" else 1)
    with pytest.raises(ValueError, match="受信"):
        build(sources, group)


def test_same_name_from_another_source_is_not_a_replacement(trusted_setup):
    sources, group = trusted_setup
    sources[0].nodes.pop(0)
    sources[1].nodes.append(landing("US Home v6"))
    with pytest.raises(ValueError, match="受信节点缺失"):
        build(sources, group)


@pytest.mark.parametrize("node", [landing("US Home v6", tls={"enabled": True, "insecure": True}),
                                  {"type": "direct", "tag": "US Home v6"},
                                  {"type": "selector", "tag": "US Home v6", "outbounds": ["Available"]}])
def test_untrusted_or_group_members_are_rejected(trusted_setup, node):
    sources, group = trusted_setup
    sources[0].nodes[0] = node
    with pytest.raises(ValueError, match="代理叶节点"):
        build(sources, group)


@pytest.mark.parametrize("option", [{"type": "urltest"}, {"direct": "last"}, {"expand": True},
                                    {"outbounds": ["Available"]}, {"include": ["AI"]},
                                    {"include_direct": False}])
def test_trusted_groups_cannot_be_auto_or_append_fallbacks(trusted_setup, option):
    sources, group = trusted_setup
    group.update(option)
    with pytest.raises(ValueError, match="手动选择器"):
        build(sources, group)


@pytest.mark.parametrize("candidate", [[], None, [{"source": "Home", "names": []}],
                                      [{"source": "Home", "regions": ["US"]}],
                                      [{"source": "Home", "names": "US Home v6"}]])
def test_trusted_candidates_require_exact_nonempty_names(trusted_setup, candidate):
    sources, group = trusted_setup
    group["candidates"] = candidate
    with pytest.raises(ValueError, match="受信候选"):
        build(sources, group)


@pytest.mark.parametrize("default", ["Available", "AI", "US Other", None, ["US Home v6"]])
def test_default_cannot_escape_trusted_members(trusted_setup, default):
    sources, group = trusted_setup
    group["default"] = default
    with pytest.raises(ValueError, match="default"):
        build(sources, group)

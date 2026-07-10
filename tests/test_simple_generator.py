import json
from pathlib import Path

import pytest

from generate_config import RequiredRegionsError, generate_configs
from parsers.common import detect_region
from singbox_config.audit import is_proxy_outbound


def make_node(tag: str, index: int) -> dict:
    return {
        "type": "vless",
        "tag": tag,
        "server": f"node-{index}.example",
        "server_port": 443,
        "uuid": f"00000000-0000-0000-0000-{index:012d}",
        "tls": {"enabled": True, "server_name": f"node-{index}.example"},
    }


def write_template(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "log": {"disabled": True},
                "dns": {"servers": [{"type": "https", "tag": "remote", "detour": "Available"}]},
                "inbounds": [
                    {"type": "tun", "tag": "tun-in", "address": ["172.18.0.1/30"]},
                    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
                ],
                "route": {"rules": [], "rule_set": [], "final": "Available"},
                "experimental": {"cache_file": {"enabled": True, "path": "cache.db"}},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def write_manifest(path: Path, nodes: list[dict], *, self_nodes: list[dict] | None = None) -> None:
    subscription = path.parent / "subscription.json"
    subscription.write_text(json.dumps({"outbounds": nodes}, ensure_ascii=False), encoding="utf-8")
    self_subscription = path.parent / "self.json"
    if self_nodes is not None:
        self_subscription.write_text(json.dumps({"outbounds": self_nodes}, ensure_ascii=False), encoding="utf-8")
    self_entry = ""
    if self_nodes is not None:
        self_entry = (
            "  - name: self-hosted\n"
            "    role: primary\n"
            "    parser: singbox-json\n"
            "    source: file\n"
            f"    path: {self_subscription.name}\n"
        )
    path.write_text(
        "subscriptions:\n"
        "  - name: provider\n"
        "    parser: singbox-json\n"
        "    source: file\n"
        f"    path: {subscription.name}\n"
        "    hot_regions_only: true\n"
        "    limits:\n"
        "      max_total_nodes: 1\n"
        + self_entry,
        encoding="utf-8",
    )


def test_simple_generator_groups_airports_self_hosted_regions_and_us_ai(tmp_path):
    nodes = [
        make_node("Hong Kong HK", 1),
        make_node("United States US", 2),
        make_node("Taiwan TW", 3),
        make_node("Japan JP", 4),
        make_node("Singapore SG", 5),
        make_node("Paris France FR", 6),
        make_node("London UK", 7),
        make_node("Germany DE", 8),
    ]
    manifest = tmp_path / "subscriptions.yaml"
    self_nodes = [make_node("Self-hosted Other", 9), make_node("Self-hosted US", 10)]
    write_manifest(manifest, nodes, self_nodes=self_nodes)
    desktop_template = tmp_path / "desktop.json"
    android_template = tmp_path / "android.json"
    write_template(desktop_template)
    write_template(android_template)

    results = generate_configs(
        ("desktop", "android"),
        subscriptions_path=manifest,
        output_dir=tmp_path / "dist",
        cache_dir=None,
        policy_aliases_path=None,
        template_paths={"desktop": desktop_template, "android": android_template},
    )

    assert [result.target for result in results] == ["desktop", "android"]
    assert all(result.node_count == len(nodes) - 1 + len(self_nodes) for result in results)
    android = json.loads((tmp_path / "dist" / "android" / "config.json").read_text(encoding="utf-8"))
    assert [inbound["type"] for inbound in android["inbounds"]] == ["tun"]
    assert sum(
        1
        for outbound in android["outbounds"]
        if isinstance(outbound, dict) and is_proxy_outbound(outbound)
    ) == len(nodes) - 1 + len(self_nodes)
    selectors = {outbound["tag"]: outbound for outbound in android["outbounds"] if outbound.get("type") == "selector"}
    for label in ("香港", "美国", "台湾", "日本", "新加坡", "法国", "英国"):
        assert f"地区/{label}" in selectors
        expected = 2 if label == "美国" else 1
        assert len(selectors[f"地区/{label}"]["outbounds"]) == expected
    assert "self-hosted" not in selectors
    assert len(selectors["自建"]["outbounds"]) == len(self_nodes)
    assert selectors["Available"]["outbounds"] == ["provider", "自建"]
    assert all(detect_region(tag) == "US" for tag in selectors["AI"]["outbounds"])


def test_simple_generator_does_not_overwrite_when_a_required_region_is_missing(tmp_path):
    manifest = tmp_path / "subscriptions.yaml"
    write_manifest(
        manifest,
        [
            make_node("Hong Kong HK", 1),
            make_node("United States US", 2),
            make_node("Taiwan TW", 3),
            make_node("Japan JP", 4),
            make_node("Singapore SG", 5),
            make_node("London UK", 7),
        ],
    )
    template = tmp_path / "desktop.json"
    write_template(template)
    output = tmp_path / "dist" / "desktop" / "config.json"
    output.parent.mkdir(parents=True)
    output.write_text('{"previous": true}', encoding="utf-8")

    with pytest.raises(RequiredRegionsError, match="法国"):
        generate_configs(
            ("desktop",),
            subscriptions_path=manifest,
            output_dir=tmp_path / "dist",
            cache_dir=None,
            policy_aliases_path=None,
            template_paths={"desktop": template},
        )

    assert json.loads(output.read_text(encoding="utf-8")) == {"previous": True}

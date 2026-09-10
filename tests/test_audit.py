from singbox_config.audit import audit_config


def node(tag, server):
    return {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000001",
    }


def test_audit_accepts_unique_disjoint_urltests():
    conf = {
        "dns": {"servers": [{"tag": "remote", "type": "https", "detour": "DNS-Out"}]},
        "route": {"rules": [], "rule_set": []},
        "outbounds": [
            {"type": "selector", "tag": "DNS-Out", "outbounds": ["n1", "direct"]},
            {"type": "urltest", "tag": "Auto", "outbounds": ["n1", "n2"]},
            node("n1", "one.example"),
            node("n2", "two.example"),
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
    }
    report = audit_config(conf, {"max_nodes": 2, "max_urltest_members": 2})
    assert report["ok"] is True
    assert report["counts"]["urltest_unique_members"] == 2


def test_audit_rejects_singleton_duplicate_and_missing_reference():
    conf = {
        "dns": {"servers": [{"tag": "remote", "type": "https", "detour": "missing"}]},
        "route": {"rules": [], "rule_set": []},
        "outbounds": [
            {"type": "urltest", "tag": "Auto1", "outbounds": ["n1"]},
            {"type": "urltest", "tag": "Auto2", "outbounds": ["n1", "n2"]},
            node("n1", "same.example"),
            node("n2", "same.example"),
            {"type": "direct", "tag": "direct"},
        ],
    }
    report = audit_config(conf)
    assert report["ok"] is False
    assert report["singleton_urltests"] == ["Auto1"]
    assert report["duplicate_urltest_members"] == ["n1"]
    assert report["counts"]["duplicate_node_entries"] == 1
    assert report["missing_references"]


def test_audit_accepts_multi_tag_rule_sets_and_object_resolvers():
    conf = {
        "dns": {"servers": [{"tag": "bootstrap", "type": "udp", "server": "1.1.1.1"}]},
        "route": {
            "default_domain_resolver": {"server": "bootstrap", "strategy": "ipv4_only"},
            "rules": [{"rule_set": "geosite-one", "action": "route", "outbound": "direct"}],
            "rule_set": [
                {
                    "tag": ["geosite-one", "geosite-two"],
                    "type": "remote",
                    "url": "https://example.invalid/{tag}.srs",
                    "initial_path": "rules/{tag}.srs",
                }
            ],
        },
        "outbounds": [
            node("n1", "one.example"),
            {"type": "direct", "tag": "direct"},
        ],
    }
    conf["outbounds"][0]["domain_resolver"] = {"server": "bootstrap"}

    report = audit_config(conf)

    assert report["ok"] is True
    assert report["missing_dns_references"] == []
    assert report["missing_rule_set_references"] == []


def test_audit_rejects_selector_cycles():
    conf = {
        "outbounds": [
            {"type": "selector", "tag": "A", "outbounds": ["B"]},
            {"type": "selector", "tag": "B", "outbounds": ["A"]},
        ],
        "route": {"final": "A", "rules": [], "rule_set": []},
    }
    report = audit_config(conf)
    assert not report["ok"]
    assert report["selector_cycles"] == ["A -> B -> A"]

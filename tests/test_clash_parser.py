from parsers.clash import parse


def test_parse_hysteria2_node_with_tls_and_obfs():
    nodes, info_nodes, warnings = parse(
        """
proxies:
  - name: HK Hysteria2
    type: hysteria2
    server: hy2.example
    port: 8443
    password: secret
    sni: edge.example
    skip-cert-verify: true
    alpn: h3,h2
    obfs: salamander
    obfs-password: obfs-secret
"""
    )

    assert info_nodes == []
    assert warnings == []
    assert nodes == [
        {
            "type": "hysteria2",
            "tag": "HK Hysteria2",
            "server": "hy2.example",
            "server_port": 8443,
            "password": "secret",
            "domain_resolver": "local",
            "tls": {
                "enabled": True,
                "server_name": "edge.example",
                "insecure": True,
                "alpn": ["h3", "h2"],
            },
            "obfs": {"type": "salamander", "password": "obfs-secret"},
            "_meta_name": "HK Hysteria2",
            "_meta_region": "HK",
        }
    ]

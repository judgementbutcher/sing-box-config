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


def test_parse_extended_clash_protocols():
    nodes, info_nodes, warnings = parse(
        """
proxies:
  - name: US Naive
    type: naive
    server: naive.example
    port: 443
    username: user
    password: pass
    sni: edge.example
    skip-cert-verify: true
    extra-headers: {X-Test: yes}
    udp-over-tcp: true
    quic: true
    quic-congestion-control: bbr
  - name: SG Trojan
    type: trojan
    server: trojan.example
    port: 443
    password: secret
    network: ws
    ws-opts:
      path: /socket
      headers: {Host: cdn.example}
  - name: JP VMess
    type: vmess
    server: vmess.example
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    network: grpc
    grpc-opts: {grpc-service-name: tunnel}
  - name: HK TUIC
    type: tuic
    server: tuic.example
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    password: secret
    congestion-controller: bbr
    udp-relay-mode: native
    reduce-rtt: true
  - name: US Hysteria
    type: hysteria
    server: hysteria.example
    port: 443
    auth-str: secret
    up: 100 Mbps
    down: 200 Mbps
    obfs: obfs-secret
  - name: HTTP Proxy
    type: http
    server: http.example
    port: 8443
    username: user
    password: pass
    tls: true
  - name: SOCKS Proxy
    type: socks5
    server: socks.example
    port: 1080
    username: user
    password: pass
    udp: false
"""
    )

    assert info_nodes == []
    assert warnings == []
    assert [node["type"] for node in nodes] == [
        "naive",
        "trojan",
        "vmess",
        "tuic",
        "hysteria",
        "http",
        "socks",
    ]
    naive, trojan, vmess, tuic, hysteria, http, socks = nodes
    assert naive["tls"]["server_name"] == "edge.example"
    assert naive["udp_over_tcp"] is True
    assert naive["quic_congestion_control"] == "bbr"
    assert trojan["transport"] == {
        "type": "ws",
        "path": "/socket",
        "headers": {"Host": "cdn.example"},
    }
    assert vmess["transport"] == {"type": "grpc", "service_name": "tunnel"}
    assert tuic["zero_rtt_handshake"] is True
    assert hysteria["auth_str"] == "secret"
    assert http["tls"]["enabled"] is True
    assert socks["network"] == "tcp"


def test_unsupported_clash_type_is_reported():
    nodes, info_nodes, warnings = parse(
        """
proxies:
  - name: Unsupported SSR
    type: ssr
    server: ssr.example
    port: 443
"""
    )
    assert nodes == []
    assert info_nodes == []
    assert warnings == ["第 1 个节点不支持或缺少必要字段: type=ssr name=Unsupported SSR"]


def test_naive_rejects_insecure_concurrency_with_quic():
    nodes, _, warnings = parse(
        """
proxies:
  - name: Invalid Naive
    type: naive
    server: naive.example
    port: 443
    username: user
    password: pass
    insecure-concurrency: 2
    quic: true
"""
    )
    assert nodes == []
    assert warnings == ["第 1 个节点解析失败: Naive insecure_concurrency 不能与 QUIC 同时启用"]

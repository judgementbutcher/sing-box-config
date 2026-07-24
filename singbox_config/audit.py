from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Set


NON_PROXY_OUTBOUND_TYPES = {"selector", "urltest", "direct", "block", "dns"}


class ConfigAuditError(RuntimeError):
    def __init__(self, messages: Iterable[str], report: Dict[str, Any] | None = None):
        self.messages = list(messages)
        self.report = report or {}
        super().__init__("; ".join(self.messages))


def _clean_outbound(outbound: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = copy.deepcopy(outbound)
    cleaned.pop("tag", None)
    for key in list(cleaned):
        if key.startswith("_meta_"):
            cleaned.pop(key, None)
    return cleaned


def outbound_fingerprint(outbound: Dict[str, Any], *, length: int = 16) -> str:
    payload = json.dumps(
        _clean_outbound(outbound),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:length]


def is_proxy_outbound(outbound: Dict[str, Any]) -> bool:
    return str(outbound.get("type") or "") not in NON_PROXY_OUTBOUND_TYPES


def is_insecure_outbound(outbound: Dict[str, Any]) -> bool:
    tls = outbound.get("tls")
    return isinstance(tls, dict) and tls.get("insecure") is True


def _referenced_outbounds(conf: Dict[str, Any]) -> List[tuple[str, str]]:
    references: List[tuple[str, str]] = []
    route_final = conf.get("route", {}).get("final")
    if route_final:
        references.append(("route.final", str(route_final)))
    for index, rule in enumerate(conf.get("route", {}).get("rules", []), 1):
        if isinstance(rule, dict) and rule.get("outbound"):
            references.append((f"route.rules[{index}].outbound", str(rule["outbound"])))
    for index, server in enumerate(conf.get("dns", {}).get("servers", []), 1):
        if isinstance(server, dict) and server.get("detour"):
            references.append((f"dns.servers[{index}].detour", str(server["detour"])))
    for index, client in enumerate(conf.get("http_clients", []), 1):
        if isinstance(client, dict) and client.get("detour"):
            references.append((f"http_clients[{index}].detour", str(client["detour"])))
    for index, rule_set in enumerate(conf.get("route", {}).get("rule_set", []), 1):
        if isinstance(rule_set, dict) and rule_set.get("download_detour"):
            references.append((f"route.rule_set[{index}].download_detour", str(rule_set["download_detour"])))
    external_ui_detour = (
        conf.get("experimental", {})
        .get("clash_api", {})
        .get("external_ui_download_detour")
    )
    if external_ui_detour:
        references.append(("experimental.clash_api.external_ui_download_detour", str(external_ui_detour)))
    return references


def audit_config(conf: Dict[str, Any], limits: Dict[str, Any] | None = None) -> Dict[str, Any]:
    limits = limits or {}
    outbounds = [item for item in conf.get("outbounds", []) if isinstance(item, dict)]
    tags = [str(item.get("tag")) for item in outbounds if item.get("tag")]
    tag_set = set(tags)
    duplicate_tags = sorted(tag for tag, count in Counter(tags).items() if count > 1)
    nodes = [item for item in outbounds if is_proxy_outbound(item)]
    selectors = [item for item in outbounds if item.get("type") == "selector"]
    urltests = [item for item in outbounds if item.get("type") == "urltest"]

    fingerprint_counts = Counter(outbound_fingerprint(item) for item in nodes)
    duplicate_node_entries = sum(count - 1 for count in fingerprint_counts.values() if count > 1)
    urltest_members = [str(tag) for test in urltests for tag in test.get("outbounds", [])]
    urltest_member_counts = Counter(urltest_members)
    duplicate_urltest_members = sorted(tag for tag, count in urltest_member_counts.items() if count > 1)
    singleton_urltests = [str(test.get("tag")) for test in urltests if len(test.get("outbounds", [])) < 2]

    missing_references: List[Dict[str, str]] = []
    for location, reference in _referenced_outbounds(conf):
        if reference not in tag_set:
            missing_references.append({"location": location, "tag": reference})
    for outbound in selectors + urltests:
        for reference in outbound.get("outbounds", []):
            if str(reference) not in tag_set:
                missing_references.append(
                    {"location": f"outbound[{outbound.get('tag')}]", "tag": str(reference)}
                )

    dns_servers = {
        str(server.get("tag"))
        for server in conf.get("dns", {}).get("servers", [])
        if isinstance(server, dict) and server.get("tag")
    }
    missing_dns_references: List[Dict[str, str]] = []
    dns_final = conf.get("dns", {}).get("final")
    if dns_final and str(dns_final) not in dns_servers:
        missing_dns_references.append({"location": "dns.final", "tag": str(dns_final)})
    for index, rule in enumerate(conf.get("dns", {}).get("rules", []), 1):
        if isinstance(rule, dict) and rule.get("server") and str(rule["server"]) not in dns_servers:
            missing_dns_references.append(
                {"location": f"dns.rules[{index}].server", "tag": str(rule["server"])}
            )
    default_resolver = conf.get("route", {}).get("default_domain_resolver")
    if default_resolver and str(default_resolver) not in dns_servers:
        missing_dns_references.append(
            {"location": "route.default_domain_resolver", "tag": str(default_resolver)}
        )
    for index, server in enumerate(conf.get("dns", {}).get("servers", []), 1):
        resolver = server.get("domain_resolver") if isinstance(server, dict) else None
        if resolver and str(resolver) not in dns_servers:
            missing_dns_references.append(
                {"location": f"dns.servers[{index}].domain_resolver", "tag": str(resolver)}
            )

    http_clients = {
        str(client.get("tag"))
        for client in conf.get("http_clients", [])
        if isinstance(client, dict) and client.get("tag")
    }
    missing_http_client_references: List[Dict[str, str]] = []
    default_http_client = conf.get("route", {}).get("default_http_client")
    if default_http_client and str(default_http_client) not in http_clients:
        missing_http_client_references.append(
            {"location": "route.default_http_client", "tag": str(default_http_client)}
        )
    for index, rule_set in enumerate(conf.get("route", {}).get("rule_set", []), 1):
        client = rule_set.get("http_client") if isinstance(rule_set, dict) else None
        if client and str(client) not in http_clients:
            missing_http_client_references.append(
                {"location": f"route.rule_set[{index}].http_client", "tag": str(client)}
            )

    rule_set_tags = {
        str(rule_set.get("tag"))
        for rule_set in conf.get("route", {}).get("rule_set", [])
        if isinstance(rule_set, dict) and rule_set.get("tag")
    }
    missing_rule_set_references: List[Dict[str, str]] = []
    for section_name, rules in (
        ("route.rules", conf.get("route", {}).get("rules", [])),
        ("dns.rules", conf.get("dns", {}).get("rules", [])),
    ):
        for index, rule in enumerate(rules, 1):
            if not isinstance(rule, dict):
                continue
            values = rule.get("rule_set")
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for value in values:
                if str(value) not in rule_set_tags:
                    missing_rule_set_references.append(
                        {"location": f"{section_name}[{index}].rule_set", "tag": str(value)}
                    )

    errors: List[str] = []
    warnings: List[str] = []
    if duplicate_tags:
        errors.append(f"存在重复 outbound tag: {', '.join(duplicate_tags)}")
    if duplicate_node_entries:
        errors.append(f"仍有 {duplicate_node_entries} 个完全重复节点")
    if missing_references:
        errors.append(f"存在 {len(missing_references)} 个不存在的 outbound 引用")
    if missing_dns_references:
        errors.append(f"存在 {len(missing_dns_references)} 个不存在的 DNS server 引用")
    if missing_http_client_references:
        errors.append(f"存在 {len(missing_http_client_references)} 个不存在的 HTTP client 引用")
    if missing_rule_set_references:
        errors.append(f"存在 {len(missing_rule_set_references)} 个不存在的 rule-set 引用")
    if singleton_urltests:
        errors.append(f"存在单节点或空 URLTest: {', '.join(singleton_urltests)}")
    # Shared members across Available/AI/Control auto pools are intentional and
    # are reported via duplicate_urltest_members without failing the build.

    max_nodes = int(limits.get("max_nodes") or 0)
    max_urltest_members = int(limits.get("max_urltest_members") or 0)
    if "max_nodes" in limits and max_nodes >= 0 and len(nodes) > max_nodes:
        errors.append(f"代理节点 {len(nodes)} 超过档位上限 {max_nodes}")
    if "max_urltest_members" in limits and max_urltest_members >= 0 and len(urltest_members) > max_urltest_members:
        errors.append(f"URLTest 成员 {len(urltest_members)} 超过档位上限 {max_urltest_members}")

    insecure_nodes = sum(1 for item in nodes if is_insecure_outbound(item))
    if insecure_nodes:
        warnings.append(f"有 {insecure_nodes} 个节点关闭了 TLS 证书校验")

    report = {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "counts": {
            "outbounds": len(outbounds),
            "proxy_nodes": len(nodes),
            "selectors": len(selectors),
            "urltests": len(urltests),
            "urltest_members": len(urltest_members),
            "urltest_unique_members": len(urltest_member_counts),
            "insecure_tls_nodes": insecure_nodes,
            "duplicate_node_entries": duplicate_node_entries,
        },
        "duplicate_tags": duplicate_tags,
        "duplicate_urltest_members": duplicate_urltest_members,
        "singleton_urltests": singleton_urltests,
        "missing_references": missing_references,
        "missing_dns_references": missing_dns_references,
        "missing_http_client_references": missing_http_client_references,
        "missing_rule_set_references": missing_rule_set_references,
    }
    return report


def require_valid_config(conf: Dict[str, Any], limits: Dict[str, Any] | None = None) -> Dict[str, Any]:
    report = audit_config(conf, limits)
    if report["errors"]:
        raise ConfigAuditError(report["errors"], report)
    return report


def config_diff_summary(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    old_nodes = {
        outbound_fingerprint(item)
        for item in old.get("outbounds", [])
        if isinstance(item, dict) and is_proxy_outbound(item)
    }
    new_nodes = {
        outbound_fingerprint(item)
        for item in new.get("outbounds", [])
        if isinstance(item, dict) and is_proxy_outbound(item)
    }

    def section_hash(value: Any) -> str:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]

    def group_map(conf: Dict[str, Any]) -> Dict[str, Any]:
        return {
            str(outbound.get("tag")): {
                key: outbound.get(key)
                for key in (
                    "type",
                    "outbounds",
                    "default",
                    "url",
                    "interval",
                    "idle_timeout",
                    "tolerance",
                )
                if key in outbound
            }
            for outbound in conf.get("outbounds", [])
            if isinstance(outbound, dict) and outbound.get("type") in {"selector", "urltest"}
        }

    old_groups = group_map(old)
    new_groups = group_map(new)
    changed_groups = sorted(
        tag
        for tag in set(old_groups) | set(new_groups)
        if section_hash(old_groups.get(tag)) != section_hash(new_groups.get(tag))
    )

    return {
        "nodes": {
            "before": len(old_nodes),
            "after": len(new_nodes),
            "added": len(new_nodes - old_nodes),
            "removed": len(old_nodes - new_nodes),
        },
        "dns_changed": section_hash(old.get("dns")) != section_hash(new.get("dns")),
        "route_changed": section_hash(old.get("route")) != section_hash(new.get("route")),
        "inbounds_changed": section_hash(old.get("inbounds")) != section_hash(new.get("inbounds")),
        "outbound_groups_changed": bool(changed_groups),
        "changed_outbound_groups": changed_groups,
    }

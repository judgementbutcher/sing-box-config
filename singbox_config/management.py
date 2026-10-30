"""Read-only inspection of working inputs and validated releases.

No command in this module recovers projections, starts a core, fetches a
subscription, or contacts a publisher/client. Rule explanation is deliberately
three-valued: missing runtime metadata is not evidence that a rule cannot match.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from . import generator, release_manager as rm
from .io_utils import parse_duration_seconds
from .manifest import contained_path, read_manifest

ROOT = Path(__file__).resolve().parents[1]
READ_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, rm.ReleaseError, yaml.YAMLError)


def _label(value: Any) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value))
    return re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", "[redacted-url]", text)[:240]


def _read_json(path: Path) -> Any:
    rm.no_links(path, recursive=False)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _working(config_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rm.no_links(config_root)
    policy = generator.load_yaml(config_root / "policy.yaml")
    items = read_manifest(config_root / "local/subscriptions.yaml", policy)["subscriptions"]
    return policy, items


def _active(runtime_root: Path) -> tuple[Path | None, dict[str, Any], str]:
    try:
        release = rm.active_release(runtime_root, validate=False)
        if release is None:
            return None, {}, "missing"
        return release, rm.validate_release(release), "valid"
    except READ_ERRORS:
        return None, {}, "invalid"


def _tree(path: Path) -> dict[str, str]:
    rm.no_links(path)
    return {p.relative_to(path).as_posix(): rm.sha256_file(p)
            for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}


def status(*, config_root: Path, runtime_root: Path, output_root: Path,
           core: Path | None = None, **_kwargs: Any) -> dict[str, Any]:
    release, metadata, state = _active(runtime_root)
    result: dict[str, Any] = {
        "active": {"build_id": release.name if release else None, "state": state,
                   "created_at": _label(metadata["created_at"]) if metadata.get("created_at") else None},
        "working_config": {"state": "unknown"}, "exports": {"state": "unknown"},
        "pending_recovery": (runtime_root / rm.JOURNAL_NAME).exists(),
        "sources": {"enabled": None, "disabled": None},
        "core": {"state": "unknown", "version": None},
        "publisher": {"state": "unknown", "note": "Not contacted by read-only inspection"},
        "client_selection": "unknown", "warnings": [],
    }
    try:
        _, items = _working(config_root)
        enabled = sum(item.get("enabled", True) for item in items)
        result["sources"] = {"enabled": enabled, "disabled": len(items) - enabled}
        if release:
            result["working_config"]["state"] = (
                "same" if _tree(config_root) == _tree(release / "inputs/config") else "changed")
    except READ_ERRORS:
        result["warnings"].append("Working policy or subscription manifest cannot be inspected")
    if release:
        try:
            targets = [output_root / p / name for p in rm.PLATFORMS
                       for name in ("config.json", "config.validated.json")]
            for target in targets:
                rm.no_links(target, recursive=False)
            if not all(p.is_file() for p in targets):
                result["exports"]["state"] = "missing"
            else:
                result["exports"]["state"] = "synced" if all(
                    rm.sha256_file(p) == rm.sha256_file(release / p.relative_to(output_root))
                    for p in targets) else "stale"
        except READ_ERRORS:
            result["warnings"].append("Compatibility exports cannot be inspected")
    if core is not None:
        try:
            rm.no_links(core, recursive=False)
            if not core.is_file():
                result["core"]["state"] = "missing"
            elif metadata and rm.sha256_file(core) == metadata.get("core_sha256"):
                result["core"] = {"state": "matches_active", "version": metadata.get("validator")}
            else:
                result["core"]["state"] = "present_unverified"
        except READ_ERRORS:
            result["core"]["state"] = "unreadable"
    if state == "invalid":
        result["warnings"].append("Active pointer or release integrity validation failed; no repair attempted")
    if result["pending_recovery"]:
        result["warnings"].append("Projection recovery is pending; read-only inspection leaves it unchanged")
    return result


def _requirements(policy: Mapping[str, Any]) -> dict[str, list[str]]:
    required: dict[str, list[str]] = {}
    for group in policy.get("groups", {}).get("services", []):
        candidates = [*group.get("candidates", []), *group.get("members", [])]
        for member in candidates:
            if isinstance(member, dict) and isinstance(member.get("source"), str):
                required.setdefault(member["source"], []).append(str(group["tag"]))
    return {key: list(dict.fromkeys(values)) for key, values in required.items()}


def _node_count(config: Mapping[str, Any], name: str) -> int | None:
    lookup = {item["tag"]: item for item in config.get("outbounds", [])}
    if name not in lookup:
        return None
    leaves: set[str] = set()

    def visit(tag: str, seen: set[str]) -> None:
        if tag in seen or tag not in lookup:
            return
        node = lookup[tag]
        if node.get("server"):
            leaves.add(tag)
        else:
            for member in node.get("outbounds", []):
                visit(member, seen | {tag})

    visit(name, set())
    return len(leaves)


def sources(*, config_root: Path, runtime_root: Path, **_kwargs: Any) -> dict[str, Any]:
    policy, items = _working(config_root)
    release, _, _ = _active(runtime_root)
    config = _read_json(release / "desktop/config.json") if release else {}
    required = _requirements(policy)
    cache_root = release / "subscription-cache" if release else runtime_root / "subscription-cache"
    max_age = parse_duration_seconds(policy.get("subscription", {}).get("cache_max_age", "3d"))
    result = []
    for item in items:
        count = _node_count(config, item["name"])
        row = {"name": _label(item["name"]), "enabled": item.get("enabled", True),
               "node_count": count, "node_count_basis": "active_snapshot" if count is not None else "unknown",
               "required_by": [_label(tag) for tag in required.get(item["name"], [])],
               "cache_age_seconds": None, "cache_status": "unknown"}
        try:
            path = contained_path(config_root / "local", item["path"])
            if not path.is_file():
                row["cache_status"] = "input_missing"
            else:
                text = path.read_text(encoding="utf-8-sig").strip()
                if not re.fullmatch(r"https?://\S+", text):
                    row["cache_status"] = "local_input"
                else:
                    cache = generator.subscription_cache_path(
                        text, str(item.get("user_agent") or "sing-box"), cache_dir=cache_root)
                    rm.no_links(cache, recursive=False)
                    if cache.is_file():
                        age = max(0, int(time.time() - cache.stat().st_mtime))
                        row.update(cache_age_seconds=age, cache_status="fresh" if age <= max_age else "expired")
                    else:
                        row["cache_status"] = "missing"
        except READ_ERRORS:
            row["cache_status"] = "unreadable"
        result.append(row)
    return {"items": result, "active_build_id": release.name if release else None,
            "note": "Node counts describe the active snapshot, not newly edited or downloaded inputs"}


def history(*, runtime_root: Path, **_kwargs: Any) -> dict[str, Any]:
    release, _, _ = _active(runtime_root)
    items = []
    for folder, legacy in (("releases", False), ("backups", True)):
        base = runtime_root / folder
        rm.no_links(base, recursive=False)
        for path in sorted(base.iterdir(), reverse=True) if base.is_dir() else []:
            if not path.is_dir():
                continue
            metadata: dict[str, Any] = {}
            valid = False
            try:
                rm.safe_id(path.name)
                if legacy:
                    rm._legacy_check(path / "dist" if (path / "dist").is_dir() else path)
                else:
                    metadata = rm.validate_release(path)
                valid = True
            except READ_ERRORS:
                pass
            items.append({"build_id": _label(path.name), "legacy": legacy, "valid": valid,
                          "active": path == release,
                          "created_at": _label(metadata["created_at"]) if metadata.get("created_at") else None,
                          "origin": _label(metadata.get("origin", "legacy" if legacy else "unknown"))})
    return {"items": items}


def _values(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _and(values: Sequence[bool | None]) -> bool | None:
    return False if False in values else None if None in values else True


def _or(values: Sequence[bool | None]) -> bool | None:
    return True if True in values else None if None in values else False


ACTION_FIELDS = {"action", "server", "outbound", "rcode", "answer", "ns", "extra", "strategy",
                 "disable_cache", "rewrite_ttl", "client_subnet", "timeout", "type", "mode", "invert"}
DOMAIN_FIELDS = {"domain", "domain_suffix", "domain_keyword", "domain_regex"}
RR_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
            "AAAA": 28, "SRV": 33, "NAPTR": 35, "OPT": 41, "DS": 43, "RRSIG": 46,
            "NSEC": 47, "DNSKEY": 48, "NSEC3": 50, "TLSA": 52, "SVCB": 64,
            "HTTPS": 65, "IXFR": 251, "AXFR": 252, "ANY": 255, "CAA": 257}


def _rr_type(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 65535 else None
    if isinstance(value, str):
        text = value.upper()
        if text in RR_TYPES:
            return RR_TYPES[text]
        if re.fullmatch(r"(?:TYPE)?[0-9]{1,5}", text):
            number = int(text.removeprefix("TYPE"))
            return number if number <= 65535 else None
    return None


def _match(rule: Mapping[str, Any], context: Mapping[str, Any], sets: Mapping[str, Any],
           seen: frozenset[str] = frozenset()) -> bool | None:
    if rule.get("match_response"):
        # No upstream DNS response exists in a static explanation. In particular,
        # a route's destination IP must not disprove a response-address predicate.
        return None
    if rule.get("type") == "logical":
        matched = [_match(item, context, sets, seen) for item in rule.get("rules", [])]
        result = _or(matched) if rule.get("mode") == "or" else _and(matched)
    else:
        conditions: list[bool | None] = []
        # sing-box combines domain predicates within one domain condition using OR.
        domain_checks = []
        for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
            if key not in rule:
                continue
            domain = context.get("domain")
            if domain is None:
                domain_checks.append(None)
            elif key == "domain":
                domain_checks.append(domain in [str(value).lower().rstrip(".") for value in _values(rule[key])])
            elif key == "domain_suffix":
                suffix_checks = []
                for value in _values(rule[key]):
                    suffix = str(value).lower().rstrip(".")
                    if suffix.startswith("."):
                        suffix_checks.append(None)
                    else:
                        suffix_checks.append(domain == suffix or domain.endswith("." + suffix))
                domain_checks.append(_or(suffix_checks))
            elif key == "domain_keyword":
                domain_checks.append(any(str(value) in domain for value in _values(rule[key])))
            else:
                # The core uses RE2, not Python's backtracking regex engine.
                domain_checks.append(None)
        if domain_checks:
            conditions.append(_or(domain_checks))
        destination_groups = sum((bool(domain_checks), "rule_set" in rule,
                                  "ip_cidr" in rule or "ip_is_private" in rule))
        if destination_groups > 1:
            # Headless sets can merge destination predicates. Do not claim the
            # reduced interpreter is equivalent to the core for mixed groups.
            return None
        for key, value in rule.items():
            if key in ACTION_FIELDS or key in DOMAIN_FIELDS:
                continue
            if key == "rule_set":
                matches = []
                for tag in _values(value):
                    item = sets.get(tag)
                    if tag in seen or not item or item.get("type") != "inline":
                        matches.append(None)
                    else:
                        matches.append(_or([_match(r, context, sets, seen | {tag}) for r in item.get("rules", [])]))
                conditions.append(_or(matches))
            elif key in ("ip_cidr", "ip_is_private", "ip_version"):
                address = context.get("ip")
                if address is None:
                    conditions.append(None)
                elif key == "ip_version":
                    conditions.append(address.version == value)
                elif key == "ip_is_private":
                    # Do not equate Python's evolving is_private registry with the core's CIDR list.
                    private = any(address in ipaddress.ip_network(net) for net in
                                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                                   "::1/128", "fc00::/7", "fe80::/10") if address.version == ipaddress.ip_network(net).version)
                    known = True if private else False if address.is_global and not address.is_multicast else None
                    conditions.append((not known) if known is not None and not value else known)
                else:
                    conditions.append(any(address in ipaddress.ip_network(net, strict=False) for net in _values(value)))
            elif key == "query_type":
                current = _rr_type(context.get(key))
                types = [_rr_type(item) for item in _values(value)]
                conditions.append(_or([None if current is None or item is None else current == item for item in types]))
            elif key in ("network", "port", "protocol", "package_name", "process_name", "inbound"):
                current = context.get(key)
                conditions.append(None if current is None else current in _values(value))
            else:
                conditions.append(None)
        result = _and(conditions)
    return (not result) if rule.get("invert") and result is not None else result


def _explain_rules(section: Mapping[str, Any], context: Mapping[str, Any], sets: Mapping[str, Any]) -> dict[str, Any]:
    candidates = []
    uncertain = False
    dynamic = False
    for index, rule in enumerate(section.get("rules", []), 1):
        matched = _match(rule, context, sets)
        if matched is False:
            continue
        action = rule.get("action", "route")
        if action == "sniff":
            continue
        row = {"rule_index": index, "match": "true" if matched is True else "unknown",
               "action": _label(action)}
        for key in ("server", "outbound", "rcode"):
            if key in rule:
                row[key] = _label(rule[key])
        if "rule_set" in rule:
            row["rule_sets"] = [_label(tag) for tag in _values(rule["rule_set"])]
        candidates.append(row)
        if action in ("resolve", "evaluate", "route-options"):
            dynamic = True
            uncertain = True
            continue
        if matched is True:
            return {"certainty": "conditional" if uncertain else "determinate",
                    "candidate": row, "candidates": candidates,
                    "requires_runtime_evaluation": dynamic}
        uncertain = True
    return {"certainty": "conditional" if uncertain else "determinate",
            "candidate": {"action": "final", "target": _label(section.get("final", "unknown"))},
            "candidates": candidates, "requires_runtime_evaluation": dynamic}


def explain(*, config_root: Path, runtime_root: Path, domain: str, platform: str = "desktop",
            ip: str | None = None, network: str | None = None, port: int | None = None,
            package_name: str | None = None, process_name: str | None = None,
            protocol: str | None = None, inbound: str | None = None, **_kwargs: Any) -> dict[str, Any]:
    domain = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if len(domain) > 253 or not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", domain):
        raise ValueError("Expected a domain name, not a URL")
    release, _, state = _active(runtime_root)
    warnings = ["Static explanation is not a live traffic trace; client selections and remote egress are unknown"]
    if release:
        config = _read_json(release / platform / "config.json")
        basis = "validated_active_release"
    else:
        rm.no_links(config_root)
        policy = generator.for_platform(generator.load_yaml(config_root / "policy.yaml"), platform)
        config = policy["config"]
        config.setdefault("route", {})["rule_set"] = generator.build_rule_sets(
            config, policy.get("rule_set_urls", {}), config_root / "rule-sets")
        basis = "working_policy_local_rules_only"
        warnings.append("No validated active release: remote rule sets are unknown and were not downloaded")
        if state == "invalid":
            warnings.append("Invalid active release was not used")
    context = {"domain": domain, "ip": ipaddress.ip_address(ip) if ip else None,
               "network": network, "port": port, "package_name": package_name,
               "process_name": process_name, "protocol": protocol, "inbound": inbound}
    sets = {item["tag"]: item for item in config.get("route", {}).get("rule_set", [])}
    groups = []
    for outbound in config.get("outbounds", []):
        if outbound.get("type") in ("selector", "urltest"):
            members = outbound.get("outbounds", [])
            groups.append({"tag": _label(outbound["tag"]), "type": outbound["type"],
                           "default": _label(outbound.get("default", members[0] if members else "unknown")),
                           "actual_selection": "unknown"})
    # Connection metadata is not a DNS response or DNS-request transport identity.
    dns = {query: _explain_rules(config.get("dns", {}), {"domain": domain, "query_type": query}, sets)
           for query in ("A", "AAAA", "HTTPS")}
    return {"domain": domain, "platform": platform, "basis": basis,
            "build_id": release.name if release else None, "warnings": warnings,
            "dns": dns, "route": _explain_rules(config.get("route", {}), context, sets),
            "groups": groups, "client_selection": "unknown",
            "limitations": ["Regex, leading-dot suffixes, response matching and unsupported predicates remain unknown",
                             "Connection metadata is not reused as DNS request metadata or DNS response addresses",
                            "No DNS lookup, protocol sniffing, client inspection or remote egress probe is performed"]}


def lint(*, config_root: Path, **_kwargs: Any) -> dict[str, Any]:
    policy, items = _working(config_root)
    issues: list[dict[str, Any]] = []

    def issue(severity: str, code: str, message: str, **extra: Any) -> None:
        issues.append({"severity": severity, "code": code, "message": message, **extra})

    enabled = {item["name"] for item in items if item.get("enabled", True)}
    for source, groups in _requirements(policy).items():
        if source not in enabled:
            issue("error", "required_source_unavailable", "A referenced source is missing or disabled",
                  source=_label(source), required_by=[_label(tag) for tag in groups])
    domains: dict[str, list[str]] = {}
    directory = config_root / "rule-sets"
    for path in sorted(directory.glob("*.txt")):
        seen = set()
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            value = raw.split("#", 1)[0].strip().lower().rstrip(".")
            if not value:
                continue
            if not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", value):
                issue("warning", "invalid_domain_suffix", "Review this domain suffix", file=path.name, line=number)
                continue
            if value in seen:
                issue("warning", "duplicate_suffix", "Duplicate suffix in one list", file=path.name, line=number)
            seen.add(value)
            domains.setdefault(value, []).append(path.stem)
    for value, tags in domains.items():
        if len(set(tags)) > 1:
            issue("info", "cross_list_overlap", "Overlap may be intentional; rule order determines priority",
                  domain=value, rule_sets=sorted(set(tags)))
        parents = [parent for parent in domains if value.endswith("." + parent)]
        if parents:
            issue("info", "suffix_covered", "A broader local suffix also covers this entry",
                  domain=value, broader_suffixes=parents)
    for platform in rm.PLATFORMS:
        scoped = generator.for_platform(policy, platform)
        config = scoped["config"]
        group_tags = {"Available", "AI", "Other", "direct", "block", *enabled}
        group_tags.update(str(group["tag"]) for group in scoped.get("groups", {}).get("services", []))
        try:
            generator.build_rule_sets(config, policy.get("rule_set_urls", {}), directory)
        except READ_ERRORS:
            issue("error", "unresolved_rule_set", "A local or remote rule-set definition is unresolved", platform=platform)
        dns_tags = {server.get("tag") for server in config.get("dns", {}).get("servers", [])}
        for server in config.get("dns", {}).get("servers", []):
            missing = []
            if "detour" in server and server["detour"] not in group_tags:
                missing.append(server["detour"])
            missing.extend(tag for tag in server.get("servers", []) if tag not in dns_tags)
            if missing:
                issue("error", "unresolved_dns_reference", "A DNS server references an unknown target",
                      platform=platform, server=_label(server.get("tag", "unknown")),
                      targets=[_label(tag) for tag in missing])
        for section_name, key, known in (("route", "outbound", group_tags), ("dns", "server", dns_tags)):
            section = config.get(section_name, {})
            if "final" in section and section["final"] not in known:
                issue("error", "unresolved_final", "A section final target is unknown", platform=platform,
                      section=section_name, target=_label(section["final"]))
            for index, rule in enumerate(section.get("rules", []), 1):
                if key in rule and rule[key] not in known:
                    issue("error", "unresolved_reference", "A rule references an unknown target",
                          platform=platform, section=section_name, rule_index=index, target=_label(rule[key]))
    return {"issues": issues, "counts": {level: sum(item["severity"] == level for item in issues)
                                         for level in ("error", "warning", "info")},
            "note": "Read-only structural checks; intentional overlaps are informational, not live reachability tests"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "sources", "history", "explain", "lint"))
    parser.add_argument("--config-root", type=Path, default=ROOT / "config")
    parser.add_argument("--runtime-root", type=Path, default=ROOT / "runtime")
    parser.add_argument("--output-root", type=Path, default=ROOT / "dist")
    parser.add_argument("--core", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--domain")
    parser.add_argument("--platform", choices=rm.PLATFORMS, default="desktop")
    parser.add_argument("--ip")
    parser.add_argument("--network", choices=("tcp", "udp"))
    parser.add_argument("--port", type=int)
    parser.add_argument("--package-name")
    parser.add_argument("--process-name")
    parser.add_argument("--protocol")
    parser.add_argument("--inbound")
    args = parser.parse_args(argv)
    try:
        for root in (args.config_root, args.runtime_root, args.output_root):
            rm.no_links(root, recursive=False)
        if args.command == "explain" and not args.domain:
            raise ValueError("explain requires --domain")
        if args.port is not None and not 1 <= args.port <= 65535:
            raise ValueError("Invalid port")
        result = globals()[args.command](**vars(args))
        print(json.dumps(result, ensure_ascii=False, indent=None if args.json else 2))
        return 0
    except READ_ERRORS:
        # Parser/YAML/path exceptions can include private URLs and node credentials.
        error = {"error": "Read-only inspection failed; check input structure, paths and permissions", "command": args.command}
        print(json.dumps(error, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())

"""Structured subscription manifests and contained local input paths."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

import yaml

KEYS = {
    "name", "path", "enabled", "user_agent", "exclude", "allow_insecure",
    "use_hosts", "ai", "ai_include", "ai_allow_insecure",
}


class ManifestLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: ManifestLoader, node: Any, deep: bool = False) -> dict[str, Any]:
    seen = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ValueError("Duplicate YAML field in manifest")
        seen.add(key)
    loader.flatten_mapping(node)
    return {loader.construct_object(k, deep=deep): loader.construct_object(v, deep=deep)
            for k, v in node.value}


ManifestLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def contained_path(root: Path, relative: str) -> Path:
    value = Path(relative)
    if not relative or value.is_absolute() or value.drive or ".." in value.parts:
        raise ValueError("Input path must be relative and contained")
    candidate = root / value
    # Check the original spelling before resolve() hides a junction/symlink.
    for path in (candidate, *candidate.parents):
        if path.is_symlink() or (path.exists() and getattr(path.stat(), "st_file_attributes", 0) & 0x400):
            raise ValueError("Reparse points/symlinks are not allowed in input paths")
    root = root.resolve()
    target = candidate.resolve()
    if target == root or root not in target.parents:
        raise ValueError("Input path escapes its root")
    return target


def validate_manifest(data: Any, policy: Mapping[str, Any], base: Path) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or set(data) != {"subscriptions"}:
        raise ValueError("Manifest must contain only subscriptions")
    items = data["subscriptions"]
    if not isinstance(items, list):
        raise ValueError("subscriptions must be a list")
    groups = policy.get("groups") or {}
    reserved = {"Available", "AI", "Other", "direct", "block", "Aether-前置"}
    reserved.update(str(group["tag"]) for group in groups.get("services") or [])
    names: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Subscription must be an object")
        if set(item) - KEYS:
            raise ValueError("Unknown subscription fields: " + ", ".join(sorted(set(item) - KEYS)))
        name, path = item.get("name"), item.get("path")
        if not isinstance(name, str) or not name.strip() or not isinstance(path, str):
            raise ValueError("Subscription requires string name and path")
        if name in names or name in reserved:
            raise ValueError(f"订阅名称重复或属于保留名称: {name}")
        names.add(name)
        contained_path(base, path)
        for key in ("enabled", "allow_insecure", "use_hosts"):
            if key in item and not isinstance(item[key], bool):
                raise ValueError(f"{name}: {key} must be boolean")
        if item.get("ai", "auto") != "auto" and not isinstance(item["ai"], bool):
            raise ValueError(f"{name}: ai must be auto / true / false")
        if "user_agent" in item and not isinstance(item["user_agent"], str):
            raise ValueError(f"{name}: user_agent must be string")
        for key in ("exclude", "ai_include"):
            if key in item:
                if not isinstance(item[key], list) or any(not isinstance(p, str) for p in item[key]):
                    raise ValueError(f"{name}: {key} must be a list of patterns")
                for pattern in item[key]:
                    re.compile(pattern)
        if "ai_allow_insecure" in item:
            exception_names = item["ai_allow_insecure"]
            if not isinstance(exception_names, list) or any(not isinstance(n, str) or not n.strip() for n in exception_names):
                raise ValueError(f"{name}: ai_allow_insecure must be a list of exact node names")
    return items


def read_manifest(path: Path, policy: Mapping[str, Any]) -> dict[str, Any]:
    data = yaml.load(path.read_text(encoding="utf-8-sig"), Loader=ManifestLoader)
    validate_manifest(data, policy, path.parent)
    return data

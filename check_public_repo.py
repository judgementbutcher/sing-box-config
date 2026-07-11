"""Reject local/private sing-box material from the public Git snapshot."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import PurePosixPath


FORBIDDEN_FILES = {
    "subscriptions.yaml",
    "template.json",
    "config.json",
    "cache.clean.db",
    "README.local.md",
}
FORBIDDEN_PARTS = {
    ".secrets",
    ".subscription-cache",
    ".venv",
    "cores",
    "dashboard",
    "dist",
    "runtime",
    "subscriptions",
}
FORBIDDEN_SUFFIXES = {".db", ".dll", ".exe", ".zip"}
NODE_URL = re.compile(r"(?i)\b(?:anytls|hy2|hysteria2|ss|trojan|tuic|vless|vmess)://[^\s'\"<>]+")
SECRET_QUERY = re.compile(r"(?i)https?://[^\s'\"<>]+[?&](?:access_?token|auth|key|sub(?:scription)?|token)=")
SAFE_FIXTURES = {"vless://placeholder"}


def public_candidates() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def forbidden_path(path_text: str) -> bool:
    path = PurePosixPath(path_text)
    return (
        path.name in FORBIDDEN_FILES
        or bool(FORBIDDEN_PARTS.intersection(path.parts))
        or path.suffix.lower() in FORBIDDEN_SUFFIXES
        or (path.parent.name == "templates" and path.suffix == ".json" and not path.name.endswith(".example.json"))
    )


def scan_text(text: str) -> list[str]:
    findings: list[str] = []
    scrubbed = text
    for fixture in SAFE_FIXTURES:
        scrubbed = scrubbed.replace(fixture, "")
    if NODE_URL.search(scrubbed):
        findings.append("proxy node URI")
    if SECRET_QUERY.search(scrubbed):
        findings.append("URL containing a secret-like query parameter")
    return findings


def worktree_findings(path_text: str) -> list[str]:
    try:
        text = open(path_text, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        return []
    return scan_text(text)


def index_findings(path_text: str) -> list[str]:
    result = subprocess.run(
        ["git", "show", f":{path_text}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode:
        return []
    try:
        return scan_text(result.stdout.decode("utf-8"))
    except UnicodeDecodeError:
        return []


def main() -> int:
    failures: list[str] = []
    for path in public_candidates():
        if forbidden_path(path):
            failures.append(f"forbidden public path: {path}")
        findings = set(worktree_findings(path)) | set(index_findings(path))
        for finding in sorted(findings):
            failures.append(f"sensitive content in {path}: {finding}")

    if failures:
        print("Public repository check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Public repository check passed: no local/private material is publishable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

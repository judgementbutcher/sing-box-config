"""Shared helpers for the sing-box configuration toolchain."""

from .audit import ConfigAuditError, audit_config, outbound_fingerprint
from .io_utils import atomic_write_json, atomic_write_text, parse_duration_seconds
from .profiles import apply_profile_to_template, load_profile

__all__ = [
    "ConfigAuditError",
    "apply_profile_to_template",
    "atomic_write_json",
    "atomic_write_text",
    "audit_config",
    "load_profile",
    "outbound_fingerprint",
    "parse_duration_seconds",
]

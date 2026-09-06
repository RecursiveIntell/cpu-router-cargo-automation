"""Closed protocol constants and canonical helpers."""

from __future__ import annotations

import hashlib
import json
import re

REQUEST_SCHEMA = "cpu-router/request-v1"
SNAPSHOT_SCHEMA = "cpu-router/cargo-snapshot-v1"
CLIENT_RECEIPT_SCHEMA = "cpu-router/client-receipt-v1"
AGENT_RECEIPT_SCHEMA = "cpu-router/agent-receipt-v1"
ELF_MACHINES = {"x86_64": 62, "aarch64": 183}
ARCH_ALIASES = {"amd64": "x86_64", "arm64": "aarch64", "arm": "aarch64"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_architecture(value: str) -> str:
    lowered = value.lower()
    return ARCH_ALIASES.get(lowered, lowered)

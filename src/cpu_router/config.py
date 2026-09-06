"""Strict client configuration loading."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .protocol import ELF_MACHINES, SHA256_RE


@dataclass(frozen=True)
class Node:
    architecture: str
    node: str
    host: str
    port: int
    user: str
    identity_file: Path
    known_hosts_file: Path
    toolchain: str
    expected_worker_sha256: str


@dataclass(frozen=True)
class Config:
    receipt_dir: Path
    real_cargo: Path
    nodes: dict[str, Node]


def expanded(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value))).resolve()


def load_config(path: Path | None = None) -> Config:
    selected = (
        path
        or Path(
            os.environ.get("CPU_ROUTER_CONFIG", "~/.config/cpu-router/config.json")
        ).expanduser()
    )
    raw = json.loads(selected.read_text())
    if not isinstance(raw, dict) or set(raw) != {"receipt_dir", "real_cargo", "nodes"}:
        raise ValueError("config keys must be receipt_dir, real_cargo, and nodes")
    if not isinstance(raw["nodes"], dict) or set(raw["nodes"]) != set(ELF_MACHINES):
        raise ValueError("config must define exactly x86_64 and aarch64 nodes")
    nodes: dict[str, Node] = {}
    expected = {
        "node",
        "host",
        "port",
        "user",
        "identity_file",
        "known_hosts_file",
        "toolchain",
        "expected_worker_sha256",
    }
    for architecture, value in raw["nodes"].items():
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError(f"{architecture} node keys do not match the contract")
        for field in ("node", "host", "user", "toolchain"):
            if (
                not isinstance(value[field], str)
                or not value[field]
                or len(value[field]) > 255
            ):
                raise ValueError(f"{architecture}.{field} is invalid")
        if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
            raise ValueError(f"{architecture}.port is invalid")
        if not isinstance(
            value["expected_worker_sha256"], str
        ) or not SHA256_RE.fullmatch(value["expected_worker_sha256"]):
            raise ValueError(f"{architecture}.expected_worker_sha256 is invalid")
        nodes[architecture] = Node(
            architecture=architecture,
            node=value["node"],
            host=value["host"],
            port=value["port"],
            user=value["user"],
            identity_file=expanded(value["identity_file"]),
            known_hosts_file=expanded(value["known_hosts_file"]),
            toolchain=value["toolchain"],
            expected_worker_sha256=value["expected_worker_sha256"],
        )
    return Config(
        receipt_dir=expanded(raw["receipt_dir"]),
        real_cargo=expanded(raw["real_cargo"]),
        nodes=nodes,
    )

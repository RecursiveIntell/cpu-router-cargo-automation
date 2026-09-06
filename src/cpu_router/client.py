"""Architecture-aware restricted-SSH client with durable receipts."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
import uuid
from pathlib import Path

from . import __version__
from .config import Config, Node, load_config
from .protocol import (
    CLIENT_RECEIPT_SCHEMA,
    REQUEST_SCHEMA,
    canonical_architecture,
    canonical_json,
    sha256,
)

EXIT_BY_STATUS = {"ok": 0, "rejected": 2, "failed": 3, "busy": 75, "in-progress": 75}


def local_node() -> str:
    return platform.node().split(".")[0]


def submit_command(node: Node) -> list[str]:
    if local_node() == node.node:
        return [sys.executable, "-m", "cpu_router.submit"]
    return [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={node.known_hosts_file}",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
        "-p",
        str(node.port),
        "-i",
        str(node.identity_file),
        f"{node.user}@{node.host}",
    ]


def dispatch(
    config: Config,
    architecture: str,
    task: str,
    value: object,
    *,
    idempotency_key: str | None = None,
    timeout: int = 1_220,
) -> tuple[dict, dict | None, Path]:
    architecture = canonical_architecture(architecture)
    if architecture not in config.nodes:
        raise ValueError("unsupported architecture")
    node = config.nodes[architecture]
    request = {
        "schema": REQUEST_SCHEMA,
        "idempotency_key": idempotency_key or str(uuid.uuid4()),
        "task": task,
        "architecture": architecture,
        "value": value,
    }
    raw = canonical_json(request)
    receipt = {
        "schema": CLIENT_RECEIPT_SCHEMA,
        "architecture": architecture,
        "target": node.node,
        "started_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "idempotency_key": request["idempotency_key"],
        "request_sha256": sha256(raw),
        "task": task,
        "status": "failed",
        "transport": "local-unix-socket"
        if local_node() == node.node
        else "restricted-key-ssh",
    }
    response = None
    try:
        proc = subprocess.run(
            submit_command(node),
            input=raw,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        receipt["exit_code"] = proc.returncode
        response = json.loads(proc.stdout)
        if response.get("status") != "ok" or proc.returncode != 0:
            receipt["status"] = response.get("status", "failed")
            receipt["error"] = response.get("error", "task failed")
        elif (
            response.get("architecture") != architecture
            or response.get("host") != node.node
        ):
            receipt["status"] = "quarantined"
            receipt["error"] = "remote identity or architecture mismatch"
        elif response.get("request_sha256") != receipt["request_sha256"]:
            receipt["status"] = "quarantined"
            receipt["error"] = "request digest mismatch"
        elif response.get("worker_sha256") != node.expected_worker_sha256:
            receipt["status"] = "quarantined"
            receipt["error"] = "worker source mismatch"
        else:
            receipt["status"] = "verified-transport-identity-and-worker-module"
    except (
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        receipt["error"] = str(exc)
    result_summary = dict((response or {}).get("result") or {})
    artifact = result_summary.get("artifact")
    if isinstance(artifact, dict):
        artifact = dict(artifact)
        artifact.pop("gzip_b64", None)
        result_summary["artifact"] = artifact
    if response:
        receipt["response_summary"] = {
            key: value for key, value in response.items() if key != "result"
        }
        receipt["response_summary"]["result"] = result_summary
    config.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = config.receipt_dir / f"{request['idempotency_key']}.{uuid.uuid4()}.json"
    with path.open("x") as handle:
        json.dump(receipt, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    return receipt, response, path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--arch", required=True, choices=["x86_64", "aarch64"])
    parser.add_argument("--idempotency-key")
    parser.add_argument("task", choices=["health"])
    args = parser.parse_args()
    config = load_config(args.config)
    receipt, response, path = dispatch(
        config,
        args.arch,
        args.task,
        None,
        idempotency_key=args.idempotency_key,
        timeout=110,
    )
    print(json.dumps({"receipt": str(path), **receipt}, indent=2))
    status = (response or {}).get("status")
    return (
        0
        if receipt["status"] == "verified-transport-identity-and-worker-module"
        else EXIT_BY_STATUS.get(str(status), 1)
    )


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Installed-package local health smoke for the agent/socket/client path."""

from __future__ import annotations

import hashlib
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cpu_router import worker
from cpu_router.client import dispatch
from cpu_router.config import Config, Node


def main() -> int:
    architecture = platform.machine().lower()
    if architecture == "amd64":
        architecture = "x86_64"
    if architecture not in {"x86_64", "aarch64"}:
        raise SystemExit(f"unsupported smoke architecture: {architecture}")
    with tempfile.TemporaryDirectory(prefix="cpu-router-smoke-") as directory:
        root = Path(directory)
        runtime = root / "cpu-router"
        state = root / "state"
        receipts = root / "receipts"
        environment = os.environ.copy()
        environment.update(
            {
                "RUNTIME_DIRECTORY": str(runtime),
                "STATE_DIRECTORY": str(state),
                "XDG_RUNTIME_DIR": str(root),
                "CPU_ROUTER_NODE": platform.node().split(".")[0],
                "CPU_ROUTER_ARCH": architecture,
                "CPU_ROUTER_TOOLCHAIN": "smoke-toolchain",
                "CPU_ROUTER_MAX_JOBS": "1",
            }
        )
        process = subprocess.Popen(
            [sys.executable, "-m", "cpu_router.agent"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            socket = runtime / "agent.sock"
            for _ in range(100):
                if socket.exists():
                    break
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    raise SystemExit(f"agent exited early: {stdout!r} {stderr!r}")
                time.sleep(0.05)
            else:
                raise SystemExit("agent socket did not appear")
            node = Node(
                architecture=architecture,
                node=platform.node().split(".")[0],
                host="unused.invalid",
                port=22,
                user="unused",
                identity_file=root / "unused-key",
                known_hosts_file=root / "unused-known-hosts",
                toolchain="smoke-toolchain",
                expected_worker_sha256=hashlib.sha256(
                    Path(worker.__file__).read_bytes()
                ).hexdigest(),
            )
            config = Config(
                receipt_dir=receipts,
                real_cargo=root / "cargo",
                nodes={architecture: node},
            )
            previous_runtime = os.environ.get("XDG_RUNTIME_DIR")
            os.environ["XDG_RUNTIME_DIR"] = str(root)
            try:
                receipt, response, path = dispatch(
                    config, architecture, "health", None, timeout=30
                )
            finally:
                if previous_runtime is None:
                    os.environ.pop("XDG_RUNTIME_DIR", None)
                else:
                    os.environ["XDG_RUNTIME_DIR"] = previous_runtime
            if receipt.get("status") != "verified-transport-identity-and-worker-module":
                raise SystemExit(f"health smoke failed: {receipt}")
            if (
                response is None
                or response.get("result", {}).get("toolchain") != "smoke-toolchain"
            ):
                raise SystemExit("health smoke returned the wrong runtime identity")
            print(f"verified local agent/socket/client path; receipt={path}")
            return 0
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())

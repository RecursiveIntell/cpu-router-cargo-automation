"""Bounded Cargo worker. It accepts no shell command or caller path."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import platform
import resource
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import __version__
from .protocol import (
    ELF_MACHINES,
    REQUEST_SCHEMA,
    UUID_RE,
    canonical_architecture,
    sha256,
)
from .snapshot import validate_cargo_request, validate_envelope, verify_and_extract

MAX_INPUT = 12_000_000
MAX_BUILD_ARTIFACT = 67_108_864
MAX_COMPRESSED_ARTIFACT = 16_777_216


class TaskFailed(Exception):
    """The request was admitted but its bounded task failed."""


def worker_sha256() -> str:
    return sha256(Path(__file__).read_bytes())


def print_worker_sha256() -> int:
    """Print the installed worker.py module-file digest for configuration."""
    print(worker_sha256())
    return 0


def configured_runtime() -> tuple[str, str, str]:
    node = os.environ.get("CPU_ROUTER_NODE", "")
    architecture = canonical_architecture(os.environ.get("CPU_ROUTER_ARCH", ""))
    toolchain = os.environ.get("CPU_ROUTER_TOOLCHAIN", "")
    if not node or architecture not in ELF_MACHINES or not toolchain:
        raise ValueError(
            "CPU_ROUTER_NODE, CPU_ROUTER_ARCH, and CPU_ROUTER_TOOLCHAIN are required"
        )
    return node, architecture, toolchain


def cargo_environment(
    job_root: Path, toolchain_root: Path, architecture: str
) -> dict[str, str]:
    cargo_home = job_root / "cargo-home"
    cargo_home.mkdir(mode=0o700)
    source_cargo_home = Path.home() / ".cargo"
    for name in ("registry", "git"):
        source = source_cargo_home / name
        if source.exists():
            (cargo_home / name).symlink_to(source)
    jobs = "6" if architecture == "x86_64" else "3"
    return {
        "HOME": str(Path.home()),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(job_root / "target"),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_BUILD_JOBS": jobs,
        "CARGO_TERM_COLOR": "never",
        "RUSTC": str(toolchain_root / "bin/rustc"),
        "PATH": f"{toolchain_root / 'bin'}:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def validate_job(
    value: object, architecture: str, toolchain: str
) -> tuple[dict, list[str]]:
    expected = {"snapshot", "action", "arguments", "toolchain"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("Cargo job keys are invalid")
    if value["toolchain"] != toolchain:
        raise ValueError(
            "Cargo job toolchain does not match the configured owner toolchain"
        )
    validate_envelope(value["snapshot"])
    command = validate_cargo_request(value["action"], value["arguments"])
    return value, command


def cargo_job(value: object, requested_architecture: str) -> dict:
    node, architecture, toolchain = configured_runtime()
    actual = canonical_architecture(platform.machine())
    if requested_architecture != architecture or actual != architecture:
        raise ValueError("requested, configured, and host architectures must match")
    admitted, command = validate_job(value, architecture, toolchain)
    toolchain_root = Path.home() / ".rustup/toolchains" / toolchain
    cargo = toolchain_root / "bin/cargo"
    rustc = toolchain_root / "bin/rustc"
    if not cargo.is_file() or not rustc.is_file():
        raise TaskFailed("configured Rust toolchain is unavailable")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cpu-router-cargo-") as directory:
        job_root = Path(directory)
        source_root = job_root / "source"
        snapshot_result = verify_and_extract(admitted["snapshot"], source_root)
        env = cargo_environment(job_root, toolchain_root, architecture)
        metadata = subprocess.run(
            [
                str(cargo),
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--offline",
                "--no-deps",
            ],
            cwd=source_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if metadata.returncode:
            raise TaskFailed("cargo metadata failed: " + metadata.stderr[-8192:])
        proc = subprocess.run(
            [str(cargo), *command],
            cwd=source_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        if proc.returncode:
            raise TaskFailed(
                f"cargo {admitted['action']} exit {proc.returncode}:\n"
                + proc.stderr[-32768:]
                + proc.stdout[-32768:]
            )
        result = {
            "action": admitted["action"],
            "command": command,
            "toolchain": toolchain,
            "manifest_sha256": snapshot_result["manifest_sha256"],
            "archive_sha256": snapshot_result["archive_sha256"],
            "source_files": snapshot_result["files"],
            "source_bytes": snapshot_result["bytes"],
            "workspace_packages": len(json.loads(metadata.stdout)["workspace_members"]),
            "stdout_tail": ""
            if admitted["action"] == "build"
            else proc.stdout[-32768:],
            "stderr_tail": proc.stderr[-32768:],
            "elapsed_seconds": time.monotonic() - started,
        }
        if admitted["action"] == "build":
            bin_index = command.index("--bin")
            binary_name = command[bin_index + 1]
            executables: list[Path] = []
            for line in proc.stdout.splitlines():
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    message.get("reason") == "compiler-artifact"
                    and message.get("target", {}).get("name") == binary_name
                    and message.get("executable")
                ):
                    executables.append(Path(message["executable"]))
            if len(executables) != 1:
                raise TaskFailed(
                    "build did not identify exactly one requested executable"
                )
            executable = executables[0].resolve(strict=True)
            executable.relative_to((job_root / "target").resolve())
            artifact = executable.read_bytes()
            if len(artifact) > MAX_BUILD_ARTIFACT:
                raise TaskFailed("build artifact exceeds 64 MiB")
            compressed = gzip.compress(artifact, compresslevel=6, mtime=0)
            if len(compressed) > MAX_COMPRESSED_ARTIFACT:
                raise TaskFailed("compressed build artifact exceeds 16 MiB")
            if (
                len(artifact) < 20
                or artifact[:4] != b"\x7fELF"
                or int.from_bytes(artifact[18:20], "little")
                != ELF_MACHINES[architecture]
            ):
                raise TaskFailed("build artifact architecture mismatch")
            result["artifact"] = {
                "name": binary_name,
                "bytes": len(artifact),
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "gzip_bytes": len(compressed),
                "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
                "gzip_b64": base64.b64encode(compressed).decode(),
                "elf_machine": ELF_MACHINES[architecture],
            }
        return {"node": node, **result}


def execute(request: object) -> dict:
    expected = {"schema", "idempotency_key", "task", "architecture", "value"}
    if not isinstance(request, dict) or set(request) != expected:
        raise ValueError("request keys do not match the closed protocol")
    if (
        request["schema"] != REQUEST_SCHEMA
        or not isinstance(request["idempotency_key"], str)
        or not UUID_RE.fullmatch(request["idempotency_key"])
    ):
        raise ValueError("request schema or idempotency key is invalid")
    architecture = canonical_architecture(str(request["architecture"]))
    if architecture not in ELF_MACHINES:
        raise ValueError("architecture is not allowlisted")
    if request["task"] == "health":
        if request["value"] is not None:
            raise ValueError("health requires null value")
        node, configured_architecture, toolchain = configured_runtime()
        if architecture != configured_architecture:
            raise ValueError("health request architecture does not match this owner")
        return {
            "node": node,
            "toolchain": toolchain,
            "cpus": os.cpu_count(),
            "load_1m": os.getloadavg()[0],
        }
    if request["task"] != "cargo-job":
        raise ValueError("task is not allowlisted")
    return cargo_job(request["value"], architecture)


def apply_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (1_000, 1_000))
    resource.setrlimit(resource.RLIMIT_AS, (12_884_901_888, 12_884_901_888))
    resource.setrlimit(resource.RLIMIT_FSIZE, (134_217_728, 134_217_728))
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    signal.alarm(1_100)
    os.nice(10)


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    try:
        if len(raw) > MAX_INPUT:
            raise ValueError("request too large")
        request = json.loads(raw)
        apply_limits()
        result = execute(request)
        response = {
            "status": "ok",
            "architecture": canonical_architecture(platform.machine()),
            "host": os.environ["CPU_ROUTER_NODE"],
            "request_sha256": sha256(raw),
            "worker_sha256": worker_sha256(),
            "runtime_version": __version__,
            "result": result,
        }
        print(json.dumps(response, separators=(",", ":")))
        return 0
    except ValueError as exc:
        print(
            json.dumps({"status": "rejected", "error": str(exc)}, separators=(",", ":"))
        )
        return 2
    except (TaskFailed, OSError, subprocess.SubprocessError) as exc:
        print(
            json.dumps({"status": "failed", "error": str(exc)}, separators=(",", ":"))
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

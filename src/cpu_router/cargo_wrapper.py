"""Cargo integration boundary: remote admitted work, explicit local passthrough."""

from __future__ import annotations

import base64
import gzip
import hashlib
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import NoReturn

from .client import dispatch, local_node
from .config import Config, load_config
from .protocol import ELF_MACHINES
from .snapshot import git_snapshot, validate_cargo_request

TARGET_ARCHITECTURES = {
    "x86_64-unknown-linux-gnu": "x86_64",
    "aarch64-unknown-linux-gnu": "aarch64",
}
REMOTE_ACTIONS = {"check", "test", "build"}
RETRY_DELAYS = (0.0, 0.25, 0.5, 1.0, 2.0, 4.0)


def passthrough(config: Config, arguments: list[str], reason: str) -> NoReturn:
    print(f"[cpu-router] local Cargo: {reason}", file=sys.stderr)
    if not config.real_cargo.is_file():
        raise SystemExit(f"real Cargo is unavailable: {config.real_cargo}")
    os.execv(config.real_cargo, [str(config.real_cargo), *arguments])


def requested_architecture(arguments: list[str]) -> tuple[str, list[str], str | None]:
    target = None
    stripped: list[str] = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value == "--target":
            if index + 1 >= len(arguments) or target is not None:
                raise ValueError("invalid or duplicate --target")
            target = arguments[index + 1]
            index += 2
            continue
        if value.startswith("--target="):
            if target is not None:
                raise ValueError("duplicate --target")
            target = value.split("=", 1)[1]
            index += 1
            continue
        stripped.append(value)
        index += 1
    if target is None:
        return "x86_64", stripped, None
    if target not in TARGET_ARCHITECTURES:
        raise ValueError(f"target is not an admitted native owner: {target}")
    return TARGET_ARCHITECTURES[target], stripped, target


def promote_artifact(
    root: Path, artifact: object, architecture: str, target: str | None
) -> Path:
    expected = {
        "name",
        "bytes",
        "sha256",
        "gzip_bytes",
        "gzip_sha256",
        "gzip_b64",
        "elf_machine",
    }
    if not isinstance(artifact, dict) or set(artifact) != expected:
        raise ValueError("invalid build artifact envelope")
    compressed = base64.b64decode(artifact["gzip_b64"], validate=True)
    if (
        len(compressed) != artifact["gzip_bytes"]
        or hashlib.sha256(compressed).hexdigest() != artifact["gzip_sha256"]
    ):
        raise ValueError("compressed artifact mismatch")
    data = gzip.decompress(compressed)
    if (
        len(data) != artifact["bytes"]
        or hashlib.sha256(data).hexdigest() != artifact["sha256"]
    ):
        raise ValueError("artifact mismatch")
    if (
        len(data) < 20
        or data[:4] != b"\x7fELF"
        or int.from_bytes(data[18:20], "little") != ELF_MACHINES[architecture]
    ):
        raise ValueError("artifact architecture mismatch")
    output_root = root / "target"
    if target:
        output_root /= target
    output = output_root / "release" / artifact["name"]
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".cpu-router-new")
    with temporary.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o755)
    temporary.replace(output)
    return output


def main() -> int:
    config = load_config()
    arguments = sys.argv[1:]
    if not arguments or arguments[0] not in REMOTE_ACTIONS:
        passthrough(config, arguments, "subcommand is not an admitted remote action")
    action = arguments[0]
    try:
        architecture, cargo_arguments, target = requested_architecture(arguments[1:])
        validate_cargo_request(action, cargo_arguments)
    except ValueError as exc:
        passthrough(config, arguments, f"request outside remote contract ({exc})")
    node = config.nodes[architecture]
    if local_node() == node.node or os.environ.get("CPU_ROUTER_LOCAL") == "1":
        passthrough(
            config, arguments, "local execution explicitly selected or already on owner"
        )
    root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if root_result.returncode:
        print("[cpu-router] remote Cargo requires a Git worktree", file=sys.stderr)
        return 1
    root = Path(root_result.stdout.strip()).resolve(strict=True)
    try:
        snapshot = git_snapshot(root)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"[cpu-router] source admission failed: {exc}", file=sys.stderr)
        return 1
    value = {
        "snapshot": snapshot.envelope(),
        "action": action,
        "arguments": cargo_arguments,
        "toolchain": node.toolchain,
    }
    print(
        f"[cpu-router] {action} -> {node.node}; {len(snapshot.manifest)} files, snapshot {snapshot.manifest_sha256[:16]}",
        file=sys.stderr,
    )
    job_key = str(uuid.uuid4())
    receipt = response = path = None
    for delay in RETRY_DELAYS:
        if delay:
            time.sleep(delay)
        receipt, response, path = dispatch(
            config, architecture, "cargo-job", value, idempotency_key=job_key
        )
        if receipt["status"] not in {"busy", "in-progress"}:
            break
    assert receipt is not None and path is not None
    if (
        receipt["status"] != "verified-transport-identity-and-worker-module"
        or response is None
    ):
        print(
            f"[cpu-router] remote Cargo failed without local fallback; receipt: {path}",
            file=sys.stderr,
        )
        print(receipt.get("error", "unknown failure"), file=sys.stderr)
        return 1
    result = response["result"]
    if (
        result.get("manifest_sha256") != snapshot.manifest_sha256
        or result.get("archive_sha256") != snapshot.archive_sha256
    ):
        print("[cpu-router] remote source identity mismatch", file=sys.stderr)
        return 1
    if result.get("stdout_tail"):
        print(
            result["stdout_tail"],
            end="" if result["stdout_tail"].endswith("\n") else "\n",
        )
    if result.get("stderr_tail"):
        print(
            result["stderr_tail"],
            end="" if result["stderr_tail"].endswith("\n") else "\n",
            file=sys.stderr,
        )
    if action == "build":
        output = promote_artifact(root, result.get("artifact"), architecture, target)
        print(f"[cpu-router] verified artifact: {output}", file=sys.stderr)
    after = git_snapshot(root)
    if (
        after.manifest_sha256 != snapshot.manifest_sha256
        or after.archive_sha256 != snapshot.archive_sha256
    ):
        print("[cpu-router] admitted source changed during remote job", file=sys.stderr)
        return 1
    print(f"[cpu-router] verified receipt: {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

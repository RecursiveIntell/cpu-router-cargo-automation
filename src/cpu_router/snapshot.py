"""Deterministic, bounded source snapshots and Cargo request admission."""

from __future__ import annotations

import base64
import gzip
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .protocol import SNAPSHOT_SCHEMA, canonical_json, sha256

MAX_FILES = 5_000
MAX_FILE_BYTES = 2_097_152
MAX_TOTAL_BYTES = 33_554_432
MAX_ARCHIVE_BYTES = 8_388_608
FORBIDDEN_COMPONENTS = {
    ".git",
    ".ares",
    ".cargo",
    ".ssh",
    "target",
    "node_modules",
    "__pycache__",
    ".venv",
    ".publication-receipts",
}
FORBIDDEN_NAMES = {
    ".env",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "authorized_keys",
}
FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx"}
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
FEATURE_RE = re.compile(r"^[A-Za-z0-9_./,+-]+$")


@dataclass(frozen=True)
class Snapshot:
    archive: bytes
    manifest: list[dict]
    manifest_sha256: str
    archive_sha256: str
    provenance: dict = field(default_factory=dict)

    def envelope(self) -> dict:
        return {
            "schema": SNAPSHOT_SCHEMA,
            "archive_b64": base64.b64encode(self.archive).decode(),
            "archive_sha256": self.archive_sha256,
            "manifest": json.loads(json.dumps(self.manifest)),
            "manifest_sha256": self.manifest_sha256,
            "provenance": json.loads(json.dumps(self.provenance)),
        }


def validate_relative_path(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or len(value.encode()) > 512:
        raise ValueError("invalid snapshot path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ValueError(f"unsafe snapshot path: {value}")
    lowered = [part.lower() for part in path.parts]
    basename = lowered[-1]
    if any(part in FORBIDDEN_COMPONENTS for part in lowered):
        raise ValueError(f"forbidden snapshot path: {value}")
    if (
        basename in FORBIDDEN_NAMES
        or basename.startswith(".env.")
        or PurePosixPath(basename).suffix in FORBIDDEN_SUFFIXES
    ):
        raise ValueError(f"forbidden secret-bearing path: {value}")
    return path


def excluded_path(value: str) -> bool:
    return any(
        part.lower() in FORBIDDEN_COMPONENTS for part in PurePosixPath(value).parts
    )


def read_regular_file_no_follow(
    root: Path, relative: PurePosixPath
) -> tuple[bytes, os.stat_result]:
    parent = root
    for component in relative.parts[:-1]:
        parent /= component
        metadata = parent.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"unsafe snapshot parent: {relative}")
    path = root.joinpath(*relative.parts)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError(
            f"symlink, missing, or unreadable path rejected: {relative}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"non-regular path rejected: {relative}")
        if before.st_size > MAX_FILE_BYTES:
            raise ValueError(f"file-size limit exceeded: {relative}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ino != before.st_ino
            or after.st_dev != before.st_dev
        ):
            raise ValueError(f"source changed while reading: {relative}")
        return data, before
    finally:
        os.close(descriptor)


def create_snapshot_from_paths(
    root: Path, paths, provenance: dict | None = None
) -> Snapshot:
    root = root.resolve(strict=True)
    unique = sorted({str(PurePosixPath(path)) for path in paths})
    if len(unique) > MAX_FILES:
        raise ValueError("snapshot file-count limit exceeded")
    if "Cargo.toml" not in unique or "Cargo.lock" not in unique:
        raise ValueError("snapshot requires root Cargo.toml and Cargo.lock")
    manifest: list[dict] = []
    payloads: dict[str, bytes] = {}
    total = 0
    for relative in unique:
        parsed = validate_relative_path(relative)
        data, metadata = read_regular_file_no_follow(root, parsed)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("snapshot aggregate-size limit exceeded")
        mode = 0o755 if metadata.st_mode & stat.S_IXUSR else 0o644
        manifest.append(
            {"path": relative, "bytes": len(data), "sha256": sha256(data), "mode": mode}
        )
        payloads[relative] = data
    manifest_hash = sha256(canonical_json(manifest))
    raw = io.BytesIO()
    with (
        gzip.GzipFile(
            fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=6
        ) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive,
    ):
        for entry in manifest:
            info = tarfile.TarInfo(entry["path"])
            info.size = entry["bytes"]
            info.mode = entry["mode"]
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(payloads[entry["path"]]))
    archive_bytes = raw.getvalue()
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("compressed snapshot exceeds 8 MiB")
    return Snapshot(
        archive_bytes, manifest, manifest_hash, sha256(archive_bytes), provenance or {}
    )


def git_snapshot(root: Path) -> Snapshot:
    root = root.resolve(strict=True)
    git_root = Path(
        subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"], text=True
        ).strip()
    ).resolve()
    if git_root != root:
        raise ValueError(f"run from Git root: {git_root}")
    raw = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ]
    )
    candidates = [path for path in raw.decode().split("\0") if path]
    excluded = sorted(path for path in candidates if excluded_path(path))
    paths = [path for path in candidates if path not in set(excluded)]
    status_default = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain=v1"]
    )
    status_all = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"]
    )
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    provenance = {
        "git_head": head.stdout.strip() if head.returncode == 0 else "UNBORN",
        "git_status_default_sha256": sha256(status_default),
        "git_status_all_sha256": sha256(status_all),
        "file_selection": "git-ls-files-cached-plus-unignored-v1",
        "excluded_paths": len(excluded),
        "excluded_paths_sha256": sha256(canonical_json(excluded)),
    }
    return create_snapshot_from_paths(root, paths, provenance)


def validate_envelope(envelope: object) -> tuple[bytes, list[dict]]:
    expected = {
        "schema",
        "archive_b64",
        "archive_sha256",
        "manifest",
        "manifest_sha256",
        "provenance",
    }
    if (
        not isinstance(envelope, dict)
        or set(envelope) != expected
        or envelope.get("schema") != SNAPSHOT_SCHEMA
    ):
        raise ValueError("invalid Cargo snapshot envelope")
    manifest = envelope["manifest"]
    if not isinstance(manifest, list) or not 2 <= len(manifest) <= MAX_FILES:
        raise ValueError("invalid manifest length")
    paths: list[str] = []
    total = 0
    for entry in manifest:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "bytes",
            "sha256",
            "mode",
        }:
            raise ValueError("invalid manifest entry")
        validate_relative_path(entry["path"])
        if type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= MAX_FILE_BYTES:
            raise ValueError("invalid manifest byte count")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", entry["sha256"]
        ):
            raise ValueError("invalid manifest digest")
        if entry["mode"] not in (0o644, 0o755):
            raise ValueError("invalid manifest mode")
        paths.append(entry["path"])
        total += entry["bytes"]
    if paths != sorted(set(paths)) or total > MAX_TOTAL_BYTES:
        raise ValueError("manifest paths or aggregate size invalid")
    if "Cargo.toml" not in paths or "Cargo.lock" not in paths:
        raise ValueError("manifest lacks Cargo root files")
    if sha256(canonical_json(manifest)) != envelope["manifest_sha256"]:
        raise ValueError("manifest digest mismatch")
    archive = base64.b64decode(envelope["archive_b64"], validate=True)
    if (
        len(archive) > MAX_ARCHIVE_BYTES
        or sha256(archive) != envelope["archive_sha256"]
    ):
        raise ValueError("archive digest or size mismatch")
    return archive, manifest


def verify_and_extract(envelope: object, destination: Path) -> dict:
    archive_bytes, manifest = validate_envelope(envelope)
    assert isinstance(envelope, dict)
    if destination.exists():
        raise ValueError("snapshot destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    expected = {entry["path"]: entry for entry in manifest}
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if names != sorted(expected) or len(names) != len(set(names)):
                raise ValueError("archive member set does not match manifest")
            for member in members:
                if not member.isfile() or member.name not in expected:
                    raise ValueError(
                        "archive contains undeclared or non-regular member"
                    )
                entry = expected[member.name]
                if member.size != entry["bytes"] or member.size > MAX_FILE_BYTES:
                    raise ValueError("archive member size mismatch")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("archive member unavailable")
                data = source.read(MAX_FILE_BYTES + 1)
                if len(data) != entry["bytes"] or sha256(data) != entry["sha256"]:
                    raise ValueError("archive member digest mismatch")
                output = destination.joinpath(*PurePosixPath(member.name).parts)
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with output.open("xb") as handle:
                    handle.write(data)
                output.chmod(entry["mode"])
                seen.add(member.name)
        if seen != set(expected):
            raise ValueError("archive member set incomplete")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return {
        "manifest_sha256": envelope["manifest_sha256"],
        "archive_sha256": envelope["archive_sha256"],
        "files": len(manifest),
        "bytes": sum(entry["bytes"] for entry in manifest),
    }


def validate_cargo_request(action: object, arguments: object) -> list[str]:
    if action not in {"check", "test", "build"} or not isinstance(arguments, list):
        raise ValueError("unsupported Cargo action")
    boolean = {
        "--workspace",
        "--all-targets",
        "--all-features",
        "--no-default-features",
        "--release",
        "--lib",
        "--bins",
        "--tests",
        "--examples",
    }
    paired = {
        "-p": NAME_RE,
        "--package": NAME_RE,
        "--features": FEATURE_RE,
        "--bin": NAME_RE,
        "--example": NAME_RE,
        "--test": NAME_RE,
    }
    admitted: list[str] = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value in boolean:
            if value not in admitted:
                admitted.append(value)
            index += 1
            continue
        if value in paired:
            if (
                index + 1 >= len(arguments)
                or not isinstance(arguments[index + 1], str)
                or not paired[value].fullmatch(arguments[index + 1])
            ):
                raise ValueError(f"invalid value for {value}")
            admitted.extend((value, arguments[index + 1]))
            index += 2
            continue
        raise ValueError(f"Cargo argument not allowlisted: {value}")
    command = [str(action), "--locked"]
    if action == "build":
        bins = [
            admitted[i + 1] for i, value in enumerate(admitted[:-1]) if value == "--bin"
        ]
        if "--release" not in admitted or len(bins) != 1:
            raise ValueError("remote build requires --release and exactly one --bin")
        command.append("--message-format=json-render-diagnostics")
    command.extend(admitted)
    return command

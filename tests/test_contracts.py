from __future__ import annotations

import base64
from dataclasses import replace
import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cpu_router import agent, cargo_wrapper, client, config, snapshot, worker


class SnapshotTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
        (root / "Cargo.lock").write_text("# lock\n")
        (root / "src/lib.rs").write_text("pub fn answer() -> u32 { 42 }\n")

    def test_snapshot_is_deterministic_and_extracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            paths = ["src/lib.rs", "Cargo.toml", "Cargo.lock"]
            one = snapshot.create_snapshot_from_paths(root, paths)
            two = snapshot.create_snapshot_from_paths(root, reversed(paths))
            self.assertEqual(one.archive, two.archive)
            out = root / "out"
            result = snapshot.verify_and_extract(one.envelope(), out)
            self.assertEqual(result["manifest_sha256"], one.manifest_sha256)
            self.assertEqual(
                (out / "src/lib.rs").read_text(), "pub fn answer() -> u32 { 42 }\n"
            )

    def test_secret_symlink_and_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / ".env").write_text("TOKEN=fake")
            with self.assertRaises(ValueError):
                snapshot.create_snapshot_from_paths(
                    root, ["Cargo.toml", "Cargo.lock", ".env"]
                )
            (root / "escape").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                snapshot.create_snapshot_from_paths(
                    root, ["Cargo.toml", "Cargo.lock", "escape"]
                )
            (root / "outside").mkdir()
            (root / "outside/value.rs").write_text("secret")
            (root / "linked-parent").symlink_to(
                root / "outside", target_is_directory=True
            )
            with self.assertRaises(ValueError):
                snapshot.create_snapshot_from_paths(
                    root, ["Cargo.toml", "Cargo.lock", "linked-parent/value.rs"]
                )
            with self.assertRaises(ValueError):
                snapshot.validate_relative_path("../escape")
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text('[build]\nrustc-wrapper="wrapper"\n')
            with self.assertRaises(ValueError):
                snapshot.create_snapshot_from_paths(
                    root, ["Cargo.toml", "Cargo.lock", ".cargo/config.toml"]
                )

    def test_manifest_and_archive_extra_tamper_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            value = snapshot.create_snapshot_from_paths(
                root, ["Cargo.lock", "Cargo.toml", "src/lib.rs"]
            )
            envelope = value.envelope()
            envelope["manifest"][0]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                snapshot.verify_and_extract(envelope, root / "bad")
            envelope = value.envelope()
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w:gz") as archive:
                info = tarfile.TarInfo("extra")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            envelope["archive_b64"] = base64.b64encode(raw.getvalue()).decode()
            envelope["archive_sha256"] = hashlib.sha256(raw.getvalue()).hexdigest()
            with self.assertRaises(ValueError):
                snapshot.verify_and_extract(envelope, root / "extra")

    def test_cargo_argument_contract(self):
        self.assertEqual(
            snapshot.validate_cargo_request("check", ["--workspace", "--all-targets"]),
            ["check", "--locked", "--workspace", "--all-targets"],
        )
        self.assertEqual(
            snapshot.validate_cargo_request("build", ["--release", "--bin", "fixture"]),
            [
                "build",
                "--locked",
                "--message-format=json-render-diagnostics",
                "--release",
                "--bin",
                "fixture",
            ],
        )
        for action, arguments in (
            ("run", []),
            ("test", ["--", "--nocapture"]),
            ("build", ["--release"]),
        ):
            with self.assertRaises(ValueError):
                snapshot.validate_cargo_request(action, arguments)


class ConfigTests(unittest.TestCase):
    def test_config_is_closed_and_expands_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {
                "receipt_dir": str(root / "receipts"),
                "real_cargo": str(root / "cargo"),
                "nodes": {
                    architecture: {
                        "node": f"{architecture}-host",
                        "host": "example.invalid",
                        "port": 22,
                        "user": "builder",
                        "identity_file": str(root / "key"),
                        "known_hosts_file": str(root / "known_hosts"),
                        "toolchain": f"pinned-{architecture}",
                        "expected_worker_sha256": "a" * 64,
                    }
                    for architecture in ("x86_64", "aarch64")
                },
            }
            path = root / "config.json"
            path.write_text(json.dumps(payload))
            loaded = config.load_config(path)
            self.assertEqual(set(loaded.nodes), {"x86_64", "aarch64"})
            payload["unexpected"] = True
            path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError):
                config.load_config(path)


class RoutingTests(unittest.TestCase):
    def test_tauri_commands_are_explicitly_local_only(self):
        self.assertTrue(cargo_wrapper.is_local_only_command(["tauri", "dev"]))
        self.assertTrue(cargo_wrapper.is_local_only_command(["tauri", "build"]))
        self.assertFalse(cargo_wrapper.is_local_only_command(["check"]))
        self.assertFalse(cargo_wrapper.is_local_only_command([]))

    def test_main_passthrough_keeps_tauri_commands_out_of_remote_dispatch(self):
        settings = SimpleNamespace()
        for arguments in (
            ["tauri", "dev", "--features", "semantic-memory-turbo-quant"],
            ["tauri", "build"],
        ):
            with self.subTest(arguments=arguments):
                with (
                    mock.patch("cpu_router.cargo_wrapper.load_config", return_value=settings),
                    mock.patch(
                        "cpu_router.cargo_wrapper.passthrough",
                        side_effect=SystemExit(0),
                    ) as passthrough,
                    mock.patch("cpu_router.cargo_wrapper.dispatch") as dispatch,
                    mock.patch(
                        "cpu_router.cargo_wrapper.sys.argv", ["cpu-cargo", *arguments]
                    ),
                ):
                    with self.assertRaises(SystemExit):
                        cargo_wrapper.main()
                    passthrough.assert_called_once_with(
                        settings,
                        arguments,
                        "Tauri commands are intentionally excluded from the remote Cargo job protocol",
                    )
                    dispatch.assert_not_called()

    def test_target_selection_is_explicit(self):
        architecture, arguments, target = cargo_wrapper.requested_architecture(
            ["--target", "aarch64-unknown-linux-gnu", "--release"]
        )
        self.assertEqual(
            (architecture, arguments, target),
            ("aarch64", ["--release"], "aarch64-unknown-linux-gnu"),
        )
        with self.assertRaises(ValueError):
            cargo_wrapper.requested_architecture(["--target", "wasm32-unknown-unknown"])

    def test_artifact_promotion_checks_digest_and_elf_machine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = bytearray(64)
            data[:4] = b"\x7fELF"
            data[18:20] = (62).to_bytes(2, "little")
            compressed = gzip.compress(bytes(data), mtime=0)
            artifact = {
                "name": "fixture",
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "gzip_bytes": len(compressed),
                "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
                "gzip_b64": base64.b64encode(compressed).decode(),
                "elf_machine": 62,
            }
            output = cargo_wrapper.promote_artifact(root, artifact, "x86_64", None)
            self.assertEqual(output.read_bytes(), data)
            artifact["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                cargo_wrapper.promote_artifact(root, artifact, "x86_64", None)

    def test_client_accepts_expected_worker_module_digest_and_quarantines_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = config.Node(
                architecture="x86_64",
                node="owner",
                host="example.invalid",
                port=22,
                user="builder",
                identity_file=root / "key",
                known_hosts_file=root / "known-hosts",
                toolchain="pinned",
                expected_worker_sha256="a" * 64,
            )
            settings = config.Config(
                receipt_dir=root / "receipts",
                real_cargo=root / "cargo",
                nodes={"x86_64": node},
            )

            def submit(_command, *, input, **_kwargs):
                response = {
                    "status": "ok",
                    "architecture": "x86_64",
                    "host": "owner",
                    "request_sha256": hashlib.sha256(input).hexdigest(),
                    "worker_sha256": "b" * 64,
                    "result": {},
                }
                return SimpleNamespace(returncode=0, stdout=json.dumps(response).encode())

            with (
                mock.patch("cpu_router.client.local_node", return_value="client"),
                mock.patch("cpu_router.client.subprocess.run", side_effect=submit),
            ):
                rejected, _, _ = client.dispatch(settings, "x86_64", "health", None)
                self.assertEqual(rejected["status"], "quarantined")
                self.assertEqual(rejected["error"], "worker source mismatch")
                accepted_settings = config.Config(
                    receipt_dir=root / "receipts",
                    real_cargo=root / "cargo",
                    nodes={
                        "x86_64": replace(node, expected_worker_sha256="b" * 64)
                    },
                )
                accepted, _, _ = client.dispatch(
                    accepted_settings, "x86_64", "health", None
                )
                self.assertEqual(
                    accepted["status"],
                    "verified-transport-identity-and-worker-module",
                )

    def test_cargo_wrapper_accepts_verified_worker_module_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = config.Node(
                architecture="x86_64",
                node="owner",
                host="example.invalid",
                port=22,
                user="builder",
                identity_file=root / "key",
                known_hosts_file=root / "known-hosts",
                toolchain="pinned",
                expected_worker_sha256="a" * 64,
            )
            settings = config.Config(
                receipt_dir=root / "receipts",
                real_cargo=root / "cargo",
                nodes={"x86_64": node},
            )
            source = SimpleNamespace(
                manifest=[{"path": "Cargo.toml"}],
                manifest_sha256="b" * 64,
                archive_sha256="c" * 64,
                envelope=lambda: {"snapshot": True},
            )
            receipt = {
                "status": "verified-transport-identity-and-worker-module"
            }
            response = {
                "result": {
                    "manifest_sha256": source.manifest_sha256,
                    "archive_sha256": source.archive_sha256,
                    "stdout_tail": "",
                    "stderr_tail": "",
                }
            }
            git_root = SimpleNamespace(returncode=0, stdout=str(root))
            with (
                mock.patch("cpu_router.cargo_wrapper.load_config", return_value=settings),
                mock.patch("cpu_router.cargo_wrapper.local_node", return_value="client"),
                mock.patch("cpu_router.cargo_wrapper.git_snapshot", return_value=source),
                mock.patch("cpu_router.cargo_wrapper.dispatch", return_value=(receipt, response, root / "receipt.json")),
                mock.patch("cpu_router.cargo_wrapper.subprocess.run", return_value=git_root),
                mock.patch("cpu_router.cargo_wrapper.sys.argv", ["cpu-cargo", "check"]),
            ):
                self.assertEqual(cargo_wrapper.main(), 0)


class WorkerAndAgentTests(unittest.TestCase):
    def test_health_is_bound_to_configured_owner(self):
        request = {
            "schema": "cpu-router/request-v1",
            "idempotency_key": "00000000-0000-4000-8000-000000000000",
            "task": "health",
            "architecture": "x86_64",
            "value": None,
        }
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CPU_ROUTER_NODE": "owner",
                    "CPU_ROUTER_ARCH": "x86_64",
                    "CPU_ROUTER_TOOLCHAIN": "pinned",
                },
                clear=False,
            ),
            mock.patch("cpu_router.worker.platform.machine", return_value="x86_64"),
        ):
            result = worker.execute(request)
        self.assertEqual(result["node"], "owner")

    def test_agent_replays_same_request_and_rejects_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            server = agent.Agent(state, 1)
            request = {
                "schema": "cpu-router/request-v1",
                "idempotency_key": "00000000-0000-4000-8000-000000000000",
                "task": "health",
                "architecture": "x86_64",
                "value": None,
            }
            raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()

            class FakeProcess:
                returncode = 0

                def communicate(self, _raw, timeout):
                    return b'{"status":"ok","result":{"value":1}}', b""

            with mock.patch(
                "cpu_router.agent.subprocess.Popen", return_value=FakeProcess()
            ):
                first = server.execute(raw)
            replay = server.execute(raw)
            self.assertEqual(first["result"], replay["result"])
            self.assertTrue(replay["agent_replayed"])
            request["value"] = {"changed": True}
            changed = json.dumps(
                request, sort_keys=True, separators=(",", ":")
            ).encode()
            self.assertEqual(
                server.execute(changed)["error"], "idempotency key collision"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

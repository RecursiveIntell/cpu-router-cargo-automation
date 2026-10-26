"""Synthetic disposable fixtures for the assigned review findings; no endpoints."""

from contextlib import ExitStack
import json
import os
import random
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from cpu_router import agent, cargo_wrapper, client, config, snapshot, worker
from cpu_router.protocol import canonical_json

KEY = "00000000-0000-4000-8000-000000000000"


def settings(root):
    node = config.Node(
        "x86_64",
        "synthetic-owner",
        "example.invalid",
        22,
        "synthetic-user",
        root / "key",
        root / "pins",
        "synthetic",
        "a" * 64,
    )
    return config.Config(
        root.parent / "synthetic-receipts", root / "cargo", {"x86_64": node}
    )


class ReviewRegressions(unittest.TestCase):
    def wrapper(
        self, root, *, cwd=None, receipt_dir=None, changed=False, action="check"
    ):
        cfg = settings(root)
        if receipt_dir is not None:
            cfg = config.Config(receipt_dir, cfg.real_cargo, cfg.nodes)
        source = SimpleNamespace(
            manifest=[],
            manifest_sha256="a" * 64,
            archive_sha256="b" * 64,
            envelope=lambda: {},
        )
        after = (
            SimpleNamespace(manifest_sha256="c" * 64, archive_sha256="d" * 64)
            if changed
            else source
        )
        response = {
            "result": {
                "manifest_sha256": source.manifest_sha256,
                "archive_sha256": source.archive_sha256,
            }
        }
        args = ["cpu-cargo", action] + (
            ["--release", "--bin", "fixture"] if action == "build" else []
        )
        with ExitStack() as stack:
            for target, kwargs in [
                ("load_config", dict(return_value=cfg)),
                (
                    "requested_architecture",
                    dict(return_value=("x86_64", args[2:], None)),
                ),
                ("local_node", dict(return_value="synthetic-client")),
                (
                    "subprocess.run",
                    dict(return_value=SimpleNamespace(returncode=0, stdout=str(root))),
                ),
                ("git_snapshot", dict(side_effect=[source, after])),
                ("sys.argv", dict(new=args)),
                ("Path.cwd", dict(return_value=cwd or root)),
            ]:
                stack.enter_context(
                    mock.patch("cpu_router.cargo_wrapper." + target, **kwargs)
                )
            stack.enter_context(mock.patch.dict(os.environ, {"CPU_ROUTER_LOCAL": "0"}))
            dispatch = stack.enter_context(
                mock.patch(
                    "cpu_router.cargo_wrapper.dispatch",
                    return_value=(
                        {"status": "verified-transport-identity-and-worker-module"},
                        response,
                        root.parent / "receipt.json",
                    ),
                )
            )
            promotion = stack.enter_context(
                mock.patch("cpu_router.cargo_wrapper.promote_artifact")
            )
            result = cargo_wrapper.main()
            return result, dispatch.call_count, promotion.call_count

    def test_63_nonroot_rejected_before_dispatch(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            member = root / "member"
            member.mkdir()
            self.assertEqual(self.wrapper(root, cwd=member)[:2], (1, 0))

    def test_69_changed_source_not_promoted(self):
        with tempfile.TemporaryDirectory() as d:
            result, _, promoted = self.wrapper(Path(d), changed=True, action="build")
            self.assertEqual(result, 1)
            self.assertEqual(promoted, 0)

    def test_7A_native_architecture(self):
        for native, expected in [
            ("aarch64", "aarch64"),
            ("arm64", "aarch64"),
            ("x86_64", "x86_64"),
        ]:
            with (
                self.subTest(native=native),
                mock.patch("platform.machine", return_value=native),
            ):
                self.assertEqual(
                    cargo_wrapper.requested_architecture([]), (expected, [], None)
                )

    def test_7F_receipts_inside_root_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for path in [root, root / "receipts"]:
                with self.subTest(path=path):
                    self.assertEqual(self.wrapper(root, receipt_dir=path)[:2], (1, 0))

    def test_7B_quarantine_health_fails(self):
        with (
            mock.patch(
                "cpu_router.client.sys.argv",
                ["cpu-router", "--arch", "x86_64", "health"],
            ),
            mock.patch("cpu_router.client.load_config"),
            mock.patch(
                "cpu_router.client.dispatch",
                return_value=(
                    {"status": "quarantined"},
                    {"status": "ok"},
                    Path("synthetic-receipt"),
                ),
            ),
        ):
            self.assertNotEqual(client.main(), 0)

    def test_7C_nonobject_responses_write_failed_receipts(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = settings(root)
            cfg = config.Config(root / "receipts", cfg.real_cargo, cfg.nodes)
            for value in [
                [],
                ["x"],
                None,
                1,
                "text",
                {"status": "ok", "result": ["bad"]},
            ]:
                with (
                    self.subTest(value=value),
                    mock.patch(
                        "cpu_router.client.local_node", return_value="synthetic-client"
                    ),
                    mock.patch(
                        "cpu_router.client.subprocess.run",
                        return_value=SimpleNamespace(
                            returncode=0, stdout=json.dumps(value).encode()
                        ),
                    ),
                ):
                    receipt, response, path = client.dispatch(
                        cfg, "x86_64", "health", None
                    )
                    self.assertIn(receipt["status"], {"failed", "quarantined"})
                    self.assertTrue(path.is_file())
                    self.assertEqual(
                        json.loads(path.read_text())["status"], receipt["status"]
                    )

    def test_7D_dedicated_trust_anchor(self):
        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch("cpu_router.client.local_node", return_value="synthetic-client"),
        ):
            command = client.submit_command(settings(Path(d)).nodes["x86_64"])
            self.assertIn("GlobalKnownHostsFile=/dev/null", command)
            self.assertIn("StrictHostKeyChecking=yes", command)

    def test_7E_complete_request_bounded_before_transport(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = settings(root)
            cfg = config.Config(root / "receipts", cfg.real_cargo, cfg.nodes)
            # Synthetic envelope: archive payload is within its separate 8 MiB cap;
            # manifest overhead pushes the complete canonical frame over 12 MB.
            value = {
                "snapshot": {
                    "archive_b64": "a" * 11_184_812,
                    "manifest": [{"path": "x" * 512}] * 2000,
                }
            }
            self.assertGreater(len(canonical_json(value)), 12_000_000)
            with mock.patch(
                "cpu_router.client.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=2, stdout=b'{"status":"rejected"}'
                ),
            ) as transport:
                with self.assertRaisesRegex(ValueError, "request.*large|wire.*limit"):
                    client.dispatch(cfg, "x86_64", "cargo-job", value)
                transport.assert_not_called()

    def test_7E_locally_admitted_snapshot_exceeds_complete_frame(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "Cargo.toml").write_text("[workspace]\n")
            (root / "Cargo.lock").write_text("# synthetic\n")
            folder = root / ("a" * 110) / ("b" * 110)
            folder.mkdir(parents=True)
            paths = ["Cargo.toml", "Cargo.lock"]
            for index in range(4994):
                file = folder / (f"{index:04d}-" + "c" * 215)
                file.touch()
                paths.append(file.relative_to(root).as_posix())
            rng = random.Random(0)
            for index in range(4):
                file = root / f"synthetic-{index}.bin"
                file.write_bytes(rng.randbytes(1_950_000))
                paths.append(file.name)
            source = snapshot.create_snapshot_from_paths(root, paths)
            snapshot.validate_envelope(source.envelope())
            self.assertLessEqual(len(source.archive), snapshot.MAX_ARCHIVE_BYTES)
            value = {
                "snapshot": source.envelope(),
                "action": "check",
                "arguments": [],
                "toolchain": "synthetic",
            }
            self.assertGreater(len(canonical_json(value)), 12_000_000)
            cfg = settings(root)
            cfg = config.Config(root / "receipts", cfg.real_cargo, cfg.nodes)
            with mock.patch(
                "cpu_router.client.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=2, stdout=b'{"status":"rejected"}'
                ),
            ) as transport:
                with self.assertRaisesRegex(ValueError, "request.*large|wire.*limit"):
                    client.dispatch(cfg, "x86_64", "cargo-job", value)
                transport.assert_not_called()

    def test_67_parent_swap_cannot_read_outside_root(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root = base / "root"
            root.mkdir()
            parent = root / "parent"
            parent.mkdir()
            (parent / "value").write_bytes(b"admitted")
            outside = base / "outside"
            outside.mkdir()
            (outside / "value").write_bytes(b"outside")
            real_open = os.open
            swapped = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if Path(path).name == "value" and not swapped:
                    swapped = True
                    parent.rename(root / "moved")
                    parent.symlink_to(outside, target_is_directory=True)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch("cpu_router.snapshot.os.open", side_effect=racing_open):
                try:
                    data, _ = snapshot.read_regular_file_no_follow(
                        root, PurePosixPath("parent/value")
                    )
                except ValueError:
                    pass
                else:
                    self.assertEqual(data, b"admitted")
            self.assertTrue(swapped)

    def test_68_inflight_collision_and_atomic_lock(self):
        with tempfile.TemporaryDirectory() as d:
            server = agent.Agent(Path(d), 2)
            raw = canonical_json({"idempotency_key": KEY, "value": None})
            entered = threading.Event()
            release = threading.Event()
            results = []

            class Process:
                returncode = 0

                def communicate(self, _raw, timeout):
                    entered.set()
                    release.wait(3)
                    return b'{"status":"ok"}', b""

            with mock.patch(
                "cpu_router.agent.subprocess.Popen", return_value=Process()
            ):
                thread = threading.Thread(
                    target=lambda: results.append(server.execute(raw))
                )
                thread.start()
                try:
                    self.assertTrue(entered.wait(2))
                    self.assertEqual(server.execute(raw)["status"], "in-progress")
                    changed = canonical_json(
                        {"idempotency_key": KEY, "value": "changed"}
                    )
                    self.assertEqual(server.execute(changed)["status"], "rejected")
                finally:
                    release.set()
                    thread.join(3)
            self.assertFalse(thread.is_alive())

    def test_65_metadata_and_job_timeout_kill_descendants(self):
        for stage in ["metadata", "check"]:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                tc = root / ".rustup/toolchains/synthetic/bin"
                tc.mkdir(parents=True)
                (tc / "rustc").touch()
                cargo = tc / "cargo"
                pidfile = root / "child.pid"
                cargo.write_text(
                    "#!"
                    + sys.executable
                    + "\nimport subprocess,sys,time\n"
                    + f"if sys.argv[1] == {stage!r}:\n"
                    + ' p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"])\n'
                    + f' open({str(pidfile)!r},"w").write(str(p.pid))\n'
                    + " time.sleep(60)\nelse:\n print('{\"workspace_members\":[]}')\n"
                )
                cargo.chmod(0o755)
                source = root / "fixture"
                source.mkdir()
                (source / "Cargo.toml").write_text("[workspace]\n")
                (source / "Cargo.lock").write_text("# synthetic\n")
                snap = snapshot.create_snapshot_from_paths(
                    source, ["Cargo.toml", "Cargo.lock"]
                )
                value = {
                    "snapshot": snap.envelope(),
                    "action": "check",
                    "arguments": [],
                    "toolchain": "synthetic",
                }
                real_popen = subprocess.Popen

                class BoundedProcess(real_popen):
                    def communicate(self, *args, timeout=None, **kwargs):
                        return super().communicate(
                            *args,
                            timeout=min(timeout, 0.5) if timeout else timeout,
                            **kwargs,
                        )

                try:
                    with (
                        mock.patch("cpu_router.worker.Path.home", return_value=root),
                        mock.patch(
                            "cpu_router.worker.configured_runtime",
                            return_value=("synthetic-owner", "x86_64", "synthetic"),
                        ),
                        mock.patch(
                            "cpu_router.worker.platform.machine", return_value="x86_64"
                        ),
                        mock.patch("subprocess.Popen", BoundedProcess),
                    ):
                        with self.assertRaises(subprocess.TimeoutExpired):
                            worker.cargo_job(value, "x86_64")
                    self.assertTrue(pidfile.exists())
                    pid = int(pidfile.read_text())
                    alive = True
                    for _ in range(20):
                        try:
                            state = Path(f"/proc/{pid}/stat").read_text().split()[2]
                            alive = state != "Z"
                        except FileNotFoundError:
                            alive = False
                        if not alive:
                            break
                        time.sleep(0.025)
                    self.assertFalse(alive, "Cargo descendant survived timeout")
                finally:
                    if pidfile.exists():
                        try:
                            os.kill(int(pidfile.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()

"""Vendored-dependency admission (B): tests.

Measured failure (receipts-v2): owner-side builds with registry dependencies fail with
``failed to download aho-corasick`` because the owner has no crates.io route. The worker already runs
cargo with CARGO_NET_OFFLINE=true, so a vendored source tree is the only way an owner can build.

These tests check that vendored sources are admitted like siblings: explicitly declared, pinned by
digest, and refused on mismatch. They cover the admission side; the owner config test is in
test_contracts.py alongside the other worker contract checks.
"""

import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cpu_router import snapshot as snap


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def _app_with_vendor(parent: Path) -> tuple[Path, Path]:
    app = parent / "app"
    (app / "src").mkdir(parents=True)
    (app / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n'
        '[dependencies]\nleft-pad = "1"\n'
    )
    (app / "Cargo.lock").write_text("version = 3\n")
    (app / "src" / "main.rs").write_text("fn main() {}\n")
    _git(app, "init", "-q")
    _git(app, "add", ".")
    _git(app, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "init")
    vendor = parent / "vendor-src"
    (vendor / "left-pad-1.0.0" / "src").mkdir(parents=True)
    (vendor / "left-pad-1.0.0" / "Cargo.toml").write_text(
        '[package]\nname = "left-pad"\nversion = "1.0.0"\nedition = "2021"\n'
    )
    (vendor / "left-pad-1.0.0" / "src" / "lib.rs").write_text("pub fn pad() {}\n")
    return app, vendor


class VendorAdmissionTests(unittest.TestCase):
    def test_registry_dependencies_are_absent_from_a_plain_snapshot(self):
        """The measured defect: nothing carries the vendored sources the offline owner needs."""
        with tempfile.TemporaryDirectory() as tmp:
            app, _vendor = _app_with_vendor(Path(tmp))
            carried = {entry["path"] for entry in snap.git_snapshot(app).manifest}
            self.assertFalse(any(p.startswith("_vendor/") for p in carried))

    def test_pinned_vendor_tree_is_admitted_under_vendor_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, vendor = _app_with_vendor(Path(tmp))
            files = ["left-pad-1.0.0/Cargo.toml", "left-pad-1.0.0/src/lib.rs"]
            pin = snap.sibling_tree_digest(vendor, files)
            built = snap.build_vendor_snapshot(app, {"root": str(vendor), "files": files, "tree_sha256": pin})
            carried = {entry["path"] for entry in built.manifest}
            self.assertIn("_vendor/left-pad-1.0.0/Cargo.toml", carried)
            self.assertIn("_vendor/left-pad-1.0.0/src/lib.rs", carried)

    def test_vendor_tree_with_wrong_pin_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, vendor = _app_with_vendor(Path(tmp))
            files = ["left-pad-1.0.0/Cargo.toml", "left-pad-1.0.0/src/lib.rs"]
            with self.assertRaisesRegex(ValueError, "tree digest does not match"):
                snap.build_vendor_snapshot(app, {"root": str(vendor), "files": files, "tree_sha256": "0" * 64})

    def test_archive_uses_the_same_read_as_the_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, source = _app_with_vendor(Path(tmp))
            relative = "left-pad-1.0.0/src/lib.rs"
            original = (source / relative).read_bytes()
            spec = {"root": source, "files": [relative], "tree_sha256": snap.sibling_tree_digest(source, [relative])}
            read = snap.read_regular_file_no_follow

            def mutate_after_read(root, path):
                data, metadata = read(root, path)
                if root == source:
                    (source / relative).write_bytes(b"modified after read")
                return data, metadata

            with patch.object(snap, "read_regular_file_no_follow", side_effect=mutate_after_read):
                built = snap.build_vendor_snapshot(app, spec)
            with tarfile.open(fileobj=io.BytesIO(built.archive), mode="r:gz") as archive:
                member = archive.extractfile("_vendor/left-pad-1.0.0/src/lib.rs")
                self.assertIsNotNone(member)
                self.assertEqual(member.read(), original)

    def test_application_path_collision_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, source = _app_with_vendor(Path(tmp))
            relative = "left-pad-1.0.0/src/lib.rs"
            spec = {"root": source, "files": [relative], "tree_sha256": snap.sibling_tree_digest(source, [relative])}
            collision = app / "_vendor/left-pad-1.0.0/src/lib.rs"
            collision.parent.mkdir(parents=True)
            collision.write_bytes(b"application file")
            with self.assertRaisesRegex(ValueError, "source path collision"):
                snap.build_vendor_snapshot(app, spec)

    def test_vendor_must_be_declared_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, vendor = _app_with_vendor(Path(tmp))
            with self.assertRaisesRegex(ValueError, "must declare root, files, and tree_sha256"):
                snap.build_vendor_snapshot(app, {"root": str(vendor)})


if __name__ == "__main__":
    unittest.main()

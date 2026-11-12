"""Sibling path-dependency admission (B+A): behavioral tests.

Measured failure (receipts-v2): a remote Cargo job whose manifest declares ``path = "../X"`` fails on
the owner with ``failed to load source for dependency``, because the snapshot is built from a single
git worktree and never carries ``../X``. These tests exercise the admission contract directly.
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


def _workspace(parent: Path) -> tuple[Path, Path]:
    """An app repo at parent/app whose Cargo.toml depends on parent/Libraries/helper (out of root)."""
    sibling = parent / "Libraries" / "helper"
    (sibling / "src").mkdir(parents=True)
    (sibling / "Cargo.toml").write_text(
        '[package]\nname = "helper"\nversion = "0.1.0"\nedition = "2021"\n'
    )
    (sibling / "src" / "lib.rs").write_text("pub fn ok() {}\n")
    app = parent / "app"
    (app / "src").mkdir(parents=True)
    (app / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n'
        '[dependencies]\nhelper = { path = "../Libraries/helper" }\n'
    )
    (app / "Cargo.lock").write_text("version = 3\n")
    (app / "src" / "main.rs").write_text("fn main() {}\n")
    _git(app, "init", "-q")
    _git(app, "add", ".")
    _git(app, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "init")
    return app, sibling


def _pin(sibling: Path, files: list[str]) -> str:
    return snap.sibling_tree_digest(sibling, files)


class SiblingAdmissionTests(unittest.TestCase):
    def test_plain_git_snapshot_does_not_carry_the_out_of_root_sibling(self):
        """The measured defect: the git snapshot silently lacks the sibling the manifest needs."""
        with tempfile.TemporaryDirectory() as tmp:
            app, _sibling = _workspace(Path(tmp))
            carried = {entry["path"] for entry in snap.git_snapshot(app).manifest}
            self.assertFalse(any(p.startswith("_siblings/") for p in carried))
            self.assertNotIn("Libraries/helper/Cargo.toml", carried)

    def test_pinned_sibling_is_admitted_under_its_own_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, sibling = _workspace(Path(tmp))
            files = ["Cargo.toml", "src/lib.rs"]
            built = snap.build_snapshot_with_siblings(
                app,
                {"helper": {"root": str(sibling), "files": files, "tree_sha256": _pin(sibling, files)}},
            )
            carried = {entry["path"] for entry in built.manifest}
            self.assertIn("_siblings/helper/Cargo.toml", carried)
            self.assertIn("_siblings/helper/src/lib.rs", carried)
            self.assertIn("Cargo.toml", carried)

    def test_sibling_with_wrong_pin_is_refused(self):
        """Negative witness: a tampered or mis-pinned sibling must not be silently carried."""
        with tempfile.TemporaryDirectory() as tmp:
            app, sibling = _workspace(Path(tmp))
            files = ["Cargo.toml", "src/lib.rs"]
            with self.assertRaisesRegex(ValueError, "tree digest does not match"):
                snap.build_snapshot_with_siblings(
                    app,
                    {"helper": {"root": str(sibling), "files": files, "tree_sha256": "0" * 64}},
                )

    def test_tampering_a_pinned_sibling_file_changes_the_refusal(self):
        """A file edited after pinning is refused: the pin binds the bytes, not the path."""
        with tempfile.TemporaryDirectory() as tmp:
            app, sibling = _workspace(Path(tmp))
            files = ["Cargo.toml", "src/lib.rs"]
            pin = _pin(sibling, files)
            (sibling / "src" / "lib.rs").write_text("pub fn evil() {}\n")
            with self.assertRaisesRegex(ValueError, "tree digest does not match"):
                snap.build_snapshot_with_siblings(
                    app, {"helper": {"root": str(sibling), "files": files, "tree_sha256": pin}}
                )

    def test_archive_uses_the_same_read_as_the_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, source = _workspace(Path(tmp))
            relative = "src/lib.rs"
            original = (source / relative).read_bytes()
            spec = {"root": source, "files": [relative], "tree_sha256": snap.sibling_tree_digest(source, [relative])}
            read = snap.read_regular_file_no_follow

            def mutate_after_read(root, path):
                data, metadata = read(root, path)
                if root == source:
                    (source / relative).write_bytes(b"modified after read")
                return data, metadata

            with patch.object(snap, "read_regular_file_no_follow", side_effect=mutate_after_read):
                built = snap.build_snapshot_with_siblings(app, {"helper": spec})
            with tarfile.open(fileobj=io.BytesIO(built.archive), mode="r:gz") as archive:
                member = archive.extractfile("_siblings/helper/src/lib.rs")
                self.assertIsNotNone(member)
                self.assertEqual(member.read(), original)

    def test_application_path_collision_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, source = _workspace(Path(tmp))
            relative = "src/lib.rs"
            spec = {"root": source, "files": [relative], "tree_sha256": snap.sibling_tree_digest(source, [relative])}
            collision = app / "_siblings/helper/src/lib.rs"
            collision.parent.mkdir(parents=True)
            collision.write_bytes(b"application file")
            with self.assertRaisesRegex(ValueError, "source path collision"):
                snap.build_snapshot_with_siblings(app, {"helper": spec})

    def test_sibling_name_and_spec_are_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, sibling = _workspace(Path(tmp))
            with self.assertRaisesRegex(ValueError, "invalid sibling name"):
                snap.build_snapshot_with_siblings(
                    app, {"../escape": {"root": str(sibling), "files": ["Cargo.toml"], "tree_sha256": "0" * 64}}
                )
            with self.assertRaisesRegex(ValueError, "must declare root, files, and tree_sha256"):
                snap.build_snapshot_with_siblings(app, {"helper": {"root": str(sibling)}})


if __name__ == "__main__":
    unittest.main()

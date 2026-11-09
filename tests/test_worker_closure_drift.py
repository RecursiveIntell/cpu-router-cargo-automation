"""Worker drift check must cover the worker's execution closure, not only worker.py.

Measured gap: worker.py imports snapshot.py, so a change to snapshot.py changes what an owner
executes while worker.py's own hash stays identical. The drift pin must therefore cover every module
the worker imports from this package.
"""

import unittest
from pathlib import Path

from cpu_router import worker

PKG = Path(worker.__file__).resolve().parent


class WorkerClosureDriftTests(unittest.TestCase):
    def test_pin_changes_when_an_imported_module_changes(self):
        """RED: today the digest is worker.py-only, so a snapshot.py change leaves it unchanged."""
        before = worker.worker_sha256()
        target = PKG / "snapshot.py"
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"\n# drift probe\n")
            after = worker.worker_sha256()
        finally:
            target.write_bytes(original)
        self.assertNotEqual(
            before,
            after,
            "worker_sha256 must change when an imported module changes; it is worker.py-only today",
        )

    def test_closure_includes_every_package_module_the_worker_imports(self):
        closure = {p.name for p in worker.worker_closure_files()}
        self.assertIn("worker.py", closure)
        self.assertIn("snapshot.py", closure)
        self.assertIn("protocol.py", closure)


if __name__ == "__main__":
    unittest.main()

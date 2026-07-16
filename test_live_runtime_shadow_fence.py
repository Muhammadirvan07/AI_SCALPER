from __future__ import annotations

from multiprocessing import get_context
from pathlib import Path
import tempfile
import unittest

from live_runtime.shadow_fence import ShadowCycleAlreadyRunning, ShadowCycleFence


def _try_child_fence(root: str, contract_id: str, queue) -> None:
    try:
        with ShadowCycleFence(root, contract_id):
            queue.put("ACQUIRED")
    except ShadowCycleAlreadyRunning:
        queue.put("BUSY")


class ShadowCycleFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.contract_id = "contract-shadow-fence"
        (self.root / "forward" / self.contract_id).mkdir(parents=True)

    def test_same_process_contention_is_nonblocking_and_release_is_reusable(self):
        first = ShadowCycleFence(self.root, self.contract_id)
        second = ShadowCycleFence(self.root, self.contract_id)
        first.acquire()
        with self.assertRaisesRegex(
            ShadowCycleAlreadyRunning,
            "already owns",
        ):
            second.acquire()
        first.close()
        with second:
            self.assertTrue(
                (
                    self.root
                    / "forward"
                    / self.contract_id
                    / ".shadow-cycle.lock"
                ).is_file()
            )

    @unittest.skipIf(
        __import__("os").name == "nt",
        "fork-based cross-process drill runs on the development host",
    )
    def test_second_process_observes_busy_without_deleting_persistent_lock(self):
        context = get_context("fork")
        queue = context.Queue()
        with ShadowCycleFence(self.root, self.contract_id):
            process = context.Process(
                target=_try_child_fence,
                args=(str(self.root), self.contract_id, queue),
            )
            process.start()
            process.join(timeout=5)
            self.assertFalse(process.is_alive())
            self.assertEqual("BUSY", queue.get(timeout=1))
        process = context.Process(
            target=_try_child_fence,
            args=(str(self.root), self.contract_id, queue),
        )
        process.start()
        process.join(timeout=5)
        self.assertFalse(process.is_alive())
        self.assertEqual("ACQUIRED", queue.get(timeout=1))

    def test_missing_contract_or_symlink_fails_closed(self):
        with self.assertRaisesRegex(ShadowCycleAlreadyRunning, "unavailable"):
            ShadowCycleFence(self.root, "missing")

        target = self.root / "real"
        target.mkdir()
        alias = self.root / "forward" / "alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        with self.assertRaisesRegex(ShadowCycleAlreadyRunning, "symlink"):
            ShadowCycleFence(self.root, "alias")


if __name__ == "__main__":
    unittest.main()

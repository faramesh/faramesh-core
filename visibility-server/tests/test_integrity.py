from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TEST_ROOT = Path(__file__).resolve().parents[1]
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

from app.integrity import run_integrity_check


class IntegrityTests(unittest.TestCase):
    def test_integrity_check_reports_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "faramesh.db"
            db_path.write_text("", encoding="utf-8")
            result = run_integrity_check(
                command_template=["sh", "-c", "exit 0"],
                db_path=db_path,
                cwd=Path(tmp),
                timeout_seconds=5,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["exit_code"], 0)

    def test_integrity_check_reports_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "faramesh.db"
            db_path.write_text("", encoding="utf-8")
            result = run_integrity_check(
                command_template=["sh", "-c", "exit 1"],
                db_path=db_path,
                cwd=Path(tmp),
                timeout_seconds=5,
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()

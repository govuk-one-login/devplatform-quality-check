import unittest
from pathlib import Path

from helpers import run_check

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHECK_ID = "GDS_DEVPLATFORM_001"


class TestIAMPassRoleWildcard(unittest.TestCase):
    def test_fail(self):
        passed, failed = run_check(FIXTURES / "fail.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_pass(self):
        passed, failed = run_check(FIXTURES / "pass.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)


if __name__ == "__main__":
    unittest.main()

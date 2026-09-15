import unittest
from pathlib import Path

from conftest import run_check

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHECK_ID = "GDS_DEVPLATFORM_002"


class TestIAMPrincipleCreation(unittest.TestCase):
    def test_fail_create_user(self):
        passed, failed = run_check(FIXTURES / "fail_create_user.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_fail_create_role(self):
        passed, failed = run_check(FIXTURES / "fail_create_role.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_fail_multiple_statements(self):
        passed, failed = run_check(FIXTURES / "fail_multiple_statements.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_fail_mixed_actions(self):
        passed, failed = run_check(FIXTURES / "fail_mixed_actions.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_fail_create_wildcard_role(self):
        passed, failed = run_check(
            FIXTURES / "fail_create_wildcard_role.yaml", CHECK_ID
        )
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_pass_unrelated_action(self):
        passed, failed = run_check(FIXTURES / "pass_unrelated_action.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)

    def test_pass_deny(self):
        passed, failed = run_check(FIXTURES / "pass_deny.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)


if __name__ == "__main__":
    unittest.main()

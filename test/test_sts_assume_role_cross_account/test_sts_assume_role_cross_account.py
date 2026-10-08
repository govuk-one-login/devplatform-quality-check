import unittest
from pathlib import Path

from conftest import run_check

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHECK_ID = "GDS_DEVPLATFORM_004"


class TestSTSAssumeRoleCrossAccount(unittest.TestCase):
    def test_pass_principal_org_id(self):
        passed, failed = run_check(
            FIXTURES / "pass_trust_policy_principal_org_id.yaml", CHECK_ID
        )
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)

    def test_pass_service_principal_not_applicable(self):
        passed, failed = run_check(FIXTURES / "pass_service_principal.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)

    def test_pass_same_account_no_condition(self):
        passed, failed = run_check(
            FIXTURES / "pass_same_account_no_condition.yaml", CHECK_ID
        )
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)

    def test_fail_no_principal_org_id(self):
        passed, failed = run_check(FIXTURES / "fail_no_principal_org_id.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_fail_bare_root_no_org_id(self):
        passed, failed = run_check(FIXTURES / "fail_bare_root_no_org_id.yaml", CHECK_ID)
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_pass_policy_specific_role_arn(self):
        passed, failed = run_check(
            FIXTURES / "pass_policy_specific_role_arn.yaml", CHECK_ID
        )
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)

    def test_pass_policy_cross_account_role_arn(self):
        passed, failed = run_check(
            FIXTURES / "pass_policy_cross_account_role_arn.yaml", CHECK_ID
        )
        self.assertIn(CHECK_ID, passed)
        self.assertNotIn(CHECK_ID, failed)

    def test_fail_policy_wildcard_resource(self):
        passed, failed = run_check(
            FIXTURES / "fail_policy_wildcard_resource.yaml", CHECK_ID
        )
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)

    def test_fail_policy_account_wildcard_arn(self):
        passed, failed = run_check(
            FIXTURES / "fail_policy_account_wildcard_arn.yaml", CHECK_ID
        )
        self.assertIn(CHECK_ID, failed)
        self.assertNotIn(CHECK_ID, passed)


if __name__ == "__main__":
    unittest.main()

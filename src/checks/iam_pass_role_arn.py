from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult
from helpers import get_policy_documents

PASS_ROLE_ACTIONS = {"iam:PassRole", "iam:*", "*"}


class IAMPassRoleArn(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure iam:PassRole is only granted on resources within the deployed AWS account",
            id="GDS_DEVPLATFORM_001",
            categories=[CheckCategories.IAM],
            supported_resources=[
                "AWS::IAM::ManagedPolicy",
                "AWS::IAM::Policy",
                "AWS::IAM::Role",
            ],
        )

    def scan_resource_conf(self, conf):
        for doc in get_policy_documents(conf):
            for statement in doc.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue

                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                if not any(a in PASS_ROLE_ACTIONS for a in actions):
                    continue

                resources = statement.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                if not all(
                    r.startswith("arn:") and "${AWS::AccountId}" in r for r in resources
                ):
                    return CheckResult.FAILED

        return CheckResult.PASSED


check = IAMPassRoleArn()

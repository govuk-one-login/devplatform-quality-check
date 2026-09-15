from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult
from helpers import get_policy_documents

PRINCIPAL_CREATION_ACTIONS = {"iam:CreateUser", "iam:CreateRole", "iam:*", "*"}


class IAMPrincipleCreation(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure IAM policies do not grant principal creation actions",
            id="GDS_DEVPLATFORM_002",
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

                if any(a in PRINCIPAL_CREATION_ACTIONS for a in actions):
                    return CheckResult.FAILED

        return CheckResult.PASSED


check = IAMPrincipleCreation()

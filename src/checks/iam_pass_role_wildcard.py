import json

from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

PASS_ROLE_ACTIONS = {"iam:passrole", "iam:*", "*"}


class IAMPassRoleWildcard(BaseResourceCheck):
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
        properties = conf.get("Properties", {})

        policy_documents = []

        # AWS::IAM::ManagedPolicy and AWS::IAM::Policy
        if "PolicyDocument" in properties:
            policy_documents.append(properties["PolicyDocument"])

        # AWS::IAM::Role inline policies
        for inline in properties.get("Policies", []):
            doc = inline.get("PolicyDocument")
            if doc:
                policy_documents.append(doc)

        for doc in policy_documents:
            if isinstance(doc, str):
                try:
                    doc = json.loads(doc)
                except (json.JSONDecodeError, TypeError):
                    continue

            for statement in doc.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue

                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                if not any(a.lower() in PASS_ROLE_ACTIONS for a in actions):
                    continue

                resources = statement.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                if not all(
                    r.startswith("arn:") and "${AWS::AccountId}" in r for r in resources
                ):
                    return CheckResult.FAILED

        return CheckResult.PASSED


check = IAMPassRoleWildcard()

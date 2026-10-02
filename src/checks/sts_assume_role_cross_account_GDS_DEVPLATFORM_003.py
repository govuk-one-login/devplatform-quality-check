from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult
from helpers import matches_with_wildcard

ASSUME_ROLE_ACTION = "sts:AssumeRole"
PRINCIPAL_ORG_ID_KEY = "aws:PrincipalOrgID"


def _statements(doc):
    if not isinstance(doc, dict):
        return []
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [s for s in statements if isinstance(s, dict)]


def _actions(statement):
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    return [action for action in actions if isinstance(action, str)]


def _references_own_account(value):
    if isinstance(value, dict):
        if value.get("Ref") == "AWS::AccountId":
            return True
        sub = value.get("Fn::Sub")
        if sub is None:
            return False
        if isinstance(sub, list):
            sub = sub[0] if sub else ""
        return "${AWS::AccountId}" in str(sub)
    return "${AWS::AccountId}" in str(value)


def _trusts_cross_account(statement):
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    aws = principal.get("AWS")
    if aws is None:
        return False
    values = aws if isinstance(aws, list) else [aws]
    if any(value == "*" for value in values):
        return True
    return any(not _references_own_account(value) for value in values)


def _has_principal_org_id(condition):
    if not isinstance(condition, dict):
        return False
    return any(
        isinstance(block, dict) and PRINCIPAL_ORG_ID_KEY in block
        for block in condition.values()
    )


class STSAssumeRoleCrossAccountOrgID(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name=(
                "Ensure cross-account sts:AssumeRole trust policies are scoped to "
                "the organisation with an aws:PrincipalOrgID condition"
            ),
            id="GDS_DEVPLATFORM_003",
            categories=[CheckCategories.IAM],
            supported_resources=["AWS::IAM::Role"],
        )

    def scan_resource_conf(self, conf):
        trust_policy = conf.get("Properties", {}).get("AssumeRolePolicyDocument")

        for statement in _statements(trust_policy):
            if statement.get("Effect") != "Allow":
                continue

            if not any(
                matches_with_wildcard(action, ASSUME_ROLE_ACTION)
                for action in _actions(statement)
            ):
                continue

            if not _trusts_cross_account(statement):
                continue

            if not _has_principal_org_id(statement.get("Condition", {})):
                return CheckResult.FAILED

        return CheckResult.PASSED


check = STSAssumeRoleCrossAccountOrgID()

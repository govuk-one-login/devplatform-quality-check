from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult


class IAMPermissionsBoundary(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure IAM policies have permissions boundary attached",
            id="GDS_DEVPLATFORM_003",
            categories=[CheckCategories.IAM],
            supported_resources=[
                "AWS::IAM::Role",
            ],
        )

    def scan_resource_conf(self, conf):
        properties = conf.get("Properties", {})
        if "PermissionsBoundary" in properties:
            return CheckResult.PASSED
        return CheckResult.FAILED


check = IAMPermissionsBoundary()

import json
<<<<<<< HEAD
import re


def matches_with_wildcard(pattern: str, target: str) -> bool:
    regex = re.escape(pattern).replace(r"\*", ".*")
    return bool(re.fullmatch(regex, target))
=======
>>>>>>> 4419fa6 (PSREDEV-3699: Refactor iam_pass_role_arn for reusability)


def get_policy_documents(conf):
    properties = conf.get("Properties", {})
    docs = []

    # AWS::IAM::ManagedPolicy and AWS::IAM::Policy
    if "PolicyDocument" in properties:
        docs.append(properties["PolicyDocument"])

    # AWS::IAM::Role inline policies
    for inline in properties.get("Policies", []):
        doc = inline.get("PolicyDocument")
        if doc:
            docs.append(doc)

    result = []
    for doc in docs:
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except (json.JSONDecodeError, TypeError):
                continue
        result.append(doc)

    return result
<<<<<<< HEAD


def is_valid_resource(resource):
    if isinstance(resource, dict):
        resource = str(resource.get("Fn::Sub", ""))
        return resource.startswith("arn:") and "${AWS::AccountId}" in resource
    return bool(re.match(r"arn:[^:]+:[^:]+::(\d{12}):", str(resource)))
=======
>>>>>>> 4419fa6 (PSREDEV-3699: Refactor iam_pass_role_arn for reusability)

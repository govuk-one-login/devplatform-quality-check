import json


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

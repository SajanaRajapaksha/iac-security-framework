# =============================================================================
# policies/terraform/compliance.rego
#
# Compliance Policies for Terraform Plan JSON
# Evaluated by Conftest (OPA/Rego)
#
# Policies:
#   CUSTOM_IAM_001 — Block IAM wildcard administrator policy
# =============================================================================

package main

import future.keywords.in

# ---------------------------------------------------------------------------
# CUSTOM_IAM_001 — Block IAM wildcard administrator policy
#
# Detects IAM policies that grant Action:"*" on Resource:"*".
# Handles both inline JSON policy documents and structured policy blocks.
# ---------------------------------------------------------------------------

# Case 1: policy document is a JSON string in the plan
deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_policy"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    policy_json := object.get(after, "policy", "")
    policy_json != ""

    # Attempt to unmarshal the JSON policy document
    doc := json.unmarshal(policy_json)
    statement := doc.Statement[_]

    is_wildcard_action(statement)
    is_wildcard_resource(statement)

    result := {
        "policy_id": "CUSTOM_IAM_001",
        "title": "Block IAM wildcard administrator policy",
        "severity": "CRITICAL",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("IAM policy '%v' contains a statement with Action:'*' and Resource:'*'. This grants full administrative access and violates least privilege.", [rc.address]),
        "compliance": ["Least Privilege", "CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Scope IAM policy actions and resources to the minimum required. Avoid using '*' wildcards.",
    }
}

# Case 2: aws_iam_role_policy (inline policy)
deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_role_policy"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    policy_json := object.get(after, "policy", "")
    policy_json != ""

    doc := json.unmarshal(policy_json)
    statement := doc.Statement[_]

    is_wildcard_action(statement)
    is_wildcard_resource(statement)

    result := {
        "policy_id": "CUSTOM_IAM_001",
        "title": "Block IAM wildcard administrator policy",
        "severity": "CRITICAL",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("IAM role inline policy '%v' contains a statement with Action:'*' and Resource:'*'. This grants full administrative access.", [rc.address]),
        "compliance": ["Least Privilege", "CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Scope IAM policy actions and resources to the minimum required. Avoid using '*' wildcards.",
    }
}

# Case 3: aws_iam_user_policy (inline policy on user)
deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_iam_user_policy"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    policy_json := object.get(after, "policy", "")
    policy_json != ""

    doc := json.unmarshal(policy_json)
    statement := doc.Statement[_]

    is_wildcard_action(statement)
    is_wildcard_resource(statement)

    result := {
        "policy_id": "CUSTOM_IAM_001",
        "title": "Block IAM wildcard administrator policy",
        "severity": "CRITICAL",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("IAM user inline policy '%v' contains a statement with Action:'*' and Resource:'*'. This grants full administrative access.", [rc.address]),
        "compliance": ["Least Privilege", "CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Scope IAM policy actions and resources to the minimum required. Avoid using '*' wildcards.",
    }
}

# ---------------------------------------------------------------------------
# Helpers: wildcard detection
# ---------------------------------------------------------------------------

# Action can be a string or a list
is_wildcard_action(statement) {
    statement.Action == "*"
}

is_wildcard_action(statement) {
    statement.Action[_] == "*"
}

# Resource can be a string or a list
is_wildcard_resource(statement) {
    statement.Resource == "*"
}

is_wildcard_resource(statement) {
    statement.Resource[_] == "*"
}

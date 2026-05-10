# =============================================================================
# policies/terraform/compliance.rego
#
# Compliance Policies for Terraform Source HCL
# Evaluated by Conftest (OPA/Rego)
#
# Policies:
#   CUSTOM_IAM_001 — Block IAM wildcard administrator policy
# =============================================================================

package main

import future.keywords.in

# ---------------------------------------------------------------------------
# Helpers: wildcard detection
# ---------------------------------------------------------------------------

to_array(x) = [x] { not is_array(x) }
to_array(x) = x { is_array(x) }

# Action can be a string or a list
is_wildcard_action(statement) {
    acts := to_array(object.get(statement, "Action", []))
    acts[_] == "*"
}

# Resource can be a string or a list
is_wildcard_resource(statement) {
    res := to_array(object.get(statement, "Resource", []))
    res[_] == "*"
}

# ---------------------------------------------------------------------------
# CUSTOM_IAM_001 — Block IAM wildcard administrator policy
# ---------------------------------------------------------------------------

# Helper to check policy blocks (handles aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy)
deny[result] {
    some type_name
    resources_of_type := input.resource[type_name]
    
    # Target IAM policy resources
    type_name in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
    
    some resource_name
    resource_block := resources_of_type[resource_name]

    policy_json := object.get(resource_block, "policy", "")
    policy_json != ""

    # Attempt to unmarshal the JSON policy document (if it's a string literal in HCL)
    doc := json.unmarshal(policy_json)
    
    statement_list := to_array(object.get(doc, "Statement", []))
    statement := statement_list[_]

    is_wildcard_action(statement)
    is_wildcard_resource(statement)

    result := {
        "policy_id": "CUSTOM_IAM_001",
        "title": "Block IAM wildcard administrator policy",
        "severity": "CRITICAL",
        "resource": sprintf("%v.%v", [type_name, resource_name]),
        "resource_type": type_name,
        "reason": sprintf("IAM policy '%v.%v' contains a statement with Action:'*' and Resource:'*'. This grants full administrative access and violates least privilege.", [type_name, resource_name]),
        "compliance": ["Least Privilege", "CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Scope IAM policy actions and resources to the minimum required. Avoid using '*' wildcards.",
        "input_type": "terraform_source_hcl"
    }
}

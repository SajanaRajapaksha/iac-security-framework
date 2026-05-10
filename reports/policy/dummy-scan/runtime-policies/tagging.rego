# =============================================================================
# policies/terraform/tagging.rego
#
# Tagging Governance Policies for Terraform Source HCL
# Evaluated by Conftest (OPA/Rego)
#
# Policies:
#   CUSTOM_TAG_001 — Require Environment tag
#   CUSTOM_TAG_002 — Require Owner tag
# =============================================================================

package main

import future.keywords.in

# ---------------------------------------------------------------------------
# Helper: check if tags contain a specific key
# ---------------------------------------------------------------------------

has_tag(tags, key) {
    tags != null
    _ = tags[key]
}

# Helper: safely get tags from the resource block
get_tags(resource_block) = tags {
    tags := object.get(resource_block, "tags", null)
    tags != null
} else = tags {
    tags := null
}

# ---------------------------------------------------------------------------
# CUSTOM_TAG_001 — Require Environment tag
# ---------------------------------------------------------------------------

deny[result] {
    # Check all resources
    some type_name
    resources_of_type := input.resource[type_name]
    some resource_name
    resource_block := resources_of_type[resource_name]

    # Assume we only care about aws_ resources that can be tagged (exclude data sources because input.resource does not contain data, input.data does)
    startswith(type_name, "aws_")

    tags := get_tags(resource_block)

    # tags is null or missing Environment key
    not has_tag(tags, "Environment")

    result := {
        "policy_id": "CUSTOM_TAG_001",
        "title": "Require Environment tag",
        "severity": "LOW",
        "resource": sprintf("%v.%v", [type_name, resource_name]),
        "resource_type": type_name,
        "reason": sprintf("Resource '%v.%v' (type: %v) does not include a required 'Environment' tag. All managed resources must be tagged with their deployment environment.", [type_name, resource_name, type_name]),
        "compliance": ["Internal Governance"],
        "remediation_hint": "Add an 'Environment' tag with a value such as 'sandbox', 'staging', or 'production'.",
        "input_type": "terraform_source_hcl"
    }
}

# ---------------------------------------------------------------------------
# CUSTOM_TAG_002 — Require Owner tag
# ---------------------------------------------------------------------------

deny[result] {
    some type_name
    resources_of_type := input.resource[type_name]
    some resource_name
    resource_block := resources_of_type[resource_name]

    startswith(type_name, "aws_")

    tags := get_tags(resource_block)

    not has_tag(tags, "Owner")

    result := {
        "policy_id": "CUSTOM_TAG_002",
        "title": "Require Owner tag",
        "severity": "LOW",
        "resource": sprintf("%v.%v", [type_name, resource_name]),
        "resource_type": type_name,
        "reason": sprintf("Resource '%v.%v' (type: %v) does not include a required 'Owner' tag. All managed resources must identify their responsible owner.", [type_name, resource_name, type_name]),
        "compliance": ["Internal Governance"],
        "remediation_hint": "Add an 'Owner' tag with the name or email of the responsible team or individual.",
        "input_type": "terraform_source_hcl"
    }
}

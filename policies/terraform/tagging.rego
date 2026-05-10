# =============================================================================
# policies/terraform/tagging.rego
#
# Tagging Governance Policies for Terraform Plan JSON
# Evaluated by Conftest (OPA/Rego)
#
# Policies:
#   CUSTOM_TAG_001 — Require Environment tag
#   CUSTOM_TAG_002 — Require Owner tag
# =============================================================================

package main

import future.keywords.in

# ---------------------------------------------------------------------------
# Helper: resource types that are data sources (should not be checked)
# ---------------------------------------------------------------------------

is_data_source(rc) {
    rc.mode == "data"
}

# Helper: actions that indicate the resource will exist after apply
is_managed_action(actions) {
    actions[_] == "create"
}

is_managed_action(actions) {
    actions[_] == "update"
}

# Helper: safely get tags from the after block
get_tags(after) = tags {
    tags := object.get(after, "tags", null)
    tags != null
} else = tags {
    tags_all := object.get(after, "tags_all", null)
    tags_all != null
    tags := tags_all
} else = tags {
    tags := null
}

# ---------------------------------------------------------------------------
# CUSTOM_TAG_001 — Require Environment tag
# ---------------------------------------------------------------------------

deny[result] {
    rc := input.resource_changes[_]
    not is_data_source(rc)
    is_managed_action(rc.change.actions)

    after := rc.change.after
    tags := get_tags(after)

    # tags is null or missing Environment key
    not has_tag(tags, "Environment")

    result := {
        "policy_id": "CUSTOM_TAG_001",
        "title": "Require Environment tag",
        "severity": "LOW",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("Resource '%v' (type: %v) does not include a required 'Environment' tag. All managed resources must be tagged with their deployment environment.", [rc.address, rc.type]),
        "compliance": ["Internal Governance"],
        "remediation_hint": "Add an 'Environment' tag with a value such as 'sandbox', 'staging', or 'production'.",
    }
}

# ---------------------------------------------------------------------------
# CUSTOM_TAG_002 — Require Owner tag
# ---------------------------------------------------------------------------

deny[result] {
    rc := input.resource_changes[_]
    not is_data_source(rc)
    is_managed_action(rc.change.actions)

    after := rc.change.after
    tags := get_tags(after)

    not has_tag(tags, "Owner")

    result := {
        "policy_id": "CUSTOM_TAG_002",
        "title": "Require Owner tag",
        "severity": "LOW",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("Resource '%v' (type: %v) does not include a required 'Owner' tag. All managed resources must identify their responsible owner.", [rc.address, rc.type]),
        "compliance": ["Internal Governance"],
        "remediation_hint": "Add an 'Owner' tag with the name or email of the responsible team or individual.",
    }
}

# ---------------------------------------------------------------------------
# Helper: check if tags contain a specific key
# ---------------------------------------------------------------------------

has_tag(tags, key) {
    tags != null
    _ = tags[key]
}

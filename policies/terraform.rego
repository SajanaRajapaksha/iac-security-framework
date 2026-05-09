# =============================================================================
# FILE: policies/terraform.rego
# TOOL: Open Policy Agent (OPA) / Rego
# PURPOSE: Placeholder for general Terraform governance policy rules
# =============================================================================
#
# FUTURE POLICY RULES (to be implemented):
#
# RULE 1 — Required Metadata Tags
#   Deny any Terraform resource that is missing mandatory tags.
#   Required tags to be enforced:
#     - "Environment"  (sandbox, staging, production)
#     - "Project"      (must match the approved project name)
#     - "Owner"        (responsible team or individual)
#     - "ManagedBy"    (must be "terraform")
#
# RULE 2 — Allowed Environments
#   Only allow deployments to approved environments.
#   Deny any deployment where Environment tag is not one of:
#     - "sandbox"
#     - "staging"
#     - "production"
#
# RULE 3 — Allowed Resource Types
#   Optionally enforce an allowlist of permitted AWS resource types.
#   Deny any resource type not explicitly approved.
#   This helps prevent shadow infrastructure from being deployed.
#
# RULE 4 — Deployment Governance
#   Enforce deployment governance rules, for example:
#     - Deny deployments without an upload_id annotation
#     - Deny resources without a defined owner
#     - Deny any resource with "test" or "temp" in its name in production
#
# RULE 5 — Provider Constraints
#   Deny any Terraform configuration using unsupported or unapproved providers.
#   Only approved providers from the internal registry should be used.
#
# HOW THIS FILE WILL BE USED:
#   Conftest will be run against Terraform plan output or .tf files
#   using this Rego policy file.
#
#   Command (future):
#     conftest test <terraform-plan.json> --policy policies/terraform.rego
#
#   Policy violations will be captured and attached to the upload_id.
#
# =============================================================================
# PLACEHOLDER — Full Rego policy rules to be implemented in future phases
# =============================================================================

package terraform

# FUTURE: Add Rego policy rules here

# Example structure (to be completed):
#
# deny[msg] {
#     resource := input.resource_changes[_]
#     not resource.change.after.tags["Environment"]
#     msg := sprintf("Resource '%v' is missing the required 'Environment' tag.", [resource.address])
# }

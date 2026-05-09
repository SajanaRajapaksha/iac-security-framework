# =============================================================================
# FILE: policies/aws-security.rego
# TOOL: Open Policy Agent (OPA) / Rego
# PURPOSE: Placeholder for AWS-specific security policy rules
# =============================================================================
#
# FUTURE POLICY RULES (to be implemented):
#
# RULE 1 — Deny Open Ingress (0.0.0.0/0)
#   Deny any aws_security_group resource that contains an ingress rule
#   allowing traffic from 0.0.0.0/0 (world-open access).
#   This prevents inadvertent public exposure of critical ports.
#
# RULE 2 — Require S3 Encryption
#   Deny any aws_s3_bucket resource that does not have:
#     - Server-side encryption enabled (AES-256 or KMS)
#   All S3 buckets must encrypt data at rest.
#
# RULE 3 — Require S3 Public Access Block
#   Deny any aws_s3_bucket resource that does not have:
#     - aws_s3_bucket_public_access_block with all four settings set to true
#   Prevents public exposure of S3 data.
#
# RULE 4 — Require CloudTrail
#   Deny any deployment that does not include an aws_cloudtrail resource
#   with log_file_validation_enabled = true.
#   CloudTrail is essential for forensic auditability.
#
# RULE 5 — Require Security Tags
#   Deny any aws resource that is missing required security classification tags:
#     - "DataClassification"   (public, internal, confidential, restricted)
#     - "SecurityContact"      (security team contact)
#
# RULE 6 — Require Logging
#   Deny resources that should have logging enabled but do not:
#     - Load balancers without access logging
#     - S3 buckets without server access logging
#     - RDS instances without enhanced monitoring
#
# RULE 7 — Deny Wildcard IAM Actions
#   Deny any aws_iam_policy document that uses "*" as an action
#   or "*" as a resource, as this violates least-privilege principles.
#
# RULE 8 — Restrict SSH/RDP Access
#   Deny any security group allowing port 22 (SSH) or 3389 (RDP) from
#   0.0.0.0/0 or ::/0 (IPv6 world-open).
#
# HOW THIS FILE WILL BE USED:
#   Conftest will be run against Terraform plan output or .tf files
#   using this Rego policy file.
#
#   Command (future):
#     conftest test <terraform-plan.json> --policy policies/aws-security.rego
#
#   All violations will be tagged with upload_id and saved in:
#     reports/static/policy-results.json
#
# =============================================================================
# PLACEHOLDER — Full Rego policy rules to be implemented in future phases
# =============================================================================

package aws_security

# FUTURE: Add Rego policy rules here

# Example structure (to be completed):
#
# deny[msg] {
#     resource := input.resource_changes[_]
#     resource.type == "aws_security_group"
#     ingress := resource.change.after.ingress[_]
#     ingress.cidr_blocks[_] == "0.0.0.0/0"
#     msg := sprintf("Security group '%v' allows unrestricted ingress from 0.0.0.0/0.", [resource.address])
# }

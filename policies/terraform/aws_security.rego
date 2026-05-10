# =============================================================================
# policies/terraform/aws_security.rego
#
# AWS Security Policies for Terraform Plan JSON
# Evaluated by Conftest (OPA/Rego)
#
# Policies:
#   CUSTOM_AWS_001 — Block public SSH ingress (port 22 from 0.0.0.0/0)
#   CUSTOM_AWS_002 — Block public RDP ingress (port 3389 from 0.0.0.0/0)
#   CUSTOM_AWS_003 — Block public S3 ACL
#   CUSTOM_AWS_004 — Prevent S3 encryption removal
# =============================================================================

package main

import future.keywords.in

# ---------------------------------------------------------------------------
# Helper: check if a CIDR list contains a world-open CIDR
# ---------------------------------------------------------------------------

is_public_cidr(cidrs) {
    cidrs[_] == "0.0.0.0/0"
}

is_public_cidr(cidrs) {
    cidrs[_] == "::/0"
}

# ---------------------------------------------------------------------------
# Helper: check if a port falls within a range
# ---------------------------------------------------------------------------

port_in_range(from_port, to_port, target) {
    from_port <= target
    to_port >= target
}

# ---------------------------------------------------------------------------
# CUSTOM_AWS_001 — Block public SSH ingress (port 22)
# ---------------------------------------------------------------------------

deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    ingress := after.ingress[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    cidr_blocks := object.get(ingress, "cidr_blocks", [])

    port_in_range(from_port, to_port, 22)
    is_public_cidr(cidr_blocks)

    result := {
        "policy_id": "CUSTOM_AWS_001",
        "title": "Block public SSH ingress",
        "severity": "HIGH",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("Security group '%v' allows SSH (port 22) ingress from 0.0.0.0/0 or ::/0. Public SSH access enables brute-force and lateral movement attacks.", [rc.address]),
        "compliance": ["CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Restrict SSH ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
    }
}

# Also check IPv6
deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    ingress := after.ingress[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    ipv6_blocks := object.get(ingress, "ipv6_cidr_blocks", [])

    port_in_range(from_port, to_port, 22)
    is_public_cidr(ipv6_blocks)

    result := {
        "policy_id": "CUSTOM_AWS_001",
        "title": "Block public SSH ingress",
        "severity": "HIGH",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("Security group '%v' allows SSH (port 22) ingress from ::/0 (IPv6). Public SSH access enables brute-force and lateral movement attacks.", [rc.address]),
        "compliance": ["CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Restrict SSH ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
    }
}

# ---------------------------------------------------------------------------
# CUSTOM_AWS_002 — Block public RDP ingress (port 3389)
# ---------------------------------------------------------------------------

deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    ingress := after.ingress[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    cidr_blocks := object.get(ingress, "cidr_blocks", [])

    port_in_range(from_port, to_port, 3389)
    is_public_cidr(cidr_blocks)

    result := {
        "policy_id": "CUSTOM_AWS_002",
        "title": "Block public RDP ingress",
        "severity": "HIGH",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("Security group '%v' allows RDP (port 3389) ingress from 0.0.0.0/0 or ::/0. Public RDP access is a common attack vector.", [rc.address]),
        "compliance": ["CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Restrict RDP ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
    }
}

deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    ingress := after.ingress[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    ipv6_blocks := object.get(ingress, "ipv6_cidr_blocks", [])

    port_in_range(from_port, to_port, 3389)
    is_public_cidr(ipv6_blocks)

    result := {
        "policy_id": "CUSTOM_AWS_002",
        "title": "Block public RDP ingress",
        "severity": "HIGH",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("Security group '%v' allows RDP (port 3389) ingress from ::/0 (IPv6). Public RDP access is a common attack vector.", [rc.address]),
        "compliance": ["CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Restrict RDP ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
    }
}

# ---------------------------------------------------------------------------
# CUSTOM_AWS_003 — Block public S3 ACL
# ---------------------------------------------------------------------------

public_acl_values := {"public-read", "public-read-write", "authenticated-read"}

# Check aws_s3_bucket_acl resource
deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_s3_bucket_acl"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    acl_value := object.get(after, "acl", "")
    public_acl_values[acl_value]

    result := {
        "policy_id": "CUSTOM_AWS_003",
        "title": "Block public S3 ACL",
        "severity": "CRITICAL",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("S3 bucket ACL '%v' uses public ACL '%v'. Public S3 ACLs can expose sensitive data to the internet.", [rc.address, acl_value]),
        "compliance": ["CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Set the S3 bucket ACL to 'private' and use bucket policies for controlled access.",
    }
}

# Check legacy acl attribute on aws_s3_bucket
deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_s3_bucket"
    actions := rc.change.actions
    actions[_] != "delete"

    after := rc.change.after
    acl_value := object.get(after, "acl", "")
    acl_value != ""
    public_acl_values[acl_value]

    result := {
        "policy_id": "CUSTOM_AWS_003",
        "title": "Block public S3 ACL",
        "severity": "CRITICAL",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("S3 bucket '%v' uses legacy public ACL '%v'. Public ACLs can expose sensitive data.", [rc.address, acl_value]),
        "compliance": ["CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Remove the legacy 'acl' argument and use aws_s3_bucket_acl with 'private' or bucket policies.",
    }
}

# ---------------------------------------------------------------------------
# CUSTOM_AWS_004 — Prevent S3 encryption removal
# ---------------------------------------------------------------------------

deny[result] {
    rc := input.resource_changes[_]
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    actions := rc.change.actions
    actions[_] == "delete"

    result := {
        "policy_id": "CUSTOM_AWS_004",
        "title": "Prevent S3 encryption removal",
        "severity": "CRITICAL",
        "resource": rc.address,
        "resource_type": rc.type,
        "reason": sprintf("Terraform plan deletes S3 encryption configuration '%v'. Removing encryption at rest violates data protection requirements.", [rc.address]),
        "compliance": ["CIS", "NIST", "Internal Baseline"],
        "remediation_hint": "Do not delete the S3 server-side encryption configuration. If replacing, ensure a new encryption configuration is created.",
    }
}

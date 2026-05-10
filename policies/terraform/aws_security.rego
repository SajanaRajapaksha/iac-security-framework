# =============================================================================
# policies/terraform/aws_security.rego
#
# AWS Security Policies for Terraform Source HCL
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
# Helper: Arrays
# ---------------------------------------------------------------------------

to_array(x) = [x] { not is_array(x) }
to_array(x) = x { is_array(x) }

# ---------------------------------------------------------------------------
# Helper: check if a CIDR list contains a world-open CIDR
# ---------------------------------------------------------------------------

is_public_cidr(cidrs) {
    c := to_array(cidrs)
    c[_] == "0.0.0.0/0"
}

is_public_cidr(cidrs) {
    c := to_array(cidrs)
    c[_] == "::/0"
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
    sg := input.resource.aws_security_group[name]
    
    ingress_list := to_array(object.get(sg, "ingress", []))
    ingress := ingress_list[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    cidr_blocks := object.get(ingress, "cidr_blocks", [])

    port_in_range(from_port, to_port, 22)
    is_public_cidr(cidr_blocks)

    result := {
        "msg": sprintf("Security group '%v' allows SSH (port 22) ingress from 0.0.0.0/0 or ::/0. Public SSH access enables brute-force and lateral movement attacks.", [name]),
        "metadata": {
            "policy_id": "CUSTOM_AWS_001",
            "title": "Block public SSH ingress",
            "severity": "HIGH",
            "resource": sprintf("aws_security_group.%v", [name]),
            "resource_type": "aws_security_group",
            "reason": sprintf("Security group '%v' allows SSH (port 22) ingress from 0.0.0.0/0 or ::/0. Public SSH access enables brute-force and lateral movement attacks.", [name]),
            "compliance": ["CIS", "NIST", "Internal Baseline"],
            "remediation_hint": "Restrict SSH ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
            "input_type": "terraform_source_hcl"
        }
    }
}

# Also check IPv6
deny[result] {
    sg := input.resource.aws_security_group[name]
    
    ingress_list := to_array(object.get(sg, "ingress", []))
    ingress := ingress_list[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    ipv6_blocks := object.get(ingress, "ipv6_cidr_blocks", [])

    port_in_range(from_port, to_port, 22)
    is_public_cidr(ipv6_blocks)

    result := {
        "msg": sprintf("Security group '%v' allows SSH (port 22) ingress from ::/0 (IPv6). Public SSH access enables brute-force and lateral movement attacks.", [name]),
        "metadata": {
            "policy_id": "CUSTOM_AWS_001",
            "title": "Block public SSH ingress",
            "severity": "HIGH",
            "resource": sprintf("aws_security_group.%v", [name]),
            "resource_type": "aws_security_group",
            "reason": sprintf("Security group '%v' allows SSH (port 22) ingress from ::/0 (IPv6). Public SSH access enables brute-force and lateral movement attacks.", [name]),
            "compliance": ["CIS", "NIST", "Internal Baseline"],
            "remediation_hint": "Restrict SSH ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
            "input_type": "terraform_source_hcl"
        }
    }
}

# ---------------------------------------------------------------------------
# CUSTOM_AWS_002 — Block public RDP ingress (port 3389)
# ---------------------------------------------------------------------------

deny[result] {
    sg := input.resource.aws_security_group[name]
    
    ingress_list := to_array(object.get(sg, "ingress", []))
    ingress := ingress_list[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    cidr_blocks := object.get(ingress, "cidr_blocks", [])

    port_in_range(from_port, to_port, 3389)
    is_public_cidr(cidr_blocks)

    result := {
        "msg": sprintf("Security group '%v' allows RDP (port 3389) ingress from 0.0.0.0/0 or ::/0. Public RDP access is a common attack vector.", [name]),
        "metadata": {
            "policy_id": "CUSTOM_AWS_002",
            "title": "Block public RDP ingress",
            "severity": "HIGH",
            "resource": sprintf("aws_security_group.%v", [name]),
            "resource_type": "aws_security_group",
            "reason": sprintf("Security group '%v' allows RDP (port 3389) ingress from 0.0.0.0/0 or ::/0. Public RDP access is a common attack vector.", [name]),
            "compliance": ["CIS", "NIST", "Internal Baseline"],
            "remediation_hint": "Restrict RDP ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
            "input_type": "terraform_source_hcl"
        }
    }
}

deny[result] {
    sg := input.resource.aws_security_group[name]
    
    ingress_list := to_array(object.get(sg, "ingress", []))
    ingress := ingress_list[_]

    from_port := object.get(ingress, "from_port", -1)
    to_port := object.get(ingress, "to_port", -1)
    ipv6_blocks := object.get(ingress, "ipv6_cidr_blocks", [])

    port_in_range(from_port, to_port, 3389)
    is_public_cidr(ipv6_blocks)

    result := {
        "msg": sprintf("Security group '%v' allows RDP (port 3389) ingress from ::/0 (IPv6). Public RDP access is a common attack vector.", [name]),
        "metadata": {
            "policy_id": "CUSTOM_AWS_002",
            "title": "Block public RDP ingress",
            "severity": "HIGH",
            "resource": sprintf("aws_security_group.%v", [name]),
            "resource_type": "aws_security_group",
            "reason": sprintf("Security group '%v' allows RDP (port 3389) ingress from ::/0 (IPv6). Public RDP access is a common attack vector.", [name]),
            "compliance": ["CIS", "NIST", "Internal Baseline"],
            "remediation_hint": "Restrict RDP ingress to specific trusted CIDR blocks or use a bastion host / VPN.",
            "input_type": "terraform_source_hcl"
        }
    }
}

# ---------------------------------------------------------------------------
# CUSTOM_AWS_003 — Block public S3 ACL
# ---------------------------------------------------------------------------

public_acl_values := {"public-read", "public-read-write", "authenticated-read"}

# Check aws_s3_bucket_acl resource
deny[result] {
    acl_res := input.resource.aws_s3_bucket_acl[name]
    acl_value := object.get(acl_res, "acl", "")
    public_acl_values[acl_value]

    result := {
        "msg": sprintf("S3 bucket ACL '%v' uses public ACL '%v'. Public S3 ACLs can expose sensitive data to the internet.", [name, acl_value]),
        "metadata": {
            "policy_id": "CUSTOM_AWS_003",
            "title": "Block public S3 ACL",
            "severity": "CRITICAL",
            "resource": sprintf("aws_s3_bucket_acl.%v", [name]),
            "resource_type": "aws_s3_bucket_acl",
            "reason": sprintf("S3 bucket ACL '%v' uses public ACL '%v'. Public S3 ACLs can expose sensitive data to the internet.", [name, acl_value]),
            "compliance": ["CIS", "NIST", "Internal Baseline"],
            "remediation_hint": "Set the S3 bucket ACL to 'private' and use bucket policies for controlled access.",
            "input_type": "terraform_source_hcl"
        }
    }
}

# Check legacy acl attribute on aws_s3_bucket
deny[result] {
    bucket := input.resource.aws_s3_bucket[name]
    acl_value := object.get(bucket, "acl", "")
    acl_value != ""
    public_acl_values[acl_value]

    result := {
        "msg": sprintf("S3 bucket '%v' uses legacy public ACL '%v'. Public ACLs can expose sensitive data.", [name, acl_value]),
        "metadata": {
            "policy_id": "CUSTOM_AWS_003",
            "title": "Block public S3 ACL",
            "severity": "CRITICAL",
            "resource": sprintf("aws_s3_bucket.%v", [name]),
            "resource_type": "aws_s3_bucket",
            "reason": sprintf("S3 bucket '%v' uses legacy public ACL '%v'. Public ACLs can expose sensitive data.", [name, acl_value]),
            "compliance": ["CIS", "NIST", "Internal Baseline"],
            "remediation_hint": "Remove the legacy 'acl' argument and use aws_s3_bucket_acl with 'private' or bucket policies.",
            "input_type": "terraform_source_hcl"
        }
    }
}

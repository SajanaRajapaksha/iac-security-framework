#!/usr/bin/env python3
"""
scripts/deployment/build_state_resource_inventory.py

Stage 30 — Parses terraform show -json (deployed-state.json) and extracts
a sanitized, forensic-ready resource inventory.

Does NOT store complete resource attribute blobs — only extracts fields needed
for identification, tag reconciliation, existence verification, and runtime
correlation.

Usage:
    python scripts/deployment/build_state_resource_inventory.py \\
        <SCAN_ID> \\
        <path-to-deployed-state.json>

Output:
    reports/deployment/<SCAN_ID>/terraform-state-resource-inventory.json
"""

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

# Attributes that might hold the ARN across resource types
ARN_ATTRS = ["arn", "id"]  # 'id' is used as fallback when no dedicated arn attr

# Attributes that commonly hold a human-readable name
NAME_ATTRS = ["name", "bucket", "db_instance_identifier", "alias_name",
              "function_name", "table_name", "cluster_identifier"]

# Attributes that indicate AWS region
REGION_ATTRS = ["region", "availability_zone"]

# AWS resource type prefix
AWS_PREFIX = "aws_"

# Sensitive attribute names (never copied to sanitized inventory)
SENSITIVE_ATTRS = {
    "password", "secret", "token", "key", "private_key", "access_key",
    "secret_access_key", "session_token", "credentials",
}


def _is_sensitive(key: str) -> bool:
    key_lower = key.lower()
    return any(s in key_lower for s in SENSITIVE_ATTRS)


def _safe_str(value) -> str | None:
    if value is None or value is True or value is False:
        return None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str) and value:
        return value
    return None


def _extract_tags(attrs: dict) -> dict:
    """Extract tags_all or tags from resource attributes."""
    tags = {}
    for key in ("tags_all", "tags"):
        val = attrs.get(key)
        if isinstance(val, dict):
            tags = {k: v for k, v in val.items()
                    if isinstance(k, str) and isinstance(v, str)}
            if tags:
                break
    return tags


def _extract_arn(attrs: dict, rtype: str) -> str | None:
    arn = _safe_str(attrs.get("arn"))
    if arn and arn.startswith("arn:aws"):
        return arn
    return None


def _extract_id(attrs: dict) -> str | None:
    return _safe_str(attrs.get("id"))


def _extract_name(attrs: dict) -> str | None:
    for k in NAME_ATTRS:
        v = _safe_str(attrs.get(k))
        if v:
            return v
    return None


def _extract_region(attrs: dict) -> str | None:
    for k in REGION_ATTRS:
        v = _safe_str(attrs.get(k))
        if v:
            return v.split("-")[0:3]  # normalize AZ → region
    return None


def _resource_taggable(rtype: str, attrs: dict) -> bool:
    return "tags" in attrs or "tags_all" in attrs


def _verification_strategy(rtype: str) -> str:
    mapping = {
        "aws_s3_bucket": "s3.head_bucket",
        "aws_s3_bucket_public_access_block": "s3.get_public_access_block",
        "aws_s3_bucket_versioning": "s3.get_bucket_versioning",
        "aws_s3_bucket_server_side_encryption_configuration": "s3.get_bucket_encryption",
        "aws_instance": "ec2.describe_instances",
        "aws_security_group": "ec2.describe_security_groups",
        "aws_vpc": "ec2.describe_vpcs",
        "aws_subnet": "ec2.describe_subnets",
        "aws_route_table": "ec2.describe_route_tables",
        "aws_internet_gateway": "ec2.describe_internet_gateways",
        "aws_network_acl": "ec2.describe_network_acls",
        "aws_iam_role": "iam.get_role",
        "aws_iam_policy": "iam.get_policy",
        "aws_iam_user": "iam.get_user",
        "aws_iam_group": "iam.get_group",
        "aws_db_instance": "rds.describe_db_instances",
        "aws_rds_cluster": "rds.describe_db_clusters",
        "aws_kms_key": "kms.describe_key",
        "aws_kms_alias": "kms.list_aliases",
    }
    return mapping.get(rtype, "generic.unsupported")


def infer_aws_service(terraform_type: str) -> str:
    """Infer the AWS service from the terraform resource type."""
    if terraform_type in (
        "aws_security_group", "aws_instance", "aws_vpc", "aws_subnet",
        "aws_route_table", "aws_internet_gateway", "aws_network_acl"
    ):
        return "ec2"
    if terraform_type in (
        "aws_s3_bucket", "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_versioning", "aws_s3_bucket_server_side_encryption_configuration"
    ):
        return "s3"
    if terraform_type in ("aws_iam_role", "aws_iam_policy", "aws_iam_user", "aws_iam_group"):
        return "iam"
    if terraform_type in ("aws_db_instance", "aws_rds_cluster"):
        return "rds"
    if terraform_type in ("aws_kms_key", "aws_kms_alias"):
        return "kms"
    if terraform_type == "aws_lambda_function":
        return "lambda"
    return "unknown"


def process_resource_values(values: dict, module_address: str, resource: dict) -> dict:
    """Extract a single resource record from a values dictionary."""
    attrs = values
    rtype = resource.get("type", "")
    provider = resource.get("provider_name", "")
    mode = resource.get("mode", "managed")

    # Prioritize the exact address provided by Terraform in the JSON
    address = resource.get("address")
    if not address:
        # Fallback if address is missing
        resource_name = resource.get("name", "")
        base_addr = f"{module_address}.{rtype}.{resource_name}" if module_address else f"{rtype}.{resource_name}"
        index = resource.get("index")
        if index is not None:
            address = f"{base_addr}[{json.dumps(index)}]"
        else:
            address = base_addr

    tags = _extract_tags(attrs)
    arn = _extract_arn(attrs, rtype)
    resource_id = _extract_id(attrs)
    name = _extract_name(attrs)
    taggable = _resource_taggable(rtype, attrs)

    region = None
    # 1. Check explicit region attributes (including availability_zone)
    for k in REGION_ATTRS:
        v = attrs.get(k)
        if isinstance(v, str) and v:
            import re
            # If it looks like an AZ (e.g. us-east-1a), strip the trailing letter
            # A region ends in a digit (e.g. us-east-1)
            az_match = re.match(r"^([a-z]{2}-[a-z]+-\d+)[a-z]$", v)
            if az_match:
                region = az_match.group(1)
            else:
                region = v
            break
            
    # 2. Extract from ARN if not found
    if not region and arn and "arn:aws:" in arn:
        parts = arn.split(":")
        if len(parts) > 3 and parts[3]:
            region = parts[3]
            
    # 3. Fallback to AWS_REGION environment variable
    if not region:
        region = os.environ.get("AWS_REGION", "unknown")

    return {
        "terraform_address": address,
        "terraform_type": rtype,
        "provider": provider,
        "resource_mode": mode,
        "resource_id": resource_id,
        "resource_arn": arn,
        "resource_name": name,
        "aws_region": region,
        "aws_service": infer_aws_service(rtype),
        "tags": tags,
        "taggable": taggable,
        "verification_strategy": _verification_strategy(rtype),
    }


def walk_resources(state_data: dict) -> list[dict]:
    """
    Recursively walk the state JSON and extract all managed resources.

    Handles root module, child modules, count, and for_each.
    """
    records: list[dict] = []

    def _walk_module(module_obj: dict, parent_address: str) -> None:
        resources = module_obj.get("resources", [])
        for resource in resources:
            mode = resource.get("mode", "managed")
            if mode != "managed":
                continue
            rtype = resource.get("type", "")
            if not rtype.startswith(AWS_PREFIX):
                continue
            
            # Extract from `values` which is where terraform show -json puts them
            values = resource.get("values") or {}
            record = process_resource_values(values, parent_address, resource)
            records.append(record)

        for child_module in module_obj.get("child_modules", []):
            child_address = child_module.get("address", "")
            _walk_module(child_module, child_address)

    root = state_data.get("values", {}).get("root_module", {})
    _walk_module(root, "")

    return records


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: build_state_resource_inventory.py <SCAN_ID> <deployed-state.json>",
              file=sys.stderr)
        sys.exit(1)

    scan_id = sys.argv[1]
    state_path = Path(sys.argv[2])

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "terraform-state-resource-inventory.json"

    if not state_path.is_file():
        print(f"[state_inventory] ERROR: State file not found: {state_path}", file=sys.stderr)
        sys.exit(1)

    state_data = safe_read_json(str(state_path))
    if not isinstance(state_data, dict):
        print(f"[state_inventory] ERROR: Could not parse state JSON: {state_path}", file=sys.stderr)
        sys.exit(1)

    resources = walk_resources(state_data)
    aws_resources = [r for r in resources if r["terraform_type"].startswith(AWS_PREFIX)]
    with_arn = [r for r in aws_resources if r["resource_arn"]]
    with_id = [r for r in aws_resources if r["resource_id"]]
    with_framework_tags = [
        r for r in aws_resources
        if r["tags"].get("scan-id") == scan_id
        and r["tags"].get("managed-by") == "iac-security-framework"
    ]
    without_framework_tags = [
        r for r in aws_resources if r not in with_framework_tags
    ]

    output = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "summary": {
            "total_managed_resources": len(resources),
            "aws_resources": len(aws_resources),
            "resources_with_arn": len(with_arn),
            "resources_with_id": len(with_id),
            "resources_with_framework_tags": len(with_framework_tags),
            "resources_without_framework_tags": len(without_framework_tags),
        },
        "resources": aws_resources,
    }

    safe_write_json(str(out_path), output)

    print(f"\n{'='*60}")
    print(f"  TERRAFORM STATE RESOURCE INVENTORY")
    print(f"{'='*60}")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  AWS Resources        : {len(aws_resources)}")
    print(f"  With ARN             : {len(with_arn)}")
    print(f"  With ID              : {len(with_id)}")
    print(f"  With Framework Tags  : {len(with_framework_tags)}")
    for r in aws_resources:
        mark = "✓" if r["taggable"] else "○"
        print(f"  {mark} {r['terraform_address']} ({r['resource_id'] or 'no-id'})")
    print(f"  Output               : {out_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

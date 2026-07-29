#!/usr/bin/env python3
"""
scripts/deployment/discover_tagged_aws_resources.py

Stage 31 — Discovers deployed AWS resources using the Resource Groups
Tagging API, filtered by both framework tags:
    scan-id=<SCAN_ID>
    managed-by=iac-security-framework

Handles pagination. Does NOT fail the pipeline if the tagging API returns
fewer resources than Terraform state (many resource types are not returned
by the tagging API).

Usage:
    python scripts/deployment/discover_tagged_aws_resources.py \\
        <SCAN_ID> \\
        [--region <AWS_REGION>]

Output:
    reports/deployment/<SCAN_ID>/tagged-aws-resource-inventory.json
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_write_json, utc_now_iso

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


def discover_resources(scan_id: str, region: str) -> list[dict]:
    """
    Use AWS Resource Groups Tagging API with pagination to discover
    all resources tagged with both scan-id=<SCAN_ID> and
    managed-by=iac-security-framework.
    """
    if not BOTO3_AVAILABLE:
        raise RuntimeError("boto3 is not installed. Run: pip install boto3")

    client = boto3.client("resourcegroupstaggingapi", region_name=region)
    paginator = client.get_paginator("get_resources")

    tag_filters = [
        {"Key": "scan-id", "Values": [scan_id]},
        {"Key": "managed-by", "Values": ["iac-security-framework"]},
    ]

    discovered_at = utc_now_iso()
    resources: list[dict] = []

    page_iterator = paginator.paginate(TagFilters=tag_filters)

    for page in page_iterator:
        for resource_tag_mapping in page.get("ResourceTagMappingList", []):
            arn = resource_tag_mapping.get("ResourceARN", "")
            raw_tags = resource_tag_mapping.get("Tags", [])
            tags = {t["Key"]: t["Value"] for t in raw_tags if "Key" in t and "Value" in t}

            # Derive resource type from ARN: arn:aws:s3:::bucket-name → s3
            rtype = ""
            parts = arn.split(":")
            if len(parts) >= 6:
                service = parts[2]
                resource_part = parts[5] if len(parts) > 5 else parts[4]
                rtype = f"{service}/{resource_part.split('/')[0]}" if "/" in resource_part else service

            resources.append({
                "resource_arn": arn,
                "resource_type": rtype,
                "tags": tags,
                "source": "resourcegroupstaggingapi",
                "discovered_at_utc": discovered_at,
            })

    return resources


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Discover AWS resources by framework tags."
    )
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument("--region", default="")
    args = parser.parse_args()

    scan_id: str = args.scan_id
    region = args.region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "tagged-aws-resource-inventory.json"

    resources: list[dict] = []
    errors: list[str] = []

    try:
        resources = discover_resources(scan_id, region)
    except RuntimeError as exc:
        errors.append(str(exc))
    except Exception as exc:
        errors.append(f"Discovery failed: {exc}")

    output = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "region": region,
        "total_discovered": len(resources),
        "resources": resources,
        "errors": errors,
        "note": (
            "The Resource Groups Tagging API does not return all AWS resource types. "
            "An absent resource here does not confirm it does not exist."
        ),
    }
    safe_write_json(str(out_path), output)

    print(f"\n{'='*60}")
    print(f"  TAGGED AWS RESOURCE DISCOVERY")
    print(f"{'='*60}")
    print(f"  SCAN_ID          : {scan_id}")
    print(f"  Region           : {region}")
    print(f"  Discovered       : {len(resources)}")
    for r in resources:
        print(f"  - {r['resource_arn']}")
    if errors:
        for e in errors:
            print(f"  ERROR: {e}")
    print(f"  Output           : {out_path}")
    print(f"{'='*60}\n")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()

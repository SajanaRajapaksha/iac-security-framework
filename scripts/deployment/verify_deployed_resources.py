#!/usr/bin/env python3
"""
scripts/deployment/verify_deployed_resources.py

Stage 32 — Runs service-specific verification for each resource in the
Terraform state inventory. Uses bounded retries with exponential back-off.

Usage:
    python scripts/deployment/verify_deployed_resources.py \\
        <SCAN_ID> \\
        <path-to-terraform-state-resource-inventory.json> \\
        [--region <AWS_REGION>]

Output:
    reports/deployment/<SCAN_ID>/deployed-resource-verification.json
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso
from scripts.deployment.resource_verifiers import get_verifier


def verify_all(resources: list[dict], scan_id: str) -> list[dict]:
    results = []
    for resource in resources:
        rtype = resource.get("terraform_type", "")
        verifier = get_verifier(rtype)
        try:
            result = verifier.verify(resource, scan_id)
        except Exception as exc:
            result = {
                "terraform_address": resource.get("terraform_address"),
                "terraform_type": rtype,
                "resource_id": resource.get("resource_id"),
                "resource_arn": resource.get("resource_arn"),
                "exists": False,
                "lifecycle_state": "ERROR",
                "framework_tags_valid": None,
                "verification_status": "ERROR",
                "verification_method": f"{rtype}.verify",
                "attempts": 1,
                "verified_at_utc": utc_now_iso(),
                "errors": [str(exc)],
                "warnings": [],
            }
        results.append(result)
    return results


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Verify deployed AWS resources.")
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument("inventory_path", help="Path to terraform-state-resource-inventory.json")
    parser.add_argument("--region", default="")
    args = parser.parse_args()

    scan_id = args.scan_id
    region = args.region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "")

    if region:
        os.environ.setdefault("AWS_DEFAULT_REGION", region)

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "deployed-resource-verification.json"

    inventory_data = safe_read_json(args.inventory_path)
    if not isinstance(inventory_data, dict):
        print(f"[verify_resources] ERROR: Cannot load inventory from {args.inventory_path}",
              file=sys.stderr)
        sys.exit(1)

    resources = inventory_data.get("resources", [])
    results = verify_all(resources, scan_id)

    # Summarize
    by_status: dict[str, int] = {}
    for r in results:
        s = r.get("verification_status", "UNKNOWN")
        by_status[s] = by_status.get(s, 0) + 1

    output = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "region": region,
        "total_resources": len(results),
        "summary": by_status,
        "resources": results,
    }
    safe_write_json(str(out_path), output)

    print(f"\n{'='*60}")
    print(f"  DEPLOYED RESOURCE VERIFICATION")
    print(f"{'='*60}")
    print(f"  SCAN_ID          : {scan_id}")
    print(f"  Resources        : {len(results)}")
    for status, count in sorted(by_status.items()):
        print(f"  {status:<25} : {count}")
    for r in results:
        mark = "✓" if r.get("exists") else "✗"
        tags = "TAGS_OK" if r.get("framework_tags_valid") else (
            "TAGS_BAD" if r.get("framework_tags_valid") is False else "TAGS_N/A"
        )
        print(f"  {mark} {r['terraform_address']} — {r['verification_status']} — {tags}")
    print(f"  Output           : {out_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

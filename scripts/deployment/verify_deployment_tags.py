#!/usr/bin/env python3
"""
scripts/deployment/verify_deployment_tags.py

Verifies that expected tags (scan-id, managed-by) were successfully injected
into taggable resources in the Terraform state.

Usage:
    python scripts/deployment/verify_deployment_tags.py <SCAN_ID> <state-inventory-path>
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_read_json, safe_write_json

def verify_tags(scan_id: str, inventory_path: Path) -> None:
    inventory = safe_read_json(str(inventory_path))
    if not inventory:
        print(f"[verify_tags] ERROR: Inventory not found at {inventory_path}", file=sys.stderr)
        sys.exit(1)

    resources = inventory.get("resources", [])
    
    expected_tags = {
        "scan-id": scan_id,
        "managed-by": "iac-security-framework"
    }

    tagged_count = 0
    untagged_count = 0
    unsupported_count = 0

    for r in resources:
        if not r.get("taggable", False):
            unsupported_count += 1
            continue

        r_tags = r.get("tags") or {}
        has_expected = all(r_tags.get(k) == v for k, v in expected_tags.items())
        
        if has_expected:
            tagged_count += 1
        else:
            untagged_count += 1

    result = {
        "expected_tags": expected_tags,
        "tagged_resource_count": tagged_count,
        "untagged_resource_count": untagged_count,
        "unsupported_tag_resource_count": unsupported_count
    }

    out_path = inventory_path.parent / "tag-verification.json"
    safe_write_json(str(out_path), result)
    
    print("============================================================")
    print("  DEPLOYMENT TAG VERIFICATION")
    print("============================================================")
    print(f"  Tagged Resources           : {tagged_count}")
    print(f"  Untagged Resources         : {untagged_count}")
    print(f"  Unsupported Tag Resources  : {unsupported_count}")
    print("============================================================")

    if untagged_count > 0:
        print("[verify_tags] WARNING: Some taggable resources lack expected deployment tags.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: verify_deployment_tags.py <SCAN_ID> <state-inventory-path>")
        sys.exit(1)
    
    scan_id = sys.argv[1]
    inventory_path = Path(sys.argv[2])
    verify_tags(scan_id, inventory_path)

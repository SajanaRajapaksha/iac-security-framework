#!/usr/bin/env python3
"""
scripts/deployment/reconcile_resource_inventories.py

Stage 32a — Reconciles the Terraform state inventory with the AWS tag-discovery
inventory using ARN as the primary correlation key.

Classifications:
    MATCHED              — Resource found in both state and tag discovery
    STATE_ONLY           — In state, not in tagging API (may be non-taggable/API gap)
    TAG_DISCOVERY_ONLY   — In tagging API, not in state (orphan or eventual consistency)
    NON_TAGGABLE         — Marked non-taggable in state inventory
    INSUFFICIENT_IDENTITY — Cannot correlate due to missing ARN and ID
    TAG_MISMATCH         — Found but framework tags differ

Usage:
    python scripts/deployment/reconcile_resource_inventories.py \\
        <SCAN_ID> \\
        <path-to-terraform-state-resource-inventory.json> \\
        <path-to-tagged-aws-resource-inventory.json>

Output:
    reports/deployment/<SCAN_ID>/deployment-resource-reconciliation.json
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


def reconcile(
    state_resources: list[dict],
    discovered_resources: list[dict],
    scan_id: str,
) -> dict:
    """
    Reconcile state vs. tag-discovery inventories.

    Primary key: resource_arn (exact match).
    """
    matched: list[dict] = []
    state_only: list[dict] = []
    tag_discovery_only: list[dict] = []
    non_taggable: list[dict] = []
    tag_mismatch: list[dict] = []
    unresolved: list[dict] = []

    # Index discovered resources by ARN
    discovered_by_arn: dict[str, dict] = {}
    for d in discovered_resources:
        arn = d.get("resource_arn") or ""
        if arn:
            discovered_by_arn[arn] = d

    matched_arns: set[str] = set()

    for sr in state_resources:
        arn = sr.get("resource_arn") or ""
        rtype = sr.get("terraform_type", "")
        taggable = sr.get("taggable", True)
        addr = sr.get("terraform_address", "")

        if not taggable:
            non_taggable.append({
                "terraform_address": addr,
                "terraform_type": rtype,
                "resource_id": sr.get("resource_id"),
                "reason": "non_taggable_resource_type",
            })
            continue

        if not arn:
            unresolved.append({
                "terraform_address": addr,
                "terraform_type": rtype,
                "resource_id": sr.get("resource_id"),
                "classification": "INSUFFICIENT_IDENTITY",
                "reason": "no_arn_in_state",
            })
            continue

        if arn in discovered_by_arn:
            disc = discovered_by_arn[arn]
            disc_tags = disc.get("tags", {})
            tags_ok = (
                disc_tags.get("scan-id") == scan_id
                and disc_tags.get("managed-by") == "iac-security-framework"
            )
            if tags_ok:
                matched.append({
                    "terraform_address": addr,
                    "terraform_type": rtype,
                    "resource_arn": arn,
                    "classification": "MATCHED",
                })
                matched_arns.add(arn)
            else:
                tag_mismatch.append({
                    "terraform_address": addr,
                    "terraform_type": rtype,
                    "resource_arn": arn,
                    "classification": "TAG_MISMATCH",
                    "expected_scan_id": scan_id,
                    "actual_scan_id": disc_tags.get("scan-id"),
                    "expected_managed_by": "iac-security-framework",
                    "actual_managed_by": disc_tags.get("managed-by"),
                })
                matched_arns.add(arn)
        else:
            state_only.append({
                "terraform_address": addr,
                "terraform_type": rtype,
                "resource_id": sr.get("resource_id"),
                "resource_arn": arn,
                "classification": "STATE_ONLY",
                "note": (
                    "Not returned by Resource Groups Tagging API. "
                    "Resource type may not be supported by the tagging API. "
                    "Existence verified separately via service APIs."
                ),
            })

    # Tag-discovery-only resources (not in state)
    for arn, disc in discovered_by_arn.items():
        if arn not in matched_arns:
            tag_discovery_only.append({
                "resource_arn": arn,
                "resource_type": disc.get("resource_type"),
                "classification": "TAG_DISCOVERY_ONLY",
                "note": "Found by tagging API but not in current Terraform state.",
            })

    # Overall status
    status = "PASS"
    if tag_mismatch:
        status = "FAIL"
    elif tag_discovery_only:
        status = "REVIEW_REQUIRED"
    elif unresolved:
        status = "REVIEW_REQUIRED"

    return {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "status": status,
        "summary": {
            "expected_state_resources": len(state_resources),
            "tag_discovered_resources": len(discovered_resources),
            "matched": len(matched),
            "state_only": len(state_only),
            "tag_discovery_only": len(tag_discovery_only),
            "non_taggable": len(non_taggable),
            "tag_mismatch": len(tag_mismatch),
            "insufficient_identity": len(unresolved),
        },
        "matched_resources": matched,
        "state_only_resources": state_only,
        "tag_discovery_only_resources": tag_discovery_only,
        "non_taggable_resources": non_taggable,
        "tag_mismatch_resources": tag_mismatch,
        "unresolved_resources": unresolved,
        "errors": [],
        "warnings": [
            "STATE_ONLY resources may be non-taggable or unsupported by the "
            "Resource Groups Tagging API. They are verified separately via service APIs."
        ] if state_only else [],
    }


def main() -> None:
    if len(sys.argv) < 4:
        print(
            "Usage: reconcile_resource_inventories.py <SCAN_ID> "
            "<state-inventory.json> <tagged-inventory.json>",
            file=sys.stderr,
        )
        sys.exit(1)

    scan_id = sys.argv[1]
    state_path = Path(sys.argv[2])
    tagged_path = Path(sys.argv[3])

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "deployment-resource-reconciliation.json"

    state_data = safe_read_json(str(state_path))
    tagged_data = safe_read_json(str(tagged_path))

    state_resources = (state_data or {}).get("resources", []) if isinstance(state_data, dict) else []
    discovered_resources = (tagged_data or {}).get("resources", []) if isinstance(tagged_data, dict) else []

    result = reconcile(state_resources, discovered_resources, scan_id)
    safe_write_json(str(out_path), result)

    s = result["summary"]
    print(f"\n{'='*60}")
    print(f"  RESOURCE INVENTORY RECONCILIATION — {result['status']}")
    print(f"{'='*60}")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  State Resources      : {s['expected_state_resources']}")
    print(f"  Tag Discovered       : {s['tag_discovered_resources']}")
    print(f"  Matched              : {s['matched']}")
    print(f"  State Only           : {s['state_only']}")
    print(f"  Tag Discovery Only   : {s['tag_discovery_only']}")
    print(f"  Non-Taggable         : {s['non_taggable']}")
    print(f"  Tag Mismatch         : {s['tag_mismatch']}")
    print(f"  Insufficient Identity: {s['insufficient_identity']}")
    print(f"  Output               : {out_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

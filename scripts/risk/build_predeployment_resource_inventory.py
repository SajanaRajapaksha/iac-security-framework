#!/usr/bin/env python3
"""
scripts/risk/build_predeployment_resource_inventory.py

Builds a deterministic pre-deployment resource inventory by parsing all
managed Terraform `resource` blocks from the cloned IaC source.

This inventory provides the authoritative total_resource_count used as
the denominator in the Pre-Deployment Risk Scoring Engine.

Counted:
    resource "<type>" "<name>" { ... }

Not counted:
    data blocks
    provider blocks
    terraform blocks
    variable / output / locals blocks
    module metadata
    framework-generated iac_framework_backend.tf

Usage:
    python scripts/risk/build_predeployment_resource_inventory.py <SCAN_ID>

Output:
    reports/risk/<SCAN_ID>/predeployment-resource-inventory.json
"""

import argparse
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import safe_write_json, utc_now_iso

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex to match `resource "<type>" "<name>"` at the start of a line
# Handles optional whitespace and both quote styles
RESOURCE_BLOCK_RE = re.compile(
    r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"',
    re.MULTILINE,
)

# Files to skip (framework-generated)
SKIP_FILES = {
    "iac_framework_backend.tf",
}

# Directories to skip
SKIP_DIRS = {
    ".terraform",
    ".git",
    "node_modules",
}


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def discover_terraform_root(scan_id: str) -> Path | None:
    """
    Locate the Terraform root for the given scan.

    Priority:
        1. repositories/cloned/<SCAN_ID>/  (security-pipeline job)
        2. deployment-source/              (terraform-plan/apply job)
    """
    candidates = [
        ROOT_DIR / "repositories" / "cloned" / scan_id,
        ROOT_DIR / "deployment-source",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def find_tf_files(root: Path) -> list[Path]:
    """Recursively find all .tf files, skipping excluded dirs/files."""
    results: list[Path] = []
    for dirpath, dirnames, filenames in sorted(root.walk()):
        dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            if fname.endswith(".tf") and fname not in SKIP_FILES:
                results.append(dirpath / fname)
    return results


def extract_resource_blocks(tf_file: Path) -> list[dict]:
    """Extract all `resource` block declarations from a single .tf file."""
    try:
        content = tf_file.read_text(encoding="utf-8")
    except Exception:
        return []

    resources: list[dict] = []
    for match in RESOURCE_BLOCK_RE.finditer(content):
        rtype = match.group(1)
        rname = match.group(2)
        resources.append({
            "resource_type": rtype,
            "resource_name": rname,
            "address": f"{rtype}.{rname}",
        })
    return resources


def build_inventory(scan_id: str, tf_root: Path) -> dict:
    """
    Build the complete pre-deployment resource inventory.

    Returns a dict ready to be serialized as JSON evidence.
    """
    tf_files = find_tf_files(tf_root)

    all_resources: list[dict] = []
    files_parsed: list[str] = []

    for tf_file in tf_files:
        rel_path = str(tf_file.relative_to(tf_root))
        files_parsed.append(rel_path)
        blocks = extract_resource_blocks(tf_file)
        for block in blocks:
            block["source_file"] = rel_path
            all_resources.append(block)

    # Deduplicate by address (same resource declared once normally)
    seen_addresses: set[str] = set()
    unique_resources: list[dict] = []
    for r in all_resources:
        if r["address"] not in seen_addresses:
            seen_addresses.add(r["address"])
            unique_resources.append(r)

    return {
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "terraform_root": str(tf_root),
        "resource_count": len(unique_resources),
        "resource_count_semantics": "total_managed_terraform_resources",
        "resource_count_source": "predeployment_resource_inventory",
        "files_parsed": len(files_parsed),
        "resources": unique_resources,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build pre-deployment Terraform resource inventory."
    )
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    args = parser.parse_args()
    scan_id: str = args.scan_id

    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id
    risk_dir.mkdir(parents=True, exist_ok=True)
    out_path = risk_dir / "predeployment-resource-inventory.json"

    tf_root = discover_terraform_root(scan_id)
    if tf_root is None:
        error_doc = {
            "scan_id": scan_id,
            "generated_at_utc": utc_now_iso(),
            "status": "ERROR",
            "error": "Cannot locate Terraform source root for resource inventory.",
            "resource_count": 0,
        }
        safe_write_json(str(out_path), error_doc)
        print(
            f"[predeployment_resource_inventory] ERROR: Cannot locate TF root",
            file=sys.stderr,
        )
        sys.exit(1)

    inventory = build_inventory(scan_id, tf_root)
    safe_write_json(str(out_path), inventory)

    rc = inventory["resource_count"]
    print(f"[predeployment_resource_inventory] SCAN_ID          : {scan_id}")
    print(f"[predeployment_resource_inventory] TF Root          : {tf_root}")
    print(f"[predeployment_resource_inventory] Files Parsed     : {inventory['files_parsed']}")
    print(f"[predeployment_resource_inventory] Resource Count   : {rc}")
    print(f"[predeployment_resource_inventory] Output           : {out_path}")

    for r in inventory["resources"]:
        print(f"  {r['address']}  ({r['source_file']})")


if __name__ == "__main__":
    main()

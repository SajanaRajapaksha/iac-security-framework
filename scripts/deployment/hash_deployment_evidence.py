#!/usr/bin/env python3
"""
scripts/deployment/hash_deployment_evidence.py

Calculates SHA-256 hashes for all deployment evidence files and produces
a forensic manifest:

    reports/deployment/<SCAN_ID>/deployment-evidence-manifest.json

Usage:
    python scripts/deployment/hash_deployment_evidence.py <SCAN_ID> [--plan-dir <DIR>]

The --plan-dir argument specifies where the Terraform plan binary lives.
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import sha256_file, safe_write_json, utc_now_iso


# Files inside reports/deployment/<SCAN_ID>/
EVIDENCE_FILES = [
    "deployment-contract-validation.json",
    "aws-provider-validation.json",
    "deployment-source-integrity.json",
    "tag-validation.json",
    "deployment-plan-evidence.json",
    "terraform-plan.json",
    "terraform-plan.txt",
    "terraform-plan.sha256",
]

# Files that live in the Terraform working directory (plan-dir)
PLAN_DIR_FILES = [
    "tfplan",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hash deployment evidence files for forensic integrity."
    )
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    parser.add_argument("--plan-dir", default=".", help="Directory containing tfplan binary")
    args = parser.parse_args()

    scan_id: str = args.scan_id
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    plan_dir = Path(args.plan_dir)

    files: list[dict] = []

    # Hash evidence files
    for name in EVIDENCE_FILES:
        filepath = deploy_dir / name
        h = sha256_file(str(filepath))
        files.append({
            "path": name,
            "sha256": h if h else "FILE_NOT_FOUND",
        })

    # Hash plan-dir files
    for name in PLAN_DIR_FILES:
        filepath = plan_dir / name
        h = sha256_file(str(filepath))
        files.append({
            "path": name,
            "sha256": h if h else "FILE_NOT_FOUND",
        })

    manifest = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "algorithm": "SHA256",
        "generated_at_utc": utc_now_iso(),
        "files": files,
    }

    out_path = deploy_dir / "deployment-evidence-manifest.json"
    safe_write_json(str(out_path), manifest)

    hashed_count = sum(1 for f in files if f["sha256"] != "FILE_NOT_FOUND")
    total_count = len(files)

    print(f"[hash_deployment_evidence] SCAN_ID = {scan_id}")
    print(f"[hash_deployment_evidence] Hashed {hashed_count}/{total_count} evidence files")
    for f in files:
        status = f["sha256"][:16] + "..." if f["sha256"] != "FILE_NOT_FOUND" else "FILE_NOT_FOUND"
        print(f"  {f['path']}: {status}")
    print(f"[hash_deployment_evidence] Manifest = {out_path}")


if __name__ == "__main__":
    main()

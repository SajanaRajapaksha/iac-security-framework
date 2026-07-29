#!/usr/bin/env python3
"""
scripts/deployment/hash_apply_evidence.py

Stage 35 — Hashes all deployment apply and validation evidence files,
generating a forensic integrity manifest.

Usage:
    python scripts/deployment/hash_apply_evidence.py <SCAN_ID>

Output:
    reports/deployment/<SCAN_ID>/deployment-apply-evidence-manifest.json
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import sha256_file, safe_write_json, utc_now_iso

# Evidence files relative to reports/deployment/<SCAN_ID>/
EVIDENCE_FILES = [
    "plan-artifact-verification.json",
    "apply-aws-identity-validation.json",
    "deployment-authorization.json",
    "terraform-apply.txt",
    "deployment-apply-evidence.json",
    "terraform-state-resource-inventory.json",
    "tagged-aws-resource-inventory.json",
    "deployment-resource-reconciliation.json",
    "deployed-resource-verification.json",
    "deployment-validation.json",
    "terraform-state.sha256",
    # Also include pre-plan evidence for completeness
    "deployment-contract-validation.json",
    "aws-provider-validation.json",
    "deployment-source-integrity.json",
    "tag-validation.json",
    "deployment-plan-evidence.json",
    "terraform-plan.sha256",
]


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: hash_apply_evidence.py <SCAN_ID>", file=sys.stderr)
        sys.exit(1)

    scan_id = sys.argv[1]
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)

    files: list[dict] = []
    for name in EVIDENCE_FILES:
        filepath = deploy_dir / name
        h = sha256_file(str(filepath))
        file_size = os.path.getsize(str(filepath)) if filepath.is_file() else None
        files.append({
            "path": name,
            "sha256": h if h else "FILE_NOT_FOUND",
            "size_bytes": file_size,
        })

    manifest = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "algorithm": "SHA256",
        "generated_at_utc": utc_now_iso(),
        "files": files,
    }

    out_path = deploy_dir / "deployment-apply-evidence-manifest.json"
    safe_write_json(str(out_path), manifest)

    hashed_count = sum(1 for f in files if f["sha256"] != "FILE_NOT_FOUND")
    total_count = len(files)

    print(f"[hash_apply_evidence] SCAN_ID = {scan_id}")
    print(f"[hash_apply_evidence] Hashed {hashed_count}/{total_count} evidence files")
    for f in files:
        status = f["sha256"][:16] + "..." if f["sha256"] != "FILE_NOT_FOUND" else "FILE_NOT_FOUND"
        print(f"  {f['path']}: {status}")
    print(f"[hash_apply_evidence] Manifest = {out_path}")


if __name__ == "__main__":
    main()

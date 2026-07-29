#!/usr/bin/env python3
"""
scripts/runtime/generate_runtime_evidence.py

Generates a SHA-256 manifest of all runtime evidence files to ensure forensic integrity.

Usage:
    python scripts/runtime/generate_runtime_evidence.py <SCAN_ID>
"""

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.utils.evidence import (
    safe_write_json,
    utc_now_iso,
    sha256_file,
    normalize_path
)

def generate_evidence_manifest(scan_id: str) -> None:
    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    manifest_out_path = runtime_dir / "runtime-evidence-manifest.json"

    print(f"[runtime_evidence] Hashing runtime evidence for {scan_id}...")

    if not runtime_dir.is_dir():
        print(f"[runtime_evidence] ERROR: Runtime directory does not exist: {runtime_dir}")
        sys.exit(1)

    evidence_records = []
    
    # Walk through all files in the runtime directory
    for filepath in runtime_dir.rglob("*"):
        if filepath.is_file() and filepath.name != "runtime-evidence-manifest.json":
            rel_path = filepath.relative_to(ROOT_DIR)
            file_hash = sha256_file(str(filepath))
            
            if file_hash:
                evidence_records.append({
                    "file_path": normalize_path(str(rel_path)),
                    "sha256": file_hash,
                    "size_bytes": filepath.stat().st_size
                })

    manifest = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "phase": "RUNTIME",
        "evidence_count": len(evidence_records),
        "files": sorted(evidence_records, key=lambda x: x["file_path"])
    }

    if safe_write_json(str(manifest_out_path), manifest):
        print(f"[runtime_evidence] Manifest saved to: {manifest_out_path}")
        print(f"[runtime_evidence] Hashed {len(evidence_records)} files.")
    else:
        print("[runtime_evidence] ERROR: Failed to save manifest.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Generate runtime evidence manifest.")
    parser.add_argument("scan_id", help="The unique SCAN_ID")
    args = parser.parse_args()
    generate_evidence_manifest(args.scan_id)

if __name__ == "__main__":
    main()

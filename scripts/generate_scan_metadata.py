"""
scripts/generate_scan_metadata.py

Inspect a cloned repository, find all .tf files, compute SHA256 hashes,
and generate forensic scan metadata.

Environment variables:
    SCAN_ID   — Unique scan identifier
    REPO_URL  — Repository URL (for metadata record)
    BRANCH    — Branch scanned

Output:
    repositories/metadata/<SCAN_ID>/scan-metadata.json
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SKIP_DIRS = {".git", ".terraform", "node_modules"}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def find_tf_files(root_dir: str) -> list[dict]:
    """Recursively find all .tf files, skipping excluded directories."""
    results = []
    root = Path(root_dir).resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            if fname.endswith(".tf"):
                abs_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(abs_path, root)
                file_size = os.path.getsize(abs_path)
                file_hash = sha256_file(abs_path)
                results.append({
                    "relative_path": rel_path,
                    "absolute_path": abs_path,
                    "sha256": file_hash,
                    "file_size_bytes": file_size,
                })
    return results


def main():
    scan_id = os.environ.get("SCAN_ID", "")
    repo_url = os.environ.get("REPO_URL", "")
    branch = os.environ.get("BRANCH", "main")

    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    clone_dir = os.path.join("repositories", "cloned", scan_id)
    metadata_dir = os.path.join("repositories", "metadata", scan_id)
    output_file = os.path.join(metadata_dir, "scan-metadata.json")

    os.makedirs(metadata_dir, exist_ok=True)

    if not os.path.isdir(clone_dir):
        print(f"ERROR: Cloned directory not found: {clone_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[scan_metadata] SCAN_ID    = {scan_id}")
    print(f"[scan_metadata] Clone dir  = {clone_dir}")

    tf_files = find_tf_files(clone_dir)

    # Compute a single repository integrity hash from all individual file hashes.
    # Sorting ensures deterministic output regardless of filesystem walk order.
    sorted_hashes = sorted(f["sha256"] for f in tf_files)
    combined = "".join(sorted_hashes)
    repo_integrity_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest() if sorted_hashes else ""

    metadata = {
        "scan_id": scan_id,
        "repo_url": repo_url,
        "branch": branch,
        "generated_at": utcnow_iso(),
        "total_terraform_files": len(tf_files),
        "repository_integrity_hash": repo_integrity_hash,
        "terraform_files": tf_files,
        "evidence_note": (
            "All Terraform files listed above are treated as digital evidence objects. "
            "SHA256 hashes were computed at the time of scan to preserve file integrity. "
            "Any modification after this point will produce a different hash, enabling "
            "tamper detection during forensic investigation. "
            "The repository_integrity_hash is a composite SHA256 derived from the sorted "
            "concatenation of all individual file hashes, providing a single fingerprint "
            "for the entire Terraform codebase at scan time."
        ),
    }

    with open(output_file, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[scan_metadata] Terraform files found = {len(tf_files)}")
    print(f"[scan_metadata] Output     = {output_file}")

    if len(tf_files) == 0:
        print("[scan_metadata] WARNING: No Terraform files found in repository.")


if __name__ == "__main__":
    main()

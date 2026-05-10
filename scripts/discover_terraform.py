"""
scripts/discover_terraform.py

Discover all directories containing .tf files in a cloned repository.

Environment variables:
    SCAN_ID — Unique scan identifier

Input:
    repositories/cloned/<SCAN_ID>/

Output:
    repositories/metadata/<SCAN_ID>/terraform-directories.json
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SKIP_DIRS = {".git", ".terraform", "node_modules"}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def discover_tf_directories(root_dir: str) -> list[dict]:
    """Find all directories that contain at least one .tf file."""
    root = Path(root_dir).resolve()
    tf_dirs: dict[str, list[str]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        tf_files_in_dir = sorted([f for f in filenames if f.endswith(".tf")])
        if tf_files_in_dir:
            abs_dir = os.path.abspath(dirpath)
            tf_dirs[abs_dir] = tf_files_in_dir

    results = []
    for abs_dir in sorted(tf_dirs.keys()):
        rel_dir = os.path.relpath(abs_dir, root)
        if rel_dir == ".":
            rel_dir = "."
        results.append({
            "path": abs_dir,
            "relative_path": rel_dir,
            "tf_file_count": len(tf_dirs[abs_dir]),
            "tf_files": tf_dirs[abs_dir],
        })
    return results


def main():
    scan_id = os.environ.get("SCAN_ID", "")
    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)

    clone_dir = os.path.join("repositories", "cloned", scan_id)
    metadata_dir = os.path.join("repositories", "metadata", scan_id)
    output_file = os.path.join(metadata_dir, "terraform-directories.json")

    os.makedirs(metadata_dir, exist_ok=True)

    if not os.path.isdir(clone_dir):
        print(f"ERROR: Cloned directory not found: {clone_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[discover_terraform] SCAN_ID   = {scan_id}")
    print(f"[discover_terraform] Clone dir = {clone_dir}")

    directories = discover_tf_directories(clone_dir)

    report = {
        "scan_id": scan_id,
        "generated_at": utcnow_iso(),
        "total_directories": len(directories),
        "terraform_directories": directories,
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[discover_terraform] Directories found = {len(directories)}")
    for d in directories:
        print(f"  - {d['relative_path']} ({d['tf_file_count']} files)")
    print(f"[discover_terraform] Output    = {output_file}")

    if len(directories) == 0:
        print("[discover_terraform] WARNING: No Terraform directories found.")


if __name__ == "__main__":
    main()

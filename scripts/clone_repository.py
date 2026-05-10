"""
scripts/clone_repository.py

Clone a GitHub repository into an isolated per-scan directory.

Environment variables:
    REPO_URL  — GitHub repository URL to clone
    BRANCH    — Branch to clone (default: main)
    SCAN_ID   — Unique scan identifier (SCAN-<uuid>)

Output:
    repositories/cloned/<SCAN_ID>/           — cloned repo content
    repositories/metadata/<SCAN_ID>/repository-metadata.json — clone metadata
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_clone(repo_url: str, branch: str, dest: str):
    """Run git clone and return (exit_code, stdout, stderr)."""
    cmd = ["git", "clone", "--depth", "1", "--branch", branch, repo_url, dest]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def main():
    scan_id = os.environ.get("SCAN_ID", "")
    repo_url = os.environ.get("REPO_URL", "")
    branch = os.environ.get("BRANCH", "main")

    if not scan_id:
        print("ERROR: SCAN_ID environment variable is required.", file=sys.stderr)
        sys.exit(1)
    if not repo_url:
        print("ERROR: REPO_URL environment variable is required.", file=sys.stderr)
        sys.exit(1)

    clone_dest = os.path.join("repositories", "cloned", scan_id)
    metadata_dir = os.path.join("repositories", "metadata", scan_id)
    metadata_file = os.path.join(metadata_dir, "repository-metadata.json")

    # If destination already exists, remove it
    if os.path.exists(clone_dest):
        shutil.rmtree(clone_dest)

    os.makedirs(metadata_dir, exist_ok=True)

    print(f"[clone_repository] SCAN_ID   = {scan_id}")
    print(f"[clone_repository] REPO_URL  = {repo_url}")
    print(f"[clone_repository] BRANCH    = {branch}")
    print(f"[clone_repository] DEST      = {clone_dest}")

    clone_started_at = utcnow_iso()
    exit_code, stdout, stderr = run_clone(repo_url, branch, clone_dest)
    clone_completed_at = utcnow_iso()

    clone_status = "SUCCESS" if exit_code == 0 else "FAILED"

    metadata = {
        "scan_id": scan_id,
        "repo_url": repo_url,
        "branch": branch,
        "cloned_path": clone_dest,
        "clone_status": clone_status,
        "clone_started_at": clone_started_at,
        "clone_completed_at": clone_completed_at,
        "git_command_exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }

    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[clone_repository] Status    = {clone_status}")
    print(f"[clone_repository] Metadata  = {metadata_file}")

    if exit_code != 0:
        print(f"[clone_repository] Clone FAILED (exit {exit_code})", file=sys.stderr)
        print(stderr, file=sys.stderr)
        sys.exit(1)

    print("[clone_repository] Clone completed successfully.")


if __name__ == "__main__":
    main()

"""
scripts/utils/evidence.py

Shared forensic-evidence utility functions used across all pipeline scripts.

All functions are designed for safety — they never crash on missing data and
always return sensible defaults so that evidence reports can be generated even
when upstream steps fail.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_file(filepath: str) -> str | None:
    """Compute the SHA-256 hex digest of a file.

    Returns None if the file does not exist or cannot be read.
    """
    if not filepath or not os.path.isfile(filepath):
        return None
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# JSON I/O
# ---------------------------------------------------------------------------

def safe_read_json(path: str) -> dict | list | None:
    """Read and parse a JSON file.

    Returns None on any error (missing file, empty file, invalid JSON).
    """
    if not path or not os.path.isfile(path):
        return None
    try:
        size = os.path.getsize(path)
        if size == 0:
            return None
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def safe_write_json(path: str, data, *, indent: int = 2) -> bool:
    """Write data as pretty-printed JSON to *path*.

    Creates parent directories automatically.  Returns True on success.
    """
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=indent)
        return True
    except OSError as exc:
        print(f"[evidence] ERROR: Could not write {path}: {exc}")
        return False


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------

def generate_finding_id() -> str:
    """Generate a unique finding identifier (UUID4 string)."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# GitHub Actions metadata
# ---------------------------------------------------------------------------

def collect_github_metadata() -> dict:
    """Collect contextual metadata from GitHub Actions environment variables.

    Returns a dict of available metadata.  Missing variables are set to None.
    """
    return {
        "repository_url": os.environ.get("REPO_URL"),
        "branch": os.environ.get("BRANCH"),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_number": os.environ.get("GITHUB_RUN_NUMBER"),
        "actor": os.environ.get("GITHUB_ACTOR"),
    }


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------

def normalize_path(path: str | None) -> str:
    """Normalise a file path for consistent evidence records.

    Strips leading '/' or './' so that paths are relative.
    Returns an empty string for None / empty input.
    """
    if not path:
        return ""
    return path.lstrip("/").lstrip("./")

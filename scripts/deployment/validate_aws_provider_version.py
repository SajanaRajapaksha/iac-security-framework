#!/usr/bin/env python3
"""
scripts/deployment/validate_aws_provider_version.py

Reads .terraform.lock.hcl after `terraform init` and verifies the selected
HashiCorp AWS provider version is >= 5.62.0.

Environment-based AWS provider default tags (TF_AWS_DEFAULT_TAGS_*) require
AWS provider >= 5.62.0.  This script enforces that constraint before planning.

Usage:
    python scripts/deployment/validate_aws_provider_version.py <SCAN_ID> <TF_ROOT>

Arguments:
    SCAN_ID   — Unique scan identifier.
    TF_ROOT   — Absolute path to the Terraform deployment root directory
                (contains .terraform.lock.hcl after terraform init).

Output:
    reports/deployment/<SCAN_ID>/aws-provider-validation.json
"""

import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_write_json, utc_now_iso

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MINIMUM_VERSION = "5.62.0"
REQUIRED_PROVIDER = "registry.terraform.io/hashicorp/aws"


# ---------------------------------------------------------------------------
# Semantic version comparison
# ---------------------------------------------------------------------------

def _parse_version(version_str: str) -> tuple[int, ...]:
    """
    Parse a semantic version string into a comparable tuple of ints.

    Supports: "5.62.0", "6.0.0", "5.62.0-beta.1" (pre-release stripped).
    Raises ValueError for unparseable input.
    """
    # Strip optional leading 'v' and any pre-release suffix after '-'
    clean = version_str.strip().lstrip("v").split("-")[0]
    parts = clean.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        raise ValueError(f"Cannot parse version: {version_str!r}")
    return tuple(int(p) for p in parts)


def version_gte(version_str: str, minimum_str: str) -> bool:
    """Return True if version_str >= minimum_str, False otherwise."""
    return _parse_version(version_str) >= _parse_version(minimum_str)


# ---------------------------------------------------------------------------
# Lock file parser
# ---------------------------------------------------------------------------

# Matches a provider block: provider "registry.terraform.io/hashicorp/aws" {
RE_PROVIDER_BLOCK = re.compile(
    r'provider\s+"([^"]+)"\s*\{([^}]*)\}',
    re.DOTALL,
)

# Extracts:  version = "5.62.0"
RE_VERSION_LINE = re.compile(r'version\s*=\s*"([^"]+)"')


def parse_lock_file(lock_content: str) -> dict[str, str]:
    """
    Parse a .terraform.lock.hcl and return {provider_source: version}.

    Only extracts the top-level provider block version (not hashes).
    """
    providers: dict[str, str] = {}
    for match in RE_PROVIDER_BLOCK.finditer(lock_content):
        provider_source = match.group(1).strip()
        block_body = match.group(2)
        version_match = RE_VERSION_LINE.search(block_body)
        if version_match:
            providers[provider_source] = version_match.group(1).strip()
    return providers


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 3:
        print(
            "Usage: validate_aws_provider_version.py <SCAN_ID> <TF_ROOT>",
            file=sys.stderr,
        )
        sys.exit(1)

    scan_id: str = sys.argv[1]
    tf_root = Path(sys.argv[2])

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "aws-provider-validation.json"

    def _fail(error_code: str, message: str, extra: dict | None = None) -> None:
        result = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "generated_at_utc": utc_now_iso(),
            "status": "FAIL",
            "error": error_code,
            "provider": REQUIRED_PROVIDER,
            "minimum_version": MINIMUM_VERSION,
            "environment_default_tags_supported": False,
            "message": message,
            **(extra or {}),
        }
        safe_write_json(str(out_path), result)

        print(f"\n{'='*60}")
        print(f"  AWS_PROVIDER_VERSION_UNSUPPORTED")
        print(f"{'='*60}")
        print(f"  SCAN_ID              : {scan_id}")
        print(f"  Selected Provider    : {REQUIRED_PROVIDER}")
        print(f"  Selected Version     : {extra.get('selected_version', 'N/A') if extra else 'N/A'}")
        print(f"  Required Version     : >= {MINIMUM_VERSION}")
        print(f"  Tag Injection Mode   : TF_AWS_DEFAULT_TAGS")
        print(f"  Error                : {error_code}")
        print(f"  Result               : BLOCKED")
        print(f"{'='*60}\n")
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # 1. Locate .terraform.lock.hcl                                       #
    # ------------------------------------------------------------------ #
    lock_file = tf_root / ".terraform.lock.hcl"
    if not lock_file.is_file():
        _fail(
            "LOCK_FILE_NOT_FOUND",
            f".terraform.lock.hcl not found at {lock_file}. "
            "Ensure `terraform init` completed successfully before running this check.",
        )

    try:
        lock_content = lock_file.read_text(encoding="utf-8")
    except OSError as exc:
        _fail("LOCK_FILE_READ_ERROR", f"Cannot read lock file: {exc}")

    # ------------------------------------------------------------------ #
    # 2. Parse providers                                                  #
    # ------------------------------------------------------------------ #
    providers = parse_lock_file(lock_content)

    if REQUIRED_PROVIDER not in providers:
        _fail(
            "AWS_PROVIDER_NOT_FOUND",
            f"{REQUIRED_PROVIDER} not found in .terraform.lock.hcl. "
            f"Providers found: {list(providers.keys())}",
            {"providers_found": list(providers.keys())},
        )

    selected_version = providers[REQUIRED_PROVIDER]

    # ------------------------------------------------------------------ #
    # 3. Semantic version check                                           #
    # ------------------------------------------------------------------ #
    try:
        supported = version_gte(selected_version, MINIMUM_VERSION)
    except ValueError as exc:
        _fail(
            "VERSION_PARSE_ERROR",
            f"Cannot parse selected provider version '{selected_version}': {exc}",
            {"selected_version": selected_version},
        )

    if not supported:
        _fail(
            "AWS_PROVIDER_VERSION_TOO_OLD",
            f"AWS provider {selected_version} is below the minimum required "
            f"{MINIMUM_VERSION} for TF_AWS_DEFAULT_TAGS environment variable support. "
            "Update the AWS provider version in the target Terraform configuration.",
            {"selected_version": selected_version},
        )

    # ------------------------------------------------------------------ #
    # 4. Success                                                          #
    # ------------------------------------------------------------------ #
    result = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "status": "PASS",
        "provider": REQUIRED_PROVIDER,
        "selected_version": selected_version,
        "minimum_version": MINIMUM_VERSION,
        "environment_default_tags_supported": True,
    }
    safe_write_json(str(out_path), result)

    print(f"\n{'='*60}")
    print(f"  AWS PROVIDER VERSION — PASS")
    print(f"{'='*60}")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  Provider             : {REQUIRED_PROVIDER}")
    print(f"  Selected Version     : {selected_version}")
    print(f"  Required Version     : >= {MINIMUM_VERSION}")
    print(f"  TF_AWS_DEFAULT_TAGS  : SUPPORTED")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

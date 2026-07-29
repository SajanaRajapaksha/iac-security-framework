#!/usr/bin/env python3
"""
scripts/deployment/validate_deployment_contract.py

Validates that a Terraform deployment source satisfies the framework's
controlled deployment contract before Terraform plan is executed.

Requirements:
    1. Exactly one Terraform root directory.
    2. variable "scan_id"   declaration present.
    3. variable "aws_region" declaration present.
    4. AWS provider default_tags containing scan-id and managed-by references.

If the contract is not met, the script fails with a clear message.
Scanning arbitrary Terraform repositories remains supported — only controlled
AWS deployment requires this contract.

Usage:
    python scripts/deployment/validate_deployment_contract.py <SCAN_ID>

Environment variables:
    SCAN_ID  — also accepted from env if not provided as CLI argument.
"""

import argparse
import os
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


# ---------------------------------------------------------------------------
# Contract patterns (regex on .tf file content)
# ---------------------------------------------------------------------------

# Match:  variable "scan_id" {
RE_VAR_SCAN_ID = re.compile(
    r'^\s*variable\s+"scan_id"\s*\{', re.MULTILINE
)

# Match:  variable "aws_region" {
RE_VAR_AWS_REGION = re.compile(
    r'^\s*variable\s+"aws_region"\s*\{', re.MULTILINE
)

# Match:  scan-id  (inside a default_tags block — loose match for presence)
RE_TAG_SCAN_ID = re.compile(
    r'scan-id\s*=', re.MULTILINE
)

# Match:  managed-by  (inside a default_tags block)
RE_TAG_MANAGED_BY = re.compile(
    r'managed-by\s*=', re.MULTILINE
)

# Match: default_tags {  (to confirm we're inside a provider aws block)
RE_DEFAULT_TAGS = re.compile(
    r'default_tags\s*\{', re.MULTILINE
)


def read_all_tf_content(tf_root: str) -> str:
    """Concatenate all .tf file contents from a directory (non-recursive)."""
    content_parts: list[str] = []
    root = Path(tf_root)
    for tf_file in sorted(root.glob("*.tf")):
        try:
            content_parts.append(tf_file.read_text(encoding="utf-8"))
        except OSError:
            continue
    return "\n".join(content_parts)


def validate_contract(tf_root: str) -> dict:
    """Check deployment contract requirements against .tf files in *tf_root*.

    Returns a dict with check results and failure details.
    """
    all_content = read_all_tf_content(tf_root)

    checks = {
        "variable_scan_id": bool(RE_VAR_SCAN_ID.search(all_content)),
        "variable_aws_region": bool(RE_VAR_AWS_REGION.search(all_content)),
        "default_tags_block": bool(RE_DEFAULT_TAGS.search(all_content)),
        "default_tags_scan_id": bool(
            RE_DEFAULT_TAGS.search(all_content) and RE_TAG_SCAN_ID.search(all_content)
        ),
        "default_tags_managed_by": bool(
            RE_DEFAULT_TAGS.search(all_content) and RE_TAG_MANAGED_BY.search(all_content)
        ),
    }

    failures: list[str] = []
    if not checks["variable_scan_id"]:
        failures.append('Missing: variable "scan_id" { ... }')
    if not checks["variable_aws_region"]:
        failures.append('Missing: variable "aws_region" { ... }')
    if not checks["default_tags_block"]:
        failures.append("Missing: provider aws { default_tags { ... } }")
    if not checks["default_tags_scan_id"]:
        failures.append('Missing: default_tags must include scan-id = var.scan_id')
    if not checks["default_tags_managed_by"]:
        failures.append('Missing: default_tags must include managed-by = "iac-security-framework"')

    status = "PASS" if not failures else "FAIL"
    return {"checks": checks, "failures": failures, "status": status}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate Terraform deployment contract for the IaC Security Framework."
    )
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    args = parser.parse_args()
    scan_id: str = args.scan_id

    # ------------------------------------------------------------------ #
    # Locate Terraform roots using existing discovery data                #
    # ------------------------------------------------------------------ #
    metadata_dir = ROOT_DIR / "repositories" / "metadata" / scan_id
    discovery_path = metadata_dir / "terraform-directories.json"

    # Also check deployment-source location (terraform-plan job context)
    deployment_source_discovery = Path("deployment-source") / "repositories" / "metadata" / scan_id / "terraform-directories.json"

    discovery = safe_read_json(str(discovery_path))
    if not isinstance(discovery, dict):
        # Try deployment-source context
        discovery = safe_read_json(str(deployment_source_discovery))

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)

    if not isinstance(discovery, dict):
        error_result = {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "status": "FAIL",
            "error": "NO_DISCOVERY_DATA",
            "message": (
                "terraform-directories.json not found. "
                "Ensure Terraform directory discovery (Stage 3) completed."
            ),
        }
        safe_write_json(str(deploy_dir / "deployment-contract-validation.json"), error_result)
        print(f"[deployment_contract] ERROR: Discovery data not found for {scan_id}", file=sys.stderr)
        sys.exit(1)

    tf_dirs = discovery.get("terraform_directories", [])

    # ------------------------------------------------------------------ #
    # Check: exactly one Terraform root                                   #
    # ------------------------------------------------------------------ #
    if len(tf_dirs) == 0:
        result = {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "status": "FAIL",
            "error": "NO_TERRAFORM_ROOTS",
            "message": "No Terraform root directories were discovered.",
            "discovered_roots": 0,
            "deployment_root": None,
        }
        safe_write_json(str(deploy_dir / "deployment-contract-validation.json"), result)
        print(f"\n{'='*60}")
        print(f"  DEPLOYMENT_CONTRACT_FAILED")
        print(f"{'='*60}")
        print(f"  SCAN_ID: {scan_id}")
        print(f"  Error: NO_TERRAFORM_ROOTS")
        print(f"  No Terraform root directories were discovered.")
        print(f"{'='*60}\n")
        sys.exit(1)

    if len(tf_dirs) > 1:
        root_paths = [d.get("relative_path", d.get("path", "?")) for d in tf_dirs]
        result = {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "status": "FAIL",
            "error": "MULTIPLE_TERRAFORM_ROOTS",
            "message": (
                f"{len(tf_dirs)} Terraform roots were discovered. "
                "Automatic AWS deployment is disabled because a unique "
                "deployment target could not be determined."
            ),
            "discovered_roots": len(tf_dirs),
            "roots": root_paths,
            "deployment_root": None,
        }
        safe_write_json(str(deploy_dir / "deployment-contract-validation.json"), result)
        print(f"\n{'='*60}")
        print(f"  DEPLOYMENT_CONTRACT_FAILED")
        print(f"{'='*60}")
        print(f"  SCAN_ID: {scan_id}")
        print(f"  Error: MULTIPLE_TERRAFORM_ROOTS")
        print(f"  {len(tf_dirs)} Terraform roots were discovered.")
        print(f"")
        for rp in root_paths:
            print(f"    - {rp}")
        print(f"")
        print(f"  Automatic AWS deployment is disabled because a unique")
        print(f"  deployment target could not be determined.")
        print(f"{'='*60}\n")
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # Single root — validate contract                                     #
    # ------------------------------------------------------------------ #
    tf_root_entry = tf_dirs[0]
    tf_root_path = tf_root_entry.get("path", "")
    tf_root_relative = tf_root_entry.get("relative_path", ".")

    if not os.path.isdir(tf_root_path):
        # In the terraform-plan job, the deployment source artifact was downloaded
        # to deployment-source/.  The artifact upload was:
        #   path: repositories/cloned/<SCAN_ID>/
        # so the repo contents land directly at deployment-source/ (the SCAN_ID
        # prefix is stripped by the artifact mechanism).
        #
        # relative_path from discovery is relative to the clone root, e.g. "." or
        # "modules/vpc".  So the actual path on the plan runner is:
        #   deployment-source/<relative_path>
        cwd = Path.cwd()

        # Normalise relative_path — "." means the clone root itself
        if tf_root_relative in (".", ""):
            candidate = cwd / "deployment-source"
        else:
            candidate = cwd / "deployment-source" / tf_root_relative

        if candidate.is_dir():
            tf_root_path = str(candidate)
        else:
            # Emit helpful diagnostics before failing
            print(f"[deployment_contract] CWD = {cwd}", file=sys.stderr)
            print(f"[deployment_contract] Expected original path : {tf_root_path}", file=sys.stderr)
            print(f"[deployment_contract] Tried fallback path    : {candidate}", file=sys.stderr)
            # List deployment-source/ contents to aid debugging
            ds = cwd / "deployment-source"
            if ds.is_dir():
                children = [p.name for p in sorted(ds.iterdir())]
                print(f"[deployment_contract] deployment-source/ contents: {children}", file=sys.stderr)
            else:
                print(f"[deployment_contract] deployment-source/ does not exist", file=sys.stderr)

            error_result = {
                "scan_id": scan_id,
                "generated_at": utc_now_iso(),
                "status": "FAIL",
                "error": "TERRAFORM_ROOT_NOT_FOUND",
                "message": (
                    f"Terraform root not found. "
                    f"Original path: {tf_root_entry.get('path', '')} | "
                    f"Fallback tried: {candidate}"
                ),
            }
            safe_write_json(str(deploy_dir / "deployment-contract-validation.json"), error_result)
            print(f"[deployment_contract] ERROR: TF root not found: {tf_root_path}", file=sys.stderr)
            sys.exit(1)

    contract = validate_contract(tf_root_path)
    warnings: list[str] = []

    result = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "status": contract["status"],
        "deployment_root": tf_root_path,
        "deployment_root_relative": tf_root_relative,
        "discovered_roots": 1,
        "checks": contract["checks"],
        "failures": contract["failures"],
        "warnings": warnings,
    }

    safe_write_json(str(deploy_dir / "deployment-contract-validation.json"), result)

    # ------------------------------------------------------------------ #
    # Console output                                                      #
    # ------------------------------------------------------------------ #
    print(f"\n{'='*60}")
    if contract["status"] == "PASS":
        print(f"  DEPLOYMENT CONTRACT — PASS")
    else:
        print(f"  DEPLOYMENT_CONTRACT_FAILED")
    print(f"{'='*60}")
    print(f"  SCAN_ID          : {scan_id}")
    print(f"  Deployment Root  : {tf_root_relative}")
    print(f"  Status           : {contract['status']}")
    print()
    for name, passed in contract["checks"].items():
        mark = "✓" if passed else "✗"
        print(f"    {mark} {name}")
    print()

    if contract["failures"]:
        print(f"  Required framework tagging configuration was not detected.")
        print(f"")
        print(f"  Required tags:")
        print(f"    scan-id=<SCAN_ID>")
        print(f'    managed-by=iac-security-framework')
        print(f"")
        print(f"  Terraform source remains valid for security scanning")
        print(f"  but is not eligible for controlled AWS deployment.")
        print(f"{'='*60}\n")
        sys.exit(1)

    print(f"  Terraform source is eligible for controlled AWS deployment.")
    print(f"{'='*60}\n")

    # Write deployment root to GITHUB_OUTPUT if available
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as fh:
            fh.write(f"deployment_root={tf_root_path}\n")
            fh.write(f"deployment_root_relative={tf_root_relative}\n")


if __name__ == "__main__":
    main()

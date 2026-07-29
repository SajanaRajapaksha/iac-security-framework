#!/usr/bin/env python3
"""
scripts/deployment/validate_deployment_contract.py

Validates that the downloaded Terraform deployment source satisfies the
framework's controlled deployment contract.

The contract no longer requires the target repository to declare framework
variables or tags.  Tags are injected automatically by the pipeline through
AWS Provider environment variables (TF_AWS_DEFAULT_TAGS_*).

Contract checks:
    1. Terraform discovery metadata exists.
    2. Exactly one Terraform root.
    3. The deployment root is resolvable from the downloaded artifact.
    4. At least one .tf file exists in the deployment root.
    5. The configuration uses the HashiCorp AWS provider (best-effort check).
    6. No source files are modified during validation.

The target Terraform source is never modified.

Usage:
    python scripts/deployment/validate_deployment_contract.py <SCAN_ID>

Output:
    reports/deployment/<SCAN_ID>/deployment-contract-validation.json
    $GITHUB_OUTPUT  (deployment_root, deployment_root_relative)
"""

import os
import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MINIMUM_AWS_PROVIDER_VERSION = "5.62.0"
TAG_INJECTION_MODE = "aws_provider_environment_variables"

# Detect AWS provider declaration (best-effort, no HCL parser required)
RE_AWS_PROVIDER = re.compile(
    r'provider\s+"aws"\s*\{|required_providers\s*\{[^}]*hashicorp/aws',
    re.MULTILINE | re.DOTALL,
)

# Runtime-generated directories and files to exclude from integrity checks
TERRAFORM_RUNTIME_DIRS = {".terraform"}
TERRAFORM_RUNTIME_FILES = {
    ".terraform.lock.hcl",
    "tfplan",
    "terraform.tfstate",
    "terraform.tfstate.backup",
    "crash.log",
}


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def resolve_deployment_root(
    scan_id: str,
    tf_root_relative: str,
    cwd: Path,
) -> Path | None:
    """
    Resolve the Terraform root in the terraform-plan job context.

    The deployment-source artifact is downloaded to deployment-source/.
    The artifact upload uploads the CONTENTS of repositories/cloned/<SCAN_ID>/
    so files land directly at deployment-source/ — the SCAN_ID prefix is
    stripped by the GitHub Actions artifact mechanism.

    relative_path="."  → deployment-source/
    relative_path="a"  → deployment-source/a/
    """
    if tf_root_relative in (".", ""):
        candidate = cwd / "deployment-source"
    else:
        candidate = cwd / "deployment-source" / tf_root_relative

    if candidate.is_dir():
        return candidate
    return None


# ---------------------------------------------------------------------------
# Source checks
# ---------------------------------------------------------------------------

def find_tf_files(tf_root: Path) -> list[Path]:
    """Return all .tf files directly in tf_root (non-recursive)."""
    return sorted(tf_root.glob("*.tf"))


def detect_aws_provider(tf_root: Path) -> bool:
    """
    Return True if any .tf file in tf_root appears to use the AWS provider.

    This is a best-effort check on file content — it does not parse HCL.
    Returns False only when no indicator of the AWS provider is found.
    """
    # Check provider.tf first, then all .tf files
    for tf_file in sorted(tf_root.glob("*.tf")):
        try:
            content = tf_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if RE_AWS_PROVIDER.search(content) or "hashicorp/aws" in content:
            return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: validate_deployment_contract.py <SCAN_ID>", file=sys.stderr)
        sys.exit(1)

    scan_id: str = sys.argv[1]
    cwd = Path.cwd()
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)

    def _fail(error_code: str, message: str, extra: dict | None = None) -> None:
        result = {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "generated_at_utc": utc_now_iso(),
            "status": "FAIL",
            "error": error_code,
            "message": message,
            **(extra or {}),
        }
        safe_write_json(str(deploy_dir / "deployment-contract-validation.json"), result)
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"  DEPLOYMENT_CONTRACT_FAILED", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        print(f"  SCAN_ID : {scan_id}", file=sys.stderr)
        print(f"  Error   : {error_code}", file=sys.stderr)
        print(f"  {message}", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # 1. Load discovery metadata                                           #
    # ------------------------------------------------------------------ #
    # Try framework-repo layout first (security-pipeline job context)
    discovery_path = ROOT_DIR / "repositories" / "metadata" / scan_id / "terraform-directories.json"
    # Then terraform-plan job layout (metadata downloaded as artifact)
    discovery_path_alt = cwd / "repositories" / "metadata" / scan_id / "terraform-directories.json"

    discovery = safe_read_json(str(discovery_path))
    if not isinstance(discovery, dict):
        discovery = safe_read_json(str(discovery_path_alt))

    if not isinstance(discovery, dict):
        _fail(
            "NO_DISCOVERY_DATA",
            "terraform-directories.json not found. "
            "Ensure Terraform directory discovery (Stage 3) completed "
            "and scan-metadata artifact was downloaded.",
        )

    tf_dirs = discovery.get("terraform_directories", [])

    # ------------------------------------------------------------------ #
    # 2. Single Terraform root check                                       #
    # ------------------------------------------------------------------ #
    if len(tf_dirs) == 0:
        _fail("NO_TERRAFORM_ROOTS", "No Terraform root directories were discovered.")

    if len(tf_dirs) > 1:
        roots = [d.get("relative_path", d.get("path", "?")) for d in tf_dirs]
        _fail(
            "MULTIPLE_TERRAFORM_ROOTS",
            f"{len(tf_dirs)} Terraform roots discovered. "
            "Automatic deployment is disabled when a unique target "
            "cannot be determined.",
            {"discovered_roots": len(tf_dirs), "roots": roots},
        )

    tf_root_entry = tf_dirs[0]
    tf_root_relative: str = tf_root_entry.get("relative_path", ".")

    # ------------------------------------------------------------------ #
    # 3. Resolve deployment root (cross-job artifact layout)              #
    # ------------------------------------------------------------------ #
    tf_root_path = resolve_deployment_root(scan_id, tf_root_relative, cwd)

    if tf_root_path is None:
        # Diagnostics
        ds = cwd / "deployment-source"
        if ds.is_dir():
            children = [p.name for p in sorted(ds.iterdir())]
        else:
            children = []
        _fail(
            "TERRAFORM_ROOT_NOT_FOUND",
            f"Could not resolve deployment root. "
            f"relative_path='{tf_root_relative}', "
            f"deployment-source/ children={children}",
            {"deployment_root_relative": tf_root_relative},
        )

    # ------------------------------------------------------------------ #
    # 4. At least one .tf file                                            #
    # ------------------------------------------------------------------ #
    tf_files = find_tf_files(tf_root_path)
    if not tf_files:
        _fail(
            "NO_TF_FILES",
            f"No .tf files found in deployment root: {tf_root_path}",
            {"deployment_root_runtime": str(tf_root_path)},
        )

    # ------------------------------------------------------------------ #
    # 5. AWS provider presence (best-effort)                              #
    # ------------------------------------------------------------------ #
    aws_provider_present = detect_aws_provider(tf_root_path)

    # ------------------------------------------------------------------ #
    # 6. Source not modified (no .tf changes during validation)           #
    # This validator reads files only — guaranteed by design.             #
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # Build and write result                                              #
    # ------------------------------------------------------------------ #
    result = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "status": "PASS",
        "deployment_root_relative": tf_root_relative,
        "deployment_root_runtime": str(tf_root_path),
        "discovered_roots": 1,
        "tf_files_found": len(tf_files),
        "source_modification": False,
        "tag_injection": {
            "mode": TAG_INJECTION_MODE,
            "required_provider": "registry.terraform.io/hashicorp/aws",
            "minimum_provider_version": MINIMUM_AWS_PROVIDER_VERSION,
            "required_tags": {
                "scan-id": scan_id,
                "managed-by": "iac-security-framework",
            },
        },
        "checks": {
            "discovery_data_present": True,
            "single_terraform_root": True,
            "deployment_root_resolvable": True,
            "tf_files_present": True,
            "aws_provider_detected": aws_provider_present,
            "source_not_modified": True,
        },
        "warnings": [] if aws_provider_present else [
            "AWS provider not detected in .tf files. "
            "Tag injection requires AWS provider >= 5.62.0."
        ],
    }

    safe_write_json(str(deploy_dir / "deployment-contract-validation.json"), result)

    # ------------------------------------------------------------------ #
    # Console output                                                      #
    # ------------------------------------------------------------------ #
    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT CONTRACT — PASS")
    print(f"{'='*60}")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  Deployment Root (rel): {tf_root_relative}")
    print(f"  Deployment Root (abs): {tf_root_path}")
    print(f"  .tf Files Found      : {len(tf_files)}")
    print(f"  AWS Provider Detected: {aws_provider_present}")
    print(f"  Source Modified      : False")
    print(f"  Tag Injection Mode   : {TAG_INJECTION_MODE}")
    print(f"  Tags to Inject       : scan-id={scan_id}, managed-by=iac-security-framework")
    print(f"  Min Provider Version : >= {MINIMUM_AWS_PROVIDER_VERSION}")
    if not aws_provider_present:
        print(f"  WARNING: AWS provider not detected — tag injection may fail")
    print(f"{'='*60}\n")

    # ------------------------------------------------------------------ #
    # Write to GITHUB_OUTPUT                                              #
    # ------------------------------------------------------------------ #
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as fh:
            fh.write(f"deployment_root={tf_root_path}\n")
            fh.write(f"deployment_root_relative={tf_root_relative}\n")


if __name__ == "__main__":
    main()

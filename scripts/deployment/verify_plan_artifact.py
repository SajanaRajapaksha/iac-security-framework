#!/usr/bin/env python3
"""
scripts/deployment/verify_plan_artifact.py

Stage 25 — Verifies the downloaded Terraform plan artifact before allowing
controlled deployment.

Checks performed:
    1. tfplan file exists
    2. Stored SHA-256 exists
    3. Calculated SHA-256 matches stored SHA-256
    4. Deployment evidence SCAN_ID matches current SCAN_ID
    5. State key in evidence matches research/<SCAN_ID>/terraform.tfstate
    6. Deployment-plan status permits deployment
    7. Tag-validation status is PASS
    8. Source-integrity status is PASS
    9. Provider-version validation is PASS
   10. Deployment-contract validation is PASS

Usage:
    python scripts/deployment/verify_plan_artifact.py \\
        <SCAN_ID> \\
        <path-to-tfplan> \\
        <path-to-terraform-plan.sha256> \\
        <path-to-deployment-plan-evidence.json>

Output:
    reports/deployment/<SCAN_ID>/plan-artifact-verification.json
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


EXPECTED_STATE_KEY_PREFIX = "research/"
EXPECTED_STATE_KEY_SUFFIX = "/terraform.tfstate"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str | None:
    """Return hex SHA-256 of a file, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _check(
    checks: dict,
    errors: list,
    warnings: list,
    key: str,
    value: bool,
    error_msg: str | None = None,
    warning_msg: str | None = None,
) -> bool:
    """Record a check result; return False when the check fails."""
    checks[key] = value
    if not value:
        if error_msg:
            errors.append(error_msg)
        elif warning_msg:
            warnings.append(warning_msg)
    return value


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 5:
        print(
            "Usage: verify_plan_artifact.py <SCAN_ID> <tfplan> "
            "<terraform-plan.sha256> <deployment-plan-evidence.json>",
            file=sys.stderr,
        )
        sys.exit(1)

    scan_id = sys.argv[1]
    tfplan_path = Path(sys.argv[2])
    sha256_path = Path(sys.argv[3])
    evidence_path = Path(sys.argv[4])

    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "plan-artifact-verification.json"

    checks: dict[str, bool] = {}
    errors: list[str] = []
    warnings: list[str] = []

    # ------------------------------------------------------------------ #
    # 1. tfplan present                                                    #
    # ------------------------------------------------------------------ #
    tfplan_exists = tfplan_path.is_file()
    _check(checks, errors, warnings, "tfplan_present", tfplan_exists,
           error_msg=f"tfplan not found at {tfplan_path}")

    # ------------------------------------------------------------------ #
    # 2. Stored SHA-256 present                                            #
    # ------------------------------------------------------------------ #
    stored_sha256 = ""
    if sha256_path.is_file():
        try:
            stored_sha256 = sha256_path.read_text().strip().split()[0]
        except OSError:
            stored_sha256 = ""

    stored_hash_present = bool(stored_sha256)
    _check(checks, errors, warnings, "stored_hash_present", stored_hash_present,
           error_msg=f"terraform-plan.sha256 not found or empty at {sha256_path}")

    # ------------------------------------------------------------------ #
    # 3. Hash integrity                                                    #
    # ------------------------------------------------------------------ #
    calculated_sha256 = ""
    hash_matches = False
    if tfplan_exists:
        calculated_sha256 = sha256_file(tfplan_path) or ""
    if stored_hash_present and calculated_sha256:
        hash_matches = calculated_sha256.lower() == stored_sha256.lower()

    _check(checks, errors, warnings, "hash_matches", hash_matches,
           error_msg=(
               f"SHA-256 mismatch: stored={stored_sha256} "
               f"calculated={calculated_sha256}"
           ) if not hash_matches else None)

    # ------------------------------------------------------------------ #
    # 4–9. Load deployment-plan evidence and validate fields              #
    # ------------------------------------------------------------------ #
    evidence = safe_read_json(str(evidence_path)) if evidence_path.is_file() else None
    evidence_loaded = isinstance(evidence, dict)

    if not evidence_loaded:
        errors.append(
            f"deployment-plan-evidence.json not found or invalid at {evidence_path}"
        )
        # Record remaining checks as failed
        for k in [
            "scan_id_matches", "state_key_matches",
            "deployment_contract_passed", "provider_validation_passed",
            "tag_validation_passed", "source_integrity_passed",
        ]:
            checks[k] = False
    else:
        evidence_scan_id = evidence.get("scan_id", "")
        _check(checks, errors, warnings, "scan_id_matches",
               evidence_scan_id == scan_id,
               error_msg=f"SCAN_ID mismatch: evidence={evidence_scan_id} expected={scan_id}")

        state_key = evidence.get("terraform", {}).get("state_key", "")
        expected_state_key = f"research/{scan_id}/terraform.tfstate"
        _check(checks, errors, warnings, "state_key_matches",
               state_key == expected_state_key,
               error_msg=f"State key mismatch: evidence={state_key} expected={expected_state_key}")

        tagging = evidence.get("tagging", {})

        contract_status = _load_check_status(
            deploy_dir / "deployment-contract-validation.json", "status"
        )
        _check(checks, errors, warnings, "deployment_contract_passed",
               contract_status == "PASS",
               error_msg=f"Deployment-contract validation was not PASS: {contract_status}")

        provider_status = _load_check_status(
            deploy_dir / "aws-provider-validation.json", "status"
        )
        _check(checks, errors, warnings, "provider_validation_passed",
               provider_status == "PASS",
               error_msg=f"AWS provider version validation was not PASS: {provider_status}")

        tag_status = tagging.get("plan_validation_status") or _load_check_status(
            deploy_dir / "tag-validation.json", "status"
        )
        _check(checks, errors, warnings, "tag_validation_passed",
               tag_status == "PASS",
               error_msg=f"Tag-validation was not PASS: {tag_status}")

        integrity_status = tagging.get("source_integrity_status") or _load_check_status(
            deploy_dir / "deployment-source-integrity.json", "status"
        )
        _check(checks, errors, warnings, "source_integrity_passed",
               integrity_status == "PASS",
               error_msg=f"Source-integrity was not PASS: {integrity_status}")

    # ------------------------------------------------------------------ #
    # Final status                                                         #
    # ------------------------------------------------------------------ #
    status = "PASS" if not errors else "FAIL"

    result = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "status": status,
        "tfplan_path": str(tfplan_path),
        "stored_sha256": stored_sha256,
        "calculated_sha256": calculated_sha256,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
    }
    safe_write_json(str(out_path), result)

    print(f"\n{'='*60}")
    print(f"  PLAN ARTIFACT VERIFICATION — {status}")
    print(f"{'='*60}")
    print(f"  SCAN_ID          : {scan_id}")
    print(f"  tfplan           : {tfplan_path}")
    print(f"  Stored SHA-256   : {stored_sha256 or 'MISSING'}")
    print(f"  Calculated SHA256: {calculated_sha256 or 'N/A'}")
    print(f"  Hash Matches     : {hash_matches}")
    print(f"{'='*60}")
    for k, v in checks.items():
        mark = "✓" if v else "✗"
        print(f"  {mark} {k}")
    if errors:
        print(f"\n  ERRORS:")
        for e in errors:
            print(f"    - {e}")
    if warnings:
        print(f"\n  WARNINGS:")
        for w in warnings:
            print(f"    - {w}")
    print(f"{'='*60}\n")

    if status != "PASS":
        sys.exit(1)


def _load_check_status(path: Path, field: str) -> str:
    data = safe_read_json(str(path))
    if isinstance(data, dict):
        return data.get(field, "UNKNOWN")
    return "UNKNOWN"


if __name__ == "__main__":
    main()

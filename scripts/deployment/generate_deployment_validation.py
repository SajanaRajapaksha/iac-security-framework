#!/usr/bin/env python3
"""
scripts/deployment/generate_deployment_validation.py

Stage 33 — Generates the final deployment validation decision by aggregating:
    - deployment-apply-evidence.json
    - terraform-state-resource-inventory.json
    - tagged-aws-resource-inventory.json
    - deployment-resource-reconciliation.json
    - deployed-resource-verification.json

Decision values:
    PASS                — Apply succeeded, all supported resources verified, tags valid
    PASS_WITH_WARNINGS  — Apply succeeded, some unsupported, no confirmed missing
    REVIEW_REQUIRED     — Apply succeeded, some unverifiable, no confirmed failure
    FAIL                — Apply failed, resources confirmed missing, or tags invalid

Usage:
    python scripts/deployment/generate_deployment_validation.py <SCAN_ID>

Output:
    reports/deployment/<SCAN_ID>/deployment-validation.json
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


def _load(deploy_dir: Path, filename: str) -> dict:
    data = safe_read_json(str(deploy_dir / filename))
    return data if isinstance(data, dict) else {}


def decide(
    apply_evidence: dict,
    state_inventory: dict,
    tagged_inventory: dict,
    reconciliation: dict,
    verification: dict,
) -> tuple[str, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    # ------------------------------------------------------------------ #
    # Apply outcome                                                       #
    # ------------------------------------------------------------------ #
    deployment_status = apply_evidence.get("deployment_status", "UNKNOWN")
    apply_exit_code = apply_evidence.get("terraform", {}).get("apply_exit_code", -1)

    if deployment_status != "APPLY_SUCCESS" or apply_exit_code != 0:
        errors.append(
            f"Terraform apply did not succeed: "
            f"deployment_status={deployment_status} exit_code={apply_exit_code}"
        )
        return "FAIL", errors, warnings

    # ------------------------------------------------------------------ #
    # Resource verification summary                                       #
    # ------------------------------------------------------------------ #
    verif_summary = verification.get("summary", {})
    not_found = verif_summary.get("NOT_FOUND", 0)
    verified = verif_summary.get("VERIFIED", 0)
    verified_warn = verif_summary.get("VERIFIED_WITH_WARNING", 0)
    unsupported = verif_summary.get("UNSUPPORTED", 0)
    access_denied = verif_summary.get("ACCESS_DENIED", 0)
    error_count = verif_summary.get("ERROR", 0)
    total_resources = verification.get("total_resources", 0)

    # Count tag failures across verified resources
    tag_failures = sum(
        1 for r in verification.get("resources", [])
        if r.get("framework_tags_valid") is False
        and r.get("verification_status") in ("VERIFIED", "VERIFIED_WITH_WARNING")
    )

    reconciliation_status = reconciliation.get("status", "UNKNOWN")
    if reconciliation_status == "FAIL":
        errors.append(
            "Reconciliation failed: framework tags mismatch detected in "
            "tag-discovery inventory."
        )

    if not_found > 0:
        errors.append(f"{not_found} resource(s) confirmed NOT_FOUND after apply.")

    if tag_failures > 0:
        errors.append(
            f"{tag_failures} taggable resource(s) exist but have invalid framework tags."
        )

    if errors:
        return "FAIL", errors, warnings

    # ------------------------------------------------------------------ #
    # Warning-level issues                                                #
    # ------------------------------------------------------------------ #
    if access_denied > 0:
        warnings.append(
            f"{access_denied} resource(s) returned ACCESS_DENIED — "
            "existence assumed but cannot be confirmed."
        )
    if error_count > 0:
        warnings.append(
            f"{error_count} resource(s) encountered errors during verification."
        )

    if access_denied > 0 or error_count > 0:
        return "REVIEW_REQUIRED", errors, warnings

    if unsupported > 0:
        warnings.append(
            f"{unsupported} resource type(s) are not yet supported by the verifier. "
            "Their existence cannot be confirmed or denied."
        )
        return "PASS_WITH_WARNINGS", errors, warnings

    if verified_warn > 0:
        warnings.append(
            f"{verified_warn} resource(s) verified with warnings "
            "(e.g. missing optional tags or non-taggable sub-resources)."
        )
        return "PASS_WITH_WARNINGS", errors, warnings

    return "PASS", errors, warnings


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: generate_deployment_validation.py <SCAN_ID>", file=sys.stderr)
        sys.exit(1)

    scan_id = sys.argv[1]
    deploy_dir = ROOT_DIR / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True, exist_ok=True)
    out_path = deploy_dir / "deployment-validation.json"

    apply_evidence = _load(deploy_dir, "deployment-apply-evidence.json")
    state_inventory = _load(deploy_dir, "terraform-state-resource-inventory.json")
    tagged_inventory = _load(deploy_dir, "tagged-aws-resource-inventory.json")
    reconciliation = _load(deploy_dir, "deployment-resource-reconciliation.json")
    verification = _load(deploy_dir, "deployed-resource-verification.json")

    verif_summary = verification.get("summary", {})
    resource_validation = {
        "expected": verification.get("total_resources", 0),
        "verified": verif_summary.get("VERIFIED", 0),
        "verified_with_warning": verif_summary.get("VERIFIED_WITH_WARNING", 0),
        "not_found": verif_summary.get("NOT_FOUND", 0),
        "unsupported": verif_summary.get("UNSUPPORTED", 0),
        "access_denied": verif_summary.get("ACCESS_DENIED", 0),
        "tag_failures": sum(
            1 for r in verification.get("resources", [])
            if r.get("framework_tags_valid") is False
            and r.get("verification_status") in ("VERIFIED", "VERIFIED_WITH_WARNING")
        ),
    }

    status, errors, warnings = decide(
        apply_evidence, state_inventory, tagged_inventory,
        reconciliation, verification
    )

    result = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "generated_at_utc": utc_now_iso(),
        "status": status,
        "deployment_status": apply_evidence.get("deployment_status", "UNKNOWN"),
        "resource_validation": resource_validation,
        "reconciliation_status": reconciliation.get("status", "UNKNOWN"),
        "evidence_status": "PASS",
        "next_stage": "RUNTIME_VALIDATION",
        "errors": errors,
        "warnings": warnings,
    }

    safe_write_json(str(out_path), result)

    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT VALIDATION — {status}")
    print(f"{'='*60}")
    print(f"  SCAN_ID              : {scan_id}")
    print(f"  Apply Status         : {result['deployment_status']}")
    print(f"  Expected Resources   : {resource_validation['expected']}")
    print(f"  Verified             : {resource_validation['verified']}")
    print(f"  Verified w/ Warnings : {resource_validation['verified_with_warning']}")
    print(f"  Not Found            : {resource_validation['not_found']}")
    print(f"  Unsupported          : {resource_validation['unsupported']}")
    print(f"  Tag Failures         : {resource_validation['tag_failures']}")
    print(f"  Reconciliation       : {result['reconciliation_status']}")
    print(f"  Final Decision       : {status}")
    print(f"  Next Stage           : RUNTIME_VALIDATION")
    if errors:
        print(f"\n  ERRORS:")
        for e in errors:
            print(f"    - {e}")
    if warnings:
        print(f"\n  WARNINGS:")
        for w in warnings:
            print(f"    - {w}")
    print(f"{'='*60}\n")

    if status == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()

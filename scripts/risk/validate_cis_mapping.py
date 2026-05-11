#!/usr/bin/env python3
"""
scripts/risk/validate_cis_mapping.py

Validate both deterministic and AI CIS mappings against allowed-controls.yml.
Invalid mappings are downgraded to UNKNOWN_SECURITY_MISCONFIGURATION.

Usage:
    python scripts/risk/validate_cis_mapping.py <SCAN_ID>

Output:
    reports/risk/<SCAN_ID>/validated-cis-mapping.json
"""

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


def load_allowed_controls(path: Path) -> set[str]:
    if not path.is_file():
        print(f"[validate_map] ERROR: allowed-controls.yml not found: {path}", file=sys.stderr)
        return set()
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    controls = data.get("allowed_controls", [])
    return {c["id"] for c in controls if isinstance(c, dict) and "id" in c}


VALID_CONFIDENCES = {"high", "medium", "low"}


def validate_mapping(m: dict, allowed: set[str]) -> dict:
    """Validate a single mapping.  Returns corrected mapping."""
    errors = []

    # Check canonical_control
    cc = m.get("canonical_control", "")
    if cc not in allowed:
        errors.append(f"canonical_control '{cc}' not in allowed controls")

    # Check base_control_criticality
    bcc = m.get("base_control_criticality")
    if not isinstance(bcc, int) or bcc < 1 or bcc > 10:
        errors.append(f"base_control_criticality '{bcc}' not integer 1-10")

    # Check mandatory_block
    mb = m.get("mandatory_block")
    if not isinstance(mb, bool):
        errors.append(f"mandatory_block '{mb}' not boolean")

    # Check mapping_confidence
    mc = m.get("mapping_confidence", "")
    if mc not in VALID_CONFIDENCES:
        errors.append(f"mapping_confidence '{mc}' not in {VALID_CONFIDENCES}")

    # Check required fields
    for field in ("finding_id", "canonical_control", "control_domain"):
        if not m.get(field):
            errors.append(f"missing required field '{field}'")

    # Check mapping_reason length
    reason = m.get("mapping_reason", "")
    if isinstance(reason, str) and len(reason.split()) > 60:
        errors.append("mapping_reason exceeds 60 words")

    if errors:
        return {
            "finding_id": m.get("finding_id", "UNKNOWN"),
            "canonical_control": "UNKNOWN_SECURITY_MISCONFIGURATION",
            "control_domain": "unknown",
            "cis_controls_v8": [],
            "aws_control_refs": [],
            "base_control_criticality": 4,
            "mandatory_block": False,
            "mapping_confidence": "low",
            "requires_review": True,
            "mapping_source": m.get("mapping_source", "unknown"),
            "matched_by": m.get("matched_by", ""),
            "mapping_reason": m.get("mapping_reason", ""),
            "validation_error": "; ".join(errors),
        }

    # Valid — pass through with requires_review preserved
    result = dict(m)
    result.setdefault("requires_review", False)
    return result


def main():
    parser = argparse.ArgumentParser(description="Validate CIS mappings.")
    parser.add_argument("scan_id", help="SCAN_ID for this pipeline run")
    args = parser.parse_args()
    scan_id = args.scan_id

    report_dir = ROOT / "reports" / "risk" / scan_id
    allowed = load_allowed_controls(ROOT / "config" / "risk" / "allowed-controls.yml")
    if not allowed:
        print("[validate_map] WARNING: No allowed controls loaded. All mappings will fail validation.")

    # Load deterministic mappings
    det_data = safe_read_json(str(report_dir / "deterministic-mappings.json"))
    det_mappings = det_data.get("mappings", []) if isinstance(det_data, dict) else []

    # Load AI mappings
    ai_data = safe_read_json(str(report_dir / "ai-cis-mapping.json"))
    ai_mappings = ai_data.get("mappings", []) if isinstance(ai_data, dict) else []

    all_mappings = det_mappings + ai_mappings
    validated = []
    error_count = 0

    for m in all_mappings:
        if not isinstance(m, dict):
            continue
        v = validate_mapping(m, allowed)
        if "validation_error" in v:
            error_count += 1
        validated.append(v)

    safe_write_json(str(report_dir / "validated-cis-mapping.json"), {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "total_validated": len(validated),
            "validation_errors": error_count,
        },
        "mappings": validated,
    })

    print(f"[validate_map] SCAN_ID           = {scan_id}")
    print(f"[validate_map] Total validated    = {len(validated)}")
    print(f"[validate_map] Validation errors  = {error_count}")


if __name__ == "__main__":
    main()

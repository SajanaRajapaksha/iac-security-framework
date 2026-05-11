#!/usr/bin/env python3
"""
scripts/risk/merge_mappings.py

Merge deterministic and validated AI CIS mappings into a single
merged-cis-mapping.json.  Deterministic mappings take priority.
Still-unmapped findings get UNKNOWN_SECURITY_MISCONFIGURATION.

Usage:
    python scripts/risk/merge_mappings.py <SCAN_ID>

Output:
    reports/risk/<SCAN_ID>/merged-cis-mapping.json
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso


def main():
    parser = argparse.ArgumentParser(description="Merge CIS mappings.")
    parser.add_argument("scan_id", help="SCAN_ID for this pipeline run")
    args = parser.parse_args()
    scan_id = args.scan_id

    report_dir = ROOT / "reports" / "risk" / scan_id

    # Load normalized findings (to know all finding_ids)
    norm_data = safe_read_json(str(report_dir / "normalized-findings.json"))
    all_finding_ids = set()
    if isinstance(norm_data, dict):
        for f in norm_data.get("findings", []):
            if isinstance(f, dict):
                all_finding_ids.add(f.get("finding_id"))

    # Load validated mappings (already includes both deterministic + AI)
    val_data = safe_read_json(str(report_dir / "validated-cis-mapping.json"))
    val_mappings = val_data.get("mappings", []) if isinstance(val_data, dict) else []

    # Build mapping index — first entry wins (deterministic comes first in validated file)
    merged_by_id: dict[str, dict] = {}
    for m in val_mappings:
        if not isinstance(m, dict):
            continue
        fid = m.get("finding_id")
        if fid and fid not in merged_by_id:
            merged_by_id[fid] = m

    # Fill unmapped with fallback
    for fid in all_finding_ids:
        if fid not in merged_by_id:
            merged_by_id[fid] = {
                "finding_id": fid,
                "canonical_control": "UNKNOWN_SECURITY_MISCONFIGURATION",
                "control_domain": "unknown",
                "cis_controls_v8": [],
                "aws_control_refs": [],
                "base_control_criticality": 4,
                "mandatory_block": False,
                "mapping_confidence": "low",
                "requires_review": True,
                "mapping_source": "unmapped_fallback",
                "mapping_reason": "No deterministic or AI mapping available.",
            }

    merged_list = sorted(merged_by_id.values(), key=lambda x: x.get("finding_id", ""))

    # Count sources
    det_count = sum(1 for m in merged_list if m.get("mapping_source") == "deterministic")
    ai_count = sum(1 for m in merged_list if m.get("mapping_source") in ("ai", "cache"))
    fallback_count = sum(1 for m in merged_list if m.get("mapping_source") in ("no_api_key_fallback", "ai_no_response", "unmapped_fallback"))

    safe_write_json(str(report_dir / "merged-cis-mapping.json"), {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "total_mappings": len(merged_list),
            "deterministic_count": det_count,
            "ai_count": ai_count,
            "fallback_count": fallback_count,
        },
        "mappings": merged_list,
    })

    print(f"[merge_map] SCAN_ID           = {scan_id}")
    print(f"[merge_map] Total mappings    = {len(merged_list)}")
    print(f"[merge_map] Deterministic     = {det_count}")
    print(f"[merge_map] AI               = {ai_count}")
    print(f"[merge_map] Fallback         = {fallback_count}")


if __name__ == "__main__":
    main()

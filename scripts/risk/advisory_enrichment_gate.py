#!/usr/bin/env python3
"""
scripts/risk/advisory_enrichment_gate.py

Enforces the advisory gate based on finding enrichment decisions.

Usage: python scripts/risk/advisory_enrichment_gate.py <SCAN_ID>
"""

import argparse
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id
    dec = safe_read_json(str(risk_dir / "finding-enrichment-decision.json"))
    
    if not isinstance(dec, dict):
        print(f"[advisory_gate] ERROR: Cannot read finding-enrichment-decision.json for {scan_id}", file=sys.stderr)
        sys.exit(1)

    decision = dec.get("suggested_decision", "UNKNOWN")
    highest_sev = dec.get("highest_severity", "UNKNOWN")

    enforce = os.environ.get("ENFORCE_RISK_GATE", "false").strip().lower() == "true"
    strict = os.environ.get("STRICT_RISK_GATE", "false").strip().lower() == "true"

    print(f"")
    print(f"{'='*60}")
    print(f"  PRE-DEPLOYMENT ADVISORY GATE")
    print(f"{'='*60}")
    print(f"  Scan ID            : {scan_id}")
    print(f"  Highest Severity   : {highest_sev}")
    print(f"  Suggested Decision : {decision}")
    print(f"  Enforcement Mode   : {'BLOCKING' if enforce else 'ADVISORY'}")

    would_fail = decision in ("BLOCK_RECOMMENDED", "REVIEW_HIGH_RISK", "REVIEW_REQUIRED")
    if strict:
        would_fail = would_fail or decision == "REVIEW"

    if not enforce:
        print(f"")
        print(f"  Mode: ADVISORY — pipeline continues regardless of findings.")
        if would_fail:
            print(f"  ⚠️  Pipeline WOULD FAIL if ENFORCE_RISK_GATE=true were set.")
        print(f"{'='*60}")
        print(f"")
        sys.exit(0)

    # Blocking mode
    if would_fail:
        print(f"")
        print(f"  ❌ PIPELINE BLOCKED — Gate enforcement active.")
        print(f"{'='*60}")
        print(f"")
        sys.exit(1)
    else:
        print(f"")
        print(f"  ✅ PIPELINE ALLOWED — Findings within acceptable threshold.")
        print(f"{'='*60}")
        print(f"")
        sys.exit(0)

if __name__ == "__main__":
    main()

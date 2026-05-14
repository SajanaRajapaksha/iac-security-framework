#!/usr/bin/env python3
"""
scripts/risk/enforce_risk_gate.py

Read risk-decision.json and enforce the advisory/blocking risk gate.

Default: advisory mode — always exit 0, print risk summary.
ENFORCE_RISK_GATE=true: exit 1 for FAIL_RECOMMENDED / BLOCK_RECOMMENDED.
STRICT_RISK_GATE=true + ENFORCE_RISK_GATE=true: also exit 1 for REVIEW.

Usage:  python scripts/risk/enforce_risk_gate.py <SCAN_ID>
"""
import argparse, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from scripts.utils.evidence import safe_read_json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    sid = args.scan_id

    rd = ROOT / "reports" / "risk" / sid
    dec = safe_read_json(str(rd / "risk-decision.json"))
    if not isinstance(dec, dict):
        print(f"[risk_gate] ERROR: Cannot read risk-decision.json for {sid}", file=sys.stderr)
        sys.exit(1)

    score = dec.get("overall_score", 0)
    level = dec.get("risk_level", "UNKNOWN")
    decision = dec.get("suggested_decision", "REVIEW")
    blocks = dec.get("mandatory_blocks_triggered", [])
    reasons = dec.get("top_reasons", [])

    enforce = os.environ.get("ENFORCE_RISK_GATE", "false").strip().lower() == "true"
    strict = os.environ.get("STRICT_RISK_GATE", "false").strip().lower() == "true"

    print(f"")
    print(f"{'='*60}")
    print(f"  PRE-DEPLOYMENT RISK ASSESSMENT")
    print(f"{'='*60}")
    print(f"  Scan ID          : {sid}")
    print(f"  Overall Score    : {score} / 100")
    print(f"  Risk Level       : {level}")
    print(f"  Suggested Decision: {decision}")
    print(f"  Enforcement Mode : {'BLOCKING' if enforce else 'ADVISORY'}")
    print(f"  Mandatory Blocks : {len(blocks)}")

    if reasons:
        print(f"  Top Reasons:")
        for r in reasons[:5]:
            print(f"    - {r}")

    if blocks:
        print(f"  Mandatory Block Details:")
        for b in blocks:
            print(f"    - {b.get('canonical_control')}: {b.get('reason','')}")

    # Would-fail indicator (always shown)
    would_fail = decision in ("FAIL_RECOMMENDED", "BLOCK_RECOMMENDED")
    if strict:
        would_fail = would_fail or decision == "REVIEW"

    if not enforce:
        print(f"")
        print(f"  Mode: ADVISORY — pipeline continues regardless of risk.")
        if would_fail:
            print(f"  ⚠️  Pipeline WOULD FAIL if ENFORCE_RISK_GATE=true were set.")
        print(f"{'='*60}")
        print(f"")
        sys.exit(0)

    # Blocking mode
    should_fail = decision in ("FAIL_RECOMMENDED", "BLOCK_RECOMMENDED")
    if strict and decision == "REVIEW":
        should_fail = True

    if should_fail:
        print(f"")
        print(f"  ❌ PIPELINE BLOCKED — Risk gate enforcement active.")
        print(f"{'='*60}")
        print(f"")
        sys.exit(1)
    else:
        print(f"")
        print(f"  ✅ PIPELINE ALLOWED — Risk within acceptable threshold.")
        print(f"{'='*60}")
        print(f"")
        sys.exit(0)

if __name__ == "__main__":
    main()

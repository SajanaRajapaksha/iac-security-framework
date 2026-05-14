#!/usr/bin/env python3
"""
scripts/risk/hash_risk_evidence.py

SHA-256 hash all risk evidence artifacts and create forensic manifest.

Usage:  python scripts/risk/hash_risk_evidence.py <SCAN_ID>
Output:
    reports/risk/<SCAN_ID>/evidence-hashes.json
    reports/risk/<SCAN_ID>/evidence-manifest.json
"""
import argparse, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from scripts.utils.evidence import sha256_file, safe_read_json, safe_write_json, utc_now_iso, collect_github_metadata

ARTIFACTS = [
    "normalized-findings.json", "deterministic-mappings.json",
    "unmapped-findings.json", "ai-request.json", "ai-cis-mapping.json",
    "validated-cis-mapping.json", "merged-cis-mapping.json",
    "finding-risk-scores.json", "resource-risk-scores.json",
    "domain-risk-scores.json", "risk-score.json", "risk-decision.json",
    "risk-summary.md", "ai-model-metadata.json", "mapping-cache.json",
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    sid = args.scan_id
    rd = ROOT / "reports" / "risk" / sid

    hashes = {}
    for name in ARTIFACTS:
        p = rd / name
        h = sha256_file(str(p))
        hashes[name] = h if h else "FILE_NOT_FOUND"

    safe_write_json(str(rd / "evidence-hashes.json"), {
        "scan_id": sid, "generated_at": utc_now_iso(), "hashes": hashes,
    })

    # Model metadata
    ai_meta = safe_read_json(str(rd / "ai-model-metadata.json")) or {}

    gh = collect_github_metadata()
    manifest = {
        "scan_id": sid,
        "generated_at": utc_now_iso(),
        "repository": gh.get("repository_url"),
        "branch": gh.get("branch"),
        "commit_sha": gh.get("commit_sha"),
        "github_run_id": gh.get("workflow_run_id"),
        "stage": "pre_deployment_risk_scoring",
        "input_files": [
            f"reports/static/{sid}/combined/static-analysis-evidence.json",
            f"reports/policy/{sid}/policy-evidence.json",
            "config/risk/cis-mapping.yml",
            "config/risk/allowed-controls.yml",
            "config/risk/scoring-model.yml",
            "config/risk/mandatory-blocks.yml",
        ],
        "generated_files": [f"reports/risk/{sid}/{n}" for n in ARTIFACTS + ["evidence-hashes.json", "evidence-manifest.json"]],
        "artifact_hashes": hashes,
        "scripts_used": [
            "scripts/risk/normalize_findings.py",
            "scripts/risk/deterministic_map_known_findings.py",
            "scripts/risk/ai_map_unmapped_findings.py",
            "scripts/risk/validate_cis_mapping.py",
            "scripts/risk/merge_mappings.py",
            "scripts/risk/calculate_risk_score.py",
            "scripts/risk/render_risk_summary.py",
            "scripts/risk/hash_risk_evidence.py",
            "scripts/risk/enforce_risk_gate.py",
        ],
        "ai_mapping_metadata": {
            "model": ai_meta.get("model", "none"),
            "api_key_present": ai_meta.get("api_key_present", False),
            "api_call_count": ai_meta.get("api_call_count", 0),
            "findings_sent_to_api": ai_meta.get("findings_sent_to_api", 0),
        },
        "forensic_note": (
            "AI (OpenAI) was used ONLY for CIS/AWS control mapping of unmapped findings. "
            "Risk scores and deployment decisions were calculated deterministically by Python code. "
            "AI did not calculate scores, make deployment decisions, or access Terraform source files."
        ),
    }
    safe_write_json(str(rd / "evidence-manifest.json"), manifest)
    print(f"[hash_evidence] SCAN_ID = {sid}")
    print(f"[hash_evidence] Hashed {sum(1 for v in hashes.values() if v != 'FILE_NOT_FOUND')} artifacts")

if __name__ == "__main__":
    main()

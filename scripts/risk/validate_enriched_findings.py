#!/usr/bin/env python3
"""
scripts/risk/validate_enriched_findings.py

Validates AI enrichment responses against normalized findings.
Prioritizes original Checkov/Policy severities over AI suggestions.
Normalizes severities to the allowed set and assigns severity orders.

Usage: python scripts/risk/validate_enriched_findings.py <SCAN_ID>
"""

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json

def load_severities():
    path = ROOT_DIR / "config" / "risk" / "allowed-severities.yml"
    data = None
    if path.is_file() and yaml:
        with open(path) as f:
            data = yaml.safe_load(f)
            
    if not isinstance(data, dict):
        data = {
            "allowed_severities": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"],
            "severity_normalization": {
                "INFORMATIONAL": "INFO", "INFO": "INFO", "LOW": "LOW", 
                "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL",
                "NONE": "UNKNOWN", "UNKNOWN": "UNKNOWN", "": "UNKNOWN"
            },
            "severity_order": {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": -1}
        }
    return data

def normalize_sev(sev, config):
    if not sev:
        return "UNKNOWN"
    sev_upper = str(sev).upper()
    norm = config["severity_normalization"].get(sev_upper, "UNKNOWN")
    if norm not in config["allowed_severities"]:
        return "UNKNOWN"
    return norm

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id
    normalized = safe_read_json(str(risk_dir / "normalized-findings.json")) or {"findings": []}
    ai_resp = safe_read_json(str(risk_dir / "ai-enrichment-response.json")) or {"findings": []}

    sev_config = load_severities()
    sev_order = sev_config.get("severity_order", {})

    norm_findings = {f["finding_id"]: f for f in normalized.get("findings", [])}
    ai_findings = {f["finding_id"]: f for f in ai_resp.get("findings", [])}

    enriched = []

    for fid, f in norm_findings.items():
        ai_f = ai_findings.get(fid, {})
        
        source_tool = f.get("source_tool")
        scanner_sev = normalize_sev(f.get("scanner_severity"), sev_config)
        policy_sev = normalize_sev(f.get("policy", {}).get("policy_severity"), sev_config)
        ai_sev = normalize_sev(ai_f.get("final_severity") or ai_f.get("ai_suggested_severity"), sev_config)

        final_severity = "UNKNOWN"
        severity_source = "ai_unavailable"
        requires_review = ai_f.get("requires_review", False)

        # 1. Source: Checkov
        if source_tool == "checkov" and scanner_sev != "UNKNOWN":
            final_severity = scanner_sev
            severity_source = "checkov_scanner_severity"
        # 2. Source: Policy
        elif source_tool == "policy" and policy_sev != "UNKNOWN":
            final_severity = policy_sev
            severity_source = "policy_defined_severity"
        # 3. AI Missing Severity Enrichment
        elif ai_sev != "UNKNOWN":
            final_severity = ai_sev
            severity_source = "ai_missing_severity_enrichment"
        # 4. Fallback
        else:
            final_severity = "UNKNOWN"
            severity_source = "ai_unavailable"
            requires_review = True

        # Validate standards references
        standards = ai_f.get("standards_references", [])
        validated_standards = []
        if isinstance(standards, list):
            for ref in standards:
                if isinstance(ref, dict) and "standard" in ref and "control_code" in ref and "reference_type" in ref and "confidence" in ref:
                    validated_standards.append(ref)
                else:
                    requires_review = True
                    if "mapping_confidence" in ai_f:
                        ai_f["mapping_confidence"] = "low"

        enriched_f = {
            "finding_id": fid,
            "scan_id": scan_id,
            "source_tool": source_tool,
            "source_rule_id": f.get("source_rule_id"),
            "title": f.get("title"),
            "description": f.get("description"),
            "resource": f.get("resource"),
            "resource_type": f.get("resource_type"),
            "file_path": f.get("file_path"),
            "scanner_severity": f.get("scanner_severity"),
            "policy_severity": f.get("policy", {}).get("policy_severity"),
            "policy_enforcement_level": f.get("policy", {}).get("enforcement_level"),
            "ai_suggested_severity": ai_sev if ai_sev != "UNKNOWN" else None,
            "final_severity": final_severity,
            "severity_source": severity_source,
            "severity_order": sev_order.get(final_severity, -1),
            "standards_references": validated_standards,
            "mapping_type": ai_f.get("mapping_type", "UNKNOWN"),
            "mapping_confidence": ai_f.get("mapping_confidence", "low"),
            "requires_review": requires_review,
            "enrichment_reason": ai_f.get("enrichment_reason", "")
        }
        enriched.append(enriched_f)

    out_path = risk_dir / "enriched-findings.json"
    safe_write_json(str(out_path), {"findings": enriched})
    print(f"[validate_enriched] Validated {len(enriched)} enriched findings.")

if __name__ == "__main__":
    main()

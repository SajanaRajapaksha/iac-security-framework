#!/usr/bin/env python3
"""
scripts/risk/ai_enrich_findings.py

AI Enrichment Engine.
Batches findings, sends them to OpenAI to fill missing severities,
and attaches standards references (AWS/CIS). Does not calculate numeric risk.

Usage: python scripts/risk/ai_enrich_findings.py <SCAN_ID>
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

try:
    import openai
except ImportError:
    openai = None
try:
    import yaml
except ImportError:
    yaml = None

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

SYSTEM_PROMPT = """You are a cloud security finding enrichment assistant for AWS Terraform IaC findings.
For each finding:
1. If existing severity is present, do not change it.
2. If severity is missing, assign one final_severity from INFO, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN using AWS security context.
3. Attach all applicable standards references from AWS Foundational Security Best Practices, CIS AWS Foundations Benchmark, CIS Controls v8, and AWS Resource Tagging where relevant.
4. Do not invent control codes. If unsure, leave control_code empty and use lower confidence.
5. Do not calculate numeric risk scores.
6. Return JSON only matching the schema.
7. Keep enrichment_reason under 40 words.

JSON Schema for your response:
{
  "findings": [
    {
      "finding_id": "STRING",
      "ai_suggested_severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN",
      "final_severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN",
      "severity_source": "checkov_scanner_severity|policy_defined_severity|ai_missing_severity_enrichment|ai_unavailable",
      "standards_references": [
        {
          "standard": "STRING",
          "control_code": "STRING",
          "control_title": "STRING",
          "reference_type": "aws_specific_control|aws_benchmark_context|security_domain|aws_governance_context",
          "confidence": "high|medium|low"
        }
      ],
      "mapping_type": "DIRECT_AWS_STANDARD|BROAD_CIS_CONTROL|AWS_RESOURCE_TAGGING|NO_DIRECT_MAPPING|UNKNOWN",
      "mapping_confidence": "high|medium|low",
      "requires_review": true|false,
      "enrichment_reason": "STRING (max 40 words)"
    }
  ]
}
"""

def get_cache_key(finding: dict) -> str:
    """Generate a cache key based on core finding properties."""
    desc = finding.get("description", "")[:50]
    desc_hash = hashlib.md5(desc.encode()).hexdigest()[:8]
    return f"{finding.get('source_tool')}:{finding.get('source_rule_id')}:{finding.get('resource_type')}:{desc_hash}"

def load_settings():
    path = ROOT_DIR / "config" / "risk" / "enrichment-settings.yml"
    data = None
    if path.is_file() and yaml:
        with open(path) as f:
            data = yaml.safe_load(f)
    if not isinstance(data, dict):
        return {}
    return data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id
    normalized_path = risk_dir / "normalized-findings.json"
    normalized_data = safe_read_json(str(normalized_path)) or {"findings": []}
    findings = normalized_data.get("findings", [])

    settings = load_settings()
    model_settings = settings.get("model", {})
    batch_size = model_settings.get("batch_size", 10)
    model_name = os.environ.get("OPENAI_MODEL", model_settings.get("default_openai_model", "gpt-4o-mini"))
    
    api_key = os.environ.get("OPENAI_API_KEY")
    client = None
    if api_key and openai:
        client = openai.OpenAI(api_key=api_key)

    ai_responses = []
    api_requests = []
    
    # Load cache
    cache_path = risk_dir / "mapping-cache.json"
    cache = safe_read_json(str(cache_path)) or {}

    stats = {
        "total_findings": len(findings),
        "cached_hits": 0,
        "api_calls": 0,
        "api_failures": 0,
        "ai_unavailable_fallbacks": 0
    }

    # Prepare batches
    batches = []
    current_batch = []
    
    for f in findings:
        ckey = get_cache_key(f)
        if ckey in cache:
            # We have it in cache, just update finding_id
            cached_resp = dict(cache[ckey])
            cached_resp["finding_id"] = f["finding_id"]
            ai_responses.append(cached_resp)
            stats["cached_hits"] += 1
            continue
            
        compact_f = {
            "finding_id": f["finding_id"],
            "source_tool": f["source_tool"],
            "source_rule_id": f["source_rule_id"],
            "scanner_severity": f.get("scanner_severity"),
            "policy_severity": f.get("policy", {}).get("policy_severity"),
            "policy_enforcement_level": f.get("policy", {}).get("enforcement_level"),
            "title": f.get("title", "")[:120],
            "description": f.get("description", "")[:200],
            "resource_type": f.get("resource_type"),
            "file_path": f.get("file_path")
        }
        
        current_batch.append((f, compact_f, ckey))
        if len(current_batch) >= batch_size:
            batches.append(current_batch)
            current_batch = []
            
    if current_batch:
        batches.append(current_batch)

    # Process batches
    if not client and batches:
        print("[ai_enrich] OpenAI API key missing or openai not installed. Using fallback.")
    
    for batch in batches:
        if not client:
            for orig_f, _, _ in batch:
                sev = orig_f.get("scanner_severity") or orig_f.get("policy", {}).get("policy_severity")
                fallback_sev = sev if sev and sev != "UNKNOWN" else "UNKNOWN"
                is_missing = not sev or sev == "UNKNOWN"
                ai_responses.append({
                    "finding_id": orig_f["finding_id"],
                    "ai_suggested_severity": "UNKNOWN",
                    "final_severity": fallback_sev,
                    "severity_source": orig_f["source_tool"] + "_scanner_severity" if not is_missing else "ai_unavailable",
                    "standards_references": [],
                    "mapping_type": "UNKNOWN",
                    "mapping_confidence": "low",
                    "requires_review": is_missing,
                    "enrichment_reason": "AI unavailable fallback."
                })
                stats["ai_unavailable_fallbacks"] += 1
            continue

        prompt_payload = [b[1] for b in batch]
        api_requests.append({
            "timestamp": utc_now_iso(),
            "batch_size": len(batch),
            "payload": prompt_payload
        })
        
        try:
            stats["api_calls"] += 1
            resp = client.chat.completions.create(
                model=model_name,
                temperature=model_settings.get("temperature", 0),
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps({"findings": prompt_payload})}
                ]
            )
            content = resp.choices[0].message.content
            parsed = json.loads(content)
            batch_resps = parsed.get("findings", [])
            
            # Map back
            for orig_f, _, ckey in batch:
                matched = next((r for r in batch_resps if r.get("finding_id") == orig_f["finding_id"]), None)
                if matched:
                    ai_responses.append(matched)
                    cache[ckey] = matched
                else:
                    raise Exception("Missing finding in AI response")
        except Exception as e:
            print(f"[ai_enrich] API error: {e}")
            stats["api_failures"] += 1
            for orig_f, _, _ in batch:
                sev = orig_f.get("scanner_severity") or orig_f.get("policy", {}).get("policy_severity")
                fallback_sev = sev if sev and sev != "UNKNOWN" else "UNKNOWN"
                is_missing = not sev or sev == "UNKNOWN"
                ai_responses.append({
                    "finding_id": orig_f["finding_id"],
                    "ai_suggested_severity": "UNKNOWN",
                    "final_severity": fallback_sev,
                    "severity_source": orig_f["source_tool"] + "_scanner_severity" if not is_missing else "ai_unavailable",
                    "standards_references": [],
                    "mapping_type": "UNKNOWN",
                    "mapping_confidence": "low",
                    "requires_review": is_missing,
                    "enrichment_reason": "API error fallback."
                })

    # Save outputs
    safe_write_json(str(risk_dir / "mapping-cache.json"), cache)
    safe_write_json(str(risk_dir / "ai-enrichment-request.json"), {"requests": api_requests})
    safe_write_json(str(risk_dir / "ai-enrichment-response.json"), {"findings": ai_responses})
    
    meta = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "model": model_name,
        "api_key_present": bool(api_key),
        "stats": stats
    }
    safe_write_json(str(risk_dir / "ai-model-metadata.json"), meta)
    
    print(f"[ai_enrich] Processed {len(findings)} findings. API calls: {stats['api_calls']}, Cached: {stats['cached_hits']}, Failures: {stats['api_failures']}")

if __name__ == "__main__":
    main()

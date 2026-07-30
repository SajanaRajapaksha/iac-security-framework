#!/usr/bin/env python3
import sys
import argparse
import os
import time
from pathlib import Path

try:
    import openai
except ImportError:
    openai = None

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.review.review_utils import safe_read_json, safe_write_json
from scripts.review.remediation_cache import generate_cache_key, load_cache, save_cache
from scripts.utils.evidence import utc_now_iso

PROMPT_VERSION = "iac-security-review-remediation-v1"
BATCH_SIZE = 10

SYSTEM_PROMPT = """You are a cloud security expert analyzing Infrastructure as Code and runtime findings.
Your task is to provide concise, actionable remediation guidance for groups of identical findings.
You MUST output valid JSON matching the exact schema requested.
DO NOT use Markdown blocks in your text fields. DO NOT exceed word limits.
DO NOT suggest disabling scanners. DO NOT output secrets.

Return JSON in this format exactly:
{
  "remediations": [
    {
      "finding_key": "STRING",
      "priority": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
      "summary": "STRING (max 25 words)",
      "terraform_action": "STRING (max 40 words, how to fix in IaC)",
      "runtime_action": "STRING (max 40 words, how to fix via AWS CLI or Console)",
      "validation_step": "STRING (max 30 words, how to verify)",
      "operational_caution": "STRING (max 25 words, risks of applying fix)"
    }
  ]
}
"""

def generate_finding_key(stage: str, scanner: str, check_id: str, resource_type: str, title: str) -> str:
    parts = [str(x).strip() for x in (stage, scanner, check_id, resource_type, title)]
    return "|".join(parts)

def build_remediation_groups(security_review: dict) -> dict:
    groups = {}
    
    def process_findings(findings: list[dict], stage: str):
        for f in findings:
            scanner = f.get("scanner", "")
            check_id = f.get("check_id", "")
            resource_type = f.get("resource_type", "")
            title = f.get("title", "")
            
            key = generate_finding_key(stage, scanner, check_id, resource_type, title)
            
            if key not in groups:
                groups[key] = {
                    "finding_key": key,
                    "stage": stage,
                    "scanner": scanner,
                    "check_id": check_id,
                    "resource_type": resource_type,
                    "title": title,
                    "description": f.get("description", ""),
                    "severity": f.get("severity", "UNKNOWN"),
                    "existing_remediation": f.get("existing_remediation", ""),
                    "affected_finding_ids": [],
                    "affected_resource_count": 0,
                    "sample_resources": []
                }
                
            groups[key]["affected_finding_ids"].append(f.get("review_finding_id"))
            groups[key]["affected_resource_count"] += 1
            if len(groups[key]["sample_resources"]) < 3 and f.get("resource"):
                groups[key]["sample_resources"].append(f.get("resource"))

    process_findings(security_review.get("pre_deployment_findings", []), "PRE_DEPLOYMENT")
    process_findings(security_review.get("post_deployment_findings", []), "POST_DEPLOYMENT")
    
    return groups

def run_ai_batch(groups: list[dict], client) -> list[dict]:
    if not openai:
        return []
        
    model = os.environ.get("OPENAI_REMEDIATION_MODEL") or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    
    payload = []
    for g in groups:
        payload.append({
            "finding_key": g["finding_key"],
            "stage": g["stage"],
            "severity": g["severity"],
            "scanner": g["scanner"],
            "check_id": g["check_id"],
            "title": g["title"],
            "resource_type": g["resource_type"],
            "description": g["description"][:500],  # truncated for safety
            "existing_remediation": g["existing_remediation"][:200],
            "affected_resource_count": g["affected_resource_count"],
            "sample_resources": g["sample_resources"]
        })
        
    try:
        response = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps({"findings_to_analyze": payload})}
            ],
            max_tokens=2048,
            temperature=0.0
        )
        content = response.choices[0].message.content
        data = json.loads(content)
        
        usage = response.usage
        tokens = {
            "prompt_tokens": usage.prompt_tokens if usage else 0,
            "completion_tokens": usage.completion_tokens if usage else 0,
            "total_tokens": usage.total_tokens if usage else 0
        }
        
        return data.get("remediations", []), tokens, None
    except Exception as e:
        return [], {}, str(e)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    scan_id = args.scan_id

    review_dir = ROOT_DIR / "reports" / "review" / scan_id
    sec_review_path = review_dir / "security-review.json"
    guidance_path = review_dir / "remediation-guidance.json"
    usage_path = review_dir / "openai-usage.json"
    
    review_dir.mkdir(parents=True, exist_ok=True)
    
    sec_review = safe_read_json(str(sec_review_path)) or {}
    groups = build_remediation_groups(sec_review)
    cache = load_cache()
    
    cache_hits = 0
    cache_misses = 0
    
    cached_guidance = []
    uncached_groups = []
    
    # Check cache
    for k, g in groups.items():
        cache_key = generate_cache_key(
            PROMPT_VERSION, g["stage"], g["scanner"], g["check_id"], g["resource_type"], g["title"], g["description"]
        )
        if cache_key in cache:
            cache_hits += 1
            # Merge cached data with current runtime stats (counts, ids)
            entry = dict(cache[cache_key])
            entry["affected_finding_ids"] = g["affected_finding_ids"]
            entry["affected_resource_count"] = g["affected_resource_count"]
            entry["scanner_remediation"] = g["existing_remediation"]
            cached_guidance.append(entry)
        else:
            cache_misses += 1
            uncached_groups.append((cache_key, g))

    api_key = os.environ.get("OPENAI_API_KEY")
    client = None
    
    ai_status = "AI_REMEDIATION_COMPLETE"
    error_log = []
    tokens_stats = {"in": 0, "out": 0, "tot": 0}
    api_requests = 0
    
    if len(uncached_groups) > 0:
        if not openai:
            ai_status = "AI_REMEDIATION_UNAVAILABLE"
            error_log.append("OpenAI library not installed.")
        elif not api_key:
            ai_status = "AI_REMEDIATION_SKIPPED_NO_API_KEY"
            error_log.append("OPENAI_API_KEY not set.")
        else:
            client = openai.OpenAI(api_key=api_key)

    new_guidance = []
    
    if client and len(uncached_groups) > 0:
        # Batch uncached
        for i in range(0, len(uncached_groups), BATCH_SIZE):
            batch = uncached_groups[i:i+BATCH_SIZE]
            batch_groups = [b[1] for b in batch]
            
            rems, t, err = run_ai_batch(batch_groups, client)
            api_requests += 1
            if err:
                error_log.append(err)
                ai_status = "AI_REMEDIATION_PARTIAL"
            else:
                tokens_stats["in"] += t.get("prompt_tokens", 0)
                tokens_stats["out"] += t.get("completion_tokens", 0)
                tokens_stats["tot"] += t.get("total_tokens", 0)
                
                # Match them back
                rem_dict = {r.get("finding_key"): r for r in rems if r.get("finding_key")}
                for b_key, b_g in batch:
                    f_key = b_g["finding_key"]
                    if f_key in rem_dict:
                        ai_resp = rem_dict[f_key]
                        entry = {
                            "finding_key": f_key,
                            "stage": b_g["stage"],
                            "scanner": b_g["scanner"],
                            "check_id": b_g["check_id"],
                            "affected_finding_ids": b_g["affected_finding_ids"],
                            "affected_resource_count": b_g["affected_resource_count"],
                            "source": "OPENAI_WITH_SCANNER_CONTEXT",
                            "priority": ai_resp.get("priority", "UNKNOWN"),
                            "scanner_remediation": b_g["existing_remediation"],
                            "ai_guidance": {
                                "summary": ai_resp.get("summary", ""),
                                "terraform_action": ai_resp.get("terraform_action", ""),
                                "runtime_action": ai_resp.get("runtime_action", ""),
                                "validation_step": ai_resp.get("validation_step", ""),
                                "operational_caution": ai_resp.get("operational_caution", "")
                            }
                        }
                        new_guidance.append(entry)
                        
                        # Cache it for next time
                        cache_entry = dict(entry)
                        cache_entry["source"] = "LOCAL_AI_REMEDIATION_CACHE"
                        del cache_entry["affected_finding_ids"]
                        del cache_entry["affected_resource_count"]
                        del cache_entry["scanner_remediation"]
                        cache[b_key] = cache_entry

            if i + BATCH_SIZE < len(uncached_groups):
                time.sleep(0.5)

    if new_guidance:
        save_cache(cache)
        
    # If some failed to generate, fallback
    all_keys = set(g["finding_key"] for g in groups.values())
    got_keys = set(g["finding_key"] for g in cached_guidance + new_guidance)
    
    fallback_guidance = []
    for f_key in all_keys - got_keys:
        b_g = groups[f_key]
        fallback_guidance.append({
            "finding_key": f_key,
            "stage": b_g["stage"],
            "scanner": b_g["scanner"],
            "check_id": b_g["check_id"],
            "affected_finding_ids": b_g["affected_finding_ids"],
            "affected_resource_count": b_g["affected_resource_count"],
            "source": "SCANNER_METADATA_ONLY",
            "priority": b_g["severity"],
            "scanner_remediation": b_g["existing_remediation"],
            "ai_guidance": {}
        })
        
    if len(groups) == 0:
        ai_status = "AI_REMEDIATION_SKIPPED_NO_FINDINGS"

    final_guidance = cached_guidance + new_guidance + fallback_guidance
    
    # Save output
    doc = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "status": ai_status,
        "prompt_version": PROMPT_VERSION,
        "guidance": final_guidance
    }
    
    safe_write_json(str(guidance_path), doc)
    
    # Update security-review.json
    sec_review["remediation"] = {
        "status": ai_status,
        "guidance_path": str(guidance_path.relative_to(ROOT_DIR)) if guidance_path.is_absolute() else str(guidance_path),
        "cache_hits": cache_hits,
        "cache_misses": cache_misses
    }
    safe_write_json(str(sec_review_path), sec_review)

    # Usage
    model_name = os.environ.get("OPENAI_REMEDIATION_MODEL") or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    usage = {
        "scan_id": scan_id,
        "module": "Security Review AI Remediation",
        "status": ai_status,
        "model": model_name,
        "prompt_version": PROMPT_VERSION,
        "request_count": api_requests,
        "groups_total": len(groups),
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "input_tokens": tokens_stats["in"],
        "cached_input_tokens": 0,
        "output_tokens": tokens_stats["out"],
        "reasoning_tokens": 0,
        "total_tokens": tokens_stats["tot"],
        "errors": error_log
    }
    safe_write_json(str(usage_path), usage)
    print(f"[generate_ai_remediation] Done. Status: {ai_status}. Hits: {cache_hits}, Misses: {cache_misses}")

if __name__ == "__main__":
    main()

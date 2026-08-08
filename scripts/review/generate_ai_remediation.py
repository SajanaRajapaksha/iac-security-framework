#!/usr/bin/env python3
import sys
import argparse
import os
import time
from pathlib import Path
import json
try:
    import openai
except ImportError:
    openai = None

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.review.review_utils import safe_read_json, safe_write_json, generate_finding_key
from scripts.review.remediation_cache import generate_cache_key, load_cache, save_cache
from scripts.utils.evidence import utc_now_iso

PROMPT_VERSION = "iac-security-review-remediation-v1"
BATCH_SIZE = 6

REQUIRED_FIELDS = {
    "finding_key",
    "priority",
    "summary",
    "terraform_action",
    "runtime_action",
    "validation_step",
    "operational_caution",
}

VALID_PRIORITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

def get_model_name() -> str:
    return (
        os.environ.get("OPENAI_REMEDIATION_MODEL")
        or os.environ.get("OPENAI_MODEL")
        or "gpt-4o-mini"
    )

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

def run_ai_batch(
    groups: list[dict],
    client,
) -> tuple[list[dict], dict, str | None]:
    if not openai:
        return [], {}, "OpenAI library not installed."
        
    model = get_model_name()
    max_tokens = min(4096, 350 * len(groups) + 400)
    
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
            max_tokens=max_tokens,
            temperature=0.0
        )
        content = response.choices[0].message.content
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return [], {}, f"JSON Decode Error: {e}"
        
        usage = response.usage
        tokens = {
            "prompt_tokens": usage.prompt_tokens if usage else 0,
            "completion_tokens": usage.completion_tokens if usage else 0,
            "total_tokens": usage.total_tokens if usage else 0
        }
        
        raw_rems = data.get("remediations", [])
        if not isinstance(raw_rems, list):
            return [], tokens, "Response 'remediations' is not a list."

        valid_rems = []
        batch_keys = {g["finding_key"] for g in groups}
        
        for rem in raw_rems:
            if not isinstance(rem, dict):
                continue
            if rem.get("finding_key") not in batch_keys:
                continue
            
            missing = REQUIRED_FIELDS - set(rem.keys())
            if missing:
                continue
                
            priority = str(rem.get("priority", "")).upper()
            if priority not in VALID_PRIORITIES:
                continue
                
            if any(not isinstance(rem[k], str) for k in REQUIRED_FIELDS):
                continue
                
            valid_rems.append(rem)
            
        return valid_rems, tokens, None
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
            
            expected_keys = {g["finding_key"] for g in batch_groups}
            returned_keys = {r["finding_key"] for r in rems}
            missing_keys = expected_keys - returned_keys
            
            if missing_keys:
                ai_status = "AI_REMEDIATION_PARTIAL"
                
            if err:
                sanitized_error = str(err)
                if api_key:
                    sanitized_error = sanitized_error.replace(api_key, "***")
                error_log.append(sanitized_error)
                ai_status = "AI_REMEDIATION_PARTIAL"
                
                print(f"[generate_ai_remediation] Batch {i // BATCH_SIZE + 1} failed: {sanitized_error}", file=sys.stderr)
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
    model_name = get_model_name()
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
    
    print("============================================================")
    print("  AI REMEDIATION SUMMARY")
    print("============================================================")
    print(f"OpenAI model             : {model_name}")
    print(f"Total remediation groups : {len(groups)}")
    print(f"Cache hits               : {cache_hits}")
    print(f"Cache misses             : {cache_misses}")
    print(f"API requests             : {api_requests}")
    print(f"AI guidance generated    : {len(new_guidance)}")
    print(f"Cached guidance used     : {len(cached_guidance)}")
    print(f"Scanner-only fallbacks   : {len(fallback_guidance)}")
    print(f"Input tokens             : {tokens_stats['in']}")
    print(f"Output tokens            : {tokens_stats['out']}")
    print(f"Total tokens             : {tokens_stats['tot']}")
    print(f"Final status             : {ai_status}")
    print("============================================================")

if __name__ == "__main__":
    main()

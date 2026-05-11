#!/usr/bin/env python3
"""
scripts/risk/ai_map_unmapped_findings.py

Use OpenAI to map unmapped findings to CIS/AWS canonical controls.
Falls back gracefully when OPENAI_API_KEY is absent.

Usage:
    python scripts/risk/ai_map_unmapped_findings.py <SCAN_ID>

Input:
    reports/risk/<SCAN_ID>/unmapped-findings.json
    config/risk/allowed-controls.yml

Output:
    reports/risk/<SCAN_ID>/ai-cis-mapping.json
    reports/risk/<SCAN_ID>/ai-request.json
    reports/risk/<SCAN_ID>/ai-model-metadata.json
    reports/risk/<SCAN_ID>/mapping-cache.json
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "gpt-4.1-nano"
BATCH_SIZE = 10
MAX_OUTPUT_TOKENS = 2048
TEMPERATURE = 0

SYSTEM_PROMPT = """You are a cybersecurity control mapping assistant for an Infrastructure-as-Code risk engine.
Map each finding to exactly one allowed canonical control and relevant CIS Controls v8/AWS control references.
Do not calculate risk scores.
Do not invent unknown IDs. If unsure, use UNKNOWN_SECURITY_MISCONFIGURATION, confidence low, requires_review true.
Return JSON only matching the schema.
Keep reasons under 40 words.

Allowed controls:
PUBLIC_ADMIN_ACCESS, PUBLIC_STORAGE_ACCESS, PUBLIC_DATABASE_ACCESS, IAM_OVER_PRIVILEGE, HARDCODED_SECRET, ENCRYPTION_DISABLED, LOGGING_DISABLED, CLOUDTRAIL_DISABLED, UNRESTRICTED_EGRESS, BACKUP_DISABLED, VERSIONING_DISABLED, WEAK_TLS_OR_HTTP, UNKNOWN_SECURITY_MISCONFIGURATION, HYGIENE_ISSUE, PUBLIC_SERVICE_EXPOSURE.

Output schema:
{
  "mappings": [
    {
      "finding_id": "string",
      "canonical_control": "string (one of allowed controls)",
      "control_domain": "string",
      "cis_controls_v8": ["string"],
      "aws_control_refs": ["string"],
      "base_control_criticality": integer 1-10,
      "mandatory_block": boolean,
      "mapping_confidence": "high|medium|low",
      "requires_review": boolean,
      "mapping_reason": "string (under 40 words)"
    }
  ]
}"""


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_key(finding: dict) -> str:
    """Create a cache key from stable finding attributes."""
    tool = finding.get("source_tool", "")
    rule = finding.get("source_rule_id", "")
    rtype = finding.get("resource_type", "")
    desc = finding.get("description", "")[:100]
    raw = f"{tool}|{rule}|{rtype}|{desc}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def load_cache(path: Path) -> dict:
    data = safe_read_json(str(path))
    return data if isinstance(data, dict) else {}


def save_cache(path: Path, cache: dict):
    safe_write_json(str(path), cache)


# ---------------------------------------------------------------------------
# Compact finding for prompt
# ---------------------------------------------------------------------------

def compact_finding(f: dict) -> dict:
    """Extract only the fields needed for the AI prompt."""
    policy = f.get("policy", {})
    return {
        "finding_id": f.get("finding_id"),
        "source_tool": f.get("source_tool"),
        "source_rule_id": f.get("source_rule_id"),
        "source_severity": f.get("source_severity"),
        "title": f.get("title", "")[:120],
        "description": f.get("description", "")[:200],
        "resource_type": f.get("resource_type", "")[:60],
        "resource": f.get("resource", "")[:80],
        "file_path": f.get("file_path", "")[:80],
        "enforcement_level": policy.get("enforcement_level", "none") if isinstance(policy, dict) else "none",
    }


# ---------------------------------------------------------------------------
# Fallback mapping (no API key)
# ---------------------------------------------------------------------------

def fallback_mapping(finding: dict, source: str = "no_api_key_fallback") -> dict:
    return {
        "finding_id": finding.get("finding_id", "UNKNOWN"),
        "canonical_control": "UNKNOWN_SECURITY_MISCONFIGURATION",
        "control_domain": "unknown",
        "cis_controls_v8": [],
        "aws_control_refs": [],
        "base_control_criticality": 4,
        "mandatory_block": False,
        "mapping_confidence": "low",
        "requires_review": True,
        "mapping_source": source,
        "mapping_reason": f"Fallback: {source}. Manual review required.",
    }


# ---------------------------------------------------------------------------
# OpenAI call
# ---------------------------------------------------------------------------

def call_openai(batch: list[dict], model: str, api_key: str) -> list[dict]:
    """Call OpenAI API for a batch of compact findings."""
    try:
        from openai import OpenAI
    except ImportError:
        print("[ai_map] WARNING: openai package not installed. Using fallback.")
        return []

    client = OpenAI(api_key=api_key)

    user_msg = json.dumps({"findings": batch}, indent=None, separators=(",", ":"))

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_OUTPUT_TOKENS,
            response_format={"type": "json_object"},
        )
    except Exception as exc:
        print(f"[ai_map] ERROR: OpenAI API call failed: {exc}")
        return []

    raw = response.choices[0].message.content if response.choices else ""
    try:
        parsed = json.loads(raw)
        mappings = parsed.get("mappings", [])
        if isinstance(mappings, list):
            return mappings
    except (json.JSONDecodeError, AttributeError):
        print(f"[ai_map] WARNING: Could not parse AI response as JSON.")
    return []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AI-map unmapped findings to CIS controls.")
    parser.add_argument("scan_id", help="SCAN_ID for this pipeline run")
    args = parser.parse_args()
    scan_id = args.scan_id

    report_dir = ROOT / "reports" / "risk" / scan_id
    report_dir.mkdir(parents=True, exist_ok=True)

    # Load unmapped findings
    unmapped_data = safe_read_json(str(report_dir / "unmapped-findings.json"))
    if not isinstance(unmapped_data, dict):
        print(f"[ai_map] ERROR: Cannot read unmapped-findings.json", file=sys.stderr)
        sys.exit(1)

    unmapped = unmapped_data.get("findings", [])
    print(f"[ai_map] SCAN_ID           = {scan_id}")
    print(f"[ai_map] Unmapped findings = {len(unmapped)}")

    # Early exit: nothing to map
    if not unmapped:
        _write_empty_outputs(report_dir, scan_id)
        print("[ai_map] No unmapped findings. Skipping AI mapping.")
        return

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model = os.environ.get("OPENAI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    # Load cache
    cache_path = report_dir / "mapping-cache.json"
    cache = load_cache(cache_path)

    all_mappings = []
    to_call: list[dict] = []  # findings needing API
    finding_to_cache_key: dict[str, str] = {}
    cache_hits = 0
    api_calls = 0

    # Check cache first
    for f in unmapped:
        fid = f.get("finding_id", "")
        ck = _cache_key(f)
        finding_to_cache_key[fid] = ck

        if ck in cache:
            cached = dict(cache[ck])
            cached["finding_id"] = fid
            cached["mapping_source"] = "cache"
            all_mappings.append(cached)
            cache_hits += 1
        else:
            to_call.append(f)

    print(f"[ai_map] Cache hits        = {cache_hits}")
    print(f"[ai_map] Need API          = {len(to_call)}")

    if not api_key:
        print("[ai_map] WARNING: OPENAI_API_KEY not set. Using fallback for all unmapped.")
        for f in to_call:
            fb = fallback_mapping(f, source="no_api_key_fallback")
            fb["mapping_source"] = "no_api_key_fallback"
            all_mappings.append(fb)
    elif to_call:
        print(f"[ai_map] Model             = {model}")
        # Batch and call
        all_requests = []
        batches = [to_call[i:i + BATCH_SIZE] for i in range(0, len(to_call), BATCH_SIZE)]
        for batch in batches:
            compact_batch = [compact_finding(f) for f in batch]
            all_requests.append(compact_batch)
            results = call_openai(compact_batch, model, api_key)
            api_calls += 1

            # Index results by finding_id
            result_map = {r.get("finding_id"): r for r in results if isinstance(r, dict)}

            for f in batch:
                fid = f.get("finding_id", "")
                if fid in result_map:
                    m = result_map[fid]
                    m["mapping_source"] = "ai"
                    all_mappings.append(m)
                    # Update cache
                    ck = finding_to_cache_key.get(fid)
                    if ck:
                        cache[ck] = {k: v for k, v in m.items() if k != "finding_id"}
                else:
                    fb = fallback_mapping(f, source="ai_no_response")
                    all_mappings.append(fb)

        # Save request bodies (no secrets)
        safe_write_json(str(report_dir / "ai-request.json"), {
            "scan_id": scan_id,
            "model": model,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "batch_count": len(batches),
            "total_findings_sent": len(to_call),
            "batches": all_requests,
            "note": "API key is NOT stored in this file.",
        })

    # Save cache
    save_cache(cache_path, cache)

    # Save AI mappings
    safe_write_json(str(report_dir / "ai-cis-mapping.json"), {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "total_unmapped": len(unmapped),
            "cache_hits": cache_hits,
            "api_calls": api_calls,
            "model": model if api_key else "none",
        },
        "mappings": all_mappings,
    })

    # Save model metadata
    safe_write_json(str(report_dir / "ai-model-metadata.json"), {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "model": model if api_key else "none",
        "api_key_present": bool(api_key),
        "temperature": TEMPERATURE,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "batch_size": BATCH_SIZE,
        "api_call_count": api_calls,
        "cache_hit_count": cache_hits,
        "total_unmapped_findings": len(unmapped),
        "findings_sent_to_api": len(to_call),
        "note": "AI was used only for CIS/AWS control mapping. Risk scoring and deployment decisions are fully deterministic.",
    })

    print(f"[ai_map] API calls         = {api_calls}")
    print(f"[ai_map] Total AI mappings = {len(all_mappings)}")


def _write_empty_outputs(report_dir: Path, scan_id: str):
    safe_write_json(str(report_dir / "ai-cis-mapping.json"), {
        "metadata": {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "total_unmapped": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "model": "none",
        },
        "mappings": [],
    })
    safe_write_json(str(report_dir / "ai-request.json"), {
        "scan_id": scan_id,
        "note": "No unmapped findings. No API call made.",
    })
    safe_write_json(str(report_dir / "ai-model-metadata.json"), {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "model": "none",
        "api_key_present": False,
        "api_call_count": 0,
        "total_unmapped_findings": 0,
        "note": "No unmapped findings. AI was not invoked.",
    })
    safe_write_json(str(report_dir / "mapping-cache.json"), {})


if __name__ == "__main__":
    main()

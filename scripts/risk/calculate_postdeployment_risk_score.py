#!/usr/bin/env python3
"""
scripts/risk/calculate_postdeployment_risk_score.py

Post-Deployment Risk Scoring Engine.

Calculates a normalized post-deployment security posture score (0-1000)
from Prowler runtime findings. Higher score = better security posture.

Formula:
    post_deployment_risk_score = round(1000 * exp(-((alpha * D) + (beta * U))))

Where:
    D = confirmed weighted finding density (severity-weighted, per-resource capped, normalised)
    U = unknown severity density (count of UNKNOWN findings / resource count)

Usage:
    python scripts/risk/calculate_postdeployment_risk_score.py <SCAN_ID>
"""

import argparse
import math
import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALPHA: float = 0.60
BETA: float = 0.20
RESOURCE_PENALTY_CAP: float = 1.50

SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 1.00,
    "HIGH":     0.80,
    "MEDIUM":   0.50,
    "LOW":      0.20,
    "INFO":     0.05,
}
CONFIRMED_SEVERITIES = set(SEVERITY_WEIGHTS.keys())

RISK_BANDS: list[tuple[int, int, str, str]] = [
    (900, 1000, "VERY_LOW_RISK",  "PASS"),
    (750,  899, "LOW_RISK",       "MONITOR"),
    (500,  749, "MODERATE_RISK",  "REMEDIATION_REQUIRED"),
    (250,  499, "HIGH_RISK",      "URGENT_REMEDIATION"),
    (0,    249, "CRITICAL_RISK",  "CRITICAL_REMEDIATION"),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assign_band(score: int) -> tuple[str, str]:
    for lo, hi, band, decision in RISK_BANDS:
        if lo <= score <= hi:
            return band, decision
    return "CRITICAL_RISK", "CRITICAL_REMEDIATION"

def _normalize_severity(sev: str) -> str:
    s = str(sev).upper()
    if s == "INFORMATIONAL":
        return "INFO"
    if s in SEVERITY_WEIGHTS:
        return s
    return "UNKNOWN"

# ---------------------------------------------------------------------------
# Core scoring logic
# ---------------------------------------------------------------------------

def calculate_score(
    findings: list[dict],
    resource_count: int,
    alpha: float = ALPHA,
    beta: float = BETA,
    resource_penalty_cap: float = RESOURCE_PENALTY_CAP,
) -> dict:
    sev_counts: dict[str, int] = {k: 0 for k in list(SEVERITY_WEIGHTS.keys()) + ["UNKNOWN"]}

    # Group by resource
    resource_map: dict[str, dict] = {}
    
    for f in findings:
        r_arn = f.get("resource", {}).get("arn")
        r_id = f.get("resource", {}).get("id")
        r_name = f.get("resource", {}).get("name")
        r_key = r_arn or r_id or r_name or "Unknown"
        
        if r_key not in resource_map:
            resource_map[r_key] = {
                "arn": r_arn or "",
                "id": r_id or "",
                "name": r_name or "",
                "service": f.get("service") or (r_arn.split(":")[2] if r_arn and ":" in r_arn else "unknown"),
                "region": f.get("region") or "",
                "confirmed": [],
                "unknown": []
            }
            
        sev = _normalize_severity(f.get("severity", {}).get("normalized") or f.get("severity", "UNKNOWN"))
        if sev in CONFIRMED_SEVERITIES:
            resource_map[r_key]["confirmed"].append(sev)
            sev_counts[sev] += 1
        else:
            resource_map[r_key]["unknown"].append(sev)
            sev_counts["UNKNOWN"] += 1

    confirmed_count = sum(sev_counts[s] for s in CONFIRMED_SEVERITIES)
    unknown_count = sev_counts["UNKNOWN"]

    resource_penalties: list[dict] = []
    total_capped_confirmed_penalty: float = 0.0

    for r_key, data in resource_map.items():
        uncapped: float = sum(SEVERITY_WEIGHTS[s] for s in data["confirmed"])
        capped: float = min(uncapped, resource_penalty_cap)
        applied_cap: bool = uncapped > resource_penalty_cap

        resource_penalties.append({
            "resource_key": r_key,
            "resource_arn": data["arn"],
            "resource_id": data["id"],
            "resource_name": data["name"],
            "service": data["service"],
            "aws_region": data["region"],
            "confirmed_finding_count": len(data["confirmed"]),
            "unknown_finding_count": len(data["unknown"]),
            "raw_confirmed_penalty": round(uncapped, 6),
            "capped_confirmed_penalty": round(capped, 6),
            "cap_applied": applied_cap,
        })
        total_capped_confirmed_penalty += capped

    resource_penalties.sort(key=lambda x: x["capped_confirmed_penalty"], reverse=True)

    if resource_count < 1:
        resource_count = 1

    D: float = total_capped_confirmed_penalty / resource_count
    U: float = unknown_count / resource_count

    if len(findings) == 0:
        D = 0.0
        U = 0.0
        
    raw_score: float = 1000.0 * math.exp(-((alpha * D) + (beta * U)))
    score: int = int(round(raw_score))
    score = max(0, min(1000, score))

    risk_band, suggested_decision = _assign_band(score)
    unknown_findings_present = unknown_count > 0
    review_required = unknown_findings_present

    return {
        "sev_counts": sev_counts,
        "confirmed_count": confirmed_count,
        "unknown_count": unknown_count,
        "resource_penalties": resource_penalties,
        "D": D,
        "U": U,
        "raw_score": raw_score,
        "score": score,
        "risk_band": risk_band,
        "suggested_decision": suggested_decision,
        "unknown_findings_present": unknown_findings_present,
        "review_required": review_required,
    }

# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------

def _write_markdown(md_path: Path, scan_id: str, results: dict, res_count: int, src: str, scope: str, paths: dict):
    lines = [
        f"# Post-Deployment Risk Score: {scan_id}",
        "",
        "## Summary",
        f"- **Score**: `{results['score']} / 1000`",
        f"- **Risk Band**: **{results['risk_band']}**",
        f"- **Suggested Action**: **{results['suggested_decision']}**",
        f"- **Resource Count**: `{res_count}` (source: `{src}`)",
        f"- **Total Findings**: `{results['confirmed_count'] + results['unknown_count']}`",
        f"- **Confirmed Findings**: `{results['confirmed_count']}`",
        f"- **Unknown Findings**: `{results['unknown_count']}`",
        f"- **Scan Scope**: `{scope}`",
        "",
        "> Higher score = better post-deployment security posture.",
        "",
        "## Formula",
        "```",
        "post_deployment_risk_score = round(1000 * exp(-((0.60 * D) + (0.20 * U))))",
        "```",
        f"- **D (Confirmed Density)**: `{round(results['D'], 6)}`",
        f"- **U (Unknown Density)**: `{round(results['U'], 6)}`",
        "",
        "## Severity Counts",
    ]
    for k, v in results['sev_counts'].items():
        lines.append(f"- **{k}**: {v}")
    
    lines.extend([
        "",
        "## Resource Penalties",
    ])
    
    if not results['resource_penalties']:
        lines.append("No findings recorded.")
    else:
        for rp in results['resource_penalties']:
            lines.extend([
                f"### `{rp['resource_key']}`",
                f"- **Service**: {rp['service']}",
                f"- **Confirmed Findings**: {rp['confirmed_finding_count']}",
                f"- **Unknown Findings**: {rp['unknown_finding_count']}",
                f"- **Raw Penalty**: {rp['raw_confirmed_penalty']}",
                f"- **Capped Penalty**: {rp['capped_confirmed_penalty']}",
                f"- **Cap Applied**: {'true' if rp['cap_applied'] else 'false'}",
                ""
            ])
            
    lines.extend([
        "## Evidence Paths",
        f"- **Runtime Findings**: `{paths['findings']}`",
        f"- **Tagged Resources**: `{paths['tagged']}`",
        f"- **Prowler Execution**: `{paths['exec']}`",
        ""
    ])
    
    safe_write_json(str(md_path).replace(".json", ".md"), "\n".join(lines))
    try:
        md_path.write_text("\n".join(lines))
    except Exception:
        pass


def _print_console(scan_id: str, results: dict, res_count: int, src: str, status: str, scope: str, json_path: Path):
    print("============================================================")
    print("  POST-DEPLOYMENT RISK SCORE")
    print("============================================================")
    print(f"SCAN_ID              : {scan_id}")
    print(f"Score                : {results['score']} / 1000")
    print(f"Risk Band            : {results['risk_band']}")
    print(f"Suggested Action     : {results['suggested_decision']}")
    print(f"Resource Count       : {res_count}  (source: {src})")
    print(f"Total Findings       : {results['confirmed_count'] + results['unknown_count']}")
    print(f"Confirmed Findings   : {results['confirmed_count']}")
    print(f"Unknown Findings     : {results['unknown_count']}")
    print(f"D                    : {round(results['D'], 6)}")
    print(f"U                    : {round(results['U'], 6)}")
    print("Formula              : round(1000 * exp(-((0.6 * D) + (0.2 * U))))")
    print("Higher Is Better     : true")
    print(f"Scan Scope           : {scope}")
    print(f"Prowler Status       : {status}")
    print()
    print("Severity Counts:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]:
        print(f"  {sev:<8} : {results['sev_counts'].get(sev, 0)}")

    print("\n------------------------------------------------------------")
    print("  RESOURCE PENALTIES")
    print("------------------------------------------------------------")
    for rp in results['resource_penalties']:
        print(f"{rp['resource_key']}")
        print(f"  Resource Name      : {rp['resource_name'] or 'unknown'}")
        print(f"  Service            : {rp['service']}")
        print(f"  Confirmed Findings : {rp['confirmed_finding_count']}")
        print(f"  Unknown Findings   : {rp['unknown_finding_count']}")
        print(f"  Raw Penalty        : {rp['raw_confirmed_penalty']}")
        print(f"  Capped Penalty     : {rp['capped_confirmed_penalty']}")
        print(f"  Cap Applied        : {'true' if rp['cap_applied'] else 'false'}")
        print()

    print("============================================================")
    print(f"  Score written to: {json_path.relative_to(ROOT_DIR) if json_path.is_absolute() else json_path}")


# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------

def _write_not_calculated(risk_dir: Path, scan_id: str, reason: str):
    risk_dir.mkdir(parents=True, exist_ok=True)
    out_path = risk_dir / "postdeployment-risk-score.json"
    doc = {
        "scan_id": scan_id,
        "module": "Post-Deployment Risk Scoring Engine",
        "status": "NOT_CALCULATED",
        "reason": reason,
        "security_conclusion_available": False
    }
    safe_write_json(str(out_path), doc)
    print(f"[postdeployment_risk_score] NOT_CALCULATED: {reason}", file=sys.stderr)
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Post-Deployment Risk Scoring Engine")
    parser.add_argument("scan_id", help="Unique SCAN_ID")
    args = parser.parse_args()
    scan_id = args.scan_id

    runtime_dir = ROOT_DIR / "reports" / "runtime" / scan_id
    risk_dir = runtime_dir / "risk"
    
    findings_path = runtime_dir / "normalized" / "runtime-findings.json"
    summary_path = runtime_dir / "normalized" / "runtime-findings-summary.json"
    tagged_path = runtime_dir / "scope" / "tagged-resources.json"
    exec_path = runtime_dir / "prowler" / "prowler-execution.json"
    out_path = risk_dir / "postdeployment-risk-score.json"
    md_path = risk_dir / "postdeployment-risk-score.md"
    
    # 1. Validation
    if not exec_path.is_file():
        _write_not_calculated(risk_dir, scan_id, "prowler-execution.json is missing")
    
    exec_data = safe_read_json(str(exec_path)) or {}
    status = exec_data.get("execution", {}).get("status", "EXECUTION_ERROR")
    
    if status not in ("SUCCESS_NO_FINDINGS", "SUCCESS_WITH_FINDINGS"):
        _write_not_calculated(risk_dir, scan_id, status)
        
    if not findings_path.is_file():
        _write_not_calculated(risk_dir, scan_id, "runtime-findings.json is missing")

    norm_data = safe_read_json(str(findings_path))
    if not isinstance(norm_data, dict):
        _write_not_calculated(risk_dir, scan_id, "normalized evidence is malformed")
        
    findings = norm_data.get("findings", [])
    scope = norm_data.get("scan_scope", {}).get("type", "TAGGED_DEPLOYMENT_RESOURCES_ONLY")

    # 2. Denominator
    res_count = 0
    res_src = ""
    
    if tagged_path.is_file():
        tagged_data = safe_read_json(str(tagged_path))
        if isinstance(tagged_data, dict):
            mapping = tagged_data.get("ResourceTagMappingList")
            if isinstance(mapping, list):
                res_count = len(mapping)
                res_src = "tagged_resources_discovered"

    if res_count == 0:
        summary_data = safe_read_json(str(summary_path))
        if isinstance(summary_data, dict) and summary_data.get("tagged_resources_discovered"):
            res_count = summary_data.get("tagged_resources_discovered")
            res_src = "summary"
        else:
            unique_res = {f.get("resource", {}).get("id") for f in findings if f.get("resource", {}).get("id")}
            if unique_res:
                res_count = len(unique_res)
                res_src = "unique_normalized_finding_resources"

    if res_count == 0:
        _write_not_calculated(risk_dir, scan_id, "tagged resource count is zero or runtime resource scope cannot be established")

    # 3. Calculate
    res = calculate_score(findings, res_count)
    
    # 4. Output
    risk_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "module": "Post-Deployment Risk Scoring Engine",
        "status": "CALCULATED",
        "score_type": "post_deployment_security_posture_score",
        "score_scale": {
            "minimum": 0,
            "maximum": 1000,
            "higher_is_better": True
        },
        "formula": "round(1000 * exp(-((alpha * D) + (beta * U))))",
        "parameters": {
            "alpha": ALPHA,
            "beta": BETA,
            "resource_penalty_cap": RESOURCE_PENALTY_CAP,
            "severity_weights": SEVERITY_WEIGHTS
        },
        "inputs": {
            "runtime_findings_path": str(findings_path.relative_to(ROOT_DIR)) if findings_path.is_absolute() else str(findings_path),
            "tagged_resources_path": str(tagged_path.relative_to(ROOT_DIR)) if tagged_path.is_absolute() else str(tagged_path),
            "prowler_execution_path": str(exec_path.relative_to(ROOT_DIR)) if exec_path.is_absolute() else str(exec_path),
            "resource_count": res_count,
            "resource_count_source": res_src,
            "total_findings": res["confirmed_count"] + res["unknown_count"],
            "confirmed_findings": res["confirmed_count"],
            "unknown_findings": res["unknown_count"],
            "prowler_execution_status": status,
            "scan_scope": scope
        },
        "severity_counts": res["sev_counts"],
        "density_values": {
            "confirmed_weighted_density_D": res["D"],
            "unknown_density_U": res["U"]
        },
        "score": {
            "raw_score": res["raw_score"],
            "post_deployment_risk_score": res["score"],
            "risk_band": res["risk_band"],
            "suggested_action": res["suggested_decision"],
            "review_required": res["review_required"],
            "unknown_findings_present": res["unknown_findings_present"]
        },
        "resource_penalties": res["resource_penalties"],
        "warnings": []
    }

    safe_write_json(str(out_path), doc)
    
    paths = {
        "findings": str(findings_path.relative_to(ROOT_DIR)) if findings_path.is_absolute() else str(findings_path),
        "tagged": str(tagged_path.relative_to(ROOT_DIR)) if tagged_path.is_absolute() else str(tagged_path),
        "exec": str(exec_path.relative_to(ROOT_DIR)) if exec_path.is_absolute() else str(exec_path)
    }
    
    _write_markdown(md_path, scan_id, res, res_count, res_src, scope, paths)
    _print_console(scan_id, res, res_count, res_src, status, scope, out_path)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
scripts/risk/calculate_predeployment_risk_score.py

Pre-Deployment Risk Scoring Engine.

Calculates a normalized pre-deployment security posture score (0–1000)
from enriched findings.  Higher score = better security posture.

Formula:
    pre_deployment_risk_score = round(1000 * exp(-((alpha * D) + (beta * U))))

Where:
    D = confirmed weighted finding density  (severity-weighted, per-resource capped, normalised)
    U = unknown severity density            (count of UNKNOWN findings / resource count)

Inputs:
    reports/risk/<SCAN_ID>/enriched-findings.json

Outputs:
    reports/risk/<SCAN_ID>/predeployment-risk-score.json
    reports/risk/<SCAN_ID>/predeployment-risk-score.md

Usage:
    python scripts/risk/calculate_predeployment_risk_score.py <SCAN_ID>
"""

import argparse
import math
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALPHA: float = 0.60          # confirmed-risk sensitivity
BETA: float = 0.20           # unknown-risk sensitivity
RESOURCE_PENALTY_CAP: float = 1.50   # per-resource confirmed-penalty cap

SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 1.00,
    "HIGH":     0.80,
    "MEDIUM":   0.50,
    "LOW":      0.20,
    "INFO":     0.05,
}
CONFIRMED_SEVERITIES = set(SEVERITY_WEIGHTS.keys())

RISK_BANDS: list[tuple[int, int, str, str]] = [
    # (min_score, max_score, band_name, suggested_decision)
    (900, 1000, "VERY_LOW_RISK",  "PASS"),
    (750,  899, "LOW_RISK",       "PASS_WITH_ADVISORY"),
    (500,  749, "MODERATE_RISK",  "REVIEW"),
    (250,  499, "HIGH_RISK",      "REVIEW_HIGH_RISK"),
    (0,    249, "CRITICAL_RISK",  "BLOCK_RECOMMENDED"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assign_band(score: int) -> tuple[str, str]:
    """Return (risk_band, suggested_decision) for *score*."""
    for lo, hi, band, decision in RISK_BANDS:
        if lo <= score <= hi:
            return band, decision
    return "CRITICAL_RISK", "BLOCK_RECOMMENDED"


def _load_predeployment_inventory(risk_dir: Path) -> dict | None:
    """Load the authoritative predeployment-resource-inventory.json."""
    inv_path = risk_dir / "predeployment-resource-inventory.json"
    data = safe_read_json(str(inv_path))
    if isinstance(data, dict) and isinstance(data.get("resource_count"), int):
        return data
    return None


def _write_not_calculated(risk_dir: Path, scan_id: str, reason: str) -> None:
    """Write a NOT_CALCULATED result and exit."""
    risk_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "module": "Pre-Deployment Risk Scoring Engine",
        "status": "NOT_CALCULATED",
        "reason": reason,
        "security_conclusion_available": False,
    }
    safe_write_json(str(risk_dir / "predeployment-risk-score.json"), doc)
    print(
        f"[predeployment_risk_score] NOT_CALCULATED: {reason}",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Core scoring logic (pure function — easy to unit-test independently)
# ---------------------------------------------------------------------------

def calculate_score(
    findings: list[dict],
    resource_count: int,
    alpha: float = ALPHA,
    beta: float = BETA,
    resource_penalty_cap: float = RESOURCE_PENALTY_CAP,
) -> dict:
    """
    Run the scoring algorithm over *findings* and return a results dict.

    This function is deliberately kept free of I/O so it can be tested in
    isolation without touching the filesystem.
    """
    sev_counts: dict[str, int] = {k: 0 for k in list(SEVERITY_WEIGHTS.keys()) + ["UNKNOWN"]}

    # Group findings by resource
    resource_map: dict[str, dict] = {}  # resource -> {"confirmed": [...], "unknown": [...]}
    for f in findings:
        res = f.get("resource") or "Unknown"
        if res not in resource_map:
            resource_map[res] = {"confirmed": [], "unknown": []}
        sev = (f.get("final_severity") or "UNKNOWN").upper()
        if sev in CONFIRMED_SEVERITIES:
            resource_map[res]["confirmed"].append(sev)
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        else:
            resource_map[res]["unknown"].append(sev)
            sev_counts["UNKNOWN"] = sev_counts.get("UNKNOWN", 0) + 1

    confirmed_count = sum(sev_counts[s] for s in CONFIRMED_SEVERITIES)
    unknown_count = sev_counts["UNKNOWN"]

    # Build per-resource penalty table
    resource_penalties: list[dict] = []
    total_capped_confirmed_penalty: float = 0.0

    for res, buckets in resource_map.items():
        uncapped: float = sum(SEVERITY_WEIGHTS[s] for s in buckets["confirmed"])
        capped: float = min(uncapped, resource_penalty_cap)
        applied_cap: bool = uncapped > resource_penalty_cap

        resource_penalties.append({
            "resource": res,
            "confirmed_finding_count": len(buckets["confirmed"]),
            "unknown_finding_count": len(buckets["unknown"]),
            "uncapped_confirmed_penalty": round(uncapped, 6),
            "capped_confirmed_penalty": round(capped, 6),
            "applied_cap": applied_cap,
        })
        total_capped_confirmed_penalty += capped

    # Sort by capped penalty descending for readability
    resource_penalties.sort(key=lambda x: x["capped_confirmed_penalty"], reverse=True)

    D: float = total_capped_confirmed_penalty / resource_count
    U: float = unknown_count / resource_count

    raw_score: float = 1000.0 * math.exp(-((alpha * D) + (beta * U)))
    score: int = int(round(raw_score))
    score = max(0, min(1000, score))  # clamp

    risk_band, suggested_decision = _assign_band(score)

    unknown_findings_present = unknown_count > 0
    review_required = unknown_findings_present  # additional rule

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
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pre-Deployment Risk Scoring Engine — calculates a normalised 0-1000 security posture score."
    )
    parser.add_argument("scan_id", help="Unique SCAN_ID (e.g. SCAN-ABCD1234)")
    args = parser.parse_args()
    scan_id: str = args.scan_id

    risk_dir = ROOT_DIR / "reports" / "risk" / scan_id
    enriched_path = risk_dir / "enriched-findings.json"

    # ------------------------------------------------------------------ #
    # Defensive: missing enriched-findings.json                           #
    # ------------------------------------------------------------------ #
    if not enriched_path.is_file():
        error_output = {
            "scan_id": scan_id,
            "generated_at": utc_now_iso(),
            "module": "Pre-Deployment Risk Scoring Engine",
            "status": "ERROR",
            "error": (
                f"enriched-findings.json not found at {enriched_path}. "
                "Ensure the Finding Enrichment Engine (Stages 12-14) completed "
                "successfully before running this module."
            ),
        }
        risk_dir.mkdir(parents=True, exist_ok=True)
        safe_write_json(str(risk_dir / "predeployment-risk-score.json"), error_output)
        print(
            f"[predeployment_risk_score] ERROR: enriched-findings.json not found "
            f"at {enriched_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    enriched = safe_read_json(str(enriched_path)) or {}
    findings: list[dict] = enriched.get("findings", [])

    warnings: list[str] = []

    # ------------------------------------------------------------------ #
    # Determine total resource count (authoritative denominator)           #
    # ------------------------------------------------------------------ #
    inventory = _load_predeployment_inventory(risk_dir)

    if inventory and inventory.get("resource_count", 0) > 0:
        total_resource_count: int = inventory["resource_count"]
        resource_count_source: str = inventory.get(
            "resource_count_source", "predeployment_resource_inventory"
        )
    else:
        _write_not_calculated(
            risk_dir, scan_id,
            "Pre-deployment resource inventory not found or contains zero resources. "
            "Run build_predeployment_resource_inventory.py before risk scoring."
        )
        return  # unreachable after sys.exit but keeps linters happy

    # ------------------------------------------------------------------ #
    # Affected resource count                                             #
    # ------------------------------------------------------------------ #
    affected_resources: set[str] = {
        f.get("resource")
        for f in findings
        if f.get("resource") and f.get("resource") != "Unknown"
    }
    affected_resource_count: int = len(affected_resources)

    if affected_resource_count > total_resource_count:
        _write_not_calculated(
            risk_dir, scan_id,
            f"Validation failure: affected_resource_count ({affected_resource_count}) "
            f"> total_resource_count ({total_resource_count}). "
            "The resource inventory may be incomplete."
        )
        return

    affected_resource_ratio: float = (
        round(affected_resource_count / total_resource_count, 4)
        if total_resource_count > 0 else 0.0
    )

    # ------------------------------------------------------------------ #
    # Score                                                               #
    # ------------------------------------------------------------------ #
    result = calculate_score(findings, total_resource_count)

    # ------------------------------------------------------------------ #
    # Build JSON output                                                   #
    # ------------------------------------------------------------------ #
    enriched_findings_rel = f"reports/risk/{scan_id}/enriched-findings.json"

    score_json: dict = {
        "scan_id": scan_id,
        "generated_at": utc_now_iso(),
        "module": "Pre-Deployment Risk Scoring Engine",
        "status": "CALCULATED",
        "score_type": "pre_deployment_security_posture_score",
        "score_scale": {
            "minimum": 0,
            "maximum": 1000,
            "higher_is_better": True,
        },
        "formula": "round(1000 * exp(-((alpha * D) + (beta * U))))",
        "parameters": {
            "alpha": ALPHA,
            "beta": BETA,
            "resource_penalty_cap": RESOURCE_PENALTY_CAP,
            "severity_weights": SEVERITY_WEIGHTS,
        },
        "inputs": {
            "enriched_findings_path": enriched_findings_rel,
            "resource_count_source": resource_count_source,
            "total_resource_count": total_resource_count,
            "affected_resource_count": affected_resource_count,
            "affected_resource_ratio": affected_resource_ratio,
            "total_findings": len(findings),
            "confirmed_findings": result["confirmed_count"],
            "unknown_findings": result["unknown_count"],
        },
        "severity_counts": result["sev_counts"],
        "density_values": {
            "confirmed_weighted_density_D": round(result["D"], 6),
            "unknown_density_U": round(result["U"], 6),
        },
        "score": {
            "raw_score": round(result["raw_score"], 4),
            "pre_deployment_risk_score": result["score"],
            "risk_band": result["risk_band"],
            "suggested_decision": result["suggested_decision"],
            "review_required": result["review_required"],
            "unknown_findings_present": result["unknown_findings_present"],
        },
        "resource_penalties": result["resource_penalties"],
        "warnings": warnings,
    }

    safe_write_json(str(risk_dir / "predeployment-risk-score.json"), score_json)

    # ------------------------------------------------------------------ #
    # Build Markdown output                                               #
    # ------------------------------------------------------------------ #
    sc = result["sev_counts"]
    md_lines: list[str] = [
        "# Pre-Deployment Risk Score",
        "",
        f"> **Higher score = better pre-deployment security posture.** "
        f"Score range: 0 (maximum risk) to 1000 (minimum risk).",
        "",
        "## Summary",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Scan ID | `{scan_id}` |",
        f"| Generated At | {score_json['generated_at']} |",
        f"| **Final Score** | **{result['score']} / 1000** |",
        f"| **Risk Band** | **{result['risk_band']}** |",
        f"| **Suggested Decision** | **{result['suggested_decision']}** |",
        f"| Review Required | {str(result['review_required']).lower()} |",
        f"| Unknown Findings Present | {str(result['unknown_findings_present']).lower()} |",
        f"| Total Resource Count | {total_resource_count} (source: {resource_count_source}) |",
        f"| Affected Resource Count | {affected_resource_count} |",
        f"| Affected Resource Ratio | {affected_resource_ratio} |",
        f"| Total Findings | {len(findings)} |",
        f"| Confirmed Findings | {result['confirmed_count']} |",
        f"| Unknown Findings | {result['unknown_count']} |",
        "",
        "## Severity Counts",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]:
        md_lines.append(f"| {sev} | {sc.get(sev, 0)} |")

    md_lines += [
        "",
        "## Scoring Formula & Parameters",
        "",
        "```",
        "pre_deployment_risk_score = round(1000 × exp(-((α × D) + (β × U))))",
        "",
        f"  α (alpha)                = {ALPHA}   [confirmed-risk sensitivity]",
        f"  β (beta)                 = {BETA}   [unknown-risk sensitivity]",
        f"  resource_penalty_cap     = {RESOURCE_PENALTY_CAP}  [max penalty per resource]",
        "",
        "  D (confirmed density)    = sum(capped_resource_penalties) / resource_count",
        "  U (unknown density)      = unknown_finding_count / resource_count",
        "```",
        "",
        "### Severity Weights",
        "",
        "| Severity | Weight |",
        "|---|---|",
    ]
    for sev, w in SEVERITY_WEIGHTS.items():
        md_lines.append(f"| {sev} | {w} |")
    md_lines.append(f"| UNKNOWN | — (handled through U) |")

    md_lines += [
        "",
        "## Density Values",
        "",
        f"| Variable | Value |",
        f"|---|---|",
        f"| D (confirmed weighted density) | {round(result['D'], 6)} |",
        f"| U (unknown density) | {round(result['U'], 6)} |",
        f"| Raw Score | {round(result['raw_score'], 4)} |",
        "",
        "## Risk Band Thresholds",
        "",
        "| Score Range | Risk Band | Suggested Decision |",
        "|---|---|---|",
        "| 900–1000 | VERY_LOW_RISK | PASS |",
        "| 750–899 | LOW_RISK | PASS_WITH_ADVISORY |",
        "| 500–749 | MODERATE_RISK | REVIEW |",
        "| 250–499 | HIGH_RISK | REVIEW_HIGH_RISK |",
        "| 0–249 | CRITICAL_RISK | BLOCK_RECOMMENDED |",
        "",
        "## Resource Penalty Table",
        "",
        "| Resource | Confirmed Findings | Unknown Findings | Raw Penalty | Capped Penalty | Cap Applied |",
        "|---|---|---|---|---|---|",
    ]
    for rp in result["resource_penalties"]:
        md_lines.append(
            f"| `{rp['resource']}` "
            f"| {rp['confirmed_finding_count']} "
            f"| {rp['unknown_finding_count']} "
            f"| {rp['uncapped_confirmed_penalty']} "
            f"| {rp['capped_confirmed_penalty']} "
            f"| {'yes' if rp['applied_cap'] else 'no'} |"
        )

    if warnings:
        md_lines += ["", "## Warnings", ""]
        for w in warnings:
            md_lines.append(f"- `{w}`")

    with open(str(risk_dir / "predeployment-risk-score.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md_lines) + "\n")

    # ------------------------------------------------------------------ #
    # Console output                                                      #
    # ------------------------------------------------------------------ #
    print(f"\n{'='*60}")
    print(f"  PRE-DEPLOYMENT RISK SCORE")
    print(f"{'='*60}")
    print(f"SCAN_ID              : {scan_id}")
    print(f"Score                : {result['score']} / 1000")
    print(f"Risk Band            : {result['risk_band']}")
    print(f"Suggested Decision   : {result['suggested_decision']}")
    print(f"Total Resource Count : {total_resource_count}  (source: {resource_count_source})")
    print(f"Affected Resources   : {affected_resource_count}")
    print(f"Affected Ratio       : {affected_resource_ratio}")
    print(f"Total Findings       : {len(findings)}")
    print(f"Confirmed Findings   : {result['confirmed_count']}")
    print(f"Unknown Findings     : {result['unknown_count']}")
    print(f"D                    : {round(result['D'], 4)}")
    print(f"U                    : {round(result['U'], 4)}")
    print(f"Formula              : round(1000 * exp(-((0.6 * D) + (0.2 * U))))")
    print(f"Higher Is Better     : true")

    print(f"\nSeverity Counts:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]:
        print(f"  {sev:<8} : {sc.get(sev, 0)}")

    if warnings:
        print(f"\nWarnings:")
        for w in warnings:
            print(f"  ! {w}")

    print(f"\n{'-'*60}")
    print(f"  RESOURCE PENALTIES")
    print(f"{'-'*60}")
    for rp in result["resource_penalties"]:
        print(f"{rp['resource']}")
        print(f"  Confirmed Findings : {rp['confirmed_finding_count']}")
        print(f"  Unknown Findings   : {rp['unknown_finding_count']}")
        print(f"  Raw Penalty        : {rp['uncapped_confirmed_penalty']}")
        print(f"  Capped Penalty     : {rp['capped_confirmed_penalty']}")
        print(f"  Cap Applied        : {'true' if rp['applied_cap'] else 'false'}")
        print()

    print(f"{'='*60}")
    print(f"  Score written to: reports/risk/{scan_id}/predeployment-risk-score.json")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
scripts/risk/render_risk_summary.py

Render a human-readable Markdown risk summary.

Usage:  python scripts/risk/render_risk_summary.py <SCAN_ID>
Output: reports/risk/<SCAN_ID>/risk-summary.md
"""
import argparse, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from scripts.utils.evidence import safe_read_json, utc_now_iso

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    sid = args.scan_id
    rd = ROOT/"reports"/"risk"/sid

    rs = safe_read_json(str(rd/"risk-score.json")) or {}
    dec = safe_read_json(str(rd/"risk-decision.json")) or {}
    frs = safe_read_json(str(rd/"finding-risk-scores.json")) or {}
    rrs = safe_read_json(str(rd/"resource-risk-scores.json")) or {}
    mm = safe_read_json(str(rd/"merged-cis-mapping.json")) or {}

    scores = frs.get("scores",[])
    resources = rrs.get("scores",[])
    mappings = mm.get("mappings",[])
    mm_meta = mm.get("metadata",{})

    lines = [
        f"# Risk Assessment Summary",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| Scan ID | `{sid}` |",
        f"| Overall Score | **{rs.get('overall_score',0)}** / 100 |",
        f"| Risk Level | **{rs.get('risk_level','UNKNOWN')}** |",
        f"| Suggested Decision | **{dec.get('suggested_decision','UNKNOWN')}** |",
        f"| Enforcement Mode | {dec.get('enforcement_mode','advisory')} |",
        f"| Pipeline Failed | {dec.get('should_fail_pipeline',False)} |",
        f"| Mandatory Blocks | {len(dec.get('mandatory_blocks_triggered',[]))} |",
        f"| Generated At | {utc_now_iso()} |",
        f"",
    ]

    # Top reasons
    reasons = dec.get("top_reasons",[])
    if reasons:
        lines.append("## Top Risk Reasons")
        lines.append("")
        for i,r in enumerate(reasons[:5],1):
            lines.append(f"{i}. {r}")
        lines.append("")

    # Mandatory blocks
    blocks = dec.get("mandatory_blocks_triggered",[])
    if blocks:
        lines.append("## Mandatory Block Recommendations")
        lines.append("")
        lines.append("| Finding ID | Control | Reason |")
        lines.append("|---|---|---|")
        for b in blocks:
            lines.append(f"| {b.get('finding_id','')} | {b.get('canonical_control','')} | {b.get('reason','')} |")
        lines.append("")

    # Top 5 resources
    if resources:
        lines.append("## Top 5 Risky Resources")
        lines.append("")
        lines.append("| Resource | Score | Findings | Top Control |")
        lines.append("|---|---|---|---|")
        for r in resources[:5]:
            lines.append(f"| `{r.get('resource','')}` | {r.get('resource_risk_score',0)} | {r.get('finding_count',0)} | {r.get('top_canonical_control','')} |")
        lines.append("")

    # Top 5 findings
    if scores:
        lines.append("## Top 5 Risky Findings")
        lines.append("")
        lines.append("| Finding | Tool | Rule | Score | Control |")
        lines.append("|---|---|---|---|---|")
        for s in scores[:5]:
            lines.append(f"| {s.get('finding_id','')} | {s.get('source_tool','')} | {s.get('source_rule_id','')} | {s.get('finding_risk_score',0)} | {s.get('canonical_control','')} |")
        lines.append("")

    # Mapping stats
    from collections import Counter
    ctrl_counts = Counter(m.get("canonical_control","UNKNOWN") for m in mappings)
    det_c = mm_meta.get("deterministic_count",0)
    ai_c = mm_meta.get("ai_count",0)
    fb_c = mm_meta.get("fallback_count",0)
    low_conf = sum(1 for m in mappings if m.get("mapping_confidence")=="low")
    review_req = sum(1 for m in mappings if m.get("requires_review"))

    lines.append("## Mapping Statistics")
    lines.append("")
    lines.append(f"- Deterministic mappings: **{det_c}**")
    lines.append(f"- AI-mapped findings: **{ai_c}**")
    lines.append(f"- Fallback mappings: **{fb_c}**")
    lines.append(f"- Low-confidence mappings: **{low_conf}**")
    lines.append(f"- Review-required mappings: **{review_req}**")
    lines.append("")

    if ctrl_counts:
        lines.append("### Findings by Canonical Control")
        lines.append("")
        lines.append("| Control | Count |")
        lines.append("|---|---|")
        for ctrl, cnt in ctrl_counts.most_common():
            lines.append(f"| {ctrl} | {cnt} |")
        lines.append("")

    # Evidence artifacts
    artifacts = [
        "normalized-findings.json", "deterministic-mappings.json",
        "unmapped-findings.json", "ai-request.json", "ai-cis-mapping.json",
        "validated-cis-mapping.json", "merged-cis-mapping.json",
        "finding-risk-scores.json", "resource-risk-scores.json",
        "domain-risk-scores.json", "risk-score.json", "risk-decision.json",
        "risk-summary.md", "evidence-manifest.json", "evidence-hashes.json",
        "ai-model-metadata.json", "mapping-cache.json",
    ]
    lines.append("## Evidence Artifacts")
    lines.append("")
    for a in artifacts:
        p = rd/a
        status = "✅" if p.is_file() else "⏳"
        lines.append(f"- {status} `reports/risk/{sid}/{a}`")
    lines.append("")

    # Disclaimer
    lines.append("## AI Usage Disclaimer")
    lines.append("")
    lines.append("> AI (OpenAI) was used **only** for CIS/AWS control mapping of unmapped findings.")
    lines.append("> The final risk score and deployment decision were calculated **deterministically**")
    lines.append("> by Python code. AI did not calculate scores or make deployment decisions.")
    lines.append("")

    out = rd/"risk-summary.md"
    out.write_text("\n".join(lines))
    print(f"[render_summary] Output = {out}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
scripts/risk/calculate_risk_score.py

Deterministic risk scoring engine. Reads normalized findings and merged
CIS mappings, calculates per-finding / per-resource / per-domain / overall
risk scores, then generates the deployment decision.

Usage:  python scripts/risk/calculate_risk_score.py <SCAN_ID>
"""

import argparse, os, re, sys
from collections import defaultdict
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from scripts.utils.evidence import safe_read_json, safe_write_json, utc_now_iso

def _yaml(p):
    if not p.is_file(): return {}
    with open(p) as f: return yaml.safe_load(f) or {}

# --- text patterns ---
_PUB   = re.compile(r"0\.0\.0\.0/0|::/0", re.I)
_P22   = re.compile(r"port\s*22\b", re.I)
_P3389 = re.compile(r"port\s*3389\b", re.I)
_PUBLIC= re.compile(r"\bpublic\b", re.I)
_S3    = re.compile(r"\bs3\b|\bbucket\b", re.I)
_IAM   = re.compile(r"\biam\b", re.I)
_SECRET= re.compile(r"\bsecret\b|\bpassword\b|\bcredential\b", re.I)
_ENC   = re.compile(r"\bencrypt|\bkms\b|\bsse\b|\btls\b", re.I)
_LOG   = re.compile(r"\blog\b|\baudit\b", re.I)
_DB    = re.compile(r"\brds\b|\bdatabase\b|\bdynamodb\b", re.I)
_MOD   = re.compile(r"\bmodules?[/\\]", re.I)
_TEST  = re.compile(r"\btest\b|\bdemo\b|\bexample\b|\bsandbox\b", re.I)

def _blob(f, m):
    return " ".join(str(f.get(k,"")) for k in ("title","description","source_rule_id","resource","resource_type","file_path")) + " " + str(m.get("canonical_control","")) + " " + str(m.get("mapping_reason",""))

# --- factors ---
def f_exposure(cc, b, c):
    e = c.get("exposure_factor",{})
    if cc == "PUBLIC_ADMIN_ACCESS": return e.get("public_admin_access",2.0)
    if cc in ("PUBLIC_STORAGE_ACCESS","PUBLIC_DATABASE_ACCESS"): return e.get("public_storage_or_database",1.9)
    if cc == "PUBLIC_SERVICE_EXPOSURE": return e.get("public_service_exposure",1.7)
    if _PUB.search(b):
        if _P22.search(b) or _P3389.search(b): return e.get("public_admin_access",2.0)
        if _S3.search(b) or _DB.search(b): return e.get("public_storage_or_database",1.9)
        return e.get("public_service_exposure",1.7)
    return e.get("default",1.2)

def f_exploit(cc, b, c):
    x = c.get("exploitability_factor",{})
    if cc == "PUBLIC_ADMIN_ACCESS" and _PUB.search(b): return x.get("direct_no_auth",2.0)
    if cc in ("PUBLIC_STORAGE_ACCESS","PUBLIC_DATABASE_ACCESS") and _PUBLIC.search(b): return x.get("direct_no_auth",2.0)
    if cc == "HARDCODED_SECRET": return x.get("direct_no_auth",2.0)
    if cc == "IAM_OVER_PRIVILEGE": return x.get("privileged_cloud_access",1.1)
    if cc in ("HYGIENE_ISSUE","BACKUP_DISABLED","VERSIONING_DISABLED"): return x.get("compliance_only",0.8)
    if _PUBLIC.search(b): return x.get("public_reachable_creds_required",1.7)
    return x.get("default",1.0)

def f_enforce(f, c):
    e = c.get("enforcement_factor",{})
    p = f.get("policy",{})
    if not isinstance(p,dict): return e.get("scanner_only",1.0)
    lv = p.get("enforcement_level","none")
    return e.get(lv, e.get("scanner_only",1.0))

def f_detect(f, all_f, m, c):
    d = c.get("detection_confidence",{})
    if m.get("mapping_confidence") == "low": return d.get("ai_only_weak",0.8)
    res = f.get("resource",""); src = f.get("source_tool","")
    others = {x.get("source_tool") for x in all_f if x.get("resource")==res and x.get("finding_id")!=f.get("finding_id")}
    tools = {src}|others
    ck,tr,pa = "checkov" in tools, "trivy" in tools, "policy" in tools
    if ck and tr and pa: return d.get("checkov_trivy_pac",1.8)
    if (ck or tr) and pa: return d.get("scanner_pac",1.6)
    if ck and tr: return d.get("checkov_trivy",1.4)
    return d.get("single_scanner",1.0)

def f_blast(f, c):
    b = c.get("blast_radius_factor",{})
    fp = f.get("file_path",""); rt = f.get("resource_type","")
    if _MOD.search(fp): return b.get("shared_module",1.8)
    br = os.environ.get("BRANCH",os.environ.get("GITHUB_REF",""))
    if any(x in br for x in ("main","master","prod")):
        if _IAM.search(rt) or "security_group" in rt: return b.get("shared_iam_network_security",1.5)
        return b.get("production_main_branch",1.6)
    if _TEST.search(fp): return b.get("test_demo_example",0.8)
    if _IAM.search(rt) or "security_group" in rt: return b.get("shared_iam_network_security",1.5)
    return b.get("default",1.0)

def f_comp(cc, b, c):
    k = c.get("compensating_control_factor",{})
    if cc in ("PUBLIC_ADMIN_ACCESS","HARDCODED_SECRET","IAM_OVER_PRIVILEGE","PUBLIC_STORAGE_ACCESS","PUBLIC_DATABASE_ACCESS"):
        return k.get("none",1.0)
    if _ENC.search(b) and cc!="ENCRYPTION_DISABLED": return k.get("encryption_enabled",0.9)
    if _LOG.search(b) and cc!="LOGGING_DISABLED": return k.get("logging_enabled",0.95)
    return k.get("default",1.0)

# --- score ---
def score_finding(fd, mp, all_f, cfg):
    b = _blob(fd, mp)
    cc = mp.get("canonical_control","UNKNOWN_SECURITY_MISCONFIGURATION")
    bcc = mp.get("base_control_criticality", cfg.get("base_control_criticality",{}).get(cc,4))
    factors = {
        "base_control_criticality": bcc,
        "exposure_factor": f_exposure(cc,b,cfg),
        "exploitability_factor": f_exploit(cc,b,cfg),
        "enforcement_factor": f_enforce(fd,cfg),
        "detection_confidence": f_detect(fd,all_f,mp,cfg),
        "blast_radius_factor": f_blast(fd,cfg),
        "compensating_control_factor": f_comp(cc,b,cfg),
    }
    raw = 1.0
    for v in factors.values(): raw *= v
    return {
        "finding_id": fd.get("finding_id"), "source_tool": fd.get("source_tool"),
        "source_rule_id": fd.get("source_rule_id"), "resource": fd.get("resource"),
        "canonical_control": cc, "control_domain": mp.get("control_domain","unknown"),
        "mandatory_block": mp.get("mandatory_block",False),
        "factors": factors, "raw_score": round(raw,4),
        "finding_risk_score": min(100, round(raw,2)),
    }

def agg_resource(fs_list, cfg):
    w = cfg.get("resource_risk",{}).get("secondary_weight",0.35)
    cap = cfg.get("resource_risk",{}).get("cap",100)
    by_r = defaultdict(list)
    for s in fs_list: by_r[s.get("resource") or "unknown"].append(s)
    out = []
    for r, ss in by_r.items():
        ss.sort(key=lambda x: x["finding_risk_score"], reverse=True)
        h = ss[0]["finding_risk_score"]
        sec = sum(s["finding_risk_score"] for s in ss[1:])
        out.append({"resource":r,"resource_risk_score":min(cap,round(h+w*sec,2)),
                     "finding_count":len(ss),"highest_finding_score":h,
                     "top_canonical_control":ss[0].get("canonical_control"),
                     "finding_ids":[s["finding_id"] for s in ss]})
    return sorted(out, key=lambda x: x["resource_risk_score"], reverse=True)

def agg_domain(fs_list, cfg):
    w = cfg.get("domain_risk",{}).get("secondary_weight",0.25)
    cap = cfg.get("domain_risk",{}).get("cap",100)
    by_d = defaultdict(list)
    for s in fs_list: by_d[s.get("control_domain") or "unknown"].append(s)
    out = []
    for d, ss in by_d.items():
        ss.sort(key=lambda x: x["finding_risk_score"], reverse=True)
        h = ss[0]["finding_risk_score"]
        sec = sum(s["finding_risk_score"] for s in ss[1:])
        out.append({"domain":d,"domain_risk_score":min(cap,round(h+w*sec,2)),
                     "finding_count":len(ss),"highest_finding_score":h})
    return sorted(out, key=lambda x: x["domain_risk_score"], reverse=True)

def policy_score(findings, cfg):
    pc = cfg.get("policy_failure_score",{})
    h=s=a=0
    for f in findings:
        p = f.get("policy",{})
        if not isinstance(p,dict) or not p.get("policy_violation"): continue
        lv = p.get("enforcement_level","none")
        if lv=="hard_mandatory": h+=1
        elif lv=="soft_mandatory": s+=1
        elif lv=="advisory": a+=1
    return min(pc.get("cap",100), h*pc.get("hard_policy_weight",30)+s*pc.get("soft_policy_weight",15)+a*pc.get("advisory_policy_weight",5))

def overall(rs, ds, ps, cfg):
    w = cfg.get("overall_risk_weights",{})
    hr = rs[0]["resource_risk_score"] if rs else 0
    t5 = [r["resource_risk_score"] for r in rs[:5]]
    a5 = sum(t5)/len(t5) if t5 else 0
    hd = ds[0]["domain_risk_score"] if ds else 0
    return round(min(100, w.get("highest_resource_risk",0.45)*hr + w.get("average_top_five_resource_risk",0.25)*a5 + w.get("highest_domain_risk",0.20)*hd + w.get("policy_failure_score",0.10)*ps),2)

def decide(score, cfg):
    for t in cfg.get("decision_thresholds",[]):
        if score <= t.get("max_score",100): return t["risk_level"], t["decision"]
    return "CRITICAL","BLOCK_RECOMMENDED"

def check_blocks(fs, mcfg):
    bc = set(mcfg.get("mandatory_block_controls",[]))
    triggered = []
    for s in fs:
        if s.get("mandatory_block") or s.get("canonical_control") in bc:
            triggered.append({"finding_id":s["finding_id"],"canonical_control":s["canonical_control"],
                              "reason":f"Mandatory block: {s['canonical_control']} on {s.get('resource','unknown')}"})
    return triggered

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()
    sid = args.scan_id
    rd = ROOT/"reports"/"risk"/sid; rd.mkdir(parents=True, exist_ok=True)
    scfg = _yaml(ROOT/"config"/"risk"/"scoring-model.yml")
    mcfg = _yaml(ROOT/"config"/"risk"/"mandatory-blocks.yml")

    nd = safe_read_json(str(rd/"normalized-findings.json"))
    findings = nd.get("findings",[]) if isinstance(nd,dict) else []
    md = safe_read_json(str(rd/"merged-cis-mapping.json"))
    mlist = md.get("mappings",[]) if isinstance(md,dict) else []
    mbyid = {m["finding_id"]:m for m in mlist if isinstance(m,dict)}

    fs = []
    for f in findings:
        if not isinstance(f,dict): continue
        mp = mbyid.get(f.get("finding_id",""),{"canonical_control":"UNKNOWN_SECURITY_MISCONFIGURATION","control_domain":"unknown","base_control_criticality":4,"mandatory_block":False})
        fs.append(score_finding(f, mp, findings, scfg))
    fs.sort(key=lambda x: x["finding_risk_score"], reverse=True)

    rs = agg_resource(fs, scfg)
    ds = agg_domain(fs, scfg)
    ps = policy_score(findings, scfg)
    ov = overall(rs, ds, ps, scfg)
    blocks = check_blocks(fs, mcfg)
    mbs = scfg.get("mandatory_block_min_score",90)
    rl, sd = decide(ov, scfg)
    if blocks:
        if ov < mbs: ov = float(mbs)
        sd = "BLOCK_RECOMMENDED"; rl = "CRITICAL"

    enf = os.environ.get("ENFORCE_RISK_GATE","false").strip().lower()=="true"
    sf = enf and sd in ("FAIL_RECOMMENDED","BLOCK_RECOMMENDED")
    if enf and os.environ.get("STRICT_RISK_GATE","false").strip().lower()=="true" and sd=="REVIEW": sf=True

    top_reasons = []
    for s in fs[:5]:
        r = f"{s['canonical_control']} on {s.get('resource','unknown')} (score {s['finding_risk_score']})"
        if r not in top_reasons: top_reasons.append(r)

    safe_write_json(str(rd/"finding-risk-scores.json"),{"metadata":{"scan_id":sid,"generated_at":utc_now_iso(),"count":len(fs)},"scores":fs})
    safe_write_json(str(rd/"resource-risk-scores.json"),{"metadata":{"scan_id":sid,"generated_at":utc_now_iso(),"count":len(rs)},"scores":rs})
    safe_write_json(str(rd/"domain-risk-scores.json"),{"metadata":{"scan_id":sid,"generated_at":utc_now_iso(),"count":len(ds)},"scores":ds})
    safe_write_json(str(rd/"risk-score.json"),{"scan_id":sid,"generated_at":utc_now_iso(),"overall_score":ov,"risk_level":rl,"policy_failure_score":ps,"highest_resource_risk":rs[0]["resource_risk_score"] if rs else 0,"highest_domain_risk":ds[0]["domain_risk_score"] if ds else 0,"total_findings_scored":len(fs),"total_resources":len(rs),"total_domains":len(ds)})
    safe_write_json(str(rd/"risk-decision.json"),{"scan_id":sid,"generated_at":utc_now_iso(),"overall_score":ov,"risk_level":rl,"suggested_decision":sd,"enforcement_mode":"blocking" if enf else "advisory","should_fail_pipeline":sf,"mandatory_blocks_triggered":blocks,"top_reasons":top_reasons})

    print(f"[risk_score] SCAN_ID           = {sid}")
    print(f"[risk_score] Findings scored   = {len(fs)}")
    print(f"[risk_score] Overall score     = {ov}")
    print(f"[risk_score] Risk level        = {rl}")
    print(f"[risk_score] Decision          = {sd}")
    print(f"[risk_score] Mandatory blocks  = {len(blocks)}")
    print(f"[risk_score] Should fail       = {sf}")

if __name__ == "__main__":
    main()

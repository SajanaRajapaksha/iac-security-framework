import unittest
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.review.review_utils import generate_finding_key
from scripts.dashboard.export_dashboard_bundle import (
    _get_remediation_doc,
    _determine_category,
    generate_scan_summary,
    generate_findings,
    normalize_severity,
    build_finding_record_key
)

class TestExportDashboardBundle(unittest.TestCase):
    def test_generate_finding_key(self):
        k = generate_finding_key("PRE_DEPLOYMENT", "checkov", "CKV_AWS_24", "aws_security_group", "Ensure no security groups allow ingress")
        self.assertEqual(k, "PRE_DEPLOYMENT|checkov|CKV_AWS_24|aws_security_group|Ensure no security groups allow ingress")

    def test_determine_category(self):
        self.assertEqual(_determine_category("reports/static/SCAN/combined.json"), "STATIC_ANALYSIS")
        self.assertEqual(_determine_category("reports/policy/SCAN/policy.json"), "POLICY_ANALYSIS")
        self.assertEqual(_determine_category("reports/deployment/SCAN/deploy.json"), "DEPLOYMENT")
        self.assertEqual(_determine_category("reports/runtime/SCAN/prowler.json"), "RUNTIME_ANALYSIS")
        self.assertEqual(_determine_category("unknown/path.json"), "UNKNOWN")

    def test_normalize_severity(self):
        self.assertEqual(normalize_severity("HIGH"), "HIGH")
        self.assertEqual(normalize_severity({"original": "LOW", "normalized": "MEDIUM"}), "MEDIUM")
        self.assertEqual(normalize_severity("{'ORIGINAL': 'CRITICAL', 'NORMALIZED': 'CRITICAL', 'SOURCE': 'PROWLER_METADATA'}"), "CRITICAL")
        self.assertEqual(normalize_severity(None), "UNKNOWN")
        self.assertEqual(normalize_severity(""), "UNKNOWN")

    def test_build_finding_record_key(self):
        k1 = build_finding_record_key("checkov", "CKV_AWS_1", "PRE_DEPLOYMENT", "aws_s3_bucket.main")
        k2 = build_finding_record_key("checkov", "CKV_AWS_1", "PRE_DEPLOYMENT", "aws_s3_bucket.other")
        self.assertNotEqual(k1, k2)
        
        k3 = build_finding_record_key("prowler", "EC2_1", "POST_DEPLOYMENT", "arn:aws:ec2:...")
        self.assertTrue(len(k3) == 16)

    def test_get_remediation_doc_available(self):
        ai_data = {
            "guidance": [
                {
                    "finding_key": "PRE_DEPLOYMENT|checkov|CKV_AWS_1|aws_s3_bucket|Bucket Title",
                    "source": "OPENAI_WITH_SCANNER_CONTEXT",
                    "priority": "HIGH",
                    "ai_guidance": {
                        "summary": "Fix this",
                        "terraform_action": "Do A",
                        "runtime_action": "",
                        "validation_step": "Verify B",
                        "operational_caution": "Careful"
                    }
                }
            ]
        }
        res = _get_remediation_doc(ai_data, "PRE_DEPLOYMENT|checkov|CKV_AWS_1|aws_s3_bucket|Bucket Title")
        self.assertTrue(res["available"])
        self.assertEqual(res["summary"], "Fix this")
        self.assertEqual(res["target"], "IAC_SOURCE")
        self.assertEqual(res["source"], "OPENAI_WITH_SCANNER_CONTEXT")
        self.assertEqual(res["priority"], "HIGH")
        self.assertEqual(res["steps"], ["Do A"])
        self.assertEqual(res["verification"], ["Verify B"])
        self.assertEqual(res["operational_caution"], "Careful")
        self.assertEqual(res["runtime_action"], "")

    def test_get_remediation_doc_missing(self):
        ai_data = {"guidance": []}
        res = _get_remediation_doc(ai_data, "PRE_DEPLOYMENT|checkov|CKV_AWS_1|aws_s3_bucket|Bucket Title")
        self.assertFalse(res["available"])

    def test_generate_findings_with_remediation(self):
        expected_key = generate_finding_key("PRE_DEPLOYMENT", "checkov", "CKV_AWS_1", "aws_s3_bucket", "Bad S3")
        evidence = {
            "enriched_findings": {
                "path": "reports/risk/enriched.json",
                "data": {
                    "findings": [{
                        "finding_id": "FIND-001",
                        "source_tool": "checkov",
                        "source_rule_id": "CKV_AWS_1",
                        "final_severity": "HIGH",
                        "title": "Bad S3",
                        "description": "Bucket public",
                        "resource_type": "aws_s3_bucket",
                        "resource": "aws_s3_bucket.main"
                    }]
                }
            },
            "ai_remediation": {
                "data": {
                    "guidance": [
                        {
                            "finding_key": expected_key,
                            "source": "LOCAL_AI_REMEDIATION_CACHE",
                            "ai_guidance": {
                                "summary": "Block public access"
                            }
                        }
                    ]
                }
            }
        }
        result = generate_findings("SCAN-TEST", evidence)
        self.assertEqual(len(result["findings"]), 1)
        f = result["findings"][0]
        self.assertEqual(f["phase"], "PRE_DEPLOYMENT")
        self.assertEqual(f["severity"], "HIGH")
        self.assertTrue(f["remediation"]["available"])
        self.assertEqual(f["remediation"]["summary"], "Block public access")
        self.assertEqual(f["remediation"]["source"], "LOCAL_AI_REMEDIATION_CACHE")

    def test_generate_findings_runtime_fallback_remediation(self):
        evidence = {
            "runtime_findings": {
                "path": "reports/runtime/normalized.json",
                "data": {
                    "findings": [{
                        "finding_id": "FIND-002",
                        "source_tool": "prowler",
                        "control_id": "EC2_1",
                        "title": "EC2 unencrypted",
                        "severity": "{'ORIGINAL': 'CRITICAL', 'NORMALIZED': 'CRITICAL', 'SOURCE': 'PROWLER_METADATA'}",
                        "remediation": {
                            "text": "Prowler native text",
                            "references": ["http://prowler.url"]
                        },
                        "resource": {
                            "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
                        }
                    }]
                }
            },
            "ai_remediation": {
                "data": {
                    "guidance": []
                }
            }
        }
        result = generate_findings("SCAN-TEST", evidence)
        self.assertEqual(len(result["findings"]), 1)
        f = result["findings"][0]
        self.assertEqual(f["phase"], "POST_DEPLOYMENT")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(f["aws_service"], "ec2")
        self.assertEqual(f["affected_resource_type"], "aws_ec2")
        self.assertTrue(f["remediation"]["available"])
        self.assertEqual(f["remediation"]["source"], "PROWLER")
        self.assertEqual(f["remediation"]["summary"], "Prowler native text")
        self.assertEqual(f["remediation"]["references"], ["http://prowler.url"])

    def test_generate_scan_summary_missing_data(self):
        result = generate_scan_summary("SCAN-EMPTY", {})
        self.assertEqual(result["scan_id"], "SCAN-EMPTY")
        self.assertEqual(result["pre_deployment"]["risk_score"], "NOT_AVAILABLE")
        self.assertEqual(result["deployment"]["status"], "NOT_EXECUTED")
        self.assertEqual(result["runtime"]["finding_count"], "NOT_EXECUTED")
        self.assertEqual(result["cleanup"]["destroy_status"], "NOT_EXECUTED")

if __name__ == '__main__':
    unittest.main()

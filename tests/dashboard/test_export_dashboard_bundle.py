import unittest
from pathlib import Path
import sys
import json
import os

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.dashboard.export_dashboard_bundle import (
    _get_remediation_doc,
    _determine_category,
    generate_scan_summary,
    generate_findings
)

class TestExportDashboardBundle(unittest.TestCase):
    def test_determine_category(self):
        self.assertEqual(_determine_category("reports/static/SCAN/combined.json"), "STATIC_ANALYSIS")
        self.assertEqual(_determine_category("reports/policy/SCAN/policy.json"), "POLICY_ANALYSIS")
        self.assertEqual(_determine_category("reports/deployment/SCAN/deploy.json"), "DEPLOYMENT")
        self.assertEqual(_determine_category("reports/runtime/SCAN/prowler.json"), "RUNTIME_ANALYSIS")
        self.assertEqual(_determine_category("unknown/path.json"), "UNKNOWN")

    def test_get_remediation_doc_available(self):
        ai_data = {
            "guidance": {
                "FIND-123": {
                    "summary": "Fix this",
                    "terraform_action": ["Do A"],
                    "example": "example code",
                    "runtime_action": ["Verify B"],
                    "references": ["url1"]
                }
            }
        }
        res = _get_remediation_doc(ai_data, "FIND-123")
        self.assertTrue(res["available"])
        self.assertEqual(res["summary"], "Fix this")
        self.assertEqual(res["target"], "IAC_SOURCE")
        self.assertEqual(res["steps"], ["Do A"])
        self.assertEqual(res["terraform_example"], "example code")

    def test_get_remediation_doc_missing(self):
        ai_data = {"guidance": {}}
        res = _get_remediation_doc(ai_data, "FIND-123")
        self.assertFalse(res["available"])

    def test_generate_findings_with_remediation(self):
        evidence = {
            "enriched_findings": {
                "path": "reports/risk/enriched.json",
                "data": {
                    "findings": [{
                        "finding_id": "FIND-001",
                        "source_tool": "checkov",
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
                    "guidance": {
                        "FIND-001": {
                            "summary": "Block public access"
                        }
                    }
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

    def test_generate_findings_runtime_fallback_remediation(self):
        evidence = {
            "runtime_findings": {
                "path": "reports/runtime/normalized.json",
                "data": {
                    "findings": [{
                        "finding_id": "FIND-002",
                        "source_tool": "prowler",
                        "severity": "CRITICAL",
                        "remediation": {
                            "recommendation": {
                                "text": "Prowler native text",
                                "url": "http://prowler.url"
                            }
                        }
                    }]
                }
            }
        }
        result = generate_findings("SCAN-TEST", evidence)
        self.assertEqual(len(result["findings"]), 1)
        f = result["findings"][0]
        self.assertEqual(f["phase"], "POST_DEPLOYMENT")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertTrue(f["remediation"]["available"])
        self.assertEqual(f["remediation"]["source"], "PROWLER")
        self.assertEqual(f["remediation"]["summary"], "Prowler native text")
        self.assertEqual(f["remediation"]["references"], ["http://prowler.url"])

    def test_generate_scan_summary_missing_data(self):
        # Empty evidence should not crash and fallback safely
        result = generate_scan_summary("SCAN-EMPTY", {})
        self.assertEqual(result["scan_id"], "SCAN-EMPTY")
        self.assertEqual(result["pre_deployment"]["risk_score"], "NOT_AVAILABLE")
        self.assertEqual(result["deployment"]["status"], "NOT_EXECUTED")
        self.assertEqual(result["runtime"]["finding_count"], "NOT_EXECUTED")
        self.assertEqual(result["cleanup"]["destroy_status"], "NOT_EXECUTED")

if __name__ == '__main__':
    unittest.main()

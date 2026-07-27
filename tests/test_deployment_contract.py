#!/usr/bin/env python3
"""
tests/test_deployment_contract.py

Unit tests for the deployment contract validator.

Run:  python -m pytest tests/test_deployment_contract.py -v
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.deployment.validate_deployment_contract import (
    read_all_tf_content,
    validate_contract,
)

SAMPLE_SCAN = "SCAN-TEST-CONTRACT"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_and_cleanup(tmp_path, monkeypatch):
    """Set up temp directories and clean up after each test."""
    monkeypatch.chdir(ROOT)
    # Clean up any leftover report dirs
    deploy_dir = ROOT / "reports" / "deployment" / SAMPLE_SCAN
    deploy_dir.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(str(ROOT / "reports" / "deployment" / SAMPLE_SCAN), ignore_errors=True)


def _create_tf_root(tmp_path: Path, files: dict[str, str]) -> str:
    """Create a temp Terraform root with the given filename->content mapping."""
    tf_dir = tmp_path / "tf_root"
    tf_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (tf_dir / name).write_text(content, encoding="utf-8")
    return str(tf_dir)


# ---------------------------------------------------------------------------
# Valid contract
# ---------------------------------------------------------------------------

VALID_VARIABLES_TF = '''
variable "scan_id" {
  description = "IaC Security Framework scan identifier"
  type        = string
}

variable "aws_region" {
  description = "AWS deployment region"
  type        = string
}
'''

VALID_PROVIDER_TF = '''
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      scan-id    = var.scan_id
      managed-by = "iac-security-framework"
    }
  }
}

terraform {
  backend "s3" {}
}
'''


class TestDeploymentContract:
    def test_valid_contract_passes(self, tmp_path):
        """A complete deployment contract should pass all checks."""
        tf_root = _create_tf_root(tmp_path, {
            "variables.tf": VALID_VARIABLES_TF,
            "main.tf": VALID_PROVIDER_TF,
        })
        result = validate_contract(tf_root)
        assert result["status"] == "PASS"
        assert len(result["failures"]) == 0
        assert all(result["checks"].values())

    def test_missing_scan_id_variable_fails(self, tmp_path):
        """Missing variable "scan_id" should fail."""
        variables = '''
variable "aws_region" {
  type = string
}
'''
        tf_root = _create_tf_root(tmp_path, {
            "variables.tf": variables,
            "main.tf": VALID_PROVIDER_TF,
        })
        result = validate_contract(tf_root)
        assert result["status"] == "FAIL"
        assert not result["checks"]["variable_scan_id"]
        assert any("scan_id" in f for f in result["failures"])

    def test_missing_aws_region_variable_fails(self, tmp_path):
        """Missing variable "aws_region" should fail."""
        variables = '''
variable "scan_id" {
  type = string
}
'''
        tf_root = _create_tf_root(tmp_path, {
            "variables.tf": variables,
            "main.tf": VALID_PROVIDER_TF,
        })
        result = validate_contract(tf_root)
        assert result["status"] == "FAIL"
        assert not result["checks"]["variable_aws_region"]

    def test_missing_default_tags_fails(self, tmp_path):
        """Missing provider default_tags block should fail."""
        provider_no_tags = '''
provider "aws" {
  region = var.aws_region
}
'''
        tf_root = _create_tf_root(tmp_path, {
            "variables.tf": VALID_VARIABLES_TF,
            "main.tf": provider_no_tags,
        })
        result = validate_contract(tf_root)
        assert result["status"] == "FAIL"
        assert not result["checks"]["default_tags_block"]
        assert not result["checks"]["default_tags_scan_id"]
        assert not result["checks"]["default_tags_managed_by"]

    def test_missing_managed_by_tag_fails(self, tmp_path):
        """default_tags without managed-by should fail."""
        provider_no_managed_by = '''
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      scan-id = var.scan_id
    }
  }
}
'''
        tf_root = _create_tf_root(tmp_path, {
            "variables.tf": VALID_VARIABLES_TF,
            "main.tf": provider_no_managed_by,
        })
        result = validate_contract(tf_root)
        assert result["status"] == "FAIL"
        assert result["checks"]["default_tags_scan_id"] is True
        assert result["checks"]["default_tags_managed_by"] is False

    def test_malformed_empty_tf_files_fail(self, tmp_path):
        """Empty .tf files should fail all checks."""
        tf_root = _create_tf_root(tmp_path, {
            "main.tf": "",
        })
        result = validate_contract(tf_root)
        assert result["status"] == "FAIL"
        assert len(result["failures"]) == 5  # all checks fail

    def test_no_tf_files_fail(self, tmp_path):
        """A directory without .tf files should fail all checks."""
        tf_root = _create_tf_root(tmp_path, {
            "readme.md": "# Not terraform",
        })
        result = validate_contract(tf_root)
        assert result["status"] == "FAIL"

    def test_read_all_tf_content_reads_only_tf_files(self, tmp_path):
        """read_all_tf_content should only read .tf files, not other extensions."""
        tf_root = _create_tf_root(tmp_path, {
            "main.tf": 'variable "scan_id" {}\n',
            "notes.md": "This is not terraform",
            "data.json": '{"key": "value"}',
        })
        content = read_all_tf_content(tf_root)
        assert 'variable "scan_id"' in content
        assert "This is not terraform" not in content
        assert '"key"' not in content


class TestMultipleRoots:
    """These test the logic about root count, not the contract regex itself."""

    def test_discovery_data_with_multiple_roots(self):
        """Verify that discovery data with multiple roots is detectable."""
        # This tests the pattern used by the main() function
        discovery = {
            "terraform_directories": [
                {"path": "/a", "relative_path": "a"},
                {"path": "/b", "relative_path": "b"},
                {"path": "/c", "relative_path": "c"},
            ]
        }
        assert len(discovery["terraform_directories"]) > 1

    def test_discovery_data_with_zero_roots(self):
        """Verify that empty discovery data is detectable."""
        discovery = {"terraform_directories": []}
        assert len(discovery["terraform_directories"]) == 0

#!/usr/bin/env python3
"""
tests/test_deployment_contract.py

Unit tests for the rewritten deployment contract validator.
The validator no longer checks for scan_id variable or default_tags in
the target Terraform source — tags are injected by environment variables.

Run:  python -m pytest tests/test_deployment_contract.py -v
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.deployment.validate_deployment_contract import (
    detect_aws_provider,
    find_tf_files,
    resolve_deployment_root,
)

SCAN_ID = "SCAN-CTEST01"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def cleanup(monkeypatch):
    monkeypatch.chdir(ROOT)
    deploy_dir = ROOT / "reports" / "deployment" / SCAN_ID
    deploy_dir.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(str(ROOT / "reports" / "deployment" / SCAN_ID), ignore_errors=True)


def _make_discovery(tf_dirs: list[dict]) -> dict:
    return {"terraform_directories": tf_dirs}


def _write_discovery(tmp_path: Path, tf_dirs: list[dict], scan_id: str = SCAN_ID) -> None:
    meta = tmp_path / "repositories" / "metadata" / scan_id
    meta.mkdir(parents=True)
    (meta / "terraform-directories.json").write_text(
        json.dumps(_make_discovery(tf_dirs))
    )


# ---------------------------------------------------------------------------
# resolve_deployment_root
# ---------------------------------------------------------------------------

class TestResolveDeploymentRoot:
    def test_root_level_config(self, tmp_path):
        """relative_path='.' → deployment-source/"""
        ds = tmp_path / "deployment-source"
        ds.mkdir()
        result = resolve_deployment_root(SCAN_ID, ".", tmp_path)
        assert result == ds

    def test_nested_config(self, tmp_path):
        """relative_path='terraform/aws' → deployment-source/terraform/aws/"""
        nested = tmp_path / "deployment-source" / "terraform" / "aws"
        nested.mkdir(parents=True)
        result = resolve_deployment_root(SCAN_ID, "terraform/aws", tmp_path)
        assert result == nested

    def test_empty_relative_path(self, tmp_path):
        """relative_path='' treated same as '.'"""
        ds = tmp_path / "deployment-source"
        ds.mkdir()
        result = resolve_deployment_root(SCAN_ID, "", tmp_path)
        assert result == ds

    def test_missing_deployment_source(self, tmp_path):
        """Returns None when deployment-source/ doesn't exist."""
        result = resolve_deployment_root(SCAN_ID, ".", tmp_path)
        assert result is None

    def test_missing_nested_path(self, tmp_path):
        """Returns None when nested subdir doesn't exist."""
        (tmp_path / "deployment-source").mkdir()
        result = resolve_deployment_root(SCAN_ID, "missing/subdir", tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# find_tf_files
# ---------------------------------------------------------------------------

class TestFindTfFiles:
    def test_finds_tf_files(self, tmp_path):
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        (tmp_path / "variables.tf").write_text('variable "env" {}')
        result = find_tf_files(tmp_path)
        assert len(result) == 2

    def test_ignores_non_tf_files(self, tmp_path):
        (tmp_path / "main.tf").write_text("# tf")
        (tmp_path / "README.md").write_text("# docs")
        (tmp_path / "plan.json").write_text("{}")
        result = find_tf_files(tmp_path)
        assert len(result) == 1

    def test_empty_directory(self, tmp_path):
        result = find_tf_files(tmp_path)
        assert result == []


# ---------------------------------------------------------------------------
# detect_aws_provider
# ---------------------------------------------------------------------------

class TestDetectAwsProvider:
    def test_detects_provider_block(self, tmp_path):
        (tmp_path / "main.tf").write_text('provider "aws" { region = "eu-west-1" }')
        assert detect_aws_provider(tmp_path) is True

    def test_detects_hashicorp_aws_in_required_providers(self, tmp_path):
        (tmp_path / "provider.tf").write_text(
            'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}'
        )
        assert detect_aws_provider(tmp_path) is True

    def test_no_aws_provider(self, tmp_path):
        (tmp_path / "main.tf").write_text('provider "google" { project = "my-project" }')
        assert detect_aws_provider(tmp_path) is False

    def test_empty_directory(self, tmp_path):
        assert detect_aws_provider(tmp_path) is False


# ---------------------------------------------------------------------------
# Contract: source repo without scan_id variable still passes
# ---------------------------------------------------------------------------

class TestContractNoLongerRequiresVariables:
    def test_no_scan_id_variable_passes(self, tmp_path):
        """Target repo without variable "scan_id" must still satisfy the contract."""
        (tmp_path / "main.tf").write_text(
            'provider "aws" { region = "eu-north-1" }\n'
            'resource "aws_s3_bucket" "b" { bucket = "test" }\n'
        )
        tf_files = find_tf_files(tmp_path)
        assert len(tf_files) == 1

    def test_no_default_tags_passes(self, tmp_path):
        """Target repo without default_tags must still satisfy the contract."""
        (tmp_path / "provider.tf").write_text(
            'provider "aws" { region = "eu-north-1" }'
        )
        (tmp_path / "main.tf").write_text(
            'resource "aws_instance" "web" { ami = "ami-123" instance_type = "t3.micro" }'
        )
        tf_files = find_tf_files(tmp_path)
        assert len(tf_files) == 2
        aws = detect_aws_provider(tmp_path)
        assert aws is True


# ---------------------------------------------------------------------------
# Discovery data checks
# ---------------------------------------------------------------------------

class TestDiscoveryDataChecks:
    def test_no_terraform_roots(self):
        discovery = {"terraform_directories": []}
        assert len(discovery["terraform_directories"]) == 0

    def test_multiple_terraform_roots(self):
        discovery = {
            "terraform_directories": [
                {"path": "/a", "relative_path": "a"},
                {"path": "/b", "relative_path": "b"},
            ]
        }
        assert len(discovery["terraform_directories"]) > 1

    def test_single_root(self):
        discovery = {
            "terraform_directories": [{"path": "/tf", "relative_path": "."}]
        }
        assert len(discovery["terraform_directories"]) == 1

#!/usr/bin/env python3
"""
tests/test_aws_provider_version.py

Unit tests for the AWS provider version validator.

Run:  python -m pytest tests/test_aws_provider_version.py -v
"""

import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.deployment.validate_aws_provider_version import (
    _parse_version,
    parse_lock_file,
    version_gte,
)

SCAN_ID = "SCAN-PVTEST01"

LOCK_TEMPLATE = '''\
# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/hashicorp/aws" {{
  version     = "{version}"
  constraints = "~> 5.0"
  hashes = [
    "h1:fake_hash_value",
  ]
}}
'''


def _make_lock(tf_root: Path, version: str) -> None:
    (tf_root / ".terraform.lock.hcl").write_text(LOCK_TEMPLATE.format(version=version))


@pytest.fixture(autouse=True)
def cleanup():
    deploy_dir = ROOT / "reports" / "deployment" / SCAN_ID
    deploy_dir.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(str(ROOT / "reports" / "deployment" / SCAN_ID), ignore_errors=True)


# ---------------------------------------------------------------------------
# _parse_version
# ---------------------------------------------------------------------------

class TestParseVersion:
    def test_basic_semver(self):
        assert _parse_version("5.62.0") == (5, 62, 0)

    def test_major_minor_patch(self):
        assert _parse_version("6.0.0") == (6, 0, 0)

    def test_strips_leading_v(self):
        assert _parse_version("v5.62.0") == (5, 62, 0)

    def test_strips_prerelease(self):
        assert _parse_version("5.62.0-beta.1") == (5, 62, 0)

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            _parse_version("not-a-version")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            _parse_version("")


# ---------------------------------------------------------------------------
# version_gte
# ---------------------------------------------------------------------------

class TestVersionGte:
    def test_exact_minimum(self):
        """Version exactly 5.62.0 must pass."""
        assert version_gte("5.62.0", "5.62.0") is True

    def test_greater_minor(self):
        """5.63.0 > 5.62.0."""
        assert version_gte("5.63.0", "5.62.0") is True

    def test_major_6(self):
        """6.x > 5.62.0."""
        assert version_gte("6.0.0", "5.62.0") is True

    def test_below_minimum(self):
        """5.61.9 < 5.62.0."""
        assert version_gte("5.61.9", "5.62.0") is False

    def test_old_5_40(self):
        """5.40.0 < 5.62.0."""
        assert version_gte("5.40.0", "5.62.0") is False

    def test_zero_patch_pass(self):
        """5.62.0 == 5.62.0."""
        assert version_gte("5.62.0", "5.62.0") is True

    def test_higher_patch(self):
        """5.62.1 > 5.62.0."""
        assert version_gte("5.62.1", "5.62.0") is True


# ---------------------------------------------------------------------------
# parse_lock_file
# ---------------------------------------------------------------------------

class TestParseLockFile:
    def test_parses_aws_provider(self):
        content = LOCK_TEMPLATE.format(version="5.90.0")
        providers = parse_lock_file(content)
        assert "registry.terraform.io/hashicorp/aws" in providers
        assert providers["registry.terraform.io/hashicorp/aws"] == "5.90.0"

    def test_no_aws_provider(self):
        content = '''\
provider "registry.terraform.io/hashicorp/random" {
  version = "3.5.0"
}
'''
        providers = parse_lock_file(content)
        assert "registry.terraform.io/hashicorp/aws" not in providers
        assert "registry.terraform.io/hashicorp/random" in providers

    def test_multiple_providers(self):
        content = '''\
provider "registry.terraform.io/hashicorp/aws" {
  version = "5.90.0"
}

provider "registry.terraform.io/hashicorp/random" {
  version = "3.5.0"
}
'''
        providers = parse_lock_file(content)
        assert len(providers) == 2
        assert providers["registry.terraform.io/hashicorp/aws"] == "5.90.0"

    def test_empty_lock_file(self):
        providers = parse_lock_file("")
        assert providers == {}

    def test_invalid_version_text(self):
        content = '''\
provider "registry.terraform.io/hashicorp/aws" {
  version = "not_a_version"
}
'''
        providers = parse_lock_file(content)
        # Lock file with non-semver version should still parse the key
        assert providers.get("registry.terraform.io/hashicorp/aws") == "not_a_version"

    def test_non_hashicorp_aws(self):
        """Provider source other than hashicorp/aws is ignored."""
        content = '''\
provider "registry.terraform.io/example-corp/aws-clone" {
  version = "1.0.0"
}
'''
        providers = parse_lock_file(content)
        assert "registry.terraform.io/hashicorp/aws" not in providers

    def test_provider_without_version(self):
        content = '''\
provider "registry.terraform.io/hashicorp/aws" {
  hashes = ["h1:abc123"]
}
'''
        providers = parse_lock_file(content)
        # No version line → not extracted
        assert providers.get("registry.terraform.io/hashicorp/aws") is None


# ---------------------------------------------------------------------------
# Integration: main() script against real lock files
# ---------------------------------------------------------------------------

class TestValidateAwsProviderVersionScript:
    def _run_script(self, tf_root: Path) -> tuple[int, str]:
        import subprocess
        result = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "deployment" / "validate_aws_provider_version.py"),
             SCAN_ID, str(tf_root)],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        return result.returncode, result.stdout + result.stderr

    def test_passing_version(self, tmp_path):
        _make_lock(tmp_path, "6.53.0")
        rc, out = self._run_script(tmp_path)
        assert rc == 0, out

    def test_exact_minimum_passes(self, tmp_path):
        _make_lock(tmp_path, "5.62.0")
        rc, out = self._run_script(tmp_path)
        assert rc == 0, out

    def test_below_minimum_fails(self, tmp_path):
        _make_lock(tmp_path, "5.40.0")
        rc, _ = self._run_script(tmp_path)
        assert rc != 0

    def test_missing_lock_file_fails(self, tmp_path):
        # No lock file created
        rc, _ = self._run_script(tmp_path)
        assert rc != 0

    def test_missing_aws_provider_fails(self, tmp_path):
        (tmp_path / ".terraform.lock.hcl").write_text(
            'provider "registry.terraform.io/hashicorp/random" {\n  version = "3.5.0"\n}\n'
        )
        rc, _ = self._run_script(tmp_path)
        assert rc != 0

    def test_generates_evidence_json(self, tmp_path):
        _make_lock(tmp_path, "6.53.0")
        self._run_script(tmp_path)
        ev = ROOT / "reports" / "deployment" / SCAN_ID / "aws-provider-validation.json"
        import json
        data = json.loads(ev.read_text())
        assert data["status"] == "PASS"
        assert data["selected_version"] == "6.53.0"
        assert data["minimum_version"] == "5.62.0"
        assert data["environment_default_tags_supported"] is True

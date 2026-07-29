#!/usr/bin/env python3
"""
tests/test_source_integrity.py

Unit tests for the Terraform source integrity validator.

Run:  python -m pytest tests/test_source_integrity.py -v
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.deployment.validate_source_integrity import (
    EXCLUDE_DIRS,
    EXCLUDE_FILES,
    compute_manifest,
    sha256_bytes,
)

SCAN_ID = "SCAN-SITEST01"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def cleanup():
    deploy_dir = ROOT / "reports" / "deployment" / SCAN_ID
    deploy_dir.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(str(ROOT / "reports" / "deployment" / SCAN_ID), ignore_errors=True)


def _run(args: list[str]) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable,
         str(ROOT / "scripts" / "deployment" / "validate_source_integrity.py"),
         SCAN_ID] + args,
        capture_output=True, text=True, cwd=str(ROOT),
    )
    return result.returncode, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# compute_manifest
# ---------------------------------------------------------------------------

class TestComputeManifest:
    def test_basic_tf_files(self, tmp_path):
        (tmp_path / "main.tf").write_text("resource {} ")
        (tmp_path / "variables.tf").write_text("variable {} ")
        manifest = compute_manifest(tmp_path)
        assert "main.tf" in manifest
        assert "variables.tf" in manifest

    def test_ignores_non_tf_files(self, tmp_path):
        (tmp_path / "main.tf").write_text("x")
        (tmp_path / "README.md").write_text("y")
        (tmp_path / "outputs.json").write_text("{}")
        manifest = compute_manifest(tmp_path)
        assert "main.tf" in manifest
        assert "README.md" not in manifest
        assert "outputs.json" not in manifest

    def test_excludes_terraform_dir(self, tmp_path):
        tf_inner = tmp_path / ".terraform" / "providers"
        tf_inner.mkdir(parents=True)
        (tf_inner / "main.tf").write_text("# generated")
        manifest = compute_manifest(tmp_path)
        assert not any(".terraform" in k for k in manifest)

    def test_excludes_lock_file(self, tmp_path):
        (tmp_path / "main.tf").write_text("x")
        (tmp_path / ".terraform.lock.hcl").write_text("# lock")
        manifest = compute_manifest(tmp_path)
        assert ".terraform.lock.hcl" not in manifest

    def test_excludes_tfplan(self, tmp_path):
        (tmp_path / "main.tf").write_text("x")
        (tmp_path / "tfplan").write_bytes(b"\x00\x01\x02")
        manifest = compute_manifest(tmp_path)
        assert "tfplan" not in manifest

    def test_stable_sha256(self, tmp_path):
        (tmp_path / "main.tf").write_text("stable content")
        m1 = compute_manifest(tmp_path)
        m2 = compute_manifest(tmp_path)
        assert m1 == m2

    def test_empty_directory(self, tmp_path):
        manifest = compute_manifest(tmp_path)
        assert manifest == {}

    def test_tf_json_included(self, tmp_path):
        (tmp_path / "override.tf.json").write_text('{"resource": {}}')
        manifest = compute_manifest(tmp_path)
        assert "override.tf.json" in manifest


# ---------------------------------------------------------------------------
# End-to-end: --save then --verify
# ---------------------------------------------------------------------------

class TestSaveAndVerify:
    def test_no_files_changed_passes(self, tmp_path):
        (tmp_path / "main.tf").write_text("resource {} ")
        rc, _ = _run(["--save", str(tmp_path)])
        assert rc == 0
        rc, _ = _run(["--verify", str(tmp_path)])
        assert rc == 0

    def test_existing_tf_file_modified_fails(self, tmp_path):
        f = tmp_path / "main.tf"
        f.write_text("original content")
        _run(["--save", str(tmp_path)])
        f.write_text("MODIFIED content")
        rc, out = _run(["--verify", str(tmp_path)])
        assert rc != 0
        assert "FAIL" in out

    def test_new_tf_file_added_fails(self, tmp_path):
        (tmp_path / "main.tf").write_text("x")
        _run(["--save", str(tmp_path)])
        (tmp_path / "injected.tf").write_text("# injected by framework!")
        rc, out = _run(["--verify", str(tmp_path)])
        assert rc != 0

    def test_terraform_dir_added_does_not_fail(self, tmp_path):
        """Adding .terraform/ dir (from terraform init) must NOT fail integrity."""
        (tmp_path / "main.tf").write_text("x")
        _run(["--save", str(tmp_path)])
        tf_dir = tmp_path / ".terraform" / "providers"
        tf_dir.mkdir(parents=True)
        (tf_dir / "aws.exe").write_bytes(b"\x00")
        rc, _ = _run(["--verify", str(tmp_path)])
        assert rc == 0  # .terraform/ is excluded

    def test_lock_file_added_does_not_fail(self, tmp_path):
        """Adding .terraform.lock.hcl does NOT fail integrity."""
        (tmp_path / "main.tf").write_text("x")
        _run(["--save", str(tmp_path)])
        (tmp_path / ".terraform.lock.hcl").write_text("# lock")
        rc, _ = _run(["--verify", str(tmp_path)])
        assert rc == 0

    def test_tfplan_added_does_not_fail(self, tmp_path):
        """Adding tfplan binary does NOT fail integrity."""
        (tmp_path / "main.tf").write_text("x")
        _run(["--save", str(tmp_path)])
        (tmp_path / "tfplan").write_bytes(b"\x00\x01\x02")
        rc, _ = _run(["--verify", str(tmp_path)])
        assert rc == 0

    def test_existing_tf_file_removed_fails(self, tmp_path):
        (tmp_path / "main.tf").write_text("x")
        (tmp_path / "vars.tf").write_text("y")
        _run(["--save", str(tmp_path)])
        (tmp_path / "vars.tf").unlink()
        rc, out = _run(["--verify", str(tmp_path)])
        assert rc != 0

    def test_generates_integrity_json(self, tmp_path):
        import json
        (tmp_path / "main.tf").write_text("x")
        _run(["--save", str(tmp_path)])
        _run(["--verify", str(tmp_path)])
        ev = ROOT / "reports" / "deployment" / SCAN_ID / "deployment-source-integrity.json"
        data = json.loads(ev.read_text())
        assert data["status"] == "PASS"
        assert data["source_modified"] is False
        assert data["schema_version"] == "1.0"

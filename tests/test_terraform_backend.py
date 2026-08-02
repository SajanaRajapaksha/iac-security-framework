import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from scripts.deployment.prepare_terraform_backend import detect_backend
from scripts.deployment.validate_source_integrity import compute_manifest

def test_detect_no_backend(tmp_path):
    # Setup
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
    backend, source = detect_backend(tmp_path)
    assert backend is None

def test_detect_s3_backend_tf(tmp_path):
    (tmp_path / "backend.tf").write_text('terraform { backend "s3" { bucket = "b" } }')
    backend, source = detect_backend(tmp_path)
    assert backend == "s3"

def test_detect_local_backend_tf(tmp_path):
    (tmp_path / "backend.tf").write_text('terraform { backend "local" { path = "p" } }')
    backend, source = detect_backend(tmp_path)
    assert backend == "local"

def test_detect_s3_backend_json(tmp_path):
    tf_json = {
        "terraform": {
            "backend": {
                "s3": {
                    "bucket": "b"
                }
            }
        }
    }
    (tmp_path / "backend.tf.json").write_text(json.dumps(tf_json))
    backend, source = detect_backend(tmp_path)
    assert backend == "s3"

def test_detect_s3_backend_json_list(tmp_path):
    tf_json = {
        "terraform": [
            {
                "backend": [
                    {
                        "s3": {
                            "bucket": "b"
                        }
                    }
                ]
            }
        ]
    }
    (tmp_path / "backend.tf.json").write_text(json.dumps(tf_json))
    backend, source = detect_backend(tmp_path)
    assert backend == "s3"

def test_source_integrity_excludes_backend(tmp_path):
    (tmp_path / "main.tf").write_text("a")
    (tmp_path / "iac_framework_backend.tf").write_text("terraform { backend \"s3\" {} }")
    (tmp_path / ".terraform.lock.hcl").write_text("l")
    
    manifest = compute_manifest(tmp_path)
    assert "main.tf" in manifest
    assert "iac_framework_backend.tf" not in manifest
    assert ".terraform.lock.hcl" not in manifest

@patch("scripts.deployment.verify_terraform_backend.sys.exit")
@patch("scripts.deployment.verify_terraform_backend.safe_write_json")
def test_verify_terraform_backend_success(mock_write, mock_exit, tmp_path):
    from scripts.deployment import verify_terraform_backend
    
    os.environ["TF_STATE_BUCKET"] = "test-bucket"
    os.environ["AWS_REGION"] = "us-east-1"
    
    # Mock .terraform/terraform.tfstate
    dot_tf = tmp_path / ".terraform"
    dot_tf.mkdir()
    state = {
        "backend": {
            "type": "s3",
            "config": {
                "bucket": "test-bucket",
                "key": "research/SCAN-1/terraform.tfstate"
            }
        }
    }
    (dot_tf / "terraform.tfstate").write_text(json.dumps(state))
    
    with patch("sys.argv", ["verify", "SCAN-1", str(tmp_path)]):
        verify_terraform_backend.main()
        
    mock_exit.assert_not_called()
    written_data = mock_write.call_args[0][1]
    assert written_data["status"] == "PASS"
    assert written_data["actual_backend"] == "s3"

@patch("scripts.deployment.verify_terraform_backend.sys.exit")
@patch("scripts.deployment.verify_terraform_backend.safe_write_json")
def test_verify_terraform_backend_wrong_bucket(mock_write, mock_exit, tmp_path):
    from scripts.deployment import verify_terraform_backend
    
    os.environ["TF_STATE_BUCKET"] = "test-bucket"
    os.environ["AWS_REGION"] = "us-east-1"
    
    dot_tf = tmp_path / ".terraform"
    dot_tf.mkdir()
    state = {
        "backend": {
            "type": "s3",
            "config": {
                "bucket": "wrong-bucket",
                "key": "research/SCAN-1/terraform.tfstate"
            }
        }
    }
    (dot_tf / "terraform.tfstate").write_text(json.dumps(state))
    
    with patch("sys.argv", ["verify", "SCAN-1", str(tmp_path)]):
        verify_terraform_backend.main()
        
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["status"] == "BACKEND_BUCKET_MISMATCH"

@patch("scripts.deployment.verify_terraform_backend.sys.exit")
@patch("scripts.deployment.verify_terraform_backend.safe_write_json")
def test_verify_terraform_backend_wrong_key(mock_write, mock_exit, tmp_path):
    from scripts.deployment import verify_terraform_backend
    
    os.environ["TF_STATE_BUCKET"] = "test-bucket"
    os.environ["AWS_REGION"] = "us-east-1"
    
    dot_tf = tmp_path / ".terraform"
    dot_tf.mkdir()
    state = {
        "backend": {
            "type": "s3",
            "config": {
                "bucket": "test-bucket",
                "key": "wrong/key"
            }
        }
    }
    (dot_tf / "terraform.tfstate").write_text(json.dumps(state))
    
    with patch("sys.argv", ["verify", "SCAN-1", str(tmp_path)]):
        verify_terraform_backend.main()
        
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["status"] == "BACKEND_KEY_MISMATCH"
    
@patch("scripts.deployment.verify_terraform_backend.sys.exit")
@patch("scripts.deployment.verify_terraform_backend.safe_write_json")
def test_verify_terraform_backend_missing_bucket(mock_write, mock_exit, tmp_path):
    from scripts.deployment import verify_terraform_backend
    
    if "TF_STATE_BUCKET" in os.environ:
        del os.environ["TF_STATE_BUCKET"]
    os.environ["AWS_REGION"] = "us-east-1"
    
    with patch("sys.argv", ["verify", "SCAN-1", str(tmp_path)]):
        verify_terraform_backend.main()
        
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["status"] == "EXPECTED_BUCKET_NOT_CONFIGURED"

@patch("scripts.deployment.verify_terraform_backend.sys.exit")
@patch("scripts.deployment.verify_terraform_backend.safe_write_json")
def test_verify_terraform_backend_missing_region(mock_write, mock_exit, tmp_path):
    from scripts.deployment import verify_terraform_backend
    
    os.environ["TF_STATE_BUCKET"] = "test-bucket"
    if "AWS_REGION" in os.environ:
        del os.environ["AWS_REGION"]
    
    with patch("sys.argv", ["verify", "SCAN-1", str(tmp_path)]):
        verify_terraform_backend.main()
        
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["status"] == "EXPECTED_REGION_NOT_CONFIGURED"
    
@patch("scripts.deployment.verify_terraform_backend.sys.exit")
@patch("scripts.deployment.verify_terraform_backend.safe_write_json")
def test_verify_terraform_backend_wrong_type(mock_write, mock_exit, tmp_path):
    from scripts.deployment import verify_terraform_backend
    
    os.environ["TF_STATE_BUCKET"] = "test-bucket"
    os.environ["AWS_REGION"] = "us-east-1"
    
    dot_tf = tmp_path / ".terraform"
    dot_tf.mkdir()
    state = {
        "backend": {
            "type": "local",
            "config": {}
        }
    }
    (dot_tf / "terraform.tfstate").write_text(json.dumps(state))
    
    with patch("sys.argv", ["verify", "SCAN-1", str(tmp_path)]):
        verify_terraform_backend.main()
        
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["status"] == "INVALID_BACKEND_TYPE"

@patch("scripts.deployment.verify_remote_state.subprocess.run")
@patch("scripts.deployment.verify_remote_state.sys.exit")
@patch("scripts.deployment.verify_remote_state.safe_write_json")
def test_verify_remote_state_success(mock_write, mock_exit, mock_run, tmp_path):
    from scripts.deployment import verify_remote_state
    os.environ["TF_STATE_BUCKET"] = "test-bucket"
    
    def side_effect(cmd, *args, **kwargs):
        res = MagicMock()
        if cmd[0] == "aws":
            res.returncode = 0
            res.stdout = '{"ContentLength": 1000, "LastModified": "2026"}'
        elif cmd[0] == "terraform":
            res.returncode = 0
            res.stdout = '{"resources": [{"type": "aws_s3_bucket"}, {"type": "aws_iam_role"}]}'
        return res
        
    mock_run.side_effect = side_effect
    
    with patch("sys.argv", ["verify_remote", "SCAN-1", str(tmp_path)]):
        verify_remote_state.main()
        
    mock_exit.assert_not_called()
    written = mock_write.call_args[0][1]
    assert written["status"] == "PASS"
    assert written["object_exists"] is True
    assert written["state_pull_success"] is True
    assert written["resource_count"] == 2
    assert "aws_access_key" not in written.keys() # no secrets

@patch("scripts.deployment.verify_remote_state.subprocess.run")
@patch("scripts.deployment.verify_remote_state.sys.exit")
@patch("scripts.deployment.verify_remote_state.safe_write_json")
def test_verify_remote_state_missing(mock_write, mock_exit, mock_run, tmp_path):
    from scripts.deployment import verify_remote_state
    
    def side_effect(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 1
        return res
        
    mock_run.side_effect = side_effect
    
    with patch("sys.argv", ["verify_remote", "SCAN-1", str(tmp_path)]):
        verify_remote_state.main()
        
    mock_exit.assert_called_with(1)
    written = mock_write.call_args[0][1]
    assert written["status"] == "REMOTE_STATE_MISSING"
    assert written["object_exists"] is False

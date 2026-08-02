import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch

@patch("scripts.deployment.generate_cleanup_evidence.sys.exit")
@patch("scripts.deployment.generate_cleanup_evidence.safe_write_json")
def test_cleanup_verified_destroyed(mock_write, mock_exit, tmp_path):
    from scripts.deployment import generate_cleanup_evidence
    
    scan_id = "SCAN-123"
    deploy_dir = tmp_path / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True)
    
    (deploy_dir / "pre-destroy-state-addresses.txt").write_text("aws_instance.one\naws_s3_bucket.two\n")
    (deploy_dir / "post-destroy-state-addresses.txt").write_text("")
    (deploy_dir / "post-destroy-tagged-resources.json").write_text('{"resource_count": 0, "resources": []}')
    (deploy_dir / "terraform-backend-verification.json").write_text('{"status": "PASS", "actual_bucket": "b", "actual_key": "research/SCAN-123/terraform.tfstate"}')
    (deploy_dir / "terraform-destroy.txt").write_text("Destroy complete!")
    
    with patch("scripts.deployment.generate_cleanup_evidence.ROOT_DIR", tmp_path):
        with patch("sys.argv", ["generate", scan_id, "--destroy-exit-code", "0", "--destroy-start-time", "2026-01-01T00:00:00Z", "--destroy-finish-time", "2026-01-01T00:01:00Z"]):
            generate_cleanup_evidence.main()
            
    mock_exit.assert_not_called()
    written_data = mock_write.call_args[0][1]
    assert written_data["cleanup_status"] == "VERIFIED_DESTROYED"
    assert written_data["Resources"]["resources_before_destroy"] == 2
    assert written_data["Resources"]["state_resources_after_destroy"] == 0
    assert written_data["Resources"]["tagged_resources_after_destroy"] == 0
    assert written_data["Destroy"]["destroy_duration_seconds"] == 60
    assert written_data["Terraform backend"]["state_key"] == "research/SCAN-123/terraform.tfstate"
    assert "aws_access_key" not in written_data["AWS"]
    
    sha_file = deploy_dir / "terraform-destroy-evidence.sha256"
    assert sha_file.exists()
    hashes = json.loads(sha_file.read_text())
    assert "terraform-destroy-evidence.json" in hashes

@patch("scripts.deployment.generate_cleanup_evidence.sys.exit")
@patch("scripts.deployment.generate_cleanup_evidence.safe_write_json")
def test_cleanup_destroy_failed(mock_write, mock_exit, tmp_path):
    from scripts.deployment import generate_cleanup_evidence
    
    scan_id = "SCAN-123"
    deploy_dir = tmp_path / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True)
    
    (deploy_dir / "pre-destroy-state-addresses.txt").write_text("aws_instance.one\naws_s3_bucket.two\n")
    (deploy_dir / "post-destroy-state-addresses.txt").write_text("")
    (deploy_dir / "post-destroy-tagged-resources.json").write_text('{"resource_count": 0}')
    (deploy_dir / "terraform-backend-verification.json").write_text('{"status": "PASS"}')
    
    with patch("scripts.deployment.generate_cleanup_evidence.ROOT_DIR", tmp_path):
        with patch("sys.argv", ["generate", scan_id, "--destroy-exit-code", "1"]):
            generate_cleanup_evidence.main()
            
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["cleanup_status"] == "DESTROY_FAILED"

@patch("scripts.deployment.generate_cleanup_evidence.sys.exit")
@patch("scripts.deployment.generate_cleanup_evidence.safe_write_json")
def test_cleanup_state_not_empty(mock_write, mock_exit, tmp_path):
    from scripts.deployment import generate_cleanup_evidence
    
    scan_id = "SCAN-123"
    deploy_dir = tmp_path / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True)
    
    (deploy_dir / "pre-destroy-state-addresses.txt").write_text("aws_instance.one\n")
    (deploy_dir / "post-destroy-state-addresses.txt").write_text("aws_instance.one\n")
    (deploy_dir / "post-destroy-tagged-resources.json").write_text('{"resource_count": 0}')
    (deploy_dir / "terraform-backend-verification.json").write_text('{"status": "PASS"}')
    
    with patch("scripts.deployment.generate_cleanup_evidence.ROOT_DIR", tmp_path):
        with patch("sys.argv", ["generate", scan_id, "--destroy-exit-code", "0"]):
            generate_cleanup_evidence.main()
            
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["cleanup_status"] == "STATE_NOT_EMPTY"

@patch("scripts.deployment.generate_cleanup_evidence.sys.exit")
@patch("scripts.deployment.generate_cleanup_evidence.safe_write_json")
def test_cleanup_tagged_resources_remain(mock_write, mock_exit, tmp_path):
    from scripts.deployment import generate_cleanup_evidence
    
    scan_id = "SCAN-123"
    deploy_dir = tmp_path / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True)
    
    (deploy_dir / "pre-destroy-state-addresses.txt").write_text("aws_instance.one\n")
    (deploy_dir / "post-destroy-state-addresses.txt").write_text("")
    (deploy_dir / "post-destroy-tagged-resources.json").write_text('{"resource_count": 1, "resources": [{"resource_arn": "abc"}]}')
    (deploy_dir / "terraform-backend-verification.json").write_text('{"status": "PASS"}')
    
    with patch("scripts.deployment.generate_cleanup_evidence.ROOT_DIR", tmp_path):
        with patch("sys.argv", ["generate", scan_id, "--destroy-exit-code", "0"]):
            generate_cleanup_evidence.main()
            
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["cleanup_status"] == "TAGGED_RESOURCES_REMAIN"

@patch("scripts.deployment.generate_cleanup_evidence.sys.exit")
@patch("scripts.deployment.generate_cleanup_evidence.safe_write_json")
def test_cleanup_backend_verification_failed(mock_write, mock_exit, tmp_path):
    from scripts.deployment import generate_cleanup_evidence
    
    scan_id = "SCAN-123"
    deploy_dir = tmp_path / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True)
    
    (deploy_dir / "pre-destroy-state-addresses.txt").write_text("")
    (deploy_dir / "post-destroy-state-addresses.txt").write_text("")
    (deploy_dir / "post-destroy-tagged-resources.json").write_text('{"resource_count": 0}')
    (deploy_dir / "terraform-backend-verification.json").write_text('{"status": "BACKEND_BUCKET_MISMATCH"}')
    
    with patch("scripts.deployment.generate_cleanup_evidence.ROOT_DIR", tmp_path):
        with patch("sys.argv", ["generate", scan_id, "--destroy-exit-code", "0"]):
            generate_cleanup_evidence.main()
            
    mock_exit.assert_called_with(1)
    written_data = mock_write.call_args[0][1]
    assert written_data["cleanup_status"] == "BACKEND_VERIFICATION_FAILED"

@patch("scripts.deployment.generate_cleanup_evidence.sys.exit")
@patch("scripts.deployment.generate_cleanup_evidence.safe_write_json")
def test_cleanup_nothing_to_destroy(mock_write, mock_exit, tmp_path):
    from scripts.deployment import generate_cleanup_evidence
    
    scan_id = "SCAN-123"
    deploy_dir = tmp_path / "reports" / "deployment" / scan_id
    deploy_dir.mkdir(parents=True)
    
    (deploy_dir / "pre-destroy-state-addresses.txt").write_text("")
    (deploy_dir / "post-destroy-state-addresses.txt").write_text("")
    (deploy_dir / "post-destroy-tagged-resources.json").write_text('{"resource_count": 0}')
    (deploy_dir / "terraform-backend-verification.json").write_text('{"status": "PASS"}')
    
    with patch("scripts.deployment.generate_cleanup_evidence.ROOT_DIR", tmp_path):
        with patch("sys.argv", ["generate", scan_id, "--destroy-exit-code", "0"]):
            generate_cleanup_evidence.main()
            
    mock_exit.assert_not_called()
    written_data = mock_write.call_args[0][1]
    assert written_data["cleanup_status"] == "NOTHING_TO_DESTROY"

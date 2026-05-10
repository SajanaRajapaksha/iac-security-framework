import subprocess
import json
import os

DUMMY_TF = """
resource "aws_security_group" "public_ssh" {
  name        = "checkov-test-public-ssh"
  description = "Intentionally insecure security group for Checkov testing"

  ingress {
    description = "SSH open to the world - Checkov should fail this"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP open to the world"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

def test_policy():
    print("Writing dummy.tf...")
    with open("dummy.tf", "w") as f:
        f.write(DUMMY_TF)

    print("Running conftest...")
    cmd = [
        "conftest", "test", "dummy.tf",
        "--policy", "policies/terraform/aws_security.rego",
        "--parser", "hcl2",
        "--output", "json"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print(f"Exit code: {result.returncode}")
    
    if result.returncode == 0:
        print("FAIL: Conftest exited with 0 (no violations found). Expected 1.")
    elif result.returncode == 1:
        print("PASS: Conftest correctly exited with 1 (violations found).")
        
        try:
            parsed = json.loads(result.stdout)
            failures = parsed[0].get("failures", [])
            print(f"Found {len(failures)} failures.")
            for f in failures:
                print(f" - {f.get('msg')}")
                print(f"   Policy ID: {f.get('metadata', {}).get('policy_id')}")
        except Exception as e:
            print("Could not parse output:", e)
            print("Raw stdout:", result.stdout)
    else:
        print(f"FAIL: Conftest exited with {result.returncode} (Tool error).")
        print("Raw stderr:", result.stderr)

    if os.path.exists("dummy.tf"):
        os.remove("dummy.tf")

if __name__ == "__main__":
    test_policy()

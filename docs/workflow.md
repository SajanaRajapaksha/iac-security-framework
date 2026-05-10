# Pipeline Workflow

## Project: Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

---

## Overview

The pipeline workflow describes the sequence of stages that every repository scan passes through, from initial URL input to forensic evidence generation. Each stage is discrete, auditable, and linked to a unique **Scan ID** (`SCAN-<UUID-prefix>`).

The framework accepts **GitHub repository URLs** as input. It never assumes a specific Terraform project layout — it dynamically discovers what Terraform structure exists inside the cloned repository.

### Implementation Status

| Stage | Status |
|---|---|
| Stage 1 — Repository Cloning | ✅ Implemented |
| Stage 2 — Scan Metadata (SHA256 hashing) | ✅ Implemented |
| Stage 3 — Terraform Discovery | ✅ Implemented |
| Stage 4 — Terraform Validation (fmt/init/validate) | ✅ Implemented |
| Stage 5 — Checkov Static Security Scanning | ✅ Implemented |
| Stage 5a — Checkov Finding Normalization | ✅ Implemented |
| Stage 5b — Checkov Forensic Summary | ✅ Implemented |
| Stages 6–12 | 🔮 Planned |

---

## Stage 1: Repository Cloning ✅

**Trigger:** User provides a GitHub repository URL via `workflow_dispatch` input. For push/PR triggers, defaults to the current repository.

**Script:** `scripts/clone_repository.py`

**Environment variables:** `SCAN_ID`, `REPO_URL`, `BRANCH`

**Actions:**
1. Read `REPO_URL`, `BRANCH`, and `SCAN_ID` from environment
2. If `repositories/cloned/<SCAN_ID>/` already exists, delete it
3. Run `git clone --depth 1 --branch <branch> <url> repositories/cloned/<SCAN_ID>/`
4. Capture git command exit code, stdout, stderr, timestamps

**Output:** `repositories/metadata/<SCAN_ID>/repository-metadata.json`
```json
{
  "scan_id": "SCAN-550e8400",
  "repo_url": "https://github.com/org/repo",
  "branch": "main",
  "cloned_path": "repositories/cloned/SCAN-550e8400/",
  "clone_status": "SUCCESS",
  "clone_started_at": "2025-01-01T12:00:00+00:00",
  "clone_completed_at": "2025-01-01T12:00:05+00:00",
  "git_command_exit_code": 0,
  "stdout": "...",
  "stderr": "..."
}
```

**Error handling:** If clone fails, metadata is written first, then exit code 1.

**Evidence produced:** ✅ Clone metadata with timestamps and command output

---

## Stage 2: Scan Metadata Generation (SHA256 Hashing) ✅

**Script:** `scripts/generate_scan_metadata.py`

**Environment variables:** `SCAN_ID`, `REPO_URL`, `BRANCH`

**Actions:**
1. Walk `repositories/cloned/<SCAN_ID>/` recursively
2. Find all `.tf` files (skipping `.git/`, `.terraform/`, `node_modules/`)
3. Compute SHA256 hash for every `.tf` file
4. Record file sizes and relative paths
5. Save metadata with an evidence note explaining forensic significance

**Output:** `repositories/metadata/<SCAN_ID>/scan-metadata.json`
```json
{
  "scan_id": "SCAN-550e8400",
  "repo_url": "https://github.com/org/repo",
  "branch": "main",
  "generated_at": "2025-01-01T12:00:06+00:00",
  "total_terraform_files": 3,
  "terraform_files": [
    { "relative_path": "main.tf", "sha256": "abc123...", "file_size_bytes": 1024 }
  ],
  "evidence_note": "All Terraform files are treated as digital evidence objects..."
}
```

**Evidence produced:** ✅ Root anchor of forensic chain — SHA256 file hashes at scan time

---

## Stage 3: Terraform Discovery ✅

**Script:** `scripts/discover_terraform.py`

**Environment variable:** `SCAN_ID`

**Actions:**
1. Walk `repositories/cloned/<SCAN_ID>/` recursively
2. Find all directories containing at least one `.tf` file
3. Skip `.git/`, `.terraform/`, `node_modules/`
4. Record each directory path, relative path, file count, and file names

**Output:** `repositories/metadata/<SCAN_ID>/terraform-directories.json`
```json
{
  "scan_id": "SCAN-550e8400",
  "generated_at": "2025-01-01T12:00:07+00:00",
  "total_directories": 3,
  "terraform_directories": [
    { "path": "/abs/path", "relative_path": ".", "tf_file_count": 3, "tf_files": ["main.tf", "variables.tf", "outputs.tf"] }
  ]
}
```

**Supported layouts:** Simple flat, multi-module, monorepo, deeply nested

**Evidence produced:** ✅ Terraform directory map

---

## Stage 4: Terraform Validation ✅

**Script:** `scripts/terraform_validate.py`

**Environment variable:** `SCAN_ID`

**Actions:**
1. Load discovered directories from `repositories/metadata/<SCAN_ID>/terraform-directories.json`
2. For each Terraform directory run:
   - `terraform fmt -check -recursive`
   - `terraform init -backend=false`
   - `terraform validate`
3. Capture per command: exit code, stdout, stderr, started_at, completed_at
4. Calculate overall PASS/FAIL status

**Output:** `reports/static/<SCAN_ID>/terraform-validation.json`

**Error handling:** If no directories found or any command fails, report is written first, then exit code 1.

**Evidence produced:** ✅ Per-directory validation records with command forensics

---

## Stage 5: Static IaC Scanning (Checkov) ✅

**Trigger:** Automatic — runs after Terraform validation succeeds. If Terraform validation fails, Checkov is **skipped** but validation reports are still uploaded as artifacts.

**Tool:** Checkov (installed via `pip install checkov`)

**Script:** `scripts/normalize_checkov.py` (normalization), `scripts/checkov_forensic_summary.py` (forensic summary)

**Environment variables:** `SCAN_ID`, `REPO_URL`

**Actions:**
1. Install Checkov via `pip install checkov` in the GitHub Actions workflow
2. Print Checkov version to workflow logs for traceability
3. Run Checkov recursively against `repositories/cloned/<SCAN_ID>/`:
   ```bash
   checkov \
     -d repositories/cloned/$SCAN_ID \
     -o json \
     --output-file-path reports/static/$SCAN_ID
   ```
4. The step uses `continue-on-error: true` so the pipeline continues even if Checkov finds security issues
5. Raw Checkov JSON output is saved as `reports/static/<SCAN_ID>/checkov-report.json`

**Output:** `reports/static/<SCAN_ID>/checkov-report.json`

**Error handling:** Checkov execution uses `continue-on-error: true`. The workflow proceeds to normalization regardless of Checkov exit code. If Terraform validation failed, Checkov is skipped entirely.

**Evidence produced:** ✅ Raw Checkov static analysis results with check IDs, resources, severities, and file paths

---

## Stage 5a: Checkov Finding Normalization ✅

**Trigger:** Automatic — runs after Checkov scan completes (only if Terraform validation succeeded).

**Script:** `scripts/normalize_checkov.py`

**Environment variable:** `SCAN_ID`

**Actions:**
1. Load raw Checkov report from `reports/static/<SCAN_ID>/checkov-report.json`
2. Handle gracefully: missing file, empty file, invalid JSON
3. Load Terraform file hash map from `repositories/metadata/<SCAN_ID>/scan-metadata.json`
4. Extract all **failed checks** from the Checkov output
5. For each failed check, normalize into the framework standard format:
   - `scan_id` — links to the specific scan
   - `finding_id` — unique UUID per finding
   - `check_id` — Checkov check identifier (e.g., `CKV_AWS_21`)
   - `check_name` — human-readable description
   - `severity` — CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN (defaults to UNKNOWN if Checkov omits severity)
   - `file_path` — path to the affected Terraform file
   - `resource` — affected Terraform resource
   - `guideline` — remediation link from Checkov
   - `category` — inferred from check metadata (encryption, networking, iam, logging, storage, etc.)
   - `check_result` — Checkov result status
   - `terraform_file_sha256` — SHA256 hash of the source Terraform file (from scan metadata)
   - `finding_generated_at` — UTC ISO 8601 timestamp
6. Generate severity summary with counts for CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
7. Save normalized findings

**Output:** `reports/static/<SCAN_ID>/normalized-checkov-findings.json`

```json
{
  "scan_id": "SCAN-550e8400",
  "generated_at": "2025-01-01T12:00:30+00:00",
  "source_tool": "checkov",
  "total_failed_checks": 5,
  "severity_summary": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 1 },
  "findings": [
    {
      "scan_id": "SCAN-550e8400",
      "finding_id": "uuid-...",
      "check_id": "CKV_AWS_21",
      "check_name": "Ensure S3 bucket has versioning enabled",
      "severity": "HIGH",
      "file_path": "/main.tf",
      "resource": "aws_s3_bucket.main",
      "category": "storage",
      "terraform_file_sha256": "abc123...",
      "finding_generated_at": "2025-01-01T12:00:30+00:00"
    }
  ]
}
```

**Evidence produced:** ✅ Normalized static IaC misconfiguration findings with SCAN_ID and file hash correlation

---

## Stage 5b: Checkov Forensic Summary ✅

**Trigger:** Automatic — runs after finding normalization completes.

**Script:** `scripts/checkov_forensic_summary.py`

**Environment variables:** `SCAN_ID`, `REPO_URL`

**Actions:**
1. Load normalized findings from `reports/static/<SCAN_ID>/normalized-checkov-findings.json`
2. Load Terraform validation results from `reports/static/<SCAN_ID>/terraform-validation.json`
3. Load scan metadata from `repositories/metadata/<SCAN_ID>/scan-metadata.json`
4. Generate comprehensive forensic summary including:
   - `scan_id` and `generated_at` timestamp
   - `repository_url`
   - `total_terraform_files` and `total_terraform_directories`
   - `total_checkov_findings` and `severity_summary`
   - `scanned_directories` with per-directory validation status
   - `repository_integrity_hash` from scan metadata
   - `evidence_note` explaining forensic significance
   - `checkov_execution_metadata` with timing information
   - `forensic_chain_summary` explaining how SCAN_ID links all evidence, Terraform hashes preserve integrity, findings preserve security evidence, and reports support investigation
5. Save forensic summary

**Output:** `reports/static/<SCAN_ID>/checkov-forensic-summary.json`

**Evidence produced:** ✅ Comprehensive forensic summary linking all Checkov evidence through SCAN_ID

---

## Stage 6: Policy-as-Code Validation (OPA / Rego / Conftest)

**Trigger:** Automatic — runs after Checkov.

**Tool:** Conftest + OPA/Rego policies

**Actions:**
1. For each root module, generate Terraform plan JSON
2. Run Conftest with `policies/terraform.rego` against each plan
3. Run Conftest with `policies/aws-security.rego` against each plan
4. Capture all violations, attach `scan_id` and `module_path`
5. Save `reports/static/<scan_id>/policy-results.json`

**Evidence produced:** ✅ Policy-as-Code violation record per module with `scan_id`

---

## Stage 7: Initial Risk Scoring

**Trigger:** Automatic — after Checkov and OPA results are available.

**Script:** `scripts/risk_score.py`

**Actions:**
1. Load normalized findings from `reports/static/<scan_id>/normalized-findings.json`
2. Load policy violations from `reports/static/<scan_id>/policy-results.json`
3. Apply severity weights and calculate normalized score (0–100)
4. Classify into risk band: LOW / MEDIUM / HIGH / CRITICAL
5. Generate initial deployment decision: **ALLOW / REVIEW / BLOCK**
6. Save `reports/static/<scan_id>/static-risk-score.json`

**Decision gates:**
- `ALLOW` → proceed to sandbox deployment
- `REVIEW` → pause for human approval (future approval gate)
- `BLOCK` → pipeline stops, no deployment

**Evidence produced:** ✅ Static risk score + initial deployment decision

---

## Stage 8: AWS Sandbox Deployment

**Trigger:** Conditional — only if initial decision is ALLOW or REVIEW (with approval).

**Tool:** Terraform CLI + AWS credentials (GitHub Secrets)

**Actions:**
1. Authenticate to isolated AWS sandbox account
2. For each identified root module: `terraform apply -auto-approve`
3. Tag all deployed resources with `scan_id`
4. Capture deployed resource ARNs, IDs, regions, timestamps
5. Save deployment metadata record

**Evidence produced:** ✅ Deployment metadata (all resources created, tagged with `scan_id`)

---

## Stage 9: Runtime Validation (Prowler)

**Trigger:** Automatic — after successful sandbox deployment.

**Tool:** Prowler + `scripts/normalize_prowler.py`

**Actions:**
1. Run Prowler against sandbox AWS account
2. Target resources tagged with `scan_id` (ensures per-scan isolation)
3. Export raw Prowler output to `reports/runtime/<scan_id>/prowler-report.json`
4. Run `normalize_prowler.py`:
   - Parse Prowler output
   - Normalize findings to framework standard format
   - Attach `scan_id` to every finding
5. Save `reports/runtime/<scan_id>/normalized-runtime-findings.json`

**Evidence produced:** ✅ Runtime cloud security findings with `scan_id`

---

## Stage 10: Final Risk Scoring

**Trigger:** Automatic — after runtime findings are normalized.

**Script:** `scripts/runtime_risk_score.py`

**Actions:**
1. Load static risk score from `reports/static/<scan_id>/`
2. Load runtime findings from `reports/runtime/<scan_id>/`
3. Detect drift: runtime findings not caught by static scanning
4. Apply runtime severity weights (higher than static weights)
5. Calculate combined normalized score (0–100)
6. Calculate Deployment Trust Score (inverse of risk)
7. Generate final decision
8. Save to `reports/final/<scan_id>/`:
   - `final-risk-score.json`
   - `deployment-decision.json`
   - `combined-summary.json`

**Evidence produced:** ✅ Final risk score + trust score + final deployment decision

---

## Stage 11: Forensic Evidence Generation

**Trigger:** Always runs — even if earlier stages fail.

**Script:** `scripts/forensic_log.py`

**Actions:**
1. Collect all pipeline artifacts for this `scan_id`:
   - Scan metadata (repository URL, branch, commit SHA)
   - Terraform discovery results
   - Terraform validation results
   - Checkov findings
   - OPA policy violations
   - Deployment metadata
   - Prowler runtime findings
   - Static and final risk scores
2. Generate `evidence_id`: `EV-<UUID>`
3. Calculate SHA256 integrity hash of the complete evidence package
4. Save `evidence/<scan_id>/evidence-<evidence_id>.json`

**Evidence produced:** ✅ SHA256-sealed forensic evidence package

---

## Stage 12: Artifact Upload

**Trigger:** Always — final stage of every pipeline run.

**Tool:** GitHub Actions `upload-artifact`

**Actions:**
1. Upload `reports/static/<scan_id>/` → GitHub Actions Artifact
2. Upload `reports/runtime/<scan_id>/` → GitHub Actions Artifact
3. Upload `reports/final/<scan_id>/` → GitHub Actions Artifact
4. Upload `evidence/<scan_id>/` → GitHub Actions Artifact

All artifacts tagged with `scan_id` for retrieval and traceability.

---

## Pipeline Summary Table

| Stage | Script / Tool | Output Location | Evidence |
|---|---|---|---|
| Repository Cloning | `clone_repository.py` | `repositories/cloned/<scan_id>/` | ✅ |
| Scan Metadata | `generate_scan_metadata.py` | `repositories/metadata/<scan_id>/scan-metadata.json` | ✅ |
| Terraform Discovery | `discover_terraform.py` | `repositories/metadata/<scan_id>/terraform-directories.json` | ✅ |
| Terraform Validation | `terraform_validate.py` | `reports/static/<scan_id>/terraform-validation.json` | ✅ |
| Checkov Scanning | Checkov CLI | `reports/static/<scan_id>/checkov-report.json` | ✅ |
| Checkov Normalization | `normalize_checkov.py` | `reports/static/<scan_id>/normalized-checkov-findings.json` | ✅ |
| Checkov Forensic Summary | `checkov_forensic_summary.py` | `reports/static/<scan_id>/checkov-forensic-summary.json` | ✅ |
| Policy Validation | Conftest + OPA/Rego | `reports/static/<scan_id>/policy-results.json` | 🔮 |
| Initial Risk Score | `risk_score.py` | `reports/static/<scan_id>/static-risk-score.json` | 🔮 |
| Sandbox Deployment | Terraform + AWS | Deployment metadata | 🔮 |
| Runtime Validation | Prowler + `normalize_prowler.py` | `reports/runtime/<scan_id>/` | 🔮 |
| Final Risk Score | `runtime_risk_score.py` | `reports/final/<scan_id>/` | 🔮 |
| Evidence Generation | `forensic_log.py` | `evidence/<scan_id>/` | 🔮 |
| Artifact Upload | GitHub Actions | Archived per `scan_id` | ✅ |

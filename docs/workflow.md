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
| Stages 5–12 | 🔮 Planned |

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

## Stage 5: Static IaC Scanning (Checkov)

**Trigger:** Automatic — after Terraform validation.

**Tool:** Checkov + `scripts/normalize_checkov.py`

**Actions:**
1. Run Checkov recursively against `repositories/cloned/<scan_id>/`
   - Single Checkov run covers all discovered `.tf` files
2. Export raw JSON to `reports/static/<scan_id>/checkov-report.json`
3. Run `normalize_checkov.py`:
   - Parse raw Checkov output
   - Normalize each finding to framework standard format
   - Attach `scan_id` and relative file path to every finding
   - Categorize by severity (CRITICAL / HIGH / MEDIUM / LOW)
4. Save `reports/static/<scan_id>/normalized-findings.json`

**Evidence produced:** ✅ Normalized static IaC misconfiguration findings with `scan_id`

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
| Terraform Discovery | `discover_terraform.py` | `reports/static/<scan_id>/terraform-discovery.json` | ✅ |
| Scan Metadata | `generate_scan_metadata.py` | `repositories/metadata/scan-<scan_id>.json` | ✅ |
| Terraform Validation | Terraform CLI | Validation results | ✅ |
| Static Scanning | Checkov + `normalize_checkov.py` | `reports/static/<scan_id>/` | ✅ |
| Policy Validation | Conftest + `normalize_checkov.py` | `reports/static/<scan_id>/policy-results.json` | ✅ |
| Initial Risk Score | `risk_score.py` | `reports/static/<scan_id>/static-risk-score.json` | ✅ |
| Sandbox Deployment | Terraform + AWS | Deployment metadata | ✅ |
| Runtime Validation | Prowler + `normalize_prowler.py` | `reports/runtime/<scan_id>/` | ✅ |
| Final Risk Score | `runtime_risk_score.py` | `reports/final/<scan_id>/` | ✅ |
| Evidence Generation | `forensic_log.py` | `evidence/<scan_id>/` | ✅ |
| Artifact Upload | GitHub Actions | Archived per `scan_id` | ✅ |

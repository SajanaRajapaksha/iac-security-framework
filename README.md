# IaC Security Framework

> **MSc Research Project Implementation**
> *"Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments"*

An end-to-end, forensic-ready Infrastructure-as-Code (IaC) security pipeline for cloud environments. The framework performs automated static analysis, policy enforcement, risk scoring, controlled cloud deployment, runtime security validation, AI-assisted remediation, and automated infrastructure cleanup — all tied together via a unique `SCAN_ID` for complete traceability.

---

## Table of Contents

1. [Project Purpose](#project-purpose)
2. [Pipeline Overview](#pipeline-overview)
3. [Software & Hardware Requirements](#software--hardware-requirements)
4. [Programming Languages, Libraries & Frameworks](#programming-languages-libraries--frameworks)
5. [Installation Procedure](#installation-procedure)
6. [Dependency Installation](#dependency-installation)
7. [Configuration Requirements](#configuration-requirements)
8. [Running the System](#running-the-system)
9. [Dashboard UI](#dashboard-ui)
10. [Evidence & Artefacts](#evidence--artefacts)
11. [Testing & Evaluation](#testing--evaluation)
12. [External Services & API Keys](#external-services--api-keys)
13. [Known Limitations](#known-limitations)

---

## Project Purpose

The IaC Security Framework provides a structured, reproducible, and forensically auditable pipeline for evaluating the security posture of Terraform-based Infrastructure-as-Code before, during, and after cloud deployment. It is designed as a research instrument to study:

- **Pre-deployment risk**: Static analysis of Terraform configurations using Checkov and Policy-as-Code (Rego/OPA via Conftest).
- **Risk quantification**: A deterministic, density-based scoring engine that assigns a numeric risk score and risk band to each scan.
- **Controlled deployment**: Terraform is applied in a fully isolated, forensically traceable manner using OIDC-authenticated AWS roles, SHA-256 plan verification, scan-ID resource tagging, and isolated S3 remote state per scan.
- **Runtime security validation**: Post-deployment cloud resources are scanned using Prowler (AWS Security Hub findings format / OCSF).
- **Post-deployment risk scoring**: A second risk score is calculated from live runtime findings.
- **Security review**: A deterministic security review decision is generated from the comparison of pre- and post-deployment scores.
- **AI remediation**: OpenAI is used to generate structured remediation guidance for each unique finding, with a local cache to reduce repeated API calls.
- **Automated cleanup**: All deployed resources are destroyed after analysis to avoid cost and leave no residual infrastructure.
- **Evidence export**: All evidence is normalized and exported to an S3 bucket for dashboard consumption.

Every stage is traceable via a unique `SCAN_ID` (e.g., `SCAN-a8f713c2`).

---

## Pipeline Overview

The pipeline runs across three sequential GitHub Actions jobs:

| Job | Trigger | Stages |
|-----|---------|--------|
| `security-pipeline` | Push/PR to `dashboard` branch, `workflow_dispatch` | 1–18: Clone, validate, Checkov, OPA, enrich, risk score |
| `terraform-plan` | Push to `dashboard`, `workflow_dispatch` | 19–24: AWS OIDC auth, S3 backend init, tag injection, saved plan, plan evidence |
| `terraform-apply` | Push to `dashboard`, `workflow_dispatch` (after plan succeeds) | 25–58: Verify plan, apply, state capture, resource verification, Prowler scan, risk score, AI remediation, security review, cleanup, S3 export |

> **Pull requests never obtain AWS deployment credentials.** The plan and apply jobs only run on direct pushes to the active branch.

### Stage Summary

| Stage | Description |
|-------|-------------|
| 1 | Clone target repository |
| 2 | Generate scan metadata (SHA-256 file hashes) |
| 3 | Discover Terraform directories |
| 4 | Terraform validation (`fmt` / `init` / `validate`) |
| 5 | Checkov static security scan |
| 7 | Generate combined static analysis evidence |
| 8 | Prepare policy validation input |
| 9 | Policy-as-Code checks (Conftest / Rego, advisory mode) |
| 10–11 | Regenerate report with policy results; print findings |
| 12–17 | Normalize, AI-enrich, validate, and gate findings |
| 18 | Build resource inventory; calculate pre-deployment risk score |
| 19–24 | AWS OIDC auth; S3 backend prep; Terraform plan with tag injection; plan evidence |
| 25–28 | Download & verify saved plan; re-authenticate AWS; reinit Terraform |
| 29 | Terraform apply (exact saved plan) with framework tag injection |
| 30 | Capture Terraform state |
| 31 | Discover tagged AWS resources |
| 32 | Reconcile inventories; verify deployed resources via AWS service APIs |
| 33–35 | Deployment validation decision; render deployment summary; hash evidence |
| 38–43 | Install Prowler; run runtime scan; normalize findings; post-deployment risk score |
| 44–47 | Generate security review; AI remediation guidance; render review; upload evidence |
| 48–55 | Re-authenticate AWS; Terraform destroy; verify cleanup; generate cleanup evidence |
| 56–58 | Build dashboard export bundle; validate JSON; upload to S3 |

---

## Software & Hardware Requirements

### Hardware

| Requirement | Minimum |
|-------------|---------|
| RAM | 4 GB (for running the pipeline locally) |
| CPU | Any modern multi-core processor |
| Storage | 2 GB free (for cloned repos, reports, Terraform state, Prowler output) |
| Network | Internet access (GitHub, AWS, OpenAI APIs) |

### Software

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.11.x | Framework scripts |
| Terraform CLI | Latest (via `hashicorp/setup-terraform@v3`) | IaC plan/apply/destroy |
| Checkov | Latest | Static IaC security scan |
| Conftest | 0.56.0 | Policy-as-Code (Rego) enforcement |
| Prowler | 5.28.1 | Runtime AWS security scan |
| Git | 2.x+ | Repository cloning |
| AWS CLI | 2.x (optional locally) | AWS operations |
| jq | 1.6+ | JSON processing in shell steps |

### Platform

The pipeline is designed to run on **GitHub Actions** (`ubuntu-latest` runners). For local testing, a Linux or macOS environment is recommended. Windows is not tested.

---

## Programming Languages, Libraries & Frameworks

### Languages

| Language | Usage |
|----------|-------|
| Python 3.11 | All framework scripts (scanning, enrichment, risk scoring, deployment, review, export) |
| HCL (Terraform) | IaC target configurations (analysed, not written by this framework) |
| Rego | Policy-as-Code rules in `policies/` (enforced via Conftest) |
| YAML | GitHub Actions workflow definition |
| JSON | All evidence files and inter-stage data exchange |

### Python Libraries

| Library | Purpose |
|---------|---------|
| `openai >= 1.30.0` | AI-assisted finding enrichment and remediation guidance generation |
| `pyyaml >= 6.0` | YAML configuration parsing |
| `jsonschema >= 4.20.0` | JSON evidence schema validation |
| `boto3` | AWS SDK — resource discovery, tag filtering, service API verification |
| `prowler == 5.28.1` | Runtime cloud security scanning (imported as a Python package) |
| Python Standard Library | `uuid`, `hashlib`, `json`, `os`, `pathlib`, `datetime`, `argparse`, `sys`, `ast` |

### External Tools (installed separately)

| Tool | Installation |
|------|-------------|
| Checkov | `pip install checkov` |
| Conftest 0.56.0 | Downloaded from GitHub releases during CI |
| Terraform CLI | `hashicorp/setup-terraform@v3` GitHub Action |
| Prowler 5.28.1 | `pip install prowler==5.28.1` |

### CI/CD Platform

- **GitHub Actions** — workflow definition in `.github/workflows/iac-security.yml`
- **GitHub Artifacts** — inter-job evidence transfer and archive (7–30 day retention)
- **GitHub Actions Cache** — AI remediation cache persistence across runs (`cache/review/remediation-guidance.json`)
- **GitHub Environments** — `research-aws-deployment` environment used to scope OIDC credentials for the apply job

---

## Installation Procedure

### 1. Fork or Clone This Repository

```bash
git clone https://github.com/SajanaRajapaksha/iac-security-framework.git
cd iac-security-framework
```

### 2. Set Up Python Environment (for local development/testing)

```bash
python3.11 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

pip install --upgrade pip
pip install -r requirements.txt
pip install checkov
```

### 3. Install Optional Local Tools

**Conftest (0.56.0):**
```bash
CONFTEST_VERSION="0.56.0"
wget -qO - "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" \
  | tar xz -C /usr/local/bin conftest
```

**Terraform CLI:**
Follow the [official Terraform installation guide](https://developer.hashicorp.com/terraform/install).

**Prowler (5.28.1):**
```bash
pip install prowler==5.28.1
```

---

## Dependency Installation

All Python dependencies are specified in `requirements.txt`:

```bash
pip install -r requirements.txt
```

**Key Python packages installed:**

```
openai>=1.30.0      # AI remediation
pyyaml>=6.0         # YAML config
jsonschema>=4.20.0  # Evidence validation
boto3               # AWS SDK
prowler==5.28.1     # Runtime scan
checkov             # Static scan (installed separately)
```

---

## Configuration Requirements

### GitHub Repository Variables

Configure in **Repository Settings → Secrets and variables → Actions → Variables**:

| Variable | Required | Example | Purpose |
|----------|----------|---------|---------|
| `AWS_REGION` | Yes | `us-east-1` | AWS region for deployment and state |
| `AWS_ROLE_ARN` | Yes | `arn:aws:iam::123456789012:role/GitHubTerraformPlanRole` | OIDC role for the `terraform-plan` job |
| `AWS_APPLY_ROLE_ARN` | No | `arn:aws:iam::123456789012:role/GitHubTerraformDeployRole` | OIDC role for `terraform-apply`; falls back to `AWS_ROLE_ARN` |
| `TF_STATE_BUCKET` | Yes | `my-terraform-state-bucket` | S3 bucket for Terraform remote backend state |
| `OPENAI_MODEL` | No | `gpt-4.1-nano` | Model for finding enrichment (defaults to `gpt-4.1-nano`) |
| `OPENAI_REMEDIATION_MODEL` | No | `gpt-4o-mini` | Model for AI remediation (defaults to `gpt-4o-mini`) |
| `ENFORCE_RISK_GATE` | No | `false` | Set to `true` to block pipeline on high risk score |
| `STRICT_RISK_GATE` | No | `false` | Set to `true` for strict risk gate enforcement |

### GitHub Repository Secrets

Configure in **Repository Settings → Secrets and variables → Actions → Secrets**:

| Secret | Required | Purpose |
|--------|----------|---------|
| `OPENAI_API_KEY` | Yes (for AI features) | OpenAI API key for finding enrichment and remediation generation |

### GitHub Environment

The `terraform-apply` job requires a GitHub Environment named **`research-aws-deployment`**:

> **Repository Settings → Environments → New environment → Name: `research-aws-deployment`**

This environment scopes OIDC credential issuance and optionally supports required reviewers. For this research project, required reviewers are **not enforced** by default.

### AWS IAM OIDC Setup

The framework uses GitHub OIDC for AWS authentication (no static credentials). You must configure:

1. An **AWS IAM OIDC Identity Provider** for `token.actions.githubusercontent.com`
2. IAM roles with trust policies scoped to your repository and branch, e.g.:

```json
{
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/iac-security-framework:ref:refs/heads/dashboard"
    }
  }
}
```

Required IAM permissions for the plan role (minimum):
- `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket` — on the Terraform state bucket
- `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem` — if using DynamoDB state locking
- Resource-specific permissions matching what the scanned Terraform IaC creates

Required IAM permissions for the apply role (additional):
- All of the above, plus creation/deletion permissions for the resources described in the scanned Terraform

### S3 Buckets Required

| Bucket | Purpose |
|--------|---------|
| `TF_STATE_BUCKET` (configured via variable) | Terraform remote state, isolated per scan: `research/<SCAN_ID>/terraform.tfstate` |
| `iac-security-framework-evidence-172201861173-us-east-1` | Dashboard evidence export (raw JSON + dashboard bundle) |

### Terraform Backend

The framework automatically injects a minimal `iac_framework_backend.tf` into the target Terraform deployment root if no `backend` block exists. The backend is always S3. The bucket, key, and region are passed via `-backend-config` flags — **not hard-coded** in any file.

---

## Running the System

### Via GitHub Actions (Primary Method)

#### Option A: Automatic (Push to `dashboard` branch)

Push to the `dashboard` branch and the full pipeline runs automatically:

```bash
git push origin dashboard
```

#### Option B: Manual Dispatch (Scan any public repository)

1. Go to **Actions → IaC Security Framework → Run workflow**
2. Fill in the inputs:

| Input | Required | Description |
|-------|----------|-------------|
| `repo_url` | Yes | GitHub URL of the Terraform repository to scan |
| `branch` | No | Branch to scan (defaults to `main`) |
| `allow_research_exception` | Yes | `true` to permit intentionally insecure IaC (research only) |
| `research_exception_reason` | Conditional | Required when `allow_research_exception=true` |

Example scan targets for testing:
- `https://github.com/bridgecrewio/terragoat.git` — a deliberately insecure Terraform repository
- Any public Terraform repository

#### Option C: Running Local Scripts

Individual scripts can be run locally if `SCAN_ID`, `REPO_URL`, and `BRANCH` environment variables are set:

```bash
export SCAN_ID="SCAN-test0001"
export REPO_URL="https://github.com/example/my-terraform-repo.git"
export BRANCH="main"

python scripts/clone_repository.py
python scripts/generate_scan_metadata.py
python scripts/discover_terraform.py
python scripts/terraform_validate.py
python scripts/checkov_scan.py
python scripts/static_analysis_report.py
python scripts/risk/normalize_findings.py "$SCAN_ID"
python scripts/risk/calculate_predeployment_risk_score.py "$SCAN_ID"
```

> **Note:** AWS-dependent stages (Terraform plan/apply, Prowler, S3 export) require valid AWS credentials and configuration.

---

## Dashboard UI

The evidence export layer exports the following normalized JSON files to S3 after each pipeline run:

| File | Contents |
|------|----------|
| `dashboard/<SCAN_ID>/scan-summary.json` | High-level scan summary (scores, finding counts, deployment status, timestamps) |
| `dashboard/<SCAN_ID>/findings.json` | Normalized pre-deployment and post-deployment findings with remediation |
| `dashboard/<SCAN_ID>/evidence-manifest.json` | SHA-256 manifest of all evidence artefacts |

A companion Flask dashboard (`Dashboard_UI/`) provides a read-only visualization of this exported data.

Refer to the [Dashboard UI repository](https://github.com/SajanaRajapaksha/iac-security-framework/tree/dashboard) and its own `README.md` for setup instructions.

---

## Evidence & Artefacts

All evidence is stored under `reports/` during pipeline execution and uploaded as GitHub Artifacts:

```
reports/
├── static/<SCAN_ID>/          # Terraform validation, Checkov, policy results
├── risk/<SCAN_ID>/            # Normalized findings, enrichment, risk score
├── deployment/<SCAN_ID>/      # Plan evidence, apply evidence, state, inventories
├── runtime/<SCAN_ID>/         # Prowler raw output, normalized findings, risk score
└── review/<SCAN_ID>/          # Security review decision, AI remediation guidance
```

Every evidence file is:
- **Timestamped** in ISO-8601 UTC format
- **SHA-256 hashed** in manifests for integrity verification
- **Immutable** — no evidence file is modified after initial generation
- **Scoped** to the generating `SCAN_ID`

---

## Testing & Evaluation


### Evaluating the Risk Score

The pre-deployment risk score uses the formula:

```
D = total capped confirmed penalty / total resource count
U = unknown finding count / total resource count

score = round(1000 × exp(-((alpha × D) + (beta × U))))
```

Risk bands:

| Score Range | Band |
|-------------|------|
| 900–1000 | `VERY_LOW_RISK` |
| 700–899 | `LOW_RISK` |
| 500–699 | `MODERATE_RISK` |
| 300–499 | `HIGH_RISK` |
| 0–299 | `CRITICAL_RISK` |

The same formula is applied for post-deployment scoring using Prowler runtime findings.

### Evaluating the Security Review Decision

The security review compares pre- and post-deployment risk scores and applies these decision rules (in priority order):

| Rule | Decision |
|------|----------|
| Pre-deployment risk is CRITICAL_RISK | `CRITICAL_REMEDIATION` |
| Post-deployment score is CRITICAL_RISK | `CRITICAL_REMEDIATION` |
| Any post-deployment CRITICAL finding | `URGENT_REVIEW` |
| Post score < Pre score | `RUNTIME_RISK_INCREASED` |
| Post improved but HIGH/CRITICAL findings remain | `IMPROVED_WITH_REMEDIATION_REQUIRED` |
| Score 1000, no findings, Prowler clean | `RUNTIME_VALIDATION_PASSED` |
| Otherwise | `REVIEW_REQUIRED` |

---

## External Services & API Keys

| Service | Required | Purpose | Where to configure |
|---------|----------|---------|-------------------|
| **AWS** | Yes (for deployment stages) | Terraform plan/apply/destroy, Prowler scanning, S3 state and evidence | OIDC role ARNs in repository variables; no static keys |
| **OpenAI API** | Yes (for AI enrichment and remediation) | AI-assisted finding enrichment (Stage 13) and remediation guidance (Stage 45) | `OPENAI_API_KEY` secret in GitHub |
| **GitHub Actions** | Yes | CI/CD execution environment | Already available in the repository |

### OpenAI API Details

- **Finding Enrichment (Stage 13)**: Uses `OPENAI_MODEL` variable (default: `gpt-4.1-nano`) to contextually enrich findings with CIS mappings and risk context.
- **Remediation Generation (Stage 45)**: Uses `OPENAI_REMEDIATION_MODEL` variable (default: `gpt-4o-mini`) to generate structured remediation guidance per unique finding group.
- A **local cache** (`cache/review/remediation-guidance.json`) persists AI responses across pipeline runs using GitHub Actions Cache, keyed per branch, to avoid repeat API costs.
- If the API key is absent or the API call fails, the pipeline continues. AI enrichment and remediation stages are marked `continue-on-error: true`.

---

## Known Limitations

1. **Single Terraform root only**: The framework currently supports repositories with a single resolvable Terraform deployment root. Multiple module roots in the same repository are not yet supported.

2. **AWS only**: The framework is designed exclusively for AWS-based Terraform configurations. Other cloud providers (Azure, GCP) are not covered by the current Prowler integration or deployment controls.

3. **Python 3.11 required**: The framework targets Python 3.11.x specifically. `Path.walk()` (Python 3.12+) is intentionally avoided; `os.walk()` is used instead.

4. **Static analysis is non-blocking**: Checkov and policy violations are recorded as evidence but do not prevent pipeline progression (advisory mode). The risk gate can be configured to block the pipeline via `ENFORCE_RISK_GATE=true`.

5. **OpenAI API dependency**: AI enrichment and remediation quality depends on the selected OpenAI model and API availability. Scan proceeds without AI enrichment if the API is unavailable, but risk scoring accuracy may be reduced for unknown findings.

6. **Research scope**: This is an MSc research instrument. The deployment controls are designed for controlled research environments, not production. Required reviewer gates on the `research-aws-deployment` GitHub Environment are optional and not enforced by default.

7. **Prowler scan scope**: Prowler scans only AWS resources tagged with `scan-id=<SCAN_ID>` and `managed-by=iac-security-framework`. Resources deployed without these tags are outside the scan scope.

8. **Evidence S3 bucket**: The dashboard evidence export bucket name (`iac-security-framework-evidence-172201861173-us-east-1`) is currently hardcoded in the upload script. This requires matching IAM permissions and bucket existence.

9. **Trivy scanner**: Trivy scan integration exists (`scripts/trivy_scan.py`) but is not currently active in the main pipeline workflow.

10. **AI remediation matching**: AI remediation is matched to findings via a deterministic key (`stage|scanner|check_id|resource_type|title`). If a scanner changes its check title or ID format between pipeline runs, the cache key will not match and a new API call will be made.

---

## Documentation

- [`docs/controlled-deployment.md`](docs/controlled-deployment.md) — Full deployment architecture
- [`docs/workflow.md`](docs/workflow.md) — Pipeline stage reference

---

## License

See [LICENSE](LICENSE) for terms.

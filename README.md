# Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

> **MSc Research Project** | `iac-security-framework`

---

## Project Overview

This project designs and implements a **forensic-ready DevSecOps security framework** for Terraform-based AWS Infrastructure-as-Code (IaC). The framework accepts a **GitHub repository URL** as its primary input, dynamically clones and analyses the target repository, and produces a complete, cryptographically verifiable forensic audit trail.

The framework is **repository-agnostic** — it adapts to whatever Terraform structure exists inside the scanned repository. Every scan is assigned a unique **Scan ID** (`SCAN-<UUID-prefix>`) that propagates through every stage of the pipeline, creating an end-to-end traceable security assessment record.

---

## Research Objective

> **To design and evaluate an end-to-end forensic-ready security framework for cloud Infrastructure-as-Code that combines static analysis, Policy-as-Code validation, runtime cloud security validation, and automated risk scoring to produce a complete, tamper-evident forensic audit trail for every Terraform repository scan.**

### Key Research Questions

1. Can static IaC security tools (Checkov, Trivy, OPA) reliably detect misconfigurations before deployment?
2. What is the gap between static IaC analysis and actual runtime security posture?
3. How can infrastructure drift be detected and quantified across the deployment lifecycle?
4. What constitutes a forensically sound evidence package for cloud infrastructure deployment?
5. How effectively can a dynamic Terraform discovery engine handle real-world multi-module repository structures?

---

## Selected Tools

| Tool | Category | Role |
|---|---|---|
| **Terraform** | IaC | Infrastructure definition and deployment |
| **AWS** | Cloud Platform | Target deployment environment |
| **GitHub Actions** | CI/CD | Pipeline orchestration and automation |
| **Terraform CLI** | IaC Tooling | Validation: fmt, init, validate |
| **Checkov** | Static Analysis (Primary) | IaC misconfiguration scanning (1000+ checks) |
| **Trivy** | Static Analysis (Secondary) | IaC config scanning with severity classification |
| **Open Policy Agent (OPA)** | Policy Engine | Custom governance and security policy evaluation |
| **Rego** | Policy Language | Policy authoring for OPA/Conftest |
| **Conftest** | Policy CLI | OPA/Rego policy execution against Terraform |
| **Prowler** | Runtime Scanning | AWS live environment security validation |
| **Python** | Scripting | Cloning, discovery, normalization, risk scoring, evidence packaging |
| **JSON** | Data Format | Inter-stage data exchange and report storage |
| **GitHub Actions Artifacts** | Storage | Report and evidence archival per scan |

See [`docs/tools.md`](docs/tools.md) for detailed tool selection rationale.

---

## Planned Architecture

The framework implements a repository-driven, multi-layer security validation architecture:

```
┌─────────────────────────────────────────────────────────┐
│   INPUT LAYER                                           │
│   GitHub Repository URL → Scan ID → git clone          │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│   DISCOVERY LAYER                                       │
│   Recursive .tf discovery → Root module identification  │
│   SHA256 hashing → Scan metadata (root forensic anchor) │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│   GITHUB ACTIONS CI/CD PIPELINE                         │
│   Automated multi-stage security validation per scan    │
└────────┬──────────────────────────────┬─────────────────┘
         │                              │
┌────────▼──────────┐        ┌──────────▼────────────────┐
│  STATIC ANALYSIS  │        │  POLICY-AS-CODE           │
│  Terraform CLI    │        │  OPA / Rego / Conftest     │
│  Checkov (primary)│        │  terraform.rego            │
│  Trivy (secondary)│        │  aws-security.rego         │
└────────┬──────────┘        └──────────┬────────────────┘
         └─────────────┬────────────────┘
                       ▼
              Combined Evidence Report
              Enforcement Decision (PASS / FAIL)
                       │
              AWS Sandbox Deployment (future)
                       │
              Prowler Runtime Validation (future)
                       │
              Final Risk Scoring + Trust Score (future)
                       │
              Forensic Evidence Package (future)
                       │
              GitHub Actions Artifacts
              (all reports archived per scan_id)
```

See [`docs/architecture.md`](docs/architecture.md) for the full architecture explanation.

---

## Implemented Pipeline Flow

```
GitHub Repository URL input
        ↓
Generate Scan ID (SCAN-<UUID-prefix>)
        ↓
Clone repository → repositories/cloned/<scan_id>/
        ↓
Recursively discover Terraform files and root modules
        ↓
Calculate SHA256 hashes → Generate scan metadata
        ↓
Terraform validation (fmt, init, validate — per root module)
        ↓
Checkov static scan (primary — all .tf files)
        ↓
Checkov normalisation + local severity enrichment
        ↓
Trivy config scan (secondary — all .tf files)
        ↓
Trivy normalisation
        ↓
Combined static analysis evidence report
        ↓
Prepare policy validation input (non-blocking handoff)
        ↓
Terraform plan generation (init / plan / show -json)
        ↓
Policy-as-Code enforcement (Conftest / Rego)
  └── Policy snapshot + SHA256 hashing
  └── Conftest evaluation against Terraform plan JSON
  └── Forensic evidence + violation report
        ↓
Update combined report with policy results
        ↓
Upload all reports as GitHub Actions Artifacts
        ↓
Enforcement gate (deny violations → pipeline FAIL)
```

See [`docs/workflow.md`](docs/workflow.md) for the detailed stage-by-stage workflow.

---

## Repository-Based Scanning Architecture

The framework is designed around **GitHub repository URLs** — not pre-uploaded Terraform files.

### Why Repository-Based Scanning?

Real-world Terraform projects vary significantly in structure. The framework must handle:

| Repository Type | Example Structure |
|---|---|
| Simple flat | `main.tf`, `variables.tf`, `outputs.tf` |
| Multi-module | `modules/network/`, `environments/dev/` |
| Multi-environment | `infra/prod/`, `infra/staging/`, `infra/dev/` |
| Monorepo | `terraform/aws/`, `terraform/gcp/` |
| Deeply nested | `infra/prod/us-east-1/main.tf` |

The `discover_terraform.py` script recursively identifies all `.tf` files and classifies directories into root modules and child modules — regardless of how deeply nested or complex the repository structure is.

See [`docs/repository-scanning.md`](docs/repository-scanning.md) for full details.

---

## Forensic Readiness Concept

Every repository scan is treated as a **forensic investigation event**. The framework captures a complete, tamper-evident record of every scan.

### Core Forensic Properties

| Property | Implementation |
|---|---|
| **Unique Identification** | `SCAN-<UUID-prefix>` assigned to every scan |
| **Source Traceability** | Repository URL + commit SHA recorded at scan time |
| **File Integrity** | SHA256 hash of every `.tf` file at clone time |
| **Tamper Detection** | SHA256 integrity hash sealing the evidence package |
| **Complete Audit Trail** | Every pipeline stage contributes evidence |
| **Per-Scan Isolation** | All artifacts namespaced under scan_id |
| **Investigation Support** | Evidence package answers: what was scanned, when, by whom, what was found, what decision was made |

See [`docs/forensic-readiness.md`](docs/forensic-readiness.md) for the full forensic readiness explanation.

---

## Terraform Validation Module (Implemented ✅)

The Terraform validation module is the first fully implemented pipeline stage. It provides end-to-end repository cloning, file discovery, and Terraform validation with forensic metadata at every step.

### How It Works

1. **Input**: Provide a `repo_url` (any public GitHub repository containing Terraform) and an optional `branch` (default: `main`) via GitHub Actions `workflow_dispatch`.
2. **SCAN_ID generation**: The pipeline generates a unique `SCAN-<8-char-UUID>` identifier that tags every output.
3. **Repository cloning** (`clone_repository.py`): Clones the target repo and writes `repository-metadata.json`.
4. **Terraform file hashing** (`generate_scan_metadata.py`): Computes SHA256 hashes and `repository_integrity_hash`.
5. **Terraform directory discovery** (`discover_terraform.py`): Identifies all directories containing `.tf` files.
6. **Terraform validation** (`terraform_validate.py`): Runs `terraform fmt -check`, `terraform init -backend=false`, and `terraform validate` per directory.

---

## Checkov Static Security Scanning — Primary Scanner (Implemented ✅)

Checkov is the **primary static IaC scanner** in this framework. It evaluates 1,000+ built-in security and compliance checks targeting AWS Terraform resources.

### How It Works

1. **Checkov installation**: Installed via `pip install checkov` in the GitHub Actions workflow.
2. **Conditional execution**: Runs **only after Terraform validation succeeds**.
3. **Recursive scanning**: Scans `repositories/cloned/<SCAN_ID>/` covering all `.tf` files.
4. **Raw report**: Saved to `reports/static/<SCAN_ID>/checkov/checkov-results.json`.
5. **Finding normalisation** (`checkov_scan.py`): Failed checks are extracted and enriched.
6. **Evidence**: Saved to `reports/static/<SCAN_ID>/checkov/checkov-evidence.json`.

### Local Severity Mapping

Checkov often returns `null` severity. This framework uses a **local severity mapping file** (`config/severity_mapping.json`) to enrich findings:

**Severity priority:**
1. Native Checkov severity (if present and valid)
2. Local severity mapping (`config/severity_mapping.json`)
3. `UNKNOWN`

The mapping file assigns each Checkov check ID a severity, category, reason, and enforcement action based on a defined risk model:

| Severity | Definition |
|---|---|
| **CRITICAL** | Direct exposure that can immediately cause full compromise or major sensitive data exposure |
| **HIGH** | Public exposure, weak access control, missing protection on sensitive resources |
| **MEDIUM** | Security weakness that increases impact, reduces resilience, weakens monitoring |
| **LOW** | Hygiene, governance, lifecycle, non-immediate operational risk |
| **UNKNOWN** | No mapping exists |

### Normalized Findings Format

Each normalized finding includes:

| Field | Description |
|---|---|
| `scan_id` | Links the finding to the specific scan |
| `finding_id` | Unique UUID for the finding |
| `check_id` | Checkov check identifier (e.g., `CKV_AWS_21`) |
| `check_name` | Human-readable check description |
| `severity` | Resolved severity (native → mapping → UNKNOWN) |
| `severity_source` | Whether severity came from `checkov`, `mapping`, or `none` |
| `category` | From mapping (encryption, networking, storage_public_access, etc.) |
| `reason` | Explanation of why this severity was assigned |
| `enforcement` | FAIL, WARN, or INFO |
| `file_path` | Path to the affected Terraform file |
| `resource` | Terraform resource name |
| `terraform_file_sha256` | SHA256 hash of the source file |
| `finding_generated_at` | UTC ISO 8601 timestamp |

---

## Trivy Config Scanning — Secondary Scanner (Implemented ✅)

Trivy runs as a **secondary scanner** providing additional coverage. Its findings are normalised separately and do not control Checkov severity.

### How It Works

1. **Installation**: Via official Trivy APT repository in GitHub Actions.
2. **Execution**: `trivy config --format json --output <path> <target_dir>`
3. **Raw report**: `reports/static/<SCAN_ID>/trivy/trivy-results.json`
4. **Evidence**: `reports/static/<SCAN_ID>/trivy/trivy-evidence.json`

Each Trivy finding includes severity, rule ID, description, message, resource, file path, line numbers, and SHA-256 hash of the affected file.

---

## Combined Evidence Report (Implemented ✅)

After both scanners complete, a combined forensic evidence report aggregates all findings:

- **Path**: `reports/static/<SCAN_ID>/combined/static-analysis-evidence.json`
- Includes Terraform validation summary, Checkov findings, Trivy findings, merged severity summary, and scanner metadata.

---

## Non-Blocking Static Analysis Design (Implemented ✅)

Static analysis is an **evidence-collection and risk-classification stage**, not an enforcement gate. The pipeline continues regardless of findings.

### Key Behaviour

- Checkov and Trivy findings are collected and preserved.
- HIGH and CRITICAL findings are classified and recorded.
- The pipeline **does not stop** because of security findings.
- A `policy-validation-input.json` file is generated for the future policy validation model.
- A `static-analysis-handoff.json` records that static analysis completed and handed off findings.
- The `enforce_static_policy.py` script is retained for future optional blocking mode but is **not called** in the current workflow.

### Risk Classification

| Condition | `static_risk_status` | `pipeline_action` | Exit Code |
|---|---|---|---|
| HIGH or CRITICAL findings present | `HIGH_RISK_FINDINGS_DETECTED` | `CONTINUE_TO_POLICY_VALIDATION` | 0 |
| No HIGH or CRITICAL findings | `NO_HIGH_RISK_FINDINGS` | `CONTINUE_TO_POLICY_VALIDATION` | 0 |
| Evidence file missing | `EVIDENCE_MISSING` | `CONTINUE` | 0 |
| Missing SCAN_ID | — | — | 1 |

### Policy Validation Handoff

The `policy-validation-input.json` file contains:
- All normalised findings from Checkov and Trivy
- Severity summary and risk classification
- `policy_validation_status: "PENDING"` on every finding
- `policy_validation_implemented: false` flag
- Forensic metadata (SCAN_ID, timestamps, repository context)

The `policy-validation-input.json` was designed as a future handoff file. With the Policy-as-Code Engine now implemented, findings flow directly from the combined evidence into the Conftest evaluation.

---

## Policy-as-Code Engine (Implemented ✅)

The Policy-as-Code Engine evaluates Terraform plan JSON against custom Rego security and compliance policies using Conftest (which uses OPA internally).

### How It Works

1. **Terraform plan generation** (`terraform_plan.py`): Runs `terraform init / plan / show -json` against the cloned repo. Saves plan JSON and command metadata.
2. **Policy metadata** (`policy-metadata.json`): Registry of 7 custom policies with version, severity, compliance mapping, and enabled/disabled status.
3. **Policy snapshot**: Enabled policy files are copied to `reports/policy/<SCAN_ID>/runtime-policies/` and SHA256-hashed per scan.
4. **Conftest execution**: `conftest test <plan.json> --policy <runtime-policies> --output json`
5. **Evidence generation** (`policy_runner.py`): Normalises Conftest output into `policy-evidence.json` with full forensic metadata.

### Custom Policies

| Policy ID | File | Name | Severity |
|---|---|---|---|
| `CUSTOM_AWS_001` | `aws_security.rego` | Block public SSH ingress | HIGH |
| `CUSTOM_AWS_002` | `aws_security.rego` | Block public RDP ingress | HIGH |
| `CUSTOM_AWS_003` | `aws_security.rego` | Block public S3 ACL | CRITICAL |
| `CUSTOM_AWS_004` | `aws_security.rego` | Prevent S3 encryption removal | CRITICAL |
| `CUSTOM_TAG_001` | `tagging.rego` | Require Environment tag | LOW |
| `CUSTOM_TAG_002` | `tagging.rego` | Require Owner tag | LOW |
| `CUSTOM_IAM_001` | `compliance.rego` | Block IAM wildcard admin | CRITICAL |

### Enforcement Behaviour

| Condition | Status | Decision | Exit Code |
|---|---|---|---|
| No policy violations | `PASS` | `ALLOW` | 0 |
| Deny violations found | `FAIL` | `DENY` | 1 |
| Tool execution error | `ERROR` | `ERROR` | 1 |

### Forensic Evidence

Each policy evaluation generates:
- `terraform-plan.json` — the exact plan that was evaluated
- `terraform-plan-metadata.json` — all terraform commands with timestamps, exit codes, stdout/stderr
- `conftest-results.json` — raw Conftest output
- `policy-evidence.json` — normalised evidence with policy snapshot, violation details, severity counts, and input hashes
- `runtime-policies/` — exact Rego files used for this specific scan (immutable snapshot)


## Report Structure

```
reports/static/<SCAN_ID>/
├── terraform-validation/
│   └── terraform-validation.json
├── checkov/
│   ├── checkov-results.json              (raw Checkov output)
│   └── checkov-evidence.json             (normalized + enriched findings)
├── trivy/
│   ├── trivy-results.json                (raw Trivy output)
│   └── trivy-evidence.json               (normalized findings)
└── combined/
    ├── static-analysis-evidence.json     (combined forensic report + policy section)
    ├── policy-validation-input.json      (input for policy model)
    └── static-analysis-handoff.json      (stage transition record)

reports/policy/<SCAN_ID>/
├── terraform-plan.json                  (Terraform plan JSON)
├── terraform-plan-metadata.json          (plan generation forensic metadata)
├── conftest-results.json                 (raw Conftest output)
├── policy-evidence.json                  (normalized policy evidence)
└── runtime-policies/                     (scan-specific policy snapshot)
    ├── aws_security.rego
    ├── tagging.rego
    └── compliance.rego
```

---

## Running Locally

### Prerequisites

- Python 3.11+
- Terraform CLI
- Checkov: `pip install checkov`
- Trivy: [Installation guide](https://aquasecurity.github.io/trivy/)
- Conftest: [Installation guide](https://www.conftest.dev/install/)

### Running Individual Scripts

```bash
# Set environment variables
export SCAN_ID="SCAN-test1234"
export REPO_URL="https://github.com/user/repo.git"
export BRANCH="main"

# Run static analysis stages
python scripts/clone_repository.py
python scripts/generate_scan_metadata.py
python scripts/discover_terraform.py
python scripts/terraform_validate.py
python scripts/checkov_scan.py
python scripts/trivy_scan.py
python scripts/static_analysis_report.py
python scripts/prepare_policy_validation_input.py

# Run Policy-as-Code stages
python scripts/terraform_plan.py
python scripts/policy_runner.py

# Regenerate combined report (includes policy results)
python scripts/static_analysis_report.py
```

### Direct Conftest debugging

```bash
# Run Conftest directly against a plan JSON
conftest test reports/policy/$SCAN_ID/terraform-plan.json --policy policies/terraform --output json
```

### Running via GitHub Actions

1. Go to **Actions** → **IaC Security Framework** → **Run workflow**
2. Enter a public GitHub repository URL containing Terraform files
3. Optionally set the branch (default: `main`)
4. Click **Run workflow**

---

## Folder Structure

```
iac-security-framework/
├── .github/
│   └── workflows/
│       └── iac-security.yml             # GitHub Actions pipeline
│
├── config/
│   └── severity_mapping.json            # Local Checkov severity mapping
│
├── repositories/
│   ├── cloned/                          # Cloned repos per scan_id
│   └── metadata/                        # Scan metadata per scan_id
│
├── policies/
│   ├── terraform/                       # Active Rego policies
│   │   ├── aws_security.rego            # SSH/RDP/S3 ACL/encryption ✅
│   │   ├── tagging.rego                 # Environment + Owner tags ✅
│   │   ├── compliance.rego              # IAM wildcard admin ✅
│   │   └── policy-metadata.json         # Policy registry (7 policies) ✅
│   ├── terraform.rego                   # Legacy placeholder (Phase 1)
│   └── aws-security.rego               # Legacy placeholder (Phase 1)
│
├── scripts/
│   ├── utils/
│   │   ├── __init__.py
│   │   └── evidence.py                  # Shared forensic utilities
│   ├── clone_repository.py             # Clone repo
│   ├── generate_scan_metadata.py       # SHA256 hashing + integrity hash
│   ├── discover_terraform.py           # Recursive .tf discovery
│   ├── terraform_validate.py           # terraform fmt / init / validate
│   ├── checkov_scan.py                 # Checkov scan + normalisation ✅
│   ├── trivy_scan.py                   # Trivy config scan + normalisation ✅
│   ├── static_analysis_report.py       # Combined evidence report ✅
│   ├── prepare_policy_validation_input.py  # Policy handoff (non-blocking) ✅
│   ├── terraform_plan.py               # Terraform plan JSON generation ✅
│   ├── policy_runner.py                # Policy-as-Code runner (Conftest) ✅
│   ├── enforce_static_policy.py        # Enforcement decision (future blocking mode)
│   ├── normalize_checkov.py            # Legacy normaliser (superseded)
│   ├── checkov_forensic_summary.py     # Legacy summary (superseded)
│   ├── normalize_prowler.py            # Prowler normalisation (placeholder)
│   ├── risk_score.py                   # Static risk scoring (placeholder)
│   ├── runtime_risk_score.py           # Final risk scoring (placeholder)
│   └── forensic_log.py                 # Forensic evidence packaging (placeholder)
│
├── reports/
│   ├── static/<scan_id>/               # Per-scan static reports
│   ├── policy/<scan_id>/               # Per-scan policy reports ✅
│   ├── runtime/<scan_id>/              # Per-scan runtime reports (future)
│   └── final/<scan_id>/                # Per-scan final reports (future)
│
├── evidence/
│   └── <scan_id>/                      # SHA256-sealed forensic evidence (future)
│
├── docs/                               # Documentation
├── requirements.txt                    # Python dependencies
├── README.md                           # This file
└── .gitignore                          # Git ignore rules
```

---

## Future Roadmap

### Phase 1 — Project Scaffolding ✅
- Initial folder and file structure
- Placeholder files with detailed comments
- Documentation foundation

### Phase 2 — Terraform Validation Module ✅
- `clone_repository.py` — Repository cloning with scan_id isolation
- `generate_scan_metadata.py` — Scan metadata with SHA256 hashing + repository integrity hash
- `discover_terraform.py` — Recursive Terraform directory discovery
- `terraform_validate.py` — terraform fmt/init/validate per directory
- GitHub Actions workflow — end-to-end pipeline with artifact upload

### Phase 3 — Static Analysis Pipeline ✅
- **Checkov** as primary scanner with local severity mapping enrichment
- **Trivy config** as secondary scanner
- `config/severity_mapping.json` — local Checkov severity mapping
- `scripts/utils/evidence.py` — shared forensic utilities
- `scripts/checkov_scan.py` — Checkov scan + normalisation + evidence
- `scripts/trivy_scan.py` — Trivy scan + normalisation + evidence
- `scripts/static_analysis_report.py` — combined forensic evidence report
- `scripts/prepare_policy_validation_input.py` — non-blocking policy handoff
- Non-blocking pipeline design — findings preserved, pipeline continues

### Phase 4 — Policy-as-Code Engine ✅
- **Conftest** as the policy runner (OPA/Rego internally)
- `policies/terraform/aws_security.rego` — SSH/RDP ingress, S3 ACL, S3 encryption
- `policies/terraform/tagging.rego` — Environment + Owner tag enforcement
- `policies/terraform/compliance.rego` — IAM wildcard admin detection
- `policies/terraform/policy-metadata.json` — 7 policies with version, severity, compliance
- `scripts/terraform_plan.py` — safe plan generation (init/plan/show -json)
- `scripts/policy_runner.py` — full forensic-ready policy evaluation
- Per-scan policy snapshots with SHA256 hashing
- Enforcement gate — deny violations fail the pipeline

### Phase 5 — AWS Sandbox Integration
- Sandbox AWS account configuration
- Terraform deployment automation
- Prowler runtime validation integration

### Phase 6 — Frontend Dashboard *(Future)*
### Phase 7 — Backend API *(Future)*

---

## Documentation

| Document | Description |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | System architecture — all layers explained |
| [`docs/workflow.md`](docs/workflow.md) | Detailed pipeline workflow |
| [`docs/forensic-readiness.md`](docs/forensic-readiness.md) | Forensic readiness principles and evidence chain |
| [`docs/repository-scanning.md`](docs/repository-scanning.md) | Repository scanning, Terraform discovery, scan isolation |
| [`docs/runtime-validation.md`](docs/runtime-validation.md) | Runtime validation rationale and drift detection |
| [`docs/tools.md`](docs/tools.md) | Tool selection rationale and roles |

---

*MSc Research Project — Designed for academic research in cloud security and digital forensics.*

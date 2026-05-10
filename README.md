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

1. Can static IaC security tools (Checkov, OPA) reliably detect misconfigurations before deployment?
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
| **Terraform CLI** | IaC Tooling | Validation: fmt, init, validate, apply |
| **Checkov** | Static Analysis | IaC misconfiguration scanning (1000+ checks) |
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
│  Checkov          │        │  terraform.rego            │
│  (multi-module)   │        │  aws-security.rego         │
└────────┬──────────┘        └──────────┬────────────────┘
         └─────────────┬────────────────┘
                       ▼
              Initial Risk Scoring
              ALLOW / REVIEW / BLOCK
                       │
              AWS Sandbox Deployment
              (resources tagged with scan_id)
                       │
              Prowler Runtime Validation
              (targets scan_id-tagged resources)
                       │
              Final Risk Scoring + Trust Score
                       │
              Forensic Evidence Package
              (SHA256 sealed, per scan_id)
                       │
              GitHub Actions Artifacts
              (all reports archived per scan_id)
                       │
              Future: Centralized Dashboard
```

See [`docs/architecture.md`](docs/architecture.md) for the full architecture explanation.

---

## Planned Pipeline Flow

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
Static IaC misconfiguration scanning (Checkov — all .tf files)
        ↓
Policy-as-Code validation (OPA/Rego + Conftest — per root module)
        ↓
Initial risk score calculation → ALLOW / REVIEW / BLOCK
        ↓
Deploy infrastructure to AWS sandbox (resources tagged with scan_id)
        ↓
Runtime cloud security validation (Prowler — targets scan_id resources)
        ↓
Normalize runtime findings
        ↓
Final risk score + Deployment Trust Score
        ↓
Generate forensic evidence package (SHA256 sealed)
        ↓
Store reports and evidence under reports/<scan_id>/ and evidence/<scan_id>/
        ↓
Upload as GitHub Actions Artifacts (tagged with scan_id)
        ↓
Future: Centralized dashboard visualization
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

### Dynamic Terraform Discovery

```
git clone <repository_url> repositories/cloned/<scan_id>/
        ↓
discover_terraform.py
  - Walk all directories recursively
  - Collect all .tf files
  - Identify root modules (containing main.tf or resource definitions)
  - Identify child modules (referenced as sources)
        ↓
terraform-discovery.json:
  {
    "root_modules": [".", "environments/dev", "environments/prod"],
    "child_modules": ["modules/network", "modules/security"],
    "all_tf_files": [...],
    "total_tf_files": 12
  }
```

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

## Runtime Validation Concept

Static analysis validates the **intent** expressed in Terraform code. Runtime validation confirms the **actual deployed state**. The gap between them — infrastructure drift — is a core research focus.

| Validation Type | What It Catches |
|---|---|
| **Static (Checkov)** | Misconfigurations in Terraform code before deployment |
| **Static (OPA/Rego)** | Policy violations in infrastructure code |
| **Runtime (Prowler)** | Actual misconfigurations in the live AWS environment |
| **Drift Detection** | Differences between code intent and deployed reality |

See [`docs/runtime-validation.md`](docs/runtime-validation.md) for the full explanation.

---

## Terraform Validation Module (Implemented ✅)

The Terraform validation module is the first fully implemented pipeline stage. It provides end-to-end repository cloning, file discovery, and Terraform validation with forensic metadata at every step.

### How It Works

1. **Input**: Provide a `repo_url` (any public GitHub repository containing Terraform) and an optional `branch` (default: `main`) via GitHub Actions `workflow_dispatch`.

2. **SCAN_ID generation**: The pipeline generates a unique `SCAN-<8-char-UUID>` identifier that tags every output.

3. **Repository cloning** (`clone_repository.py`): Clones the target repo into `repositories/cloned/<SCAN_ID>/` and writes `repository-metadata.json` with clone status, timestamps, stdout/stderr.

4. **Terraform file hashing** (`generate_scan_metadata.py`): Walks the cloned directory, finds all `.tf` files (skipping `.git/`, `.terraform/`, `node_modules/`), computes SHA256 hashes, computes a composite `repository_integrity_hash`, and writes `scan-metadata.json`.

5. **Terraform directory discovery** (`discover_terraform.py`): Identifies all directories containing `.tf` files and writes `terraform-directories.json`.

6. **Terraform validation** (`terraform_validate.py`): For each discovered directory, runs `terraform fmt -check -recursive`, `terraform init -backend=false`, and `terraform validate`. Captures command output, exit codes, and timestamps. Writes `terraform-validation.json` to `reports/static/<SCAN_ID>/`.

---

## Checkov Static Security Scanning (Implemented ✅)

The Checkov module provides automated static security analysis of all Terraform files in the scanned repository. It runs **after** Terraform validation succeeds and produces forensic-ready security findings.

### What Checkov Does

- **Recursive Terraform scanning**: Checkov scans the entire cloned repository (`repositories/cloned/<SCAN_ID>/`) recursively, covering all Terraform directories and modules in a single pass.
- **AWS IaC misconfiguration detection**: Checkov evaluates 1,000+ built-in security and compliance checks targeting AWS resources — including S3 encryption, security group rules, IAM policies, CloudTrail logging, VPC configurations, and more.
- **JSON output**: Raw scan results are exported as structured JSON for downstream processing.

### How It Works

1. **Checkov installation**: Installed via `pip install checkov` in the GitHub Actions workflow.
2. **Conditional execution**: Checkov runs **only after Terraform validation succeeds**. If validation fails, Checkov is skipped but validation reports are still uploaded.
3. **Recursive scanning**: Checkov scans `repositories/cloned/<SCAN_ID>/` recursively, covering all `.tf` files.
4. **Raw report generation**: The raw Checkov JSON output is saved to `reports/static/<SCAN_ID>/checkov-report.json`.
5. **Finding normalization** (`normalize_checkov.py`): Failed checks are extracted, normalized into a structured format, and correlated with Terraform file SHA256 hashes.
6. **Forensic summary** (`checkov_forensic_summary.py`): A comprehensive forensic summary links all Checkov evidence through the SCAN_ID.

### Normalized Findings Format

Each normalized finding includes:

| Field | Description |
|---|---|
| `scan_id` | Links the finding to the specific scan |
| `finding_id` | Unique UUID for the finding |
| `check_id` | Checkov check identifier (e.g., `CKV_AWS_21`) |
| `check_name` | Human-readable check description |
| `severity` | CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN |
| `file_path` | Path to the affected Terraform file |
| `resource` | Terraform resource name |
| `category` | Inferred category (encryption, networking, iam, etc.) |
| `terraform_file_sha256` | SHA256 hash of the source Terraform file |
| `finding_generated_at` | UTC timestamp of finding generation |

### SCAN_ID Linkage

Every Checkov output is tagged with the same `SCAN_ID` used across the entire pipeline. This enables full traceability from repository cloning → file hashing → Terraform validation → Checkov scanning → forensic summary.

### Terraform File Hashing

Normalized findings are correlated with Terraform file hashes from `scan-metadata.json`. Each finding includes the `terraform_file_sha256` of its source file, enabling tamper detection and evidence integrity verification.

### Generated Reports

| File | Location |
|---|---|
| `repository-metadata.json` | `repositories/metadata/<SCAN_ID>/` |
| `scan-metadata.json` | `repositories/metadata/<SCAN_ID>/` |
| `terraform-directories.json` | `repositories/metadata/<SCAN_ID>/` |
| `terraform-validation.json` | `reports/static/<SCAN_ID>/` |
| `checkov-report.json` | `reports/static/<SCAN_ID>/` |
| `normalized-checkov-findings.json` | `reports/static/<SCAN_ID>/` |
| `checkov-forensic-summary.json` | `reports/static/<SCAN_ID>/` |

All reports are uploaded as GitHub Actions Artifacts (even if Checkov finds issues) and tagged with SCAN_ID.

### Running the Workflow

1. Go to **Actions** → **IaC Security Framework** → **Run workflow**
2. Enter a public GitHub repository URL containing Terraform files
3. Optionally set the branch (default: `main`)
4. Click **Run workflow**

The workflow also runs on push/PR to `main`, scanning the framework repository itself.

---

## Folder Structure

```
iac-security-framework/
├── .github/
│   └── workflows/
│       └── iac-security.yml        # GitHub Actions pipeline (repository URL input)
│
├── repositories/
│   ├── cloned/                     # Cloned repos — one subdirectory per scan_id
│   └── metadata/                   # Scan metadata JSON — one file per scan_id
│
├── policies/
│   ├── terraform.rego              # Terraform governance policies (OPA/Rego)
│   └── aws-security.rego           # AWS security policies (OPA/Rego)
│
├── scripts/
│   ├── clone_repository.py         # Clone repo → repositories/cloned/<scan_id>/
│   ├── generate_scan_metadata.py   # SHA256 hashing + scan metadata + integrity hash
│   ├── discover_terraform.py       # Recursive .tf directory discovery
│   ├── terraform_validate.py       # terraform fmt / init / validate per directory
│   ├── normalize_checkov.py        # Checkov output normalization ✅
│   ├── checkov_forensic_summary.py # Checkov forensic summary generation ✅
│   ├── normalize_prowler.py        # Prowler output normalization (placeholder)
│   ├── risk_score.py               # Static risk scoring (placeholder)
│   ├── runtime_risk_score.py       # Final risk scoring (placeholder)
│   └── forensic_log.py             # Forensic evidence packaging (placeholder)
│
├── reports/
│   ├── static/<scan_id>/           # Checkov, OPA, static risk score — per scan
│   ├── runtime/<scan_id>/          # Prowler, runtime risk score — per scan
│   └── final/<scan_id>/            # Final risk score, decision, summary — per scan
│
├── evidence/
│   └── <scan_id>/                  # SHA256-sealed forensic evidence package — per scan
│
├── runtime-validation/
│   ├── prowler/                    # Prowler configuration and integration
│   └── sandbox/                    # AWS sandbox deployment configuration
│
├── docs/
│   ├── architecture.md             # System architecture overview
│   ├── workflow.md                 # Pipeline workflow (all 12 stages)
│   ├── forensic-readiness.md       # Forensic readiness principles
│   ├── repository-scanning.md      # Repository scanning, discovery, isolation model
│   ├── runtime-validation.md       # Runtime validation rationale
│   └── tools.md                    # Tool selection and roles
│
├── requirements.txt                # Python dependencies
├── README.md                       # This file
└── .gitignore                      # Git ignore rules
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

### Phase 3 (Current) — Checkov Static Security Scanning ✅
- Checkov installation and version output in GitHub Actions
- Recursive Checkov scanning of cloned repositories
- Raw JSON report generation (`checkov-report.json`)
- `normalize_checkov.py` — Forensic-ready finding normalization with file hash correlation
- `checkov_forensic_summary.py` — Comprehensive forensic summary generation
- Conditional execution (runs only after Terraform validation succeeds)
- Artifact upload with SCAN_ID tagging

### Phase 4 — Further Security Scanning
- `normalize_prowler.py` — Prowler output normalization
- `risk_score.py` — Static risk scoring engine
- `runtime_risk_score.py` — Final combined risk scoring
- `forensic_log.py` — Forensic evidence package generation

### Phase 5 — Policy Implementation
- `terraform.rego` — Terraform governance policies
- `aws-security.rego` — AWS security policies

### Phase 6 — AWS Sandbox Integration
- Sandbox AWS account configuration
- Terraform deployment automation
- Prowler runtime validation integration

### Phase 7 — Frontend Dashboard *(Future)*
- Repository URL submission form
- Pipeline status and stage visualization
- Risk score trends and scan history
- Evidence package viewer

### Phase 8 — Backend API *(Future)*
- Scan submission API
- Report retrieval API
- Evidence package API
- Dashboard data API

---

## Documentation

| Document | Description |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | System architecture — all layers explained |
| [`docs/workflow.md`](docs/workflow.md) | Detailed 12-stage pipeline workflow |
| [`docs/forensic-readiness.md`](docs/forensic-readiness.md) | Forensic readiness principles and evidence chain |
| [`docs/repository-scanning.md`](docs/repository-scanning.md) | Repository scanning, Terraform discovery, scan isolation |
| [`docs/runtime-validation.md`](docs/runtime-validation.md) | Runtime validation rationale and drift detection |
| [`docs/tools.md`](docs/tools.md) | Tool selection rationale and roles |

---

*MSc Research Project — Designed for academic research in cloud security and digital forensics.*

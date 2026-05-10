# Repository Scanning

## Project: Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

---

## 1. Overview

The framework operates on **GitHub repository URLs** as its primary input. Rather than accepting pre-uploaded Terraform files, the pipeline clones the target repository dynamically, discovers its Terraform structure, and applies all security analysis against the discovered content.

This design makes the framework **repository-agnostic** — it can handle any Terraform project structure without modification to the framework itself.

---

## 2. Why Repository-Based Scanning?

### 2.1 Arbitrary Terraform Structures

Real-world Terraform repositories do not follow a single predictable layout. Projects may use:
- Flat single-module layouts
- Multi-module structures with `modules/` directories
- Multi-environment layouts (`environments/dev/`, `environments/prod/`)
- Terraform monorepos containing infrastructure for multiple cloud providers
- Complex nested directory structures

Requiring users to conform to a specific structure would:
- Limit the framework's applicability
- Create friction for adoption
- Fail to represent real-world IaC diversity

### 2.2 Forensic Traceability to Source

Using a repository URL as input provides:
- **Commit-level traceability**: The exact git commit SHA is recorded at scan time
- **Branch context**: The specific branch being scanned is documented
- **Provenance**: The complete lineage from source repository to deployment decision is preserved

This is essential for forensic readiness — investigators can trace a finding directly back to the specific line in the specific commit of the specific repository that produced it.

---

## 3. Scan Isolation Model

Every repository scan runs in complete isolation via a unique **Scan ID**.

### 3.1 Scan ID Format

```
SCAN-<8-character-UUID-prefix>
Examples: SCAN-550e8400, SCAN-a1b2c3d4, SCAN-ff001122
```

### 3.2 Isolation Scope

The Scan ID creates a dedicated namespace for every artifact produced by the scan:

| Artifact Category | Path |
|---|---|
| Cloned repository | `repositories/cloned/<SCAN_ID>/` |
| Repository metadata | `repositories/metadata/<SCAN_ID>/repository-metadata.json` |
| Scan metadata (hashes) | `repositories/metadata/<SCAN_ID>/scan-metadata.json` |
| Terraform discovery | `repositories/metadata/<SCAN_ID>/terraform-directories.json` |
| Static reports | `reports/static/<SCAN_ID>/` |
| Runtime reports | `reports/runtime/<SCAN_ID>/` (planned) |
| Final reports | `reports/final/<SCAN_ID>/` (planned) |
| Forensic evidence | `evidence/<SCAN_ID>/` (planned) |

### 3.3 Multi-Scan Support

The isolation model enables:

- **Concurrent scans**: Multiple repositories can be scanned simultaneously without interference
- **Repeat scanning**: The same repository can be scanned multiple times (different branches, commits, or time periods) — each receives a unique Scan ID
- **Scan history**: Historical scan results are preserved independently per Scan ID
- **Comparative analysis** (future): Results from multiple scans of the same repository can be compared to track security posture over time

---

## 4. Recursive Terraform Discovery

### 4.1 The Discovery Problem

After cloning a repository, the framework must determine **where Terraform code exists** and **which directories are root modules** suitable for `terraform init / plan / validate`.

This is non-trivial because:
- `.tf` files can exist at any depth in the directory tree
- Not every directory containing `.tf` files is a root module
- Some directories are child modules, called by parent modules
- Some repositories mix Terraform with other code

### 4.2 Discovery Algorithm (✅ Implemented — `discover_terraform.py`)

**Step 1 — Find all `.tf` files:**
```
Walk the entire cloned repository directory recursively.
Collect every file with a .tf extension.
Exclude: .terraform/, .git/, node_modules/, .terragrunt-cache/
```

**Step 2 — Identify root module directories:**
```
A directory is a candidate root module if:
  - It contains a main.tf file  (strong indicator)
  - OR it contains at least one .tf file defining resources or outputs
  - AND it is not referenced as a module source by a parent directory
```

**Step 3 — Classify all directories:**
```
root_modules    → directories to run terraform init/validate/plan against
child_modules   → directories referenced as sources by root modules
loose_tf_files  → .tf files not clearly belonging to any module
```

### 4.3 Supported Repository Structures

The discovery engine is designed to handle all of the following:

**Example 1 — Simple flat layout:**
```
main.tf
variables.tf
outputs.tf
```
→ Root module: `.` (repository root)

**Example 2 — Multi-module structure:**
```
modules/
  network/
    main.tf
    variables.tf
  security/
    main.tf
environments/
  dev/
    main.tf
    variables.tf
  prod/
    main.tf
```
→ Root modules: `environments/dev`, `environments/prod`
→ Child modules: `modules/network`, `modules/security`

**Example 3 — Multi-cloud monorepo:**
```
terraform/
  aws/
    main.tf
    variables.tf
  gcp/
    main.tf
```
→ Root modules: `terraform/aws`, `terraform/gcp`

**Example 4 — Deeply nested environments:**
```
infra/
  prod/
    us-east-1/
      main.tf
    eu-west-1/
      main.tf
  staging/
    eu-west-1/
      main.tf
```
→ Root modules: `infra/prod/us-east-1`, `infra/prod/eu-west-1`, `infra/staging/eu-west-1`

### 4.4 Discovery Output

`discover_terraform.py` produces a structured discovery report saved to:
`repositories/metadata/<SCAN_ID>/terraform-directories.json`

```json
{
  "scan_id":              "SCAN-550e8400",
  "generated_at":         "2025-01-01T12:00:00+00:00",
  "total_directories":    3,
  "terraform_directories": [
    {
      "path": "/abs/path/to/root",
      "relative_path": ".",
      "tf_file_count": 3,
      "tf_files": ["main.tf", "outputs.tf", "variables.tf"]
    },
    {
      "path": "/abs/path/to/environments/dev",
      "relative_path": "environments/dev",
      "tf_file_count": 2,
      "tf_files": ["main.tf", "variables.tf"]
    }
  ]
}
```

---

## 5. Scanning Each Discovered Module

After discovery, the pipeline processes each identified root module independently:

| Operation | Tool | Scope |
|---|---|---|
| Format check | `terraform fmt -check` | Per root module |
| Initialisation | `terraform init` | Per root module |
| Validation | `terraform validate` | Per root module |
| Static scanning | Checkov | Entire cloned directory (recursive) |
| Policy validation | Conftest + OPA | Per root module plan output |

Checkov natively supports recursive directory scanning, so it processes the entire cloned repository in a single run and reports findings per file path.

All findings are tagged with both the `scan_id` and the relative module path:

```json
{
  "scan_id":      "SCAN-550e8400",
  "module_path":  "environments/dev",
  "check_id":     "CKV_AWS_19",
  "resource":     "aws_s3_bucket.data",
  "severity":     "HIGH"
}
```

---

## 6. Repository Cloning Details

### 6.1 Clone Command (✅ Implemented)

```bash
git clone --depth 1 \
    --branch <branch> \
    <repository_url> \
    repositories/cloned/<scan_id>/
```

- `--depth 1`: Shallow clone — only the latest commit (reduces bandwidth and storage)
- `--branch <branch>`: Target specific branch (default: main/master)
- Commit SHA is recorded via `git rev-parse HEAD` after cloning

### 6.2 Supported Repository Types (Planned)

| Repository Type | Support Status |
|---|---|
| Public GitHub repositories | ✅ Implemented |
| Private GitHub repositories (with token) | 🔮 Future |
| GitHub Enterprise | 🔮 Future |
| GitLab repositories | 🔮 Future |
| Bitbucket repositories | 🔮 Future |
| Generic Git repositories | 🔮 Future |

### 6.3 Clone Failure Handling

The pipeline must handle:
- Invalid or unreachable repository URLs
- Authentication failures (private repositories)
- Network timeouts
- Repositories with no `.tf` files (valid scan result: "No Terraform content found")

All failure cases are recorded in the scan metadata and forensic evidence package.

---

## 7. Scan History and Auditability

Every scan creates a permanent, isolated record. This enables:

- **Audit queries**: "Show all scans of `github.com/org/infra` from the last 30 days"
- **Regression tracking**: "Did this repository's security posture improve between scan SCAN-abc and SCAN-def?"
- **Incident investigation**: "What was the exact state of the repository when it was scanned before the incident?"
- **Compliance evidence**: "Provide evidence that this repository was scanned before production deployment"

The combination of `repository_url + commit_sha + scan_id + forensic evidence package` provides a complete, tamper-evident record of the security assessment for any repository at any point in time.

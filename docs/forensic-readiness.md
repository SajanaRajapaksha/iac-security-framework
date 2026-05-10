# Forensic Readiness

## Project: Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

---

## 1. What is Forensic Readiness?

**Forensic readiness** is the proactive preparation of an organisation's systems, processes, and documentation to support digital forensic investigations before an incident occurs. It ensures that when a security incident, audit, or legal review takes place, sufficient, authentic, and admissible digital evidence is already available.

In the context of this framework, forensic readiness means that **every Terraform infrastructure deployment attempt is treated as a potential subject of future investigation** — and that comprehensive, verifiable evidence is captured at every stage of the pipeline.

---

## 2. Core Forensic Readiness Principles Applied

### 2.1 Every Scanned Repository is a Digital Evidence Object

When a GitHub repository URL is submitted for scanning, the cloned Terraform content is immediately registered as a **digital evidence object**. This means:

- The scan is given a globally unique, immutable **Scan ID** (`SCAN-<UUID-prefix>`)
- The exact byte-level content of each `.tf` file is captured using SHA256 hashing at clone time
- A timestamped, structured metadata record is created before any modification or processing occurs
- The scan can never be "forgotten" — it has a permanent record from the moment the repository was cloned

This mirrors the evidence intake procedures in digital forensics, where physical evidence is logged with a chain-of-custody record immediately upon collection.

### 2.2 Every Scan Receives a Unique SCAN_ID

Every repository scan receives a globally unique identifier:

```
SCAN-<8-character-UUID-prefix>
Example: SCAN-550e8400
```

This Scan ID is the **primary key** that links every artifact across the entire pipeline. It is attached to:

| Artifact | Purpose |
|---|---|
| Repository clone metadata | Root anchor of the evidence chain |
| Terraform file hashes | Prove file integrity at clone time |
| Terraform validation results | Link validation commands to the specific scan |
| Checkov findings | Link finding to the specific scan |
| OPA policy violations | Link policy breach to the specific scan |
| Deployment metadata | Link deployed resources to the specific scan |
| Prowler runtime findings | Link runtime issues to the specific scan |
| Risk score reports | Link decision to the specific scan |
| Forensic evidence package | Complete, linked evidence record |

No two scans can share a Scan ID. Once generated, it is immutable.

### 2.3 Every Stage Contributes Metadata

Forensic readiness requires that **no stage of the pipeline is invisible**. Each stage must produce a structured, timestamped record that becomes part of the evidence chain.

| Stage | Metadata Produced | Status |
|---|---|---|
| Repository Cloning | scan_id, repo_url, branch, clone timestamps, stdout/stderr | ✅ Implemented |
| Scan Metadata | SHA256 file hashes, file sizes, file paths, evidence note | ✅ Implemented |
| Terraform Discovery | directory paths, .tf file counts per directory | ✅ Implemented |
| Terraform Validation | command, exit code, stdout, stderr, started_at, completed_at per fmt/init/validate | ✅ Implemented |
| Checkov Scanning | Finding details, check IDs, resource names, severity | 🔮 Planned |
| Policy Validation | Violated rules, rule descriptions, affected resources | 🔮 Planned |
| Initial Risk Score | Score calculation, risk band, decision | 🔮 Planned |
| Sandbox Deployment | Resource ARNs, deployed state, deployment time | 🔮 Planned |
| Runtime Validation | Live findings, resource states, AWS account details | 🔮 Planned |
| Final Risk Score | Combined score, trust score, final decision | 🔮 Planned |
| Evidence Generation | Evidence package, integrity hash, evidence_id | 🔮 Planned |

Together, these records form a **complete audit trail** for every scan.

### 2.4 SHA256 Hashes Preserve Integrity

Cryptographic hashing is the foundation of digital evidence integrity. This framework uses **SHA256** hashing at multiple points:

- **File Hashing (Clone Time):** Every `.tf` file is hashed immediately after cloning via `generate_scan_metadata.py`. If any file is modified after cloning, the hash will not match, revealing tampering. This is implemented and operational.
- **Evidence Package Hashing (future):** The complete forensic evidence package will be hashed on creation. Any post-generation modification to the evidence file will produce a different hash.

SHA256 is a one-way, collision-resistant cryptographic function widely accepted in digital forensics for demonstrating file integrity.

### 2.5 Evidence Chain Links Repository to Deployment Decision

The forensic evidence chain connects every stage via SCAN_ID:

```
Repository URL + Branch
  │ (SCAN_ID)
  ▼
Clone Metadata (timestamp, stdout/stderr)   ← ✅ Implemented
  │ (SCAN_ID)
  ▼
SHA256 File Hashes (.tf files)               ← ✅ Implemented
  │ (SCAN_ID)
  ▼
Terraform Directory Discovery                ← ✅ Implemented
  │ (SCAN_ID)
  ▼
Terraform Validation (fmt/init/validate)     ← ✅ Implemented
  │ (SCAN_ID)
  ▼
Checkov Findings                             ← 🔮 Planned
  │ (SCAN_ID)
  ▼
OPA Policy Violations                        ← 🔮 Planned
  │ (SCAN_ID)
  ▼
Initial Risk Score                           ← 🔮 Planned
  │ (SCAN_ID)
  ▼
Deployment Metadata                          ← 🔮 Planned
  │ (SCAN_ID)
  ▼
Prowler Runtime Findings                     ← 🔮 Planned
  │ (SCAN_ID)
  ▼
Final Risk Score & Decision                  ← 🔮 Planned
  │ (SCAN_ID + evidence_id)
  ▼
Forensic Evidence Package (SHA256 sealed)    ← 🔮 Planned
```

Every node in this chain is independently verifiable. A forensic investigator can begin at any point and trace both forwards and backwards through the complete pipeline history.

### 2.6 Timestamps Support Investigation Timeline Reconstruction

All implemented scripts capture precise UTC timestamps using ISO 8601 format:

- `clone_started_at` / `clone_completed_at` — when the repository was cloned
- `generated_at` — when scan metadata and discovery reports were created
- `started_at` / `completed_at` — when each Terraform command (fmt/init/validate) ran

These timestamps allow investigators to reconstruct the exact timeline of a scan, identify latency issues, and correlate scan events with external activities.

### 2.7 Command Outputs Preserve Validation Evidence

Every Terraform CLI command executed during validation captures:
- The full **command string** that was run
- **stdout** — standard output (successful messages, plan output)
- **stderr** — error output (warnings, errors, diagnostic messages)
- **exit code** — numeric result (0 = success, non-zero = failure)

This forensic-grade command logging means that even if a repository is modified after scanning, the framework retains an exact record of what Terraform reported at scan time.

### 2.8 Investigation and Auditability Support

The framework is designed to answer the following investigative questions:

| Question | Evidence Source |
|---|---|
| What repository was scanned? | `repository-metadata.json` → `repo_url`, `branch` |
| What was the exact content at scan time? | `scan-metadata.json` → `terraform_files[].sha256` |
| What Terraform directories were found? | `terraform-directories.json` |
| Did the Terraform code pass validation? | `terraform-validation.json` → `overall_status` |
| What specific validation errors occurred? | `terraform-validation.json` → `directories[].validate.stderr` |
| What security issues were detected? | `normalized-findings.json`, `policy-results.json` (planned) |
| Has the evidence been tampered with? | `evidence_hash` in `evidence-<id>.json` (planned) |

---

## 3. Forensic Evidence Package Structure

Each pipeline run produces a single sealed forensic evidence package:

```json
{
  "evidence_id":          "EV-<UUID>",
  "scan_id":              "SCAN-<UUID-prefix>",
  "generated_at":         "<UTC ISO 8601 timestamp>",
  "pipeline_run_id":      "<GitHub Actions run ID>",
  "upload_metadata":      { ... },
  "workflow_metadata":    { ... },
  "terraform_validation": { ... },
  "checkov_findings":     { ... },
  "policy_violations":    { ... },
  "runtime_findings":     { ... },
  "static_risk_score":    { ... },
  "final_risk_score":     { ... },
  "final_decision":       "ALLOW | REVIEW | BLOCK",
  "evidence_hash":        "<SHA256 of entire package>"
}
```

This single document is the **complete digital record** of a Terraform deployment attempt. It can be:
- Downloaded and stored for compliance purposes
- Submitted as evidence in a security investigation
- Used to reconstruct the exact state of the infrastructure at deployment time
- Compared against future deployments to detect configuration drift over time

---

## 4. Alignment with Digital Forensics Standards

This framework's forensic readiness approach aligns with:

- **ISO/IEC 27037** — Identification, collection, acquisition and preservation of digital evidence
- **ISO/IEC 27041** — Assurance for digital evidence investigation methods
- **NIST SP 800-86** — Guide to integrating forensic techniques into incident response
- **UK ACPO Good Practice Guide** — Digital forensic principles (particularly the non-alteration principle)

The SHA256 hashing at clone time fulfils the requirement that evidence must be **collected without alteration**, while the immutable `SCAN_ID` satisfies the requirement for a **unique identifier** for each piece of evidence.

# Forensic Readiness

## Project: Designing an End-to-End Forensic-Ready Infrastructure-as-Code Security Framework for Cloud Environments

---

## 1. What is Forensic Readiness?

**Forensic readiness** is the proactive preparation of an organisation's systems, processes, and documentation to support digital forensic investigations before an incident occurs. It ensures that when a security incident, audit, or legal review takes place, sufficient, authentic, and admissible digital evidence is already available.

In the context of this framework, forensic readiness means that **every Terraform infrastructure deployment attempt is treated as a potential subject of future investigation** — and that comprehensive, verifiable evidence is captured at every stage of the pipeline.

---

## 2. Core Forensic Readiness Principles Applied

### 2.1 Every Terraform Upload is a Digital Evidence Object

When a Terraform template is uploaded to the pipeline, it is immediately registered as a **digital evidence object**. This means:

- The upload is given a globally unique, immutable **Upload ID**
- The exact byte-level content of each file is captured using SHA256 hashing
- A timestamped, structured metadata record is created before any modification or processing occurs
- The upload can never be "forgotten" — it has a permanent record from the moment it entered the pipeline

This mirrors the evidence intake procedures in digital forensics, where physical evidence is logged with a chain-of-custody record immediately upon collection.

### 2.2 Every Upload Receives a Unique Upload ID

Every Terraform upload receives a globally unique identifier:

```
TF-UPLOAD-<UUID>
```

This Upload ID is the **primary key** that links every artifact across the entire pipeline. It is attached to:

| Artifact | Purpose |
|---|---|
| Upload metadata | Root anchor of the evidence chain |
| Terraform file hashes | Prove file integrity at upload time |
| Checkov findings | Link finding to the specific upload |
| OPA policy violations | Link policy breach to the specific upload |
| Deployment metadata | Link deployed resources to the specific upload |
| Prowler runtime findings | Link runtime issues to the specific upload |
| Risk score reports | Link decision to the specific upload |
| Forensic evidence package | Complete, linked evidence record |

No two uploads can share an Upload ID. Once generated, it is immutable.

### 2.3 Every Stage Contributes Metadata

Forensic readiness requires that **no stage of the pipeline is invisible**. Each stage must produce a structured, timestamped record that becomes part of the evidence chain.

| Stage | Metadata Produced |
|---|---|
| Upload Intake | upload_id, timestamps, file hashes, uploader identity |
| Terraform Validation | Command results, exit codes, error messages |
| Checkov Scanning | Finding details, check IDs, resource names, severity |
| Policy Validation | Violated rules, rule descriptions, affected resources |
| Initial Risk Score | Score calculation, risk band, decision |
| Sandbox Deployment | Resource ARNs, deployed state, deployment time |
| Runtime Validation | Live findings, resource states, AWS account details |
| Final Risk Score | Combined score, trust score, final decision |
| Evidence Generation | Evidence package, integrity hash, evidence_id |

Together, these records form a **complete audit trail** for every deployment attempt.

### 2.4 SHA256 Hashes Preserve Integrity

Cryptographic hashing is the foundation of digital evidence integrity. This framework uses **SHA256** hashing at multiple points:

- **File Hashing (Upload Time):** Every `.tf` file is hashed at upload. If any file is modified after upload, the hash will not match, revealing tampering.
- **Metadata Hashing:** The upload metadata JSON is itself hashed, ensuring the metadata record cannot be silently altered.
- **Evidence Package Hashing:** The complete forensic evidence package is hashed on creation. Any post-generation modification to the evidence file will produce a different hash.

SHA256 is a one-way, collision-resistant cryptographic function widely accepted in digital forensics for demonstrating file integrity.

### 2.5 Evidence Chain Links Upload to Deployment Decision

The forensic evidence chain connects every stage:

```
Upload
  │ (upload_id)
  ▼
SHA256 File Hashes
  │ (upload_id)
  ▼
Terraform Validation Result
  │ (upload_id)
  ▼
Checkov Findings
  │ (upload_id)
  ▼
OPA Policy Violations
  │ (upload_id)
  ▼
Initial Risk Score
  │ (upload_id)
  ▼
Deployment Metadata
  │ (upload_id)
  ▼
Prowler Runtime Findings
  │ (upload_id)
  ▼
Final Risk Score & Decision
  │ (upload_id + evidence_id)
  ▼
Forensic Evidence Package (SHA256 sealed)
```

Every node in this chain is independently verifiable. A forensic investigator can begin at any point and trace both forwards and backwards through the complete pipeline history.

### 2.6 Investigation and Auditability Support

The framework is designed to answer the following investigative questions:

| Question | Evidence Source |
|---|---|
| Who uploaded this Terraform template? | `upload_metadata.json` → `uploaded_by` |
| What was the exact content at upload time? | `upload_metadata.json` → `file_hashes` |
| What security issues were detected? | `normalized-findings.json`, `policy-results.json` |
| Was the deployment decision appropriate? | `static-risk-score.json` |
| What was deployed to AWS? | `deployment_metadata` in evidence package |
| What did Prowler find at runtime? | `normalized-runtime-findings.json` |
| Was there infrastructure drift? | `runtime_risk_score.py` drift detection |
| What was the final trust assessment? | `final-risk-score.json` |
| Has the evidence been tampered with? | `evidence_hash` in `evidence-<id>.json` |

---

## 3. Forensic Evidence Package Structure

Each pipeline run produces a single sealed forensic evidence package:

```json
{
  "evidence_id":          "EV-<UUID>",
  "upload_id":            "TF-UPLOAD-<UUID>",
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

The SHA256 hashing at upload time fulfils the requirement that evidence must be **collected without alteration**, while the immutable `upload_id` satisfies the requirement for a **unique identifier** for each piece of evidence.

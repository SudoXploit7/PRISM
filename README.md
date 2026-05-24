# PRISM — Privilege Risk IAM Security Mapper

> A purple-team AWS security assessment framework that maps, analyzes, and visualizes cloud environments from an attacker's perspective — without touching a single resource.

PRISM performs **read-only** analysis of AWS accounts using boto3. It calculates the Minimum Viable Compromise path to Account Admin, detects privilege escalation vectors across 21 documented techniques, identifies dormant identities with dangerous permissions, and surfaces findings through a real-time WebSocket dashboard and exportable PDF reports.

---

<img width="1497" height="937" alt="Screenshot 2026-04-16 182642" src="https://github.com/user-attachments/assets/adec7b58-b99c-4e50-a340-c390d7dd91c2" />

---

## What It Does

Most AWS security tools tell you *what* is misconfigured. PRISM tells you *how bad it actually is* — by computing the shortest attack path from any identity to full account compromise, estimating time-to-compromise per phase, and generating a red-team-style narrative using your account's real data.

**Read-only.** No `Put`, `Create`, `Delete`, or `Update` API calls are made at any point.

---

## Modules

### Core Analysis

| Module | What It Detects | MITRE Coverage |
|:---|:---|:---|
| **Privilege Escalation Scanner** | 21 documented IAM escalation vectors across users and roles | T1098, T1078, T1548 |
| **Shadow Admin Hunter** | Non-admin identities with indirect paths to full privilege | T1098 |
| **Network Exposure Analyzer** | Security groups, public subnets, and internet-facing resources | T1190 |
| **CloudTrail Evasion Analyzer** | Gaps in logging coverage and evasion-capable permissions | T1562.008 |
| **Lambda Backdoor Detector** | Code injection vectors via Lambda and execution role abuse | T1059 |
| **Secrets Exfiltration Detector** | Identities capable of reading Secrets Manager and SSM parameters | T1552 |
| **Cross-Account Analyzer** | Trust relationships enabling lateral movement across accounts | T1199 |
| **Credential Age Analyzer** | Stale access keys and unused console credentials | T1078 |

### Offensive Suite

| Module | What It Computes | MITRE Coverage |
|:---|:---|:---|
| **MVC Engine** | Minimum Viable Compromise — shortest BFS path from any identity to Account Admin, with step-by-step attack sequence and estimated time per hop | T1098, T1078, T1548 |
| **Golden SAML Detector** | Identity providers and federation roles vulnerable to SAML token forgery and IDP bypass | T1606.002 |
| **Assumed Breach** | Post-compromise blast radius assuming an attacker already holds a given identity | T1078 |
| **Ransomware Readiness** | S3 buckets and backup infrastructure missing versioning, Object Lock, or replication | T1486, T1485 |
| **Supply Chain Mapper** | Lambda, ECR, and CodeBuild permissions enabling code injection into the deployment pipeline | T1195.002 |

### Unique Capabilities

These modules have no equivalent in existing open-source AWS security tooling (Prowler, ScoutSuite, CloudMapper, Cartography, PMapper):

| Module | Description |
|:---|:---|
| **Ghost Identity Detector** | Finds IAM users and roles that have *never* made an API call but hold dangerous permissions — dormant attack surfaces invisible to activity-based monitoring |
| **Temporal Kill Chain** | Builds a time-sequenced attack narrative using real CloudTrail configuration and IAM structure to estimate attacker dwell time and detection gaps per phase |
| **Permission Entropy Engine** | Quantifies IAM permission chaos across all identities using entropy scoring — surfaces over-provisioning patterns that individual policy reviews miss |
| **Policy Drift Fingerprinter** | Hashes attached policies against a built-in threat intelligence database of 20+ known dangerous permission patterns |
| **Blast Radius 3D** | Calculates five-dimensional downstream impact (Data, Compute, Identity, Billing, Logging) for any compromised identity, including estimated dollar exposure from compute abuse |
| **Attack Narrative Generator** | Produces a structured red-team-style attack report using actual scan findings — not generic templates |

---

## Architecture

PRISM runs a Flask + SocketIO backend. The browser communicates over WebSocket for real-time terminal streaming during scans. All AWS data is collected via boto3 in read-only mode, processed through the analysis pipeline, and rendered in an interactive dashboard with vis.js attack graph visualization.

```
PRISM/
├── main.py                          # Entry point — launches Flask-SocketIO server
├── requirements.txt
├── demo/
│   └── demo_infrastructure.tf       # Free-tier Terraform lab with intentional misconfigurations
├── src/
│   ├── collectors/
│   │   └── aws_collector.py         # boto3 read-only data collection (IAM, EC2, S3, Lambda, CloudTrail, VPC)
│   ├── analysis/
│   │   ├── iam_shadow_admin_detector.py
│   │   ├── privilege_escalation_paths.py
│   │   ├── network_exposure_analyzer.py
│   │   ├── cloudtrail_evasion_analyzer.py
│   │   ├── lambda_backdoor_detector.py
│   │   ├── secrets_exfil_detector.py
│   │   ├── cross_account_analyzer.py
│   │   ├── credential_age_analyzer.py
│   │   ├── risk_engine.py
│   │   └── remediation_engine.py
│   ├── offensive/
│   │   ├── mvc_engine.py            # Minimum Viable Compromise (BFS path to admin)
│   │   ├── golden_saml_detector.py
│   │   ├── assumed_breach.py
│   │   ├── ransomware_detector.py
│   │   └── supply_chain_mapper.py
│   ├── unique/
│   │   ├── ghost_identity_detector.py
│   │   ├── temporal_kill_chain.py
│   │   ├── blast_radius_3d.py
│   │   ├── permission_entropy_engine.py
│   │   ├── policy_drift_fingerprinter.py
│   │   └── attack_narrative_generator.py
│   ├── scoring/
│   │   └── cvss.py                  # CVSS v3.1 base score calculator
│   ├── graph/
│   │   └── attack_graph.py          # NetworkX-based IAM attack graph
│   ├── report/
│   │   └── pdf_engine.py            # ReportLab PDF report generator
│   └── dashboard/
│       ├── app.py                   # Flask routes + SocketIO handlers
│       ├── templates/index.html
│       └── static/
└── tests/
    └── test_analysis.py
```

---

## Screenshots

<img width="1419" height="825" alt="Screenshot 2026-04-16 182716" src="https://github.com/user-attachments/assets/95133196-6abe-4242-b121-d1ea94fcf4a0" />


<img width="1446" height="830" alt="Screenshot 2026-04-16 182750" src="https://github.com/user-attachments/assets/9b1c979c-1ccb-4175-a927-f7059344dc91" />


<img width="1396" height="800" alt="Screenshot 2026-04-16 182803" src="https://github.com/user-attachments/assets/4b513151-2bcf-4012-971c-342522f12fb3" />


---

## Setup

**Requirements:** Python 3.10+, an AWS account with IAM credentials attached to the `ReadOnlyAccess` and `SecurityAudit` managed policies.

```bash
# Clone the repository
git clone https://github.com/<your-username>/PRISM.git
cd PRISM

# Install dependencies
pip install -r requirements.txt

# Launch the dashboard
python main.py
```

The dashboard opens automatically at **http://127.0.0.1:5000**

Enter your AWS Access Key ID and Secret Access Key in the credential panel and click **Start Scan**. Credentials are used only at runtime and are never written to disk. Scan results are cached locally to `prism_cache.json` with all credential keys explicitly stripped before writing.

---

## Demo Lab

PRISM is most useful run against a real environment, but a free-tier-compatible Terraform lab is included with intentional misconfigurations for safe demonstration:

```bash
cd demo/
terraform init
terraform apply
```

The lab provisions:
- A role with `AdministratorAccess` and an overly permissive trust policy (`Principal: "*"`)
- A user with `iam:PassRole` + `lambda:CreateFunction` — a classic privilege escalation pair
- A public S3 bucket without versioning or Object Lock (ransomware target)

Run PRISM against the test account. It will correctly identify the `iam:PassRole` escalation path, the wildcard trust relationship, and the ransomware-vulnerable bucket.

```bash
terraform destroy  # clean up when done
```

---

## Security & Privacy

- Credentials are accepted at runtime only and are never persisted to disk
- All boto3 calls are strictly read-only — the AWS SDK is never invoked with write, create, or delete actions
- `prism_cache.json` is sanitized before writing; the `access_key`, `secret_key`, and collector object are explicitly excluded
- The Flask server binds to `0.0.0.0` for local use — do not expose it to an untrusted network without adding authentication

---

## Tests

```bash
pytest tests/
```

The test suite covers the MVC Engine (path-to-admin BFS), Golden SAML Detector (federation modifier detection), Shadow Admin Detector (PassRole escalation), and Permission Entropy Engine (chaos scoring) with clean and adversarial fixture data.

---

## Dependencies

| Package | Version | Purpose |
|:---|:---|:---|
| `flask` | ≥ 3.0 | Web framework |
| `flask-socketio` | ≥ 5.3 | Real-time WebSocket communication |
| `boto3` | ≥ 1.34 | AWS SDK |
| `networkx` | ≥ 3.2 | Attack graph construction |
| `reportlab` | ≥ 4.1 | PDF report generation |
| `loguru` | ≥ 0.7 | Structured logging |
| `Pillow` | ≥ 10.2 | Image processing for reports |
| `python-socketio` | ≥ 5.11 | SocketIO server |
| `simple-websocket` | ≥ 1.0 | WebSocket transport |

---

## Disclaimer

PRISM is a defensive security tool intended for use on AWS accounts you own or have explicit written authorization to assess. All data collection is read-only. The authors are not responsible for misuse.

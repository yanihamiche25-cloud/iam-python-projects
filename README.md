# IAM & NHI Security Toolkit

Python-based security automation tools for Identity & Access Management (IAM) 
and Non-Human Identity (NHI) governance across AWS and Azure.

Built as part of my transition toward **AI Security Engineering**.

---

## 🛠️ Projects

### P1 — Inactive User Auditor
Scans a CSV list of users and identifies accounts inactive beyond a configurable threshold.
Exports a prioritized CSV report sorted by risk level (highest risk first).

**Key features:**
- Configurable inactivity threshold via command line
- Risk-sorted output
- Dated CSV export

```bash
python audit_inactive_users.py        # default: 90 days
python audit_inactive_users.py 60     # custom threshold
```

---

### P2 — Microsoft Entra ID Auditor (Graph API)
Connects to Microsoft Entra ID via Microsoft Graph API using OAuth 2.0 
Client Credentials flow. Retrieves real cloud users and identifies inactive accounts.

**Key features:**
- OAuth 2.0 authentication (Client Credentials flow)
- Real-time data from Microsoft Graph API
- CSV export with remediation actions

```bash
python graph_iam_auditor.py
```

---

### P3 — AWS IAM Least Privilege Analyzer
Connects to AWS IAM via boto3 and scans all users for security issues.

**Key features:**
- Detects overpermissioned accounts (AdministratorAccess, PowerUserAccess)
- Flags access keys older than 90 days
- Detects accounts without MFA
- CSV export

```bash
python aws_iam_auditor.py
```

---

### P4 — Unified NHI Inventory Tool (AWS + Azure) ⭐
**Signature project.** Inventories all non-human identities across AWS IAM 
and Azure App Registrations in a single unified report with risk scoring.

**Key features:**
- Multi-cloud: AWS IAM + Microsoft Entra ID
- Risk scoring algorithm (0–100)
- Risk levels: CRITIQUE / ÉLEVÉ / MOYEN / OK
- Unified CSV report sortable by risk

```bash
python nhi_inventory.py
```

---

## 🎯 Why This Matters

Non-human identities (service accounts, API keys, app registrations) outnumber 
human identities 25–50x in modern enterprises. They bypass MFA, never expire 
by default, and are prime targets for attackers.

This toolkit addresses the core NHI security challenges:
- **Visibility** — inventory all NHIs across clouds
- **Least Privilege** — detect overpermissioned identities
- **Lifecycle** — flag stale credentials and inactive accounts

---

## 🔧 Tech Stack

- **Python 3.12**
- **boto3** — AWS SDK
- **msal** — Microsoft Authentication Library
- **requests** — HTTP calls to Microsoft Graph API

## ☁️ Cloud Platforms

- AWS IAM (Free Tier)
- Microsoft Entra ID (Azure)

## 📜 Certifications (in progress)

- SC-300 — Microsoft Identity and Access Administrator
- CompTIA SecAI+
- AWS SAA-C03
- CAISP — Certified AI Security Professional

---

## 👤 About

Cybersecurity professional specializing in **Identity & Access Management (IAM)**.
Transitioning toward **AI Security Engineering** with focus on:
- Non-Human Identity (NHI) security
- AI system security (OWASP LLM Top 10)
- Cloud security (AWS + Azure)

📍 Québec, Canada
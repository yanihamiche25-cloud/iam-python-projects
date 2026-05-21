# IAM Python Projects

Python scripts for Identity & Access Management (IAM) security automation.
Built as part of my transition toward AI Security Engineering.

## Projects

### 1. Inactive User Auditor
Scans a list of users and identifies accounts inactive beyond a configurable threshold.
Exports a prioritized CSV report sorted by risk level.

**Usage:**
```bash
python audit_inactive_users.py        # default 90-day threshold
python audit_inactive_users.py 60     # custom threshold
python audit_inactive_users.py 180    # stricter threshold
```

**Features:**
- Configurable inactivity threshold via command line
- Reads users from CSV input file
- Sorts results by days inactive (highest risk first)
- Exports dated CSV report

## Tech Stack
- Python 3.12
- Libraries: `csv`, `datetime`, `sys`

## Background
Cybersecurity professional specializing in Identity & Access Management (IAM).
Building expertise in AI Security and Non-Human Identity (NHI) security.

## Certifications (in progress)
- SC-300 — Microsoft Identity and Access Administrator
- AWS SAA — Solutions Architect Associate
- CAISP — Certified AI Security Professional

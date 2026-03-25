<div align="center">

<img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="Version"/>
<img src="https://img.shields.io/badge/license-Apache%202.0-green?style=for-the-badge" alt="License"/>
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"/>
<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
<img src="https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React"/>
<img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
<img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL"/>

<br/>
<br/>

# 🔐 ZeroTrustOps Platform

### **Self-Hosted DevSecOps for Kubernetes — Scan Every Push. Block Misconfigurations Before They Reach Production.**

A self-hosted DevSecOps platform that scans every Git push and blocks security misconfigurations, hardcoded secrets, and infrastructure vulnerabilities before they reach production.

[🚀 Quick Start](#-quick-start) · [📖 Documentation](#-architecture) · [🛡️ SecTL Engine](#-sectl--security-enforcement-engine) · [🗺️ Roadmap](#-roadmap) · [🤝 Contributing](#-contributing)

</div>

---

## 📸 Screenshots

### Dashboard Overview
![Dashboard Overview](screenshots/DashboardView.png)
> Real-time overview of connected repositories, scan history, and security posture at a glance.

### Repository Management
![Repository Management](screenshots/repoDashboardView.png)
> Add, remove, and monitor repositories — each automatically webhook-connected to the scan pipeline.

![Repositories](screenshots/repo.png)
> Per-repository scan summary with status indicators and quick-action controls.

### Scan Results & Findings
![Scan Dashboard](screenshots/scanDashboardView.png)
> Scan history list with PASS/FAIL status, timestamps, and scan type breakdown.

![Scan Results](screenshots/scanResult1.png)
> Detailed findings view — rule ID, severity, file path, description, and remediation guidance per violation.

![Scan Result Dashboard](screenshots/scanResultDashboardView.png)
> High-level scan result summary grouped by severity (CRITICAL → LOW) with finding counts.

### Triggering a Scan
![Scan Trigger](screenshots/scanTrigger.png)
> Manually trigger a scan from the dashboard, or let the GitHub webhook fire it automatically on every push.

---

## 🧭 Overview

ZeroTrustOps scans every Git push, detects misconfigurations and secrets, and blocks insecure infrastructure before it reaches production.

Powered by a custom enforcement engine (SecTL), along with Gitleaks for secrets detection, it provides an end-to-end DevSecOps pipeline with automated scanning, CI/CD enforcement, and a real-time dashboard — all running locally with a single command.


## ⚡ How it works

Every push is treated as a security checkpoint. If it fails, it never deploys.

git push
  └── GitHub webhook triggers the scan pipeline
        └── Repository is cloned into an isolated scan environment
              │
              ├── 🔍 Static Analysis (SecTL)
              │     ├── Scans IaC: Kubernetes, Terraform, Helm
              │     ├── Detects misconfigurations (RBAC, networking, privilege escalation)
              │     ├── Applies 70+ security rules
              │     └── Assigns severity levels (CRITICAL → LOW)
              │
              ├── 🔑 Secrets Detection (Gitleaks)
              │     └── Identifies API keys, tokens, passwords, and exposed credentials
              │
              ├── 🧠 Findings Processing
              │     ├── Normalizes results (rule_id, severity, file path)
              │     ├── Deduplicates issues
              │     └── Attaches precise remediation guidance
              │
              ├── 🚦 Enforcement Engine (CI/CD Gate)
              │     ├── Evaluates findings against severity thresholds
              │     └── Returns binary decision → PASS / FAIL
              │
              ├── 🗄️ Persistence Layer
              │     └── Stores scan results, history, and findings in PostgreSQL
              │
              └── 📊 Real-time Feedback Loop
                    ├── Updates dashboard instantly
                    ├── Displays repo status (PASS / FAIL)
                    ├── Shows severity breakdown
                    └── Provides actionable fixes per finding

## 🚀 What it actually does

- 🚫 **Blocks insecure Kubernetes deployments** before they ever reach your cluster  
- 🔑 **Prevents secrets from leaving your repo** by detecting hardcoded credentials on every push  
- 🚦 **Fails CI instantly on critical issues** with a clear PASS/FAIL security gate  
- 🛡️ **Enforces security policies at deployment time** using admission control (Kyverno)  
- 🔍 **Detects misconfigurations across IaC and containers** (Kubernetes, Terraform, Helm, images)  
- 📊 **Gives actionable insights, not just logs** — every finding includes exact fixes and context

---

## 🏗️ Architecture

| Component       | Technology        | Role                                                     |
|-----------------|-------------------|----------------------------------------------------------|
| **SecTL CLI**   | Go 1.21+          | Custom static analysis engine — 70+ built-in rules       |
| **Platform API**| Python / FastAPI  | Webhook receiver, scan orchestrator, REST API            |
| **Dashboard**   | React + Vite      | Real-time scan results and repository management         |
| **Database**    | PostgreSQL 16     | Persistent storage for repos, scans, and findings        |
| **Secrets Scanner** | Gitleaks      | Detects hardcoded secrets and credentials                |

All services run in **Docker Compose** and communicate over an internal bridge network.

```
┌────────────────────────────────────────────────────────────┐
│                     Docker Compose Network                 │
│                                                            │
│  ┌──────────────┐    ┌──────────────┐    ┌─────────────┐   │
│  │  React       │    │  FastAPI     │    │ PostgreSQL  │   │
│  │  Dashboard   │◄──►│  Backend     │◄──►│    16       │   │
│  │  :3000       │    │  :8000       │    │  :5432      │   │
│  └──────────────┘    └──────┬───────┘    └─────────────┘   │
│                             │                              │
│                    ┌────────▼────────┐                     │
│                    │   SecTL CLI     │                     │
│                    │   + Gitleaks    │                     │
│                    └─────────────────┘                     │
└────────────────────────────────────────────────────────────┘
                            ▲
                            │  GitHub Webhook (ngrok tunnel)
                            │
                      ┌─────┴──────┐
                      │  GitHub    │
                      │  Repos     │
                      └────────────┘
```

---

## 🛡️ SecTL — Security Enforcement Engine

SecTL is a purpose-built CLI tool written in Go. It scans Infrastructure-as-Code files for security misconfigurations and produces a **binary PASS/FAIL exit code** suitable for use as a CI/CD gate.

### Scan Types

| Type            | Target                   | Coverage                                                              |
|-----------------|--------------------------|-----------------------------------------------------------------------|
| `k8s`           | Kubernetes manifests     | Pods, Deployments, RBAC, Ingress, ConfigMaps, ServiceAccounts         |
| `terraform`     | Infrastructure as Code   | AWS, GCP, Azure — S3, IAM, Security Groups, RDS, EKS, CloudTrail      |
| `helm`          | Helm charts              | Chart.yaml, values.yaml, rendered templates                           |
| `posture`       | Live AWS account         | IAM root keys, MFA enforcement, password policy, S3 bucket posture    |
| `supply-chain`  | Container images         | Digest pinning, `:latest` tag detection, EOL base images              |

### Selected Rules

#### 🔴 Kubernetes — Critical & High

| Rule ID   | Severity     | Description                                          |
|-----------|--------------|------------------------------------------------------|
| K8S-001   | 🔴 CRITICAL  | `hostPID` enabled — container sees all host processes|
| K8S-004   | 🔴 CRITICAL  | Privileged container — full host device access       |
| K8S-020   | 🔴 CRITICAL  | RBAC wildcard `apiGroups` (`*`)                      |
| K8S-024   | 🔴 CRITICAL  | Binding to `cluster-admin` role                      |
| K8S-025   | 🔴 CRITICAL  | Binding to unauthenticated/anonymous subject         |
| K8S-031   | 🟠 HIGH      | Hardcoded secret in environment variable             |
| K8S-005   | 🟠 HIGH      | `allowPrivilegeEscalation` not set to `false`        |

#### 🔴 Terraform — Critical & High

| Rule ID      | Severity     | Description                                          |
|--------------|--------------|------------------------------------------------------|
| TF-S3-010    | 🔴 CRITICAL  | S3 bucket ACL set to public                          |
| TF-IAM-001   | 🔴 CRITICAL  | IAM policy allows `Action: *` (all actions)          |
| TF-SG-001    | 🔴 CRITICAL  | Security group: sensitive port open to internet      |
| TF-RDS-002   | 🔴 CRITICAL  | RDS instance publicly accessible                     |
| TF-EKS-002   | 🟠 HIGH      | EKS API server publicly accessible                   |

> 📋 Full rule list: `sectl rules` — filter with `--source k8s`, `--source terraform`, `--severity critical`

### Usage

```bash
# Scan Kubernetes manifests
sectl scan ./manifests --type k8s

# Scan Terraform — fail CI on HIGH or above
sectl scan ./infra --type terraform --severity high --fail-on-findings

# Scan Helm chart
sectl scan ./charts/myapp --type helm

# Verify container images (digest, EOL, latest tag)
sectl verify nginx:latest myapp:1.0.0

# Audit live AWS account posture
sectl audit --provider aws --region us-east-1

# JSON output for programmatic use
sectl scan ./manifests --type k8s --output json

# SARIF output for GitHub Security tab
sectl scan ./manifests --type k8s --output sarif
```

---

## 🚀 Quick Start

### Prerequisites

| Dependency     | Minimum Version | Notes                        |
|----------------|-----------------|------------------------------|
| Docker         | 24+             | With Docker Compose plugin   |
| Docker Compose | 2.x             | Bundled with Docker Desktop  |
| Go             | 1.21+           | For compiling SecTL          |
| Git            | Any             | For cloning and webhook use  |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Debasish-87/ZeroTrustOps-Platform.git
cd ZeroTrustOps-Platform

# 2. Run the one-command installer
bash setup.sh
```

The `setup.sh` script will automatically:

1. ✅ Verify all prerequisites are installed
2. ⚙️ Compile the SecTL binary from source
3. 🐳 Build and start all Docker containers
4. 🩺 Wait for all services to pass health checks

### Access

| Service           | URL                            | Description               |
|-------------------|--------------------------------|---------------------------|
| 📊 Dashboard      | http://localhost:3000          | React UI — main interface |
| ⚡ API            | http://localhost:8000          | FastAPI backend            |
| 📖 API Reference  | http://localhost:8000/docs     | Swagger / OpenAPI docs    |

### GitHub Webhook Integration

```bash
# Step 1: Expose the local platform publicly via ngrok
ngrok http 8000
```

In your GitHub repository → **Settings > Webhooks > Add webhook**:

| Field         | Value                                       |
|---------------|---------------------------------------------|
| Payload URL   | `https://<your-ngrok-url>/webhook/github`   |
| Content type  | `application/json`                          |
| Events        | ✅ Push events                              |

Every subsequent `git push` will **automatically trigger a full scan**.

### Uninstall

```bash
bash uninstall.sh
```

> Removes all containers, volumes, images, networks, and the `sectl` binary. **Source code is not affected.**

---

## 🌐 REST API Reference

| Method   | Endpoint                | Description                              | Auth |
|----------|-------------------------|------------------------------------------|------|
| `GET`    | `/health`               | Health check — all services              | —    |
| `GET`    | `/api/stats`            | Dashboard overview counts                | —    |
| `GET`    | `/api/repos`            | List all connected repositories          | —    |
| `POST`   | `/api/repos`            | Add a new repository                     | —    |
| `DELETE` | `/api/repos/:id`        | Remove a repository                      | —    |
| `GET`    | `/api/scans`            | List recent scans                        | —    |
| `GET`    | `/api/scans/:id`        | Scan detail with all findings            | —    |
| `POST`   | `/api/scans/trigger`    | Manually trigger a scan                  | —    |
| `POST`   | `/webhook/github`       | GitHub push webhook receiver             | HMAC |

### Example: Trigger a Scan

```bash
curl -X POST http://localhost:8000/api/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{"repo_id": 1}'
```

### Example: Get Scan Findings

```bash
curl http://localhost:8000/api/scans/42 | jq '.findings[] | select(.severity == "CRITICAL")'
```

---

## 🗂️ Project Structure

```
ZeroTrustOps-Platform/
├── setup.sh                    # One-command installer
├── uninstall.sh                # Complete cleanup script
├── docker-compose.yml          # Service orchestration
│
├── sectl/                      # Security CLI (Go)
│   ├── main.go
│   ├── cmd/                    # scan, audit, verify, rules commands
│   │   ├── audit.go
│   │   ├── helpers.go
│   │   ├── root.go
│   │   ├── rules.go
│   │   ├── scan.go
│   │   └── verify.go
│   └── internal/
│       ├── scanner/            # K8s, Terraform, Helm analyzers + unit tests
│       │   ├── finding.go
│       │   ├── helm.go
│       │   ├── k8s.go
│       │   ├── k8s_test.go
│       │   ├── terraform.go
│       │   └── terraform_test.go
│       ├── posture/            # Live AWS account audit
│       │   └── aws.go
│       ├── supply/             # Container image supply chain checks
│       │   └── chain.go
│       └── report/             # Table, JSON, SARIF output renderers
│           └── render.go
│
├── platform/
│   ├── api/                    # FastAPI backend
│   │   ├── main.py             # Webhook handler, scan engine, REST API
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   ├── web/                    # React dashboard
│   │   ├── src/
│   │   │   ├── pages/          # Dashboard, Repositories, Scans, Setup
│   │   │   │   ├── Dashboard.jsx
│   │   │   │   ├── Repositories.jsx
│   │   │   │   ├── ScanDetail.jsx
│   │   │   │   ├── Scans.jsx
│   │   │   │   └── Setup.jsx
│   │   │   ├── components/
│   │   │   │   └── Layout.jsx
│   │   │   ├── App.jsx
│   │   │   └── main.jsx
│   │   └── Dockerfile
│   └── db/
│       └── init.sql            # PostgreSQL schema
│
└── manifests/
    ├── dev/                    # Hardened Kubernetes deployment example
    │   ├── deployment.yaml
    │   └── service.yaml
    └── kyverno-policies/       # Admission control enforcement policies
        ├── disallow-latest-tag.yaml
        ├── disallow-privileged.yaml
        └── require-resource-limits.yaml
```

---

## 🛡️ Kyverno Admission Control Policies

Three cluster-wide admission control policies are included. All run in **`Enforce` mode** — they actively **block** non-compliant resources from entering the cluster.

| Policy                      | Mode    | Enforcement                                                          |
|-----------------------------|---------|----------------------------------------------------------------------|
| `disallow-latest-tag`       | Enforce | Blocks containers using `:latest` or untagged images                 |
| `disallow-privileged`       | Enforce | Blocks privileged containers, privilege escalation, host namespaces  |
| `require-resource-limits`   | Enforce | Requires CPU and memory requests and limits on all containers        |

### Apply Policies

```bash
# Apply all Kyverno policies to your cluster
kubectl apply -f manifests/kyverno-policies/

# Verify policies are active
kubectl get clusterpolicy
```

---

## 🗄️ Database Schema

```
organizations
    └── repositories
            └── scans
                    └── findings
```

Each `finding` record stores:

| Field         | Type    | Description                                   |
|---------------|---------|-----------------------------------------------|
| `tool`        | text    | `sectl` or `gitleaks`                         |
| `rule_id`     | text    | e.g. `K8S-001`, `TF-IAM-001`                  |
| `severity`    | text    | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`           |
| `category`    | text    | e.g. `rbac`, `network`, `secrets`             |
| `title`       | text    | Short rule description                        |
| `description` | text    | Full violation explanation                    |
| `file_path`   | text    | Relative path to the affected file            |
| `remediation` | text    | How to fix the violation                      |

---

## 🧪 Running Tests

```bash
# Unit tests for SecTL scanners
cd sectl
go test ./internal/scanner/... -v

# Run with race condition detection
go test -race ./internal/...

# Test against sample manifests
sectl scan ./sectl/testdata/k8s --type k8s
sectl scan ./sectl/testdata/terraform --type terraform
```

**Test data included:**

| File                              | Purpose                         |
|-----------------------------------|---------------------------------|
| `testdata/k8s/bad-deployment.yaml`    | Triggers K8S rules          |
| `testdata/k8s/good-deployment.yaml`   | Should produce zero findings|
| `testdata/terraform/bad-infra.tf`     | Triggers TF rules           |
| `testdata/terraform/good-infra.tf`    | Should produce zero findings|

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root (copied from `.env.example`):

```env
# Database
POSTGRES_USER=zerotrust
POSTGRES_PASSWORD=changeme
POSTGRES_DB=zerotrust

# GitHub Webhook
GITHUB_WEBHOOK_SECRET=your-secret-here

# API
API_HOST=0.0.0.0
API_PORT=8000
```

### Docker Compose Ports

| Service    | Internal Port | External Port | Configurable |
|------------|---------------|---------------|--------------|
| Dashboard  | 3000          | 3000          | ✅           |
| API        | 8000          | 8000          | ✅           |
| PostgreSQL | 5432          | 5432          | ✅           |

---

## 🗺️ Roadmap

- [ ] GitHub commit status API — report PASS/FAIL directly on pull requests
- [ ] Slack and Microsoft Teams webhook notifications  
- [ ] Trivy container image vulnerability scanning
- [ ] Falco runtime threat detection
- [ ] SARIF upload to GitHub Advanced Security via API
- [ ] Multi-organization support
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Role-based access control (RBAC) for multi-team environments
- [ ] GitLab webhook support

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

```bash
# Fork and clone
git clone https://github.com/<your-handle>/ZeroTrustOps-Platform.git
cd ZeroTrustOps-Platform

# Create a feature branch
git checkout -b feature/my-new-rule

# Add your rule in sectl/internal/scanner/
# Add a test in the corresponding _test.go file
# Add test data in sectl/testdata/

# Run tests
go test ./...

# Submit a pull request
```

**Adding a new SecTL rule:** See `sectl/internal/scanner/k8s.go` or `terraform.go` for patterns. Each rule requires a `RuleID`, `Severity`, `Title`, `Description`, and `Remediation`.

## 🧪 Example

A developer pushes a Kubernetes manifest with:
- privileged container enabled
- latest image tag

→ Scan triggers automatically  
→ Critical issues detected  
→ CI fails  
→ Deployment is BLOCKED  

Nothing insecure reaches production.

---

## 💡 Why this matters

Most security tools only detect issues.

ZeroTrustOps enforces them.

If it's insecure, it doesn't deploy. Period.

---

## 📄 License

Distributed under the [Apache 2.0 License](LICENSE).

---

## 👤 Maintainer

**Debasish Mohanty**

[![GitHub](https://img.shields.io/badge/GitHub-Debasish--87-181717?style=for-the-badge&logo=github)](https://github.com/Debasish-87)

---

<div align="center">

> *"Trust nothing. Scan everything. Deploy with confidence."*

⭐ **Star this repo if it helps secure your infrastructure!** ⭐

</div>

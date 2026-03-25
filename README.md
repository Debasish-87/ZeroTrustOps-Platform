# ZeroTrustOps Platform

A self-hosted DevSecOps platform that automatically scans repositories for security
misconfigurations on every push — before it reaches production.

---

## Overview

ZeroTrustOps integrates a custom-built static analysis engine (SecTL), secrets detection
via Gitleaks, a FastAPI backend, and a React dashboard. Everything runs locally with a
single command.

```
git push
  └── GitHub webhook fires
        └── Platform clones repository
              ├── SecTL   scans K8s, Terraform, Helm
              └── Gitleaks scans for hardcoded secrets
                    └── PASS / FAIL stored in PostgreSQL
                          └── Dashboard displays results
```

---

## Architecture

| Component       | Technology        | Role                                                     |
|-----------------|-------------------|----------------------------------------------------------|
| SecTL CLI       | Go                | Custom static analysis engine — 70+ built-in rules       |
| Platform API    | Python / FastAPI  | Webhook receiver, scan orchestrator, REST API            |
| Dashboard       | React + Vite      | Real-time scan results and repository management         |
| Database        | PostgreSQL 16     | Persistent storage for repos, scans, and findings        |
| Secrets Scanner | Gitleaks          | Detects hardcoded secrets and credentials                |

All three services run in Docker Compose and communicate over an internal bridge network.

---

## SecTL — Security Enforcement Engine

SecTL is a purpose-built CLI tool written in Go. It scans Infrastructure-as-Code files
for security misconfigurations and produces a binary PASS/FAIL exit code suitable for
use as a CI/CD gate.

### Scan Types

| Type          | Target                   | Coverage                                                             |
|---------------|--------------------------|----------------------------------------------------------------------|
| `k8s`         | Kubernetes manifests     | Pods, Deployments, RBAC, Ingress, ConfigMaps, ServiceAccounts        |
| `terraform`   | Infrastructure as Code   | AWS, GCP, Azure — S3, IAM, Security Groups, RDS, EKS, CloudTrail    |
| `helm`        | Helm charts              | Chart.yaml, values.yaml, rendered templates                          |
| `posture`     | Live AWS account         | IAM root keys, MFA enforcement, password policy, S3 bucket posture   |
| `supply-chain`| Container images         | Digest pinning, `:latest` tag detection, EOL base images             |

### Selected Rules

| Rule ID      | Severity | Description                                          |
|--------------|----------|------------------------------------------------------|
| K8S-001      | CRITICAL | hostPID enabled — container sees all host processes  |
| K8S-004      | CRITICAL | Privileged container — full host device access       |
| K8S-020      | CRITICAL | RBAC wildcard apiGroups (*)                          |
| K8S-024      | CRITICAL | Binding to cluster-admin role                        |
| K8S-025      | CRITICAL | Binding to unauthenticated/anonymous subject         |
| K8S-031      | HIGH     | Hardcoded secret in environment variable             |
| K8S-005      | HIGH     | allowPrivilegeEscalation not set to false            |
| TF-S3-010    | CRITICAL | S3 bucket ACL set to public                          |
| TF-IAM-001   | CRITICAL | IAM policy allows Action: * (all actions)            |
| TF-SG-001    | CRITICAL | Security group: sensitive port open to internet      |
| TF-RDS-002   | CRITICAL | RDS instance publicly accessible                     |
| TF-EKS-002   | HIGH     | EKS API server publicly accessible                   |

Full list: `sectl rules` — filter with `--source k8s`, `--source terraform`, `--severity critical`.

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

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Go 1.21 or later
- Git

### Installation

```bash
git clone https://github.com/Debasish-87/ZeroTrustOps-Platform.git
cd ZeroTrustOps-Platform
bash setup.sh
```

The setup script will:

1. Verify prerequisites
2. Compile the SecTL binary from source
3. Build and start all Docker containers
4. Wait for services to pass health checks

### Access

| Service           | URL                            |
|-------------------|--------------------------------|
| Dashboard         | http://localhost:3000          |
| API               | http://localhost:8000          |
| API Reference     | http://localhost:8000/docs     |

### GitHub Webhook Integration

```bash
# Expose the local platform publicly
ngrok http 3000
```

In your GitHub repository, go to **Settings > Webhooks > Add webhook**:

- Payload URL: `https://<your-ngrok-url>/webhook/github`
- Content type: `application/json`
- Events: Push events

Every subsequent push will trigger an automated scan.

### Uninstall

```bash
bash uninstall.sh
```

Removes all containers, volumes, images, networks, and the `sectl` binary.
Source code files are not affected.

---

## REST API

| Method | Endpoint               | Description                          |
|--------|------------------------|--------------------------------------|
| GET    | `/health`              | Health check                         |
| GET    | `/api/stats`           | Dashboard overview counts            |
| GET    | `/api/repos`           | List connected repositories          |
| POST   | `/api/repos`           | Add a repository                     |
| DELETE | `/api/repos/:id`       | Remove a repository                  |
| GET    | `/api/scans`           | List recent scans                    |
| GET    | `/api/scans/:id`       | Scan detail with all findings        |
| POST   | `/api/scans/trigger`   | Manually trigger a scan              |
| POST   | `/webhook/github`      | GitHub push webhook receiver         |

---

## Project Structure

```
ZeroTrustOps-Platform/
├── setup.sh                    # One-command installer
├── uninstall.sh                # Complete cleanup script
├── docker-compose.yml          # Service orchestration
│
├── sectl/                      # Security CLI (Go)
│   ├── main.go
│   ├── cmd/                    # scan, audit, verify, rules commands
│   └── internal/
│       ├── scanner/            # K8s, Terraform, Helm analyzers + unit tests
│       ├── posture/            # Live AWS account audit
│       ├── supply/             # Container image supply chain checks
│       └── report/             # Table, JSON, SARIF output renderers
│
├── platform/
│   ├── api/                    # FastAPI backend
│   │   ├── main.py             # Webhook handler, scan engine, REST API
│   │   └── Dockerfile
│   ├── web/                    # React dashboard
│   │   ├── src/pages/          # Dashboard, Repositories, Scans, Setup
│   │   └── Dockerfile
│   └── db/
│       └── init.sql            # PostgreSQL schema
│
└── manifests/
    ├── dev/                    # Hardened Kubernetes deployment example
    └── kyverno-policies/       # Admission control enforcement policies
```

---

## Kyverno Policies

Three cluster-wide admission control policies are included. All run in `Enforce` mode —
they actively block non-compliant resources from entering the cluster.

| Policy                    | Enforcement                                                         |
|---------------------------|---------------------------------------------------------------------|
| `disallow-latest-tag`     | Blocks containers using `:latest` or untagged images                |
| `disallow-privileged`     | Blocks privileged containers, privilege escalation, host namespaces |
| `require-resource-limits` | Requires CPU and memory requests and limits on all containers       |

---

## Database Schema

```
organizations
    └── repositories
            └── scans
                    └── findings
```

Each `finding` record stores: `tool`, `rule_id`, `severity`, `category`, `title`,
`description`, `file_path`, and `remediation`.

---

## Roadmap

- [ ] GitHub commit status API — report PASS/FAIL directly on pull requests
- [ ] Slack and Microsoft Teams webhook notifications
- [ ] Trivy container image vulnerability scanning
- [ ] Falco runtime threat detection
- [ ] SARIF upload to GitHub Advanced Security via API
- [ ] Multi-organization support
- [ ] Prometheus metrics endpoint

---

## License

[Apache 2.0](LICENSE)

---

## Maintainer

Debasish Mohanty — [github.com/Debasish-87](https://github.com/Debasish-87)

> "Trust nothing. Scan everything. Deploy with confidence."

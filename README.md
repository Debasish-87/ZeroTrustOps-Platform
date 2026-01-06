
# 🔐 ZeroTrustOps — Cloud-Native Kubernetes Security & DevSecOps Platform

> **Lightweight but Legendary** — A streamlined DevSecOps pipeline to build, scan, and secure Kubernetes workloads with Zero Trust principles.

---

## 📦 Project Structure

```bash
ZeroTrustOps-Platform/
├── Jenkinsfile                         # Jenkins CI/CD pipeline definition
├── LICENSE                             # Open-source license
├── README.md                           # This file!
├── docs/                               # Documentation & architecture
│   └── architecture.md
├── html-report/                        # HTML Dashboard for scan reports
│   ├── index.html
│   └── assets/
│       └── styles.css
├── manifests/                          # K8s manifests for app + policies
│   ├── argocd-apps/
│   │   └── argocd-kyverno-policies.yaml
│   ├── dev/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   └── kyverno-policies/
│       ├── bad-deployment.yaml
│       └── disallow-latest-tag.yaml
├── pre-commit-hooks/                   # Hooks config (e.g., lint, secrets scan)
├── reports/                            # Static scan reports
│   ├── gitleaks/
│   │   └── gitleaks-report.json
│   ├── kubeaudit/
│   │   └── kubeaudit-report.json
│   └── trivy/
│       ├── config-scan.json
│       └── image-scan.json
```

---

## 🚀 What It Does

✅ Git-based CI/CD with Jenkins  
✅ Scans for vulnerabilities, secrets & misconfigurations  
✅ GitOps deployment using ArgoCD  
✅ Policy enforcement with Kyverno  
✅ HTML dashboard for scan results  
✅ Extensible pre-commit hook system  
✅ Ready for Zero Trust Kubernetes environments  

---

## 🔁 Workflow Architecture

You can read the full architecture description [here](docs/architecture.md).

### 🧭 High-Level Pipeline

<p align="center">
  <img src="docs/zero-trust-pipeline.png" alt="Zero Trust DevSecOps Pipeline" width="100%">
  <img src="docs/workflow.png" alt="Zero Trust DevSecOps Pipeline" width="100%">

</p>

---

## 🔧 Security Tools Used

| Tool         | Purpose                                |
|--------------|----------------------------------------|
| **Trivy**    | Scan Docker images & IaC for CVEs      |
| **Gitleaks** | Detect hardcoded secrets in source     |
| **Kubeaudit**| Identify insecure K8s configurations   |
| **Kyverno**  | Enforce policies (e.g., block `latest`)|
| **ArgoCD**   | GitOps-based deployment                |

---

## 📁 CI/CD: Jenkinsfile Overview

Your pipeline performs:

- Git change detection
- Trivy version check
- Gitleaks version check
- Kubeaudit version check
- Future-ready to add full scan + auto-alert stages

---

## 💻 HTML Report Dashboard

📂 Path: `html-report/index.html`  
View vulnerabilities, secrets, and misconfigs in one place.  
Easily extend it with charts, summary counts, and filter logic.

---

## 🧪 Pre-Commit Hooks (optional)

Add hooks in `pre-commit-hooks/.pre-commit-config.yaml` to automate:

- Linting
- Secret scans (Gitleaks)
- K8s schema validation
- Trivy config scan

Use [`pre-commit`](https://pre-commit.com) to enforce these before pushing!

---

## 📜 Sample Kyverno Policies

- ❌ Block use of `latest` image tags  
- ❌ Prevent privilege escalation  
- ✅ Ensure resource limits are defined  
- 🔒 Secure labels/annotations for workloads  

Defined in: `manifests/kyverno-policies/`

---

## 🛡 Future Enhancements 

- Runtime Threat Detection with Falco  
- Istio Service Mesh with mTLS  
- SOAR-based auto responses  
- Prometheus + Grafana Monitoring  
- EFK or Loki-based centralized logging  
- Role-based dashboard & alerts to Teams/Slack  

---

## 📖 Documentation

Full architecture breakdown in:  
📄 [`docs/architecture.md`](docs/architecture.md)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE)

---

## 🙌 Contributions

Contributions, suggestions & PRs are welcome!  
Let’s build a secure cloud-native future — one commit at a time 💪

---

## 🧠 Maintainer

**Debasish | aka darkrootx**  
_Cloud Native | Kubernetes | DevSecOps Architect_  
📫 [GitHub](https://github.com/Debasish-87)

---

> “Trust nothing. Automate everything.” – ZeroTrustOps
> This project showcases how QA, DevOps, and Security integrate in modern cloud-native delivery pipelines.

```

---


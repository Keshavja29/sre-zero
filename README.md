# SRE-Zero ⚡
### Autonomous Cloud Incident Command & Self-Healing RCA Platform
> **Built for Startup Buildathon India 2026** • Powered by **Google Gemini 4 Hydrogen**

[![Live Demo](https://img.shields.io/badge/LIVE%20DEMO-Google%20Cloud%20Run-34A853?style=for-the-badge&logo=googlecloud&logoColor=white)](https://sre-zero-871182125141.us-central1.run.app)
[![API Health](https://img.shields.io/badge/HEALTH-200%20OK-00C853?style=for-the-badge&logo=statuspage&logoColor=white)](https://sre-zero-871182125141.us-central1.run.app/api/health)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/Node.js-20.x-green.svg)](https://nodejs.org/)
[![AI Engine](https://img.shields.io/badge/AI%20Engine-Gemini%204%20Hydrogen-blueviolet.svg)](https://aistudio.google.com/)
[![Target SLA](https://img.shields.io/badge/Target%20SLA-99.98%25-brightgreen.svg)]()

---

### 🌐 Live Production Deployments
- **Interactive Web Platform:** [https://sre-zero-871182125141.us-central1.run.app](https://sre-zero-871182125141.us-central1.run.app)
- **Live Health & Telemetry Probe:** [https://sre-zero-871182125141.us-central1.run.app/api/health](https://sre-zero-871182125141.us-central1.run.app/api/health)
- **Hosted on:** Google Cloud Run (`us-central1`) • Fully Serverless Auto-scaling

---

## 🎯 Executive Summary
During high-traffic production incidents, manual Site Reliability Engineering (SRE) triage takes **45 to 90 minutes**, leading to cascading outages and severe financial loss.

**SRE-Zero** is an autonomous cloud incident commander that intercepts production crashes, correlates pod logs with Git commit deltas via multi-modal AST analysis, and enables automated, verified 1-click hotfix rollbacks in **under 15 seconds** (**-99.3% reduction in MTTR**).

---

## 🚀 Key Features

### 1. Multi-Agent Swarm (Parallel SRE Specialists)
- **Log Triage Agent:** AST stacktrace parsing across distributed GKE pods.
- **Git Blame Agent:** Pinpoints breaking commit deltas and pull requests in merge history.
- **Remediation Verifier:** Evaluates database DDL irreversible migrations & Kafka consumer lag before permitting rollback.

### 2. Universal Application Integration Hub (Connect in 60s)
Connect any client company's microservice or cluster using:
- **Python (FastAPI / Flask / Django):** 2-line middleware integration.
- **Node.js (Express / NestJS / Next.js):** Error handler interceptor.
- **Kubernetes (GKE / EKS / AKS):** 1-command Helm cluster DaemonSet.
- **Webhook Sinks:** Direct Prometheus AlertManager & Datadog ingress.

### 3. Step-by-Step Incident Lifecycle Runbook
- **[01] Ingest & Detect:** Real-time HTTP 500 anomaly threshold (>2.0%).
- **[02] AI Swarm Triage:** Multi-pod log correlation & culprit commit isolation.
- **[03] Line Code Hotfix:** Side-by-side diffs across 5 production microservices.
- **[04] Safety Gates:** 4/4 automated pre-flight checks (DDL, Kafka, Health Probes, RBAC).
- **[05] Rollback & Restore:** 1-click safe commit revert, 99.98% SLA recovery, and immutable SOC2 audit ledger.

### 4. Telemetry Horizon Histogram (Non-Line Graph)
Stepped anomaly horizon histogram with real-time error chunking and SLA breach threshold line, fully resilient to reset crashes.

---

## 🛠️ Quick Start (Local Run)

```bash
# Clone the repository
git clone https://github.com/Keshavja29/sre-zero.git
cd sre-zero

# Install dependencies
npm install

# Start the server
npm start
```
Open **`http://localhost:3000`** in your browser.

---

## 🐳 Cloud & Container Deployment (Google Cloud Run / Render)

### Option A: Google Cloud Run (One-Command)
```bash
gcloud run deploy sre-zero \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated
```

### Option B: Docker Container
```bash
docker build -t sre-zero .
docker run -p 8080:8080 sre-zero
```

---

## 📄 License
This project is open-source under the MIT License.

# SentinelOps: AI-Assisted Security Investigation Toolkit

**SentinelOps** is a modular security investigation platform that simulates how a Security Operations Center (SOC) analyzes identity-based alerts. By combining rule-based analytics with a **Local Retrieval-Augmented Generation (RAG)** pipeline, it transforms raw authentication telemetry into actionable, analyst-grade investigation summaries.

---

## 🚀 Key Features

### 🛡️ Authentication Telemetry Pipeline
Normalizes disparate logs into a unified schema, tracking:
* **Identity:** User, Application, MFA Status.
* **Context:** IP Address, Geo-location, ASN/ISP.
* **Environment:** Device ID, Browser Fingerprint, VPN Indicators.

### 🔍 Alert Investigation Engine
Modular components that perform automated "pre-triage":
* **Alert Explainer:** Contextualizes triggers like *Impossible Travel* or anomalous timing.
* **False Positive Checker:** Cross-references known devices and VPN exit nodes to generate a confidence score.
* **Timeline Builder:** Reconstructs the sequence of events surrounding an alert.
* **Entity Risk Profiler:** Aggregates real-time risk scores for Users, IPs, and Devices.

### 🤖 AI Investigation Assistant (Local RAG)
A privacy-first local AI component that interprets alerts using:
* **Inference:** Ollama (Llama 3.1 8B).
* **Vector Store:** ChromaDB.
* **Knowledge Base:** Security playbooks and incident response frameworks.

---

## 🏗️ Architecture & Workflow

```mermaid
graph TD
    A[Security Logs] --> B[Log Normalization]
    B --> C{Investigation Engine}
    C --> D[Risk Scoring]
    C --> E[Timeline Builder]
    D & E --> F[Local RAG Assistant]
    F --> G[Streamlit SOC Dashboard]
---

## 🛠️ Tech Stack

* **Language:** Python 3.11+
* **Frontend:** Streamlit (Interactive SOC Dashboard)
* **Data Science:** Pandas, NumPy
* **AI/ML:** Ollama, Llama 3.1, ChromaDB (Vector DB)

---

## 💻 Getting Started

### Prerequisites

* [Ollama](https://ollama.com/) installed and running.
* Python 3.9+

### Installation

1. **Clone & Setup**
```bash
git clone [https://github.com/YOUR_USERNAME/sentinelops.git](https://github.com/YOUR_USERNAME/sentinelops.git)
cd sentinelops
pip install -r requirements.txt

```


2. **Download Local Models**
```bash
ollama pull llama3.1:8b
ollama pull nomic-embed-text

```


3. **Initialize Knowledge Base**
```bash
python utils/build_rag_store.py

```


4. **Launch Dashboard**
```bash
streamlit run app/dashboard.py

```



---

## 📖 Example Analysis

**Input Alert:** `Impossible Travel detected for rkhatri@company.com`

**AI Summary Output:**

> "The system detected a login from Durham, US followed by Berlin, DE within 3 minutes. While the device ID matched a known asset, the source IP is a known TOR exit node. Recommended Action: **Immediate Session Revocation.**"

---

## 🛡️ Project Purpose

This project demonstrates how security analytics pipelines can be combined with local AI models to assist analysts during identity-based alert investigations. Focus areas include:

* Authentication Anomaly Detection
* Alert Triage Automation
* Explainable AI (XAI) Workflows

---

## 👤 Author

**Rishal Khatri** *Computer Science (Cybersecurity)* **University of New Hampshire '26**

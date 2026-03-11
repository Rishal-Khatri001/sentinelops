SentinelOps: AI-Assisted Security Investigation Toolkit

SentinelOps is a modular security investigation platform that simulates how a Security Operations Center (SOC) analyzes identity-based alerts. The system processes authentication telemetry, reconstructs investigation context, evaluates risk signals, and uses a local Retrieval-Augmented Generation (RAG) pipeline to generate analyst-style investigation summaries.

The project demonstrates how rule-based security analytics and local AI models can work together to assist analysts during alert triage.

⸻

Key Features

Authentication Telemetry Pipeline

SentinelOps ingests and normalizes authentication logs that include fields such as:
	•	user
	•	timestamp
	•	IP address
	•	location
	•	device information
	•	browser
	•	application
	•	authentication result
	•	MFA status
	•	VPN indicator

This normalized telemetry becomes the foundation for alert analysis.

⸻

Alert Investigation Engine

SentinelOps contains modular investigation components that analyze alerts step-by-step.

Alert Explainer
Explains why an alert triggered using contextual log data.

Example:
	•	impossible travel detection
	•	location change analysis
	•	login timing comparison

False Positive Checker
Evaluates benign indicators such as:
	•	VPN usage
	•	known device
	•	same browser or OS
	•	domestic routing anomalies

This module produces a false positive confidence score.

Investigation Timeline Builder
Reconstructs events surrounding the alert to provide investigation context.

Example timeline:

09:23 login | Durham US | device_103
09:26 login | Berlin DE | device_716
09:43 login | Durham US | device_103

Entity Risk Profiler
Calculates risk scores for:
	•	user
	•	device
	•	IP address

These scores help prioritize investigations.

Response Recommendation Engine
Based on the investigation results, SentinelOps recommends response actions such as:
	•	escalate alert
	•	force password reset
	•	revoke active sessions
	•	investigate new device
	•	monitor account activity

⸻

AI Investigation Assistant (Local RAG)

SentinelOps includes a local AI component that generates analyst-style investigation summaries.

The system uses:
	•	Ollama for local LLM inference
	•	Llama 3.1 for generation
	•	ChromaDB for vector search
	•	security playbooks as the knowledge base

Workflow:

Alert
   ↓
Investigation modules
   ↓
Structured investigation context
   ↓
Vector retrieval from security playbooks
   ↓
Local LLM explanation

Example AI output:

The alert indicates a potential impossible travel event for user rkhatri@company.com.

The user logged in from Durham, US and then Berlin, DE within three minutes using a different device.

Key indicators include cross-border login behavior, a new device identifier, and a suspicious IP range.

False positive analysis found no VPN evidence, increasing the likelihood of credential misuse.

Recommended action: escalate the alert and contain the account.


⸻

SentinelOps Architecture

Security Logs
     ↓
Log Normalization
     ↓
Alert Investigation Modules
     ↓
Risk Scoring + Response Recommendation
     ↓
Local RAG AI Investigation Assistant
     ↓
SOC Dashboard (Streamlit)


⸻

Dashboard

SentinelOps includes a Streamlit dashboard that allows interactive investigations.

The dashboard displays:
	•	alert details
	•	investigation explanation
	•	false positive analysis
	•	timeline reconstruction
	•	entity risk scores
	•	response recommendations
	•	AI investigation summary

⸻

Installation

Clone the repository:

git clone https://github.com/YOUR_USERNAME/sentinelops.git
cd sentinelops

Install dependencies:

pip install -r requirements.txt


⸻

Install Local AI Models

Install Ollama and pull required models:

ollama pull llama3.1:8b
ollama pull embeddinggemma


⸻

Build the Vector Knowledge Base

python utils/build_rag_store.py


⸻

Run the Dashboard

streamlit run app/dashboard.py


⸻

Technologies Used
	•	Python
	•	Streamlit
	•	Pandas
	•	ChromaDB
	•	Ollama
	•	Llama 3.1
	•	Local Retrieval-Augmented Generation (RAG)

⸻

Project Purpose

This project was built to demonstrate how security analytics pipelines can be combined with local AI models to assist analysts during identity-based alert investigations.

It focuses on:
	•	authentication anomaly detection
	•	alert triage automation
	•	explainable investigation workflows
	•	AI-assisted security analysis

⸻

Author

Rishal Khatri
Computer Science (Cybersecurity)
University of New Hampshire
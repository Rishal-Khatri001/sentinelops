import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import requests
import chromadb
import pandas as pd

from modules.alert_explainer import explain_impossible_travel
from modules.false_positive_checker import score_false_positive
from modules.timeline_builder import build_timeline
from modules.risk_profiler import calculate_risk
from modules.response_engine import generate_response_recommendation


OLLAMA_BASE_URL = "http://localhost:11434"
GEN_MODEL = "llama3.1:8b"
EMBED_MODEL = "embeddinggemma"
CHROMA_PATH = "chroma_db"
COLLECTION_NAME = "sentinelops_knowledge"


def load_alerts(alerts_path: str) -> list[dict]:
    with open(alerts_path, "r") as file:
        return json.load(file)


def load_logs(logs_path: str) -> pd.DataFrame:
    df = pd.read_csv(logs_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def get_embedding(text: str) -> list[float]:
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()["embedding"]


def retrieve_context(query_text: str, n_results: int = 3) -> list[str]:
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_collection(COLLECTION_NAME)

    query_embedding = get_embedding(query_text)

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
    )

    return results["documents"][0] if results["documents"] else []


def build_investigation_context(alert: dict, logs: pd.DataFrame) -> dict:
    explanation = explain_impossible_travel(alert, logs)
    false_positive = score_false_positive(alert, logs)
    timeline = build_timeline(alert, logs)
    risk = calculate_risk(alert, logs)
    response = generate_response_recommendation(alert, logs)

    timeline_records = timeline[
        ["timestamp", "event_type", "location", "device_id", "result"]
    ].copy()
    timeline_records["timestamp"] = timeline_records["timestamp"].astype(str)

    return {
        "alert": alert,
        "explanation": explanation,
        "false_positive": false_positive,
        "risk": risk,
        "response": response,
        "timeline": timeline_records.to_dict(orient="records"),
    }


def generate_ai_summary(context: dict, retrieved_docs: list[str]) -> str:
    prompt = f"""
You are a security analyst assistant inside SentinelOps.

Use the investigation data and retrieved security notes below to write a concise,
grounded investigation summary.

Rules:
- Base your summary only on the provided context.
- Do not invent facts.
- Mention whether the alert appears suspicious or possibly benign.
- Mention the key reasons.
- Mention the recommended action.
- Keep it under 200 words.

Retrieved security notes:
{chr(10).join(retrieved_docs)}

Investigation context:
{json.dumps(context, indent=2)}

Return a plain-English investigation summary.
"""

    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json={
            "model": GEN_MODEL,
            "prompt": prompt,
            "stream": False,
        },
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["response"].strip()


def main() -> None:
    alerts = load_alerts("data/alerts.json")
    logs = load_logs("data/normalized_auth_logs.csv")

    if not alerts:
        print("No alerts found.")
        return

    first_alert = alerts[0]
    context = build_investigation_context(first_alert, logs)

    query_text = (
        f"{first_alert['alert_type']} for user {first_alert['user']} "
        f"with trigger reason: {first_alert['trigger_reason']}"
    )
    retrieved_docs = retrieve_context(query_text)
    summary = generate_ai_summary(context, retrieved_docs)

    print("\nAI Investigation Summary")
    print("-" * 60)
    print(summary)


if __name__ == "__main__":
    main()
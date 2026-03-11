import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
import json

from modules.alert_explainer import explain_impossible_travel
from modules.false_positive_checker import score_false_positive
from modules.timeline_builder import build_timeline
from modules.risk_profiler import calculate_risk
from modules.response_engine import generate_response_recommendation


st.set_page_config(page_title="SentinelOps", layout="wide")

st.title("SentinelOps Security Investigation Toolkit")

st.sidebar.header("Data Sources")

logs_path = "data/normalized_auth_logs.csv"
alerts_path = "data/alerts.json"

logs = pd.read_csv(logs_path)
logs["timestamp"] = pd.to_datetime(logs["timestamp"])

with open(alerts_path, "r") as f:
    alerts = json.load(f)

alert_ids = [a["alert_id"] for a in alerts]

selected_alert_id = st.sidebar.selectbox("Select Alert", alert_ids)

selected_alert = next(a for a in alerts if a["alert_id"] == selected_alert_id)

st.header("Alert Overview")

st.write(selected_alert)

if st.button("Run Investigation"):

    st.header("Alert Explanation")

    explanation = explain_impossible_travel(selected_alert, logs)
    st.json(explanation)

    st.header("False Positive Analysis")

    fp = score_false_positive(selected_alert, logs)
    st.json(fp)

    st.header("Timeline")

    timeline = build_timeline(selected_alert, logs)
    st.dataframe(timeline)

    st.header("Risk Profile")

    risk = calculate_risk(selected_alert, logs)
    st.json(risk)

    st.header("Response Recommendation")

    response = generate_response_recommendation(selected_alert, logs)
    st.json(response)
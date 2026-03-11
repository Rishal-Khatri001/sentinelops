import json
import pandas as pd


SUSPICIOUS_IP_PREFIXES = [
    "185.",
    "91.",
    "103."
]


def load_alerts(alerts_path: str) -> list[dict]:
    with open(alerts_path, "r") as file:
        return json.load(file)


def load_logs(logs_path: str) -> pd.DataFrame:
    df = pd.read_csv(logs_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def get_alert_event(logs: pd.DataFrame, user: str, alert_time: pd.Timestamp):
    matches = logs[
        (logs["user"] == user)
        & (logs["timestamp"] == alert_time)
        & (logs["event_type"] == "login")
    ]

    if matches.empty:
        return None

    return matches.iloc[0]


def get_prior_event(logs: pd.DataFrame, user: str, alert_time: pd.Timestamp):
    matches = logs[
        (logs["user"] == user)
        & (logs["timestamp"] < alert_time)
        & (logs["event_type"] == "login")
        & (logs["result"] == "success")
    ].sort_values("timestamp")

    if matches.empty:
        return None

    return matches.iloc[-1]


def ip_is_suspicious(ip: str) -> bool:
    for prefix in SUSPICIOUS_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def calculate_risk(alert: dict, logs: pd.DataFrame) -> dict:
    user = alert["user"]
    alert_time = pd.to_datetime(alert["timestamp"])

    alert_event = get_alert_event(logs, user, alert_time)
    prior_event = get_prior_event(logs, user, alert_time)

    if alert_event is None:
        return {"error": "Alert event not found in logs"}

    user_score = 50
    device_score = 40
    ip_score = 40

    indicators = []

    if prior_event is not None:
        if alert_event["location"] != prior_event["location"]:
            user_score += 20
            indicators.append("Cross-border login detected")

        if alert_event["device_id"] != prior_event["device_id"]:
            device_score += 30
            indicators.append("New device observed")

    if ip_is_suspicious(alert_event["ip_address"]):
        ip_score += 40
        indicators.append("Suspicious IP address used")

    user_score = min(user_score, 100)
    device_score = min(device_score, 100)
    ip_score = min(ip_score, 100)

    return {
        "user": user,
        "user_risk_score": user_score,
        "device_risk_score": device_score,
        "ip_risk_score": ip_score,
        "indicators": indicators
    }


def print_risk(result: dict):
    print("\nEntity Risk Profile")
    print("-" * 60)

    if "error" in result:
        print(result["error"])
        return

    print(f"User: {result['user']}")
    print()

    print(f"User Risk Score: {result['user_risk_score']}")
    print(f"Device Risk Score: {result['device_risk_score']}")
    print(f"IP Risk Score: {result['ip_risk_score']}")
    print()

    print("Indicators")
    for indicator in result["indicators"]:
        print(f"- {indicator}")


def main():
    alerts = load_alerts("data/alerts.json")
    logs = load_logs("data/normalized_auth_logs.csv")

    first_alert = alerts[0]

    result = calculate_risk(first_alert, logs)

    print_risk(result)


if __name__ == "__main__":
    main()
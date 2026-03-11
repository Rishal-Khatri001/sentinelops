import json
import pandas as pd


def load_alerts(alerts_path: str) -> list[dict]:
    with open(alerts_path, "r") as file:
        return json.load(file)


def load_logs(logs_path: str) -> pd.DataFrame:
    df = pd.read_csv(logs_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def get_prior_login(logs: pd.DataFrame, user: str, alert_time: pd.Timestamp) -> pd.Series | None:
    user_logins = logs[
        (logs["user"] == user)
        & (logs["event_type"] == "login")
        & (logs["result"] == "success")
        & (logs["timestamp"] < alert_time)
    ].sort_values("timestamp")

    if user_logins.empty:
        return None

    return user_logins.iloc[-1]


def get_alert_login(logs: pd.DataFrame, user: str, alert_time: pd.Timestamp) -> pd.Series | None:
    matches = logs[
        (logs["user"] == user)
        & (logs["event_type"] == "login")
        & (logs["result"] == "success")
        & (logs["timestamp"] == alert_time)
    ]

    if matches.empty:
        return None

    return matches.iloc[0]


def explain_impossible_travel(alert: dict, logs: pd.DataFrame) -> dict:
    user = alert["user"]
    alert_time = pd.to_datetime(alert["timestamp"])

    alert_event = get_alert_login(logs, user, alert_time)
    prior_event = get_prior_login(logs, user, alert_time)

    if alert_event is None:
        return {
            "alert_id": alert["alert_id"],
            "alert_type": alert["alert_type"],
            "user": user,
            "error": "No matching alert login event found in normalized logs.",
        }

    if prior_event is None:
        return {
            "alert_id": alert["alert_id"],
            "alert_type": alert["alert_type"],
            "user": user,
            "error": "No prior successful login found for comparison.",
        }

    time_diff_minutes = int((alert_event["timestamp"] - prior_event["timestamp"]).total_seconds() / 60)
    new_device = alert_event["device_id"] != prior_event["device_id"]
    vpn_detected = alert_event["vpn_flag"] == "true"

    risk_summary = (
        "This pattern is consistent with impossible travel and may indicate credential misuse or account compromise."
    )

    if vpn_detected and not new_device:
        risk_summary = (
            "This pattern triggered an impossible travel alert, but the presence of VPN usage and a known device may indicate a benign explanation."
        )

    explanation = (
        f"This alert triggered because {user} logged in from {prior_event['location']} "
        f"and then {alert_event['location']} within {time_diff_minutes} minutes."
    )

    return {
        "alert_id": alert["alert_id"],
        "alert_type": alert["alert_type"],
        "user": user,
        "alert_timestamp": str(alert_time),
        "explanation": explanation,
        "prior_location": prior_event["location"],
        "alert_location": alert_event["location"],
        "time_difference_minutes": time_diff_minutes,
        "prior_device_id": prior_event["device_id"],
        "alert_device_id": alert_event["device_id"],
        "new_device_observed": new_device,
        "vpn_detected": vpn_detected,
        "risk_summary": risk_summary,
    }


def print_explanation(result: dict) -> None:
    print("\nAlert Explanation")
    print("-" * 60)

    if "error" in result:
        print(f"User: {result['user']}")
        print(f"Error: {result['error']}")
        return

    print(f"Alert ID: {result['alert_id']}")
    print(f"User: {result['user']}")
    print(f"Type: {result['alert_type']}")
    print(f"Time: {result['alert_timestamp']}")
    print()
    print(result["explanation"])
    print()
    print("Key Indicators")
    print(f"- Previous location: {result['prior_location']}")
    print(f"- New location: {result['alert_location']}")
    print(f"- Time difference: {result['time_difference_minutes']} minutes")
    print(f"- Prior device: {result['prior_device_id']}")
    print(f"- Alert device: {result['alert_device_id']}")
    print(f"- New device observed: {result['new_device_observed']}")
    print(f"- VPN detected: {result['vpn_detected']}")
    print()
    print("Risk Assessment")
    print(result["risk_summary"])


def main() -> None:
    alerts = load_alerts("data/alerts.json")
    logs = load_logs("data/normalized_auth_logs.csv")

    if not alerts:
        print("No alerts found.")
        return

    first_alert = alerts[0]
    result = explain_impossible_travel(first_alert, logs)
    print_explanation(result)


if __name__ == "__main__":
    main()
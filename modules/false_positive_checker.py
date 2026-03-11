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


def score_false_positive(alert: dict, logs: pd.DataFrame) -> dict:
    user = alert["user"]
    alert_time = pd.to_datetime(alert["timestamp"])

    alert_event = get_alert_login(logs, user, alert_time)
    prior_event = get_prior_login(logs, user, alert_time)

    if alert_event is None or prior_event is None:
        return {
            "alert_id": alert["alert_id"],
            "user": user,
            "error": "Could not find enough login history to evaluate false positive likelihood.",
        }

    score = 0
    evidence = []

    same_device = alert_event["device_id"] == prior_event["device_id"]
    same_os = alert_event["operating_system"] == prior_event["operating_system"]
    same_browser = alert_event["browser"] == prior_event["browser"]
    vpn_detected = alert_event["vpn_flag"] == "true"

    prior_country = str(prior_event["location"]).split(",")[-1].strip()
    alert_country = str(alert_event["location"]).split(",")[-1].strip()
    same_country = prior_country == alert_country

    if vpn_detected:
        score += 35
        evidence.append("VPN usage detected on the alert event")

    if same_device:
        score += 25
        evidence.append("Login came from a previously known device")

    if same_os:
        score += 10
        evidence.append("Operating system matches prior successful login")

    if same_browser:
        score += 10
        evidence.append("Browser matches prior successful login")

    if same_country:
        score += 10
        evidence.append("Location change remained within the same country")

    if not same_device:
        score -= 20
        evidence.append("New device observed, reducing false positive confidence")

    if not same_country:
        score -= 15
        evidence.append("Cross-border location change increases suspicion")

    score = max(0, min(score, 100))

    if score >= 70:
        likelihood = "High"
        assessment = "This alert is likely a false positive or benign travel anomaly."
    elif score >= 40:
        likelihood = "Moderate"
        assessment = "This alert has some benign indicators, but still requires analyst review."
    else:
        likelihood = "Low"
        assessment = "This alert has limited false positive evidence and appears more suspicious."

    return {
        "alert_id": alert["alert_id"],
        "user": user,
        "false_positive_score": score,
        "likelihood": likelihood,
        "vpn_detected": vpn_detected,
        "same_device": same_device,
        "same_os": same_os,
        "same_browser": same_browser,
        "same_country": same_country,
        "evidence": evidence,
        "assessment": assessment,
    }


def print_false_positive_result(result: dict) -> None:
    print("\nFalse Positive Check")
    print("-" * 60)

    if "error" in result:
        print(f"User: {result['user']}")
        print(f"Error: {result['error']}")
        return

    print(f"Alert ID: {result['alert_id']}")
    print(f"User: {result['user']}")
    print(f"False Positive Score: {result['false_positive_score']} / 100")
    print(f"Likelihood: {result['likelihood']}")
    print()
    print("Indicators")
    print(f"- VPN detected: {result['vpn_detected']}")
    print(f"- Same device: {result['same_device']}")
    print(f"- Same OS: {result['same_os']}")
    print(f"- Same browser: {result['same_browser']}")
    print(f"- Same country: {result['same_country']}")
    print()
    print("Evidence")
    for item in result["evidence"]:
        print(f"- {item}")
    print()
    print("Assessment")
    print(result["assessment"])


def main() -> None:
    alerts = load_alerts("data/alerts.json")
    logs = load_logs("data/normalized_auth_logs.csv")

    if not alerts:
        print("No alerts found.")
        return

    first_alert = alerts[0]
    result = score_false_positive(first_alert, logs)
    print_false_positive_result(result)


if __name__ == "__main__":
    main()
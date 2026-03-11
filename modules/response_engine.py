import json
import pandas as pd

try:
    from modules.false_positive_checker import score_false_positive
    from modules.risk_profiler import calculate_risk
except ModuleNotFoundError:
    # Allow running this file directly: `python modules/response_engine.py`
    from false_positive_checker import score_false_positive
    from risk_profiler import calculate_risk


def load_alerts(alerts_path: str) -> list[dict]:
    with open(alerts_path, "r") as file:
        return json.load(file)


def load_logs(logs_path: str) -> pd.DataFrame:
    df = pd.read_csv(logs_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def generate_response_recommendation(alert: dict, logs: pd.DataFrame) -> dict:
    fp_result = score_false_positive(alert, logs)
    risk_result = calculate_risk(alert, logs)

    if "error" in fp_result:
        return {"error": fp_result["error"]}

    if "error" in risk_result:
        return {"error": risk_result["error"]}

    avg_risk = (
        risk_result["user_risk_score"]
        + risk_result["device_risk_score"]
        + risk_result["ip_risk_score"]
    ) / 3

    false_positive_score = fp_result["false_positive_score"]

    primary_action = ""
    secondary_actions = []
    rationale = ""

    if avg_risk >= 70 and false_positive_score < 40:
        primary_action = "Escalate alert and contain the account"
        secondary_actions = [
            "Force password reset",
            "Revoke active sessions or tokens",
            "Investigate the new device",
            "Review additional login activity for the user",
        ]
        rationale = (
            "The alert shows high overall risk with limited false positive evidence."
        )

    elif avg_risk >= 50 and false_positive_score < 70:
        primary_action = "Investigate further before containment"
        secondary_actions = [
            "Review user login history",
            "Validate device and IP reputation",
            "Check for MFA anomalies",
            "Monitor for repeated suspicious activity",
        ]
        rationale = (
            "The alert has meaningful risk indicators, but additional analyst review is warranted."
        )

    else:
        primary_action = "Monitor or close as likely benign"
        secondary_actions = [
            "Document benign indicators",
            "Monitor the account for future anomalies",
        ]
        rationale = (
            "The alert contains enough benign evidence to reduce immediate concern."
        )

    return {
        "alert_id": alert["alert_id"],
        "user": alert["user"],
        "average_risk_score": round(avg_risk, 2),
        "false_positive_score": false_positive_score,
        "primary_action": primary_action,
        "secondary_actions": secondary_actions,
        "rationale": rationale,
    }


def print_recommendation(result: dict) -> None:
    print("\nResponse Recommendation")
    print("-" * 60)

    if "error" in result:
        print(f"Error: {result['error']}")
        return

    print(f"Alert ID: {result['alert_id']}")
    print(f"User: {result['user']}")
    print(f"Average Risk Score: {result['average_risk_score']}")
    print(f"False Positive Score: {result['false_positive_score']}")
    print()
    print("Primary Action")
    print(f"- {result['primary_action']}")
    print()
    print("Secondary Actions")
    for action in result["secondary_actions"]:
        print(f"- {action}")
    print()
    print("Rationale")
    print(result["rationale"])


def main() -> None:
    alerts = load_alerts("data/alerts.json")
    logs = load_logs("data/normalized_auth_logs.csv")

    if not alerts:
        print("No alerts found.")
        return

    first_alert = alerts[0]
    result = generate_response_recommendation(first_alert, logs)
    print_recommendation(result)


if __name__ == "__main__":
    main()

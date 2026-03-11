import json
import pandas as pd


def load_alerts(alerts_path: str) -> list[dict]:
    with open(alerts_path, "r") as file:
        return json.load(file)


def load_logs(logs_path: str) -> pd.DataFrame:
    df = pd.read_csv(logs_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def build_timeline(alert: dict, logs: pd.DataFrame, window_minutes: int = 30) -> pd.DataFrame:
    user = alert["user"]
    alert_time = pd.to_datetime(alert["timestamp"])

    start_time = alert_time - pd.Timedelta(minutes=window_minutes)
    end_time = alert_time + pd.Timedelta(minutes=window_minutes)

    timeline = logs[
        (logs["user"] == user)
        & (logs["timestamp"] >= start_time)
        & (logs["timestamp"] <= end_time)
    ].sort_values("timestamp")

    return timeline


def print_timeline(alert: dict, timeline: pd.DataFrame) -> None:
    print("\nInvestigation Timeline")
    print("-" * 60)
    print(f"Alert ID: {alert['alert_id']}")
    print(f"User: {alert['user']}")
    print()

    if timeline.empty:
        print("No events found in the investigation window.")
        return

    for _, row in timeline.iterrows():
        print(
            f"{row['timestamp']} | "
            f"{row['event_type']} | "
            f"{row['location']} | "
            f"{row['device_id']} | "
            f"{row['result']}"
        )


def main() -> None:
    alerts = load_alerts("data/alerts.json")
    logs = load_logs("data/normalized_auth_logs.csv")

    if not alerts:
        print("No alerts found.")
        return

    first_alert = alerts[0]
    timeline = build_timeline(first_alert, logs)

    print_timeline(first_alert, timeline)


if __name__ == "__main__":
    main()
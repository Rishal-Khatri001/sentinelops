import csv
import json
import random
from datetime import datetime, timedelta

USERS = [
    "jdoe@company.com",
    "asmith@company.com",
    "rkhatri@company.com",
    "bjohnson@company.com",
    "mlee@company.com",
]

USER_BASELINES = {
    "jdoe@company.com": {
        "location": "Boston, US",
        "device_id": "device_101",
        "device_type": "laptop",
        "operating_system": "Windows",
        "browser": "Chrome",
        "application": "Office365",
    },
    "asmith@company.com": {
        "location": "New York, US",
        "device_id": "device_102",
        "device_type": "laptop",
        "operating_system": "MacOS",
        "browser": "Safari",
        "application": "Office365",
    },
    "rkhatri@company.com": {
        "location": "Durham, US",
        "device_id": "device_103",
        "device_type": "laptop",
        "operating_system": "Windows",
        "browser": "Chrome",
        "application": "AzurePortal",
    },
    "bjohnson@company.com": {
        "location": "Chicago, US",
        "device_id": "device_104",
        "device_type": "mobile",
        "operating_system": "iOS",
        "browser": "Safari",
        "application": "Office365",
    },
    "mlee@company.com": {
        "location": "Seattle, US",
        "device_id": "device_105",
        "device_type": "laptop",
        "operating_system": "Windows",
        "browser": "Edge",
        "application": "VPNPortal",
    },
}

NORMAL_IPS = [
    "52.14.22.11",
    "44.201.19.10",
    "18.207.44.91",
    "3.91.201.18",
    "34.226.10.55",
]

SUSPICIOUS_IPS = [
    "185.220.101.1",
    "91.214.124.22",
    "103.154.232.8",
]

FOREIGN_LOCATIONS = [
    "Berlin, DE",
    "Moscow, RU",
    "Tokyo, JP",
    "London, UK",
]

VPN_LOCATIONS = [
    "Ashburn, US",
    "Dallas, US",
    "Amsterdam, NL",
]

CSV_FIELDS = [
    "timestamp",
    "user",
    "ip_address",
    "location",
    "device_id",
    "device_type",
    "operating_system",
    "browser",
    "application",
    "event_type",
    "result",
    "mfa_status",
    "vpn_flag",
]


def random_time(start_time: datetime, max_minutes: int) -> datetime:
    return start_time + timedelta(minutes=random.randint(0, max_minutes))


def make_event(
    timestamp: datetime,
    user: str,
    ip_address: str,
    location: str,
    device_id: str,
    device_type: str,
    operating_system: str,
    browser: str,
    application: str,
    event_type: str,
    result: str,
    mfa_status: str,
    vpn_flag: bool,
) -> dict:
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "ip_address": ip_address,
        "location": location,
        "device_id": device_id,
        "device_type": device_type,
        "operating_system": operating_system,
        "browser": browser,
        "application": application,
        "event_type": event_type,
        "result": result,
        "mfa_status": mfa_status,
        "vpn_flag": str(vpn_flag).lower(),
    }


def generate_normal_activity(start_time: datetime, count: int) -> list[dict]:
    events = []

    for _ in range(count):
        user = random.choice(USERS)
        baseline = USER_BASELINES[user]
        event_time = random_time(start_time, 60 * 24 * 5)

        login_event = make_event(
            timestamp=event_time,
            user=user,
            ip_address=random.choice(NORMAL_IPS),
            location=baseline["location"],
            device_id=baseline["device_id"],
            device_type=baseline["device_type"],
            operating_system=baseline["operating_system"],
            browser=baseline["browser"],
            application=baseline["application"],
            event_type="login",
            result="success",
            mfa_status="passed",
            vpn_flag=False,
        )
        events.append(login_event)

        if random.random() < 0.6:
            token_event = make_event(
                timestamp=event_time + timedelta(minutes=1),
                user=user,
                ip_address=login_event["ip_address"],
                location=baseline["location"],
                device_id=baseline["device_id"],
                device_type=baseline["device_type"],
                operating_system=baseline["operating_system"],
                browser=baseline["browser"],
                application=baseline["application"],
                event_type="token_issue",
                result="success",
                mfa_status="passed",
                vpn_flag=False,
            )
            events.append(token_event)

    return events


def generate_impossible_travel(start_time: datetime, count: int) -> tuple[list[dict], list[dict]]:
    events = []
    alerts = []

    for i in range(count):
        user = random.choice(USERS)
        baseline = USER_BASELINES[user]
        first_time = random_time(start_time, 60 * 24 * 3)
        second_time = first_time + timedelta(minutes=random.randint(2, 5))
        foreign_location = random.choice(FOREIGN_LOCATIONS)

        first_event = make_event(
            timestamp=first_time,
            user=user,
            ip_address=random.choice(NORMAL_IPS),
            location=baseline["location"],
            device_id=baseline["device_id"],
            device_type=baseline["device_type"],
            operating_system=baseline["operating_system"],
            browser=baseline["browser"],
            application=baseline["application"],
            event_type="login",
            result="success",
            mfa_status="passed",
            vpn_flag=False,
        )

        second_event = make_event(
            timestamp=second_time,
            user=user,
            ip_address=random.choice(SUSPICIOUS_IPS),
            location=foreign_location,
            device_id=f"device_{random.randint(300, 999)}",
            device_type="laptop",
            operating_system=baseline["operating_system"],
            browser=baseline["browser"],
            application=baseline["application"],
            event_type="login",
            result="success",
            mfa_status="passed",
            vpn_flag=False,
        )

        events.extend([first_event, second_event])

        alerts.append(
            {
                "alert_id": f"A{i+1:03}",
                "alert_type": "impossible_travel",
                "user": user,
                "timestamp": second_event["timestamp"],
                "trigger_reason": (
                    f"Login from {baseline['location']} followed by {foreign_location} "
                    f"within minutes"
                ),
            }
        )

    return events, alerts


def generate_vpn_false_positives(start_time: datetime, count: int) -> tuple[list[dict], list[dict]]:
    events = []
    alerts = []

    for i in range(count):
        user = random.choice(USERS)
        baseline = USER_BASELINES[user]
        first_time = random_time(start_time, 60 * 24 * 3)
        second_time = first_time + timedelta(minutes=random.randint(2, 5))
        vpn_location = random.choice(VPN_LOCATIONS)

        first_event = make_event(
            timestamp=first_time,
            user=user,
            ip_address=random.choice(NORMAL_IPS),
            location=baseline["location"],
            device_id=baseline["device_id"],
            device_type=baseline["device_type"],
            operating_system=baseline["operating_system"],
            browser=baseline["browser"],
            application=baseline["application"],
            event_type="login",
            result="success",
            mfa_status="passed",
            vpn_flag=False,
        )

        second_event = make_event(
            timestamp=second_time,
            user=user,
            ip_address=random.choice(NORMAL_IPS),
            location=vpn_location,
            device_id=baseline["device_id"],
            device_type=baseline["device_type"],
            operating_system=baseline["operating_system"],
            browser=baseline["browser"],
            application="VPNPortal",
            event_type="login",
            result="success",
            mfa_status="passed",
            vpn_flag=True,
        )

        events.extend([first_event, second_event])

        alerts.append(
            {
                "alert_id": f"VPN{i+1:03}",
                "alert_type": "impossible_travel",
                "user": user,
                "timestamp": second_event["timestamp"],
                "trigger_reason": (
                    f"Location change from {baseline['location']} to {vpn_location}; "
                    f"likely VPN-related"
                ),
            }
        )

    return events, alerts


def generate_failed_logins(start_time: datetime, count: int) -> list[dict]:
    events = []

    for _ in range(count):
        user = random.choice(USERS)
        baseline = USER_BASELINES[user]
        base_time = random_time(start_time, 60 * 24 * 4)
        suspicious_ip = random.choice(SUSPICIOUS_IPS)

        for minute_offset in range(3):
            failed_event = make_event(
                timestamp=base_time + timedelta(minutes=minute_offset),
                user=user,
                ip_address=suspicious_ip,
                location=random.choice(FOREIGN_LOCATIONS),
                device_id=f"device_{random.randint(400, 999)}",
                device_type="laptop",
                operating_system="Windows",
                browser="Chrome",
                application=baseline["application"],
                event_type="login",
                result="failure",
                mfa_status="failed",
                vpn_flag=False,
            )
            events.append(failed_event)

        success_event = make_event(
            timestamp=base_time + timedelta(minutes=4),
            user=user,
            ip_address=suspicious_ip,
            location=random.choice(FOREIGN_LOCATIONS),
            device_id=f"device_{random.randint(400, 999)}",
            device_type="laptop",
            operating_system="Windows",
            browser="Chrome",
            application=baseline["application"],
            event_type="login",
            result="success",
            mfa_status="passed",
            vpn_flag=False,
        )
        events.append(success_event)

    return events


def write_csv(filepath: str, rows: list[dict]) -> None:
    with open(filepath, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(filepath: str, data: list[dict]) -> None:
    with open(filepath, "w") as file:
        json.dump(data, file, indent=2)


def main() -> None:
    random.seed(42)
    start_time = datetime(2026, 3, 1, 8, 0, 0)

    normal_events = generate_normal_activity(start_time, 180)
    impossible_travel_events, impossible_travel_alerts = generate_impossible_travel(start_time, 12)
    vpn_events, vpn_alerts = generate_vpn_false_positives(start_time, 8)
    failed_login_events = generate_failed_logins(start_time, 10)

    all_events = normal_events + impossible_travel_events + vpn_events + failed_login_events
    all_events.sort(key=lambda x: x["timestamp"])

    all_alerts = impossible_travel_alerts + vpn_alerts
    all_alerts.sort(key=lambda x: x["timestamp"])

    write_csv("data/auth_logs.csv", all_events)
    write_json("data/alerts.json", all_alerts)

    print(f"Generated {len(all_events)} auth log events.")
    print(f"Generated {len(all_alerts)} alerts.")
    print("Files written to data/auth_logs.csv and data/alerts.json")


if __name__ == "__main__":
    main()
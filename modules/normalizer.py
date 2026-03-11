import pandas as pd


OS_MAP = {
    "windows": "Windows",
    "win11": "Windows",
    "win10": "Windows",
    "macos": "MacOS",
    "mac": "MacOS",
    "ios": "iOS",
}

BROWSER_MAP = {
    "chrome": "Chrome",
    "google chrome": "Chrome",
    "safari": "Safari",
    "edge": "Edge",
    "microsoft edge": "Edge",
}

DEVICE_TYPE_MAP = {
    "laptop": "laptop",
    "notebook": "laptop",
    "mobile": "mobile",
    "phone": "mobile",
    "tablet": "tablet",
}

EVENT_TYPE_MAP = {
    "login": "login",
    "logon": "login",
    "token_issue": "token_issue",
    "token": "token_issue",
}

RESULT_MAP = {
    "success": "success",
    "succeeded": "success",
    "failure": "failure",
    "failed": "failure",
}

MFA_MAP = {
    "passed": "passed",
    "success": "passed",
    "failed": "failed",
    "not_required": "not_required",
}

VPN_MAP = {
    "true": "true",
    "false": "false",
    "1": "true",
    "0": "false",
    "yes": "true",
    "no": "false",
}


def normalize_value(value: str, mapping: dict, default: str | None = None) -> str | None:
    if pd.isna(value):
        return default
    cleaned = str(value).strip().lower()
    return mapping.get(cleaned, value if default is None else default)


def normalize_auth_logs(input_path: str, output_path: str) -> pd.DataFrame:
    df = pd.read_csv(input_path)

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df["operating_system"] = df["operating_system"].apply(
        lambda x: normalize_value(x, OS_MAP, "Unknown")
    )
    df["browser"] = df["browser"].apply(
        lambda x: normalize_value(x, BROWSER_MAP, "Unknown")
    )
    df["device_type"] = df["device_type"].apply(
        lambda x: normalize_value(x, DEVICE_TYPE_MAP, "unknown")
    )
    df["event_type"] = df["event_type"].apply(
        lambda x: normalize_value(x, EVENT_TYPE_MAP, "unknown")
    )
    df["result"] = df["result"].apply(
        lambda x: normalize_value(x, RESULT_MAP, "unknown")
    )
    df["mfa_status"] = df["mfa_status"].apply(
        lambda x: normalize_value(x, MFA_MAP, "unknown")
    )
    df["vpn_flag"] = df["vpn_flag"].apply(
        lambda x: normalize_value(x, VPN_MAP, "false")
    )

    df["location"] = df["location"].astype(str).str.strip()
    df["user"] = df["user"].astype(str).str.strip().str.lower()
    df["application"] = df["application"].astype(str).str.strip()
    df["device_id"] = df["device_id"].astype(str).str.strip()
    df["ip_address"] = df["ip_address"].astype(str).str.strip()

    df = df.sort_values("timestamp").reset_index(drop=True)

    df.to_csv(output_path, index=False)
    return df


def main() -> None:
    input_path = "data/auth_logs.csv"
    output_path = "data/normalized_auth_logs.csv"

    df = normalize_auth_logs(input_path, output_path)

    print(f"Normalized {len(df)} auth log events.")
    print(f"Output written to {output_path}")
    print("\nSample rows:")
    print(df.head(5).to_string(index=False))


if __name__ == "__main__":
    main()
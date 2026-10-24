import pandas as pd
import numpy as np
from datetime import timedelta
from config import WORK_HOUR_START, WORK_HOUR_END, SENSITIVE_RESOURCES


def extract_features(logs_df: pd.DataFrame, window_hours: int = 24) -> pd.DataFrame:
    """
    Group logs by user_id and fixed daily windows, then extract behavioral features.
    Returns DataFrame with user_id, window_start, window_end, + feature columns.
    """
    if logs_df.empty:
        return pd.DataFrame()

    logs_df = logs_df.copy()
    logs_df["timestamp"] = pd.to_datetime(logs_df["timestamp"], errors="coerce")
    logs_df = logs_df.dropna(subset=["timestamp"])

    # Create day-level window key
    logs_df["window_start"] = logs_df["timestamp"].dt.floor(f"{window_hours}h")
    logs_df["window_end"] = logs_df["window_start"] + timedelta(hours=window_hours)

    records = []
    for (user_id, window_start), grp in logs_df.groupby(["user_id", "window_start"]):
        window_end = window_start + timedelta(hours=window_hours)

        # Hour of day (mean login hour)
        login_events = grp[grp["event_type"] == "login"]
        hour_of_day = login_events["timestamp"].dt.hour.mean() if not login_events.empty else 12.0

        # Fraction of events outside work hours
        total = len(grp)
        off_hours_mask = (grp["timestamp"].dt.hour < WORK_HOUR_START) | (grp["timestamp"].dt.hour >= WORK_HOUR_END)
        is_off_hours = off_hours_mask.sum() / total if total > 0 else 0.0

        # Day of week (mode)
        day_of_week = grp["timestamp"].dt.dayofweek.mode()
        day_of_week = int(day_of_week.iloc[0]) if not day_of_week.empty else 0

        # Weekend flag
        is_weekend = 1 if grp["timestamp"].dt.dayofweek.isin([5, 6]).any() else 0

        # Failed login count
        failed_login_count = int((grp["event_type"] == "failed_login").sum())

        # File access count
        file_access_count = int((grp["event_type"] == "file_access").sum())

        # Sensitive file accesses
        sensitive_mask = grp["resource"].isin(SENSITIVE_RESOURCES)
        sensitive_file_count = int(sensitive_mask.sum())

        # Session duration: diff between last logout and first login (minutes)
        logins = grp[grp["event_type"] == "login"]["timestamp"]
        logouts = grp[grp["event_type"] == "logout"]["timestamp"]
        if not logins.empty and not logouts.empty:
            session_duration_minutes = (logouts.max() - logins.min()).total_seconds() / 60.0
        elif not logins.empty:
            session_duration_minutes = (grp["timestamp"].max() - logins.min()).total_seconds() / 60.0
        else:
            session_duration_minutes = 0.0
        session_duration_minutes = max(0.0, session_duration_minutes)

        # Login count
        login_count = int((grp["event_type"] == "login").sum())

        # Unique IPs
        unique_ips = int(grp["ip_address"].nunique())

        records.append({
            "user_id": user_id,
            "window_start": window_start,
            "window_end": window_end,
            "hour_of_day": round(hour_of_day, 2),
            "is_off_hours": round(is_off_hours, 4),
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "failed_login_count": failed_login_count,
            "file_access_count": file_access_count,
            "sensitive_file_count": sensitive_file_count,
            "session_duration_minutes": round(session_duration_minutes, 2),
            "login_count": login_count,
            "unique_ips": unique_ips,
        })

    return pd.DataFrame(records)


def get_user_profile(logs_df: pd.DataFrame, user_id: str) -> dict:
    """Return baseline stats (mean ± std) for each feature for a given user."""
    user_logs = logs_df[logs_df["user_id"] == user_id]
    if user_logs.empty:
        return {}
    features_df = extract_features(user_logs)
    if features_df.empty:
        return {}

    from config import FEATURES
    profile = {}
    for col in FEATURES:
        if col in features_df.columns:
            profile[col] = {
                "mean": round(float(features_df[col].mean()), 3),
                "std": round(float(features_df[col].std()), 3),
                "min": round(float(features_df[col].min()), 3),
                "max": round(float(features_df[col].max()), 3),
            }
    return profile

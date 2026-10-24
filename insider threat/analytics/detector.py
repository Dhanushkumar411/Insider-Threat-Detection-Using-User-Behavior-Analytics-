import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest

from config import (
    CONTAMINATION, N_ESTIMATORS, RANDOM_STATE,
    THRESHOLD_HIGH, THRESHOLD_MEDIUM, FEATURES,
)
from analytics.feature_engineer import extract_features
from database.db_manager import (
    get_all_logs, insert_anomaly_score, insert_alert, get_all_users,
)


class ThreatDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=RANDOM_STATE,
        )
        self.is_trained = False
        self.feature_cols = FEATURES

    def train(self, features_df: pd.DataFrame):
        if features_df.empty or len(features_df) < 5:
            return
        X = features_df[self.feature_cols].fillna(0)
        self.model.fit(X)
        self.is_trained = True

    def predict(self, features_df: pd.DataFrame) -> pd.DataFrame:
        if features_df.empty:
            return features_df
        result = features_df.copy()
        X = result[self.feature_cols].fillna(0)

        if not self.is_trained:
            self.model.fit(X)
            self.is_trained = True

        result["anomaly_score"] = self.model.decision_function(X)
        result["is_anomaly"] = (self.model.predict(X) == -1).astype(int)

        def get_severity(score):
            if score <= THRESHOLD_HIGH:
                return "high"
            elif score <= THRESHOLD_MEDIUM:
                return "medium"
            return "normal"

        result["severity"] = result["anomaly_score"].apply(get_severity)
        return result

    def explain(self, row: pd.Series) -> str:
        reasons = []

        if row.get("is_off_hours", 0) > 0.3:
            reasons.append("Off-hours activity detected")
        if row.get("failed_login_count", 0) >= 5:
            reasons.append(f"Excessive failed logins ({int(row['failed_login_count'])})")
        elif row.get("failed_login_count", 0) >= 3:
            reasons.append(f"Multiple failed logins ({int(row['failed_login_count'])})")
        if row.get("file_access_count", 0) >= 40:
            reasons.append(f"Mass file access ({int(row['file_access_count'])} files)")
        elif row.get("file_access_count", 0) >= 25:
            reasons.append(f"Elevated file access ({int(row['file_access_count'])} files)")
        if row.get("sensitive_file_count", 0) >= 3:
            reasons.append(f"Sensitive resource access ({int(row['sensitive_file_count'])} files)")
        if row.get("unique_ips", 0) >= 3:
            reasons.append(f"Access from {int(row['unique_ips'])} different IPs")
        if row.get("is_weekend", 0) == 1 and row.get("file_access_count", 0) > 5:
            reasons.append("Unusual weekend activity")
        hour = row.get("hour_of_day", 12)
        if hour < 6 or hour >= 22:
            reasons.append(f"Login at unusual hour ({hour:.0f}:00)")

        if not reasons:
            reasons.append("Statistical deviation from baseline behavior")

        return ". ".join(reasons) + "."

    def run_full_detection(self, db_manager_module=None) -> list:
        logs = get_all_logs()
        if not logs:
            return []

        logs_df = pd.DataFrame(logs)
        features_df = extract_features(logs_df)
        if features_df.empty:
            return []

        self.train(features_df)
        result_df = self.predict(features_df)

        alert_list = []
        for _, row in result_df.iterrows():
            feat_dict = {col: row[col] for col in self.feature_cols if col in row}
            insert_anomaly_score(
                user_id=row["user_id"],
                window_start=row["window_start"],
                window_end=row["window_end"],
                score=row["anomaly_score"],
                is_anomaly=int(row["is_anomaly"]),
                severity=row["severity"],
                features_dict=feat_dict,
            )

            if row["is_anomaly"] == 1 and row["severity"] in ("medium", "high"):
                explanation = self.explain(row)
                alert_type = _classify_alert_type(row)
                insert_alert(
                    user_id=row["user_id"],
                    alert_type=alert_type,
                    severity=row["severity"],
                    description=explanation,
                    timestamp=row["window_start"],
                )
                alert_list.append({
                    "user_id": row["user_id"],
                    "severity": row["severity"],
                    "description": explanation,
                    "score": float(row["anomaly_score"]),
                })

        print(f"[Detector] Processed {len(result_df)} windows — {len(alert_list)} alerts generated.")
        return alert_list

    def score_single_event(self, event_dict: dict, all_logs: list) -> dict:
        """Score a single new event by appending it to existing logs and re-predicting."""
        all_logs.append(event_dict)
        logs_df = pd.DataFrame(all_logs)
        features_df = extract_features(logs_df)
        if features_df.empty:
            return {"anomaly_score": 0.0, "is_anomaly": 0, "severity": "normal", "explanation": "Not enough data."}

        # Only score windows containing this user's latest window
        user_windows = features_df[features_df["user_id"] == event_dict["user_id"]]
        if user_windows.empty:
            return {"anomaly_score": 0.0, "is_anomaly": 0, "severity": "normal", "explanation": "No window found."}

        if not self.is_trained:
            self.train(features_df)

        result_df = self.predict(user_windows)
        latest = result_df.iloc[-1]
        explanation = self.explain(latest)
        return {
            "anomaly_score": round(float(latest["anomaly_score"]), 4),
            "is_anomaly": int(latest["is_anomaly"]),
            "severity": latest["severity"],
            "explanation": explanation,
        }


def _classify_alert_type(row: pd.Series) -> str:
    if row.get("failed_login_count", 0) >= 5:
        return "Brute Force Attempt"
    if row.get("is_off_hours", 0) > 0.5:
        return "Off-Hours Access"
    if row.get("file_access_count", 0) >= 40:
        return "Data Exfiltration Risk"
    if row.get("unique_ips", 0) >= 3:
        return "Suspicious IP Activity"
    if row.get("sensitive_file_count", 0) >= 3:
        return "Unauthorized Sensitive Access"
    return "Anomalous Behavior"

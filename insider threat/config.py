import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "insider_threat.db")

# Isolation Forest config
CONTAMINATION = 0.05
N_ESTIMATORS = 100
RANDOM_STATE = 42

# Alert severity thresholds (more negative = more anomalous)
THRESHOLD_HIGH = -0.15
THRESHOLD_MEDIUM = -0.05

# Working hours (24h format)
WORK_HOUR_START = 8
WORK_HOUR_END = 18

# Feature columns used by the model
FEATURES = [
    "hour_of_day",
    "is_off_hours",
    "day_of_week",
    "is_weekend",
    "failed_login_count",
    "file_access_count",
    "sensitive_file_count",
    "session_duration_minutes",
    "login_count",
    "unique_ips",
]

SENSITIVE_RESOURCES = [
    "/hr/payroll", "/finance/reports", "/admin/config",
    "/exec/strategy", "/legal/contracts", "/security/audit",
    "/db/customer_data", "/prod/deploy_keys",
]

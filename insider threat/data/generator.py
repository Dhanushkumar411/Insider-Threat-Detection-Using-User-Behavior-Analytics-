import random
import json
from datetime import datetime, timedelta
from config import SENSITIVE_RESOURCES
from database.db_manager import insert_user, insert_activity_log

random.seed(42)

DEPARTMENTS = {
    "Engineering": ["Software Engineer", "DevOps Engineer", "QA Engineer"],
    "Finance":     ["Financial Analyst", "Accountant", "CFO"],
    "HR":          ["HR Manager", "Recruiter", "HR Analyst"],
    "Legal":       ["Legal Counsel", "Paralegal"],
    "Executive":   ["CEO", "CTO", "VP Operations"],
}

DEPT_RESOURCES = {
    "Engineering": ["/repo/codebase", "/ci/pipelines", "/docs/api", "/jira/tickets", "/confluence/pages"],
    "Finance":     ["/finance/reports", "/finance/invoices", "/erp/dashboard", "/bank/statements"],
    "HR":          ["/hr/payroll", "/hr/employees", "/hr/benefits", "/recruitment/profiles"],
    "Legal":       ["/legal/contracts", "/legal/filings", "/compliance/reports"],
    "Executive":   ["/exec/strategy", "/board/presentations", "/kpi/dashboard", "/admin/config"],
}


def generate_users():
    users = []
    uid = 1
    for dept, roles in DEPARTMENTS.items():
        count = 2 if dept != "Executive" else 2
        for i in range(count):
            role = roles[i % len(roles)]
            user = {
                "user_id": f"U{uid:03d}",
                "username": f"{role.lower().replace(' ', '.')}_{uid}",
                "department": dept,
                "role": role,
            }
            users.append(user)
            uid += 1
    return users


def _rand_ip(base="192.168.1"):
    return f"{base}.{random.randint(2, 50)}"


def generate_normal_logs(users, days=30):
    logs = []
    base_date = datetime.utcnow() - timedelta(days=days)

    user_ips = {u["user_id"]: _rand_ip() for u in users}

    for user in users:
        uid = user["user_id"]
        dept = user["department"]
        resources = DEPT_RESOURCES.get(dept, ["/shared/docs"])
        ip = user_ips[uid]

        for day_offset in range(days):
            current_day = base_date + timedelta(days=day_offset)
            # Skip weekends for normal users (80% chance)
            if current_day.weekday() >= 5 and random.random() < 0.85:
                continue

            # Login time: 08:00 – 17:00
            login_hour = random.randint(8, 11)
            login_min = random.randint(0, 59)
            login_dt = current_day.replace(hour=login_hour, minute=login_min, second=0, microsecond=0)

            # Session duration 60–480 min
            session_len = random.randint(60, 480)
            logout_dt = login_dt + timedelta(minutes=session_len)

            # Login event
            logs.append({
                "user_id": uid,
                "timestamp": login_dt,
                "event_type": "login",
                "resource": "/auth/login",
                "ip_address": ip,
                "status": "success",
                "details": {"session_minutes": session_len},
            })

            # 0–1 failed login per day
            if random.random() < 0.15:
                fail_dt = login_dt - timedelta(minutes=random.randint(1, 5))
                logs.append({
                    "user_id": uid,
                    "timestamp": fail_dt,
                    "event_type": "failed_login",
                    "resource": "/auth/login",
                    "ip_address": ip,
                    "status": "failure",
                    "details": {"reason": "wrong_password"},
                })

            # 5–15 file accesses during session
            num_accesses = random.randint(5, 15)
            for _ in range(num_accesses):
                access_offset = random.randint(1, max(1, session_len - 1))
                access_dt = login_dt + timedelta(minutes=access_offset)
                resource = random.choice(resources)
                logs.append({
                    "user_id": uid,
                    "timestamp": access_dt,
                    "event_type": "file_access",
                    "resource": resource,
                    "ip_address": ip,
                    "status": "success",
                    "details": {"file_size_kb": random.randint(10, 5000)},
                })

            # Logout
            logs.append({
                "user_id": uid,
                "timestamp": logout_dt,
                "event_type": "logout",
                "resource": "/auth/logout",
                "ip_address": ip,
                "status": "success",
                "details": {},
            })

    return logs


def inject_anomalies(logs, users):
    anomalous_users = random.sample(users, min(3, len(users)))
    base_date = datetime.utcnow() - timedelta(days=7)

    for idx, user in enumerate(anomalous_users):
        uid = user["user_id"]

        if idx == 0:
            # Off-hours logins over last 5 days
            for i in range(5):
                day = base_date + timedelta(days=i)
                hour = random.choice([1, 2, 3, 23])
                login_dt = day.replace(hour=hour, minute=random.randint(0, 59), second=0, microsecond=0)
                logs.append({
                    "user_id": uid,
                    "timestamp": login_dt,
                    "event_type": "login",
                    "resource": "/auth/login",
                    "ip_address": "10.0.0.99",
                    "status": "success",
                    "details": {"anomaly": "off_hours"},
                })
                # Also access sensitive files
                for _ in range(8):
                    logs.append({
                        "user_id": uid,
                        "timestamp": login_dt + timedelta(minutes=random.randint(1, 30)),
                        "event_type": "file_access",
                        "resource": random.choice(SENSITIVE_RESOURCES),
                        "ip_address": "10.0.0.99",
                        "status": "success",
                        "details": {"anomaly": "sensitive_access"},
                    })

        elif idx == 1:
            # Repeated failed logins (brute force simulation)
            for i in range(3):
                day = base_date + timedelta(days=i * 2)
                fail_dt = day.replace(hour=random.randint(9, 17), minute=0, second=0, microsecond=0)
                for j in range(random.randint(6, 10)):
                    logs.append({
                        "user_id": uid,
                        "timestamp": fail_dt + timedelta(minutes=j),
                        "event_type": "failed_login",
                        "resource": "/auth/login",
                        "ip_address": f"172.16.{random.randint(1,10)}.{random.randint(1,254)}",
                        "status": "failure",
                        "details": {"anomaly": "brute_force"},
                    })

        elif idx == 2:
            # Mass file access + unusual IP
            for i in range(4):
                day = base_date + timedelta(days=i)
                login_dt = day.replace(hour=random.randint(8, 17), minute=0, second=0, microsecond=0)
                unusual_ip = f"203.0.113.{random.randint(1, 254)}"
                logs.append({
                    "user_id": uid,
                    "timestamp": login_dt,
                    "event_type": "login",
                    "resource": "/auth/login",
                    "ip_address": unusual_ip,
                    "status": "success",
                    "details": {"anomaly": "unusual_ip"},
                })
                # 50–80 file accesses
                for _ in range(random.randint(50, 80)):
                    logs.append({
                        "user_id": uid,
                        "timestamp": login_dt + timedelta(minutes=random.randint(1, 120)),
                        "event_type": "file_access",
                        "resource": random.choice(SENSITIVE_RESOURCES + ["/shared/all_data"]),
                        "ip_address": unusual_ip,
                        "status": "success",
                        "details": {"anomaly": "mass_access"},
                    })

    return logs


def seed_database(db_path=None):
    users = generate_users()
    for u in users:
        insert_user(u["user_id"], u["username"], u["department"], u["role"])

    logs = generate_normal_logs(users, days=30)
    logs = inject_anomalies(logs, users)

    # Sort by timestamp
    logs.sort(key=lambda x: x["timestamp"] if isinstance(x["timestamp"], str) else x["timestamp"].isoformat())

    for log in logs:
        insert_activity_log(
            user_id=log["user_id"],
            timestamp=log["timestamp"],
            event_type=log["event_type"],
            resource=log.get("resource", ""),
            ip_address=log.get("ip_address", ""),
            status=log.get("status", "success"),
            details_dict=log.get("details", {}),
        )

    print(f"[Seeder] Inserted {len(users)} users and {len(logs)} activity logs.")
    return users

#!/usr/bin/env python3
"""
generate_logs.py
Generates realistic synthetic authentication logs for testing/demoing the
SOC Threat Detection & Log Analyzer - no real data involved.

Produces a mix of:
  - normal successful logins (business hours, known users/IPs)
  - occasional isolated failed logins (typos, forgotten passwords)
  - brute force attack bursts (many failed logins in a short window,
    sometimes followed by a successful login)
  - password-spraying / multi-IP patterns (one user, many source IPs)
  - off-hours activity

Output can be written as CSV (the tool's native format) or as raw Linux
sshd auth.log style text.

Usage:
  python src/generate_logs.py --output sample_logs/generated.csv --events 500
  python src/generate_logs.py --output sample_logs/generated.log --format sshd --events 500
  python src/generate_logs.py --output sample_logs/generated.csv --events 1000 \
      --brute-force-bursts 3 --spray-users 2 --seed 42
"""

import argparse
import csv
import random
from datetime import datetime, timedelta

NORMAL_USERS = ["jdoe", "mjones", "ksmith", "asharma", "rverma", "npatel", "svc_backup"]
ATTACKER_TARGET_USERS = ["admin", "root", "administrator", "test", "guest"]
INTERNAL_IPS = ["10.0.0.15", "10.0.0.22", "10.0.0.31", "10.0.0.44", "10.0.0.5"]

FAIL_MESSAGES = [
    "Failed password for {user}",
    "Invalid password attempt for {user}",
    "Authentication failure for {user}",
]
SUCCESS_MESSAGES = [
    "Accepted password for {user}",
    "Login succeeded for {user}",
]


def random_public_ip(rng):
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def make_event(ts, user, ip, event_id, status, message):
    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": event_id,
        "user": user,
        "src_ip": ip,
        "status": status,
        "message": message,
    }


def generate_normal_activity(rng, start, count):
    # Each normal user gets a fixed "home" IP (desk workstation) plus one
    # occasional secondary IP (e.g. laptop) - capped at 2 total, so normal
    # users never trip the multi-IP threshold and only real attack patterns do.
    home_ip = {}
    backup_ip = {}
    for user in NORMAL_USERS:
        primary, secondary = rng.sample(INTERNAL_IPS, 2)
        home_ip[user] = primary
        backup_ip[user] = secondary

    events = []
    for _ in range(count):
        user = rng.choice(NORMAL_USERS)
        ip = home_ip[user] if rng.random() < 0.95 else backup_ip[user]
        # weighted toward business hours, occasional off-hours (e.g. automated jobs)
        hour = rng.choices(
            population=list(range(24)),
            weights=[1, 1, 1, 1, 1, 2, 3, 5, 8, 8, 7, 7, 6, 7, 7, 6, 6, 5, 3, 2, 1, 1, 1, 1],
            k=1,
        )[0]
        ts = start + timedelta(days=rng.randint(0, 6), hours=hour,
                                minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        if rng.random() < 0.05:  # small chance of an isolated failed login (typo)
            events.append(make_event(ts, user, ip, "4625", "FAILED",
                                      rng.choice(FAIL_MESSAGES).format(user=user)))
        else:
            events.append(make_event(ts, user, ip, "4624", "SUCCESS",
                                      rng.choice(SUCCESS_MESSAGES).format(user=user)))
    return events


def generate_brute_force_burst(rng, start, user=None, attempts=None, succeed=None):
    user = user or rng.choice(ATTACKER_TARGET_USERS)
    ip = random_public_ip(rng)
    attempts = attempts or rng.randint(6, 20)
    succeed = rng.random() < 0.4 if succeed is None else succeed

    base_ts = start + timedelta(days=rng.randint(0, 6), hours=rng.randint(0, 23),
                                 minutes=rng.randint(0, 59))
    events = []
    t = base_ts
    for i in range(attempts):
        t = t + timedelta(seconds=rng.randint(5, 25))
        events.append(make_event(t, user, ip, "4625", "FAILED",
                                  rng.choice(FAIL_MESSAGES).format(user=user)))
    if succeed:
        t = t + timedelta(seconds=rng.randint(5, 20))
        events.append(make_event(t, user, ip, "4624", "SUCCESS",
                                  rng.choice(SUCCESS_MESSAGES).format(user=user)))
    return events


def generate_password_spray(rng, start, user=None, ip_count=None):
    """One legitimate-looking user authenticating from many distinct IPs -
    simulates credential sharing / spraying / compromised account."""
    user = user or rng.choice(NORMAL_USERS + ATTACKER_TARGET_USERS)
    ip_count = ip_count or rng.randint(4, 8)
    base_ts = start + timedelta(days=rng.randint(0, 6), hours=rng.randint(8, 20))
    events = []
    t = base_ts
    for _ in range(ip_count):
        ip = random_public_ip(rng)
        t = t + timedelta(minutes=rng.randint(1, 30))
        status = "SUCCESS" if rng.random() < 0.7 else "FAILED"
        event_id = "4624" if status == "SUCCESS" else "4625"
        msg_pool = SUCCESS_MESSAGES if status == "SUCCESS" else FAIL_MESSAGES
        events.append(make_event(t, user, ip, event_id, status,
                                  rng.choice(msg_pool).format(user=user)))
    return events


def to_sshd_line(event):
    dt = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
    ts_str = dt.strftime("%b %d %H:%M:%S")
    port = random.randint(30000, 65000)
    if event["status"] == "FAILED":
        return f"{ts_str} webserver sshd[{random.randint(1000,9999)}]: Failed password for {event['user']} from {event['src_ip']} port {port} ssh2"
    return f"{ts_str} webserver sshd[{random.randint(1000,9999)}]: Accepted password for {event['user']} from {event['src_ip']} port {port} ssh2"


def write_csv(events, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_id", "user", "src_ip", "status", "message"])
        for e in events:
            writer.writerow([e["timestamp"], e["event_id"], e["user"],
                              e["src_ip"], e["status"], e["message"]])


def write_sshd(events, path):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            if e["event_id"] in {"4624", "4625"}:  # sshd format only supports these
                f.write(to_sshd_line(e) + "\n")


def parse_args():
    p = argparse.ArgumentParser(description="Generate synthetic auth logs for testing the SOC analyzer")
    p.add_argument("--output", required=True, help="Output file path (e.g. sample_logs/generated.csv)")
    p.add_argument("--format", choices=["csv", "sshd"], default="csv", help="Output format (default: csv)")
    p.add_argument("--events", type=int, default=300, help="Number of normal background events to generate")
    p.add_argument("--brute-force-bursts", type=int, default=2, help="Number of brute force attack bursts to inject")
    p.add_argument("--spray-users", type=int, default=1, help="Number of password-spray / multi-IP patterns to inject")
    p.add_argument("--days-back", type=int, default=7, help="Spread generated events over this many days")
    p.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    return p.parse_args()


def main():
    args = parse_args()
    rng = random.Random(args.seed)
    if args.seed is not None:
        random.seed(args.seed)

    start = datetime.now() - timedelta(days=args.days_back)

    events = []
    events += generate_normal_activity(rng, start, args.events)
    for _ in range(args.brute_force_bursts):
        events += generate_brute_force_burst(rng, start)
    for _ in range(args.spray_users):
        events += generate_password_spray(rng, start)

    events.sort(key=lambda e: e["timestamp"])

    if args.format == "csv":
        write_csv(events, args.output)
    else:
        write_sshd(events, args.output)

    print(f"✔ Generated {len(events)} events -> {args.output} (format={args.format})")
    print(f"  Includes {args.brute_force_bursts} brute-force burst(s) and "
          f"{args.spray_users} multi-IP spray pattern(s)")


if __name__ == "__main__":
    main()

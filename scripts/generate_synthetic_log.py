#!/usr/bin/env python3
"""Generate the synthetic authentication log used in this investigation.

Fixed random seed -> identical output every run. All IPs come from RFC 5737
documentation ranges and all users are fictional. The log is deliberately
messy (mixed timestamp formats/time zones, mixed-case usernames, different
result labels) so that the normalization step has real work to do.

Usage: python scripts/generate_synthetic_log.py [output_csv]
"""
import csv
import random
import sys
from datetime import datetime, timedelta, timezone

rng = random.Random(42)
UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30))
rows = []  # (datetime_utc, username, ip, country, endpoint, outcome, user_agent)

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SCRIPT = "python-requests/2.31"


def add(ts, user, ip, country, endpoint, ok, ua=BROWSER):
    rows.append((ts, user, ip, country, endpoint, "SUCCESS" if ok else "FAIL", ua))


# ---------- baseline: 10 staff, 2 days, business hours (03:30-12:30 UTC = 09:00-18:00 IST) ----------
users = {
    "a.sharma": "203.0.113.10", "r.iyer": "203.0.113.11", "m.patel": "203.0.113.12",
    "s.kumar": "203.0.113.10", "k.nair": "203.0.113.14", "d.joseph": "203.0.113.55",
    "p.menon": "203.0.113.16", "l.fernandez": "203.0.113.17", "finance_svc": "203.0.113.20",
    "j.thomas": "203.0.113.21",
}
for day in (20, 21):
    for user, ip in users.items():
        for _ in range(rng.randint(3, 5)):
            t = datetime(2026, 10, day, 3, 30, tzinfo=UTC) + timedelta(minutes=rng.randint(0, 540), seconds=rng.randint(0, 59))
            if rng.random() < 0.08 and user != "d.joseph":  # occasional single typo, then success
                add(t - timedelta(seconds=20), user, ip, "IN", "/login", False)
            add(t, user, ip, "IN", rng.choice(["/login", "/portal", "/vpn"]), True)

# benign noise: d.joseph forgets password (4 failures, below brute-force threshold), then succeeds
t0 = datetime(2026, 10, 20, 6, 2, 0, tzinfo=UTC)
for i in range(4):
    add(t0 + timedelta(seconds=40 * i), "d.joseph", "203.0.113.55", "IN", "/login", False)
add(t0 + timedelta(seconds=190), "d.joseph", "203.0.113.55", "IN", "/login", True)

# ---------- attack 1: password spraying from 198.51.100.77 (21 Oct, ~02:05 UTC) ----------
SPRAY_IP = "198.51.100.77"
targets = ["admin", "a.sharma", "r.iyer", "m.patel", "s.kumar", "k.nair", "d.joseph", "p.menon",
           "l.fernandez", "finance_svc", "j.thomas", "test", "guest", "svc_backup"]
t = datetime(2026, 10, 21, 2, 5, 0, tzinfo=UTC)
for rnd in range(2):  # two passes, one guess per account per pass
    for user in targets:
        if user == "m.patel" and rnd == 1:
            continue
        add(t, user, SPRAY_IP, "RU", "/login", False, SCRIPT)
        t += timedelta(seconds=rng.randint(40, 55))
# the second guess for m.patel works
add(t, "m.patel", SPRAY_IP, "RU", "/login", True, SCRIPT)
add(t + timedelta(seconds=75), "m.patel", SPRAY_IP, "RU", "/portal", True, SCRIPT)
add(t + timedelta(seconds=380), "m.patel", SPRAY_IP, "RU", "/admin/export", True, SCRIPT)
add(t + timedelta(seconds=520), "m.patel", SPRAY_IP, "RU", "/admin/export", True, SCRIPT)

# ---------- attack 2: brute force from 192.0.2.45 against admin (21 Oct, ~03:10 UTC) ----------
t = datetime(2026, 10, 21, 3, 10, 0, tzinfo=UTC)
for _ in range(42):
    add(t, "admin", "192.0.2.45", "NL", "/login", False, SCRIPT)
    t += timedelta(seconds=rng.randint(7, 10))
add(t, "admin", "192.0.2.45", "NL", "/login", True, SCRIPT)
add(t + timedelta(seconds=110), "admin", "192.0.2.45", "NL", "/admin/users", True, SCRIPT)

# ---------- anomaly: impossible travel for s.kumar (21 Oct) ----------
add(datetime(2026, 10, 21, 5, 5, 12, tzinfo=UTC), "s.kumar", "203.0.113.10", "IN", "/login", True)
add(datetime(2026, 10, 21, 5, 41, 40, tzinfo=UTC), "s.kumar", "192.0.2.150", "BR", "/login", True)

# ---------- write CSV with deliberately inconsistent formatting ----------
rows.sort(key=lambda r: r[0])
RESULT_LABELS = {"SUCCESS": ["SUCCESS", "success", "OK", "200"], "FAIL": ["FAIL", "Failed", "DENIED", "401", "failure"]}


def fmt_ts(ts):
    style = rng.choice(["iso_z", "space", "ist"])
    if style == "iso_z":
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    if style == "space":
        return ts.strftime("%Y-%m-%d %H:%M:%S")          # naive, UTC by convention
    return ts.astimezone(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30")


def fmt_user(u):
    return rng.choice([u, u, u, u.upper(), u.title(), f" {u} "])


out = sys.argv[1] if len(sys.argv) > 1 else "data/synthetic_authentication_log.csv"
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "username", "source_ip", "country", "endpoint", "result", "user_agent"])
    for ts, user, ip, country, endpoint, outcome, ua in rows:
        w.writerow([fmt_ts(ts), fmt_user(user), ip, country, endpoint, rng.choice(RESULT_LABELS[outcome]), ua])
print(f"Wrote {len(rows)} events to {out}")

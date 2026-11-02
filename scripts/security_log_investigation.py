#!/usr/bin/env python3
"""Security Log Investigation: normalize authentication logs, detect attacks, build a timeline.

Usage:
    python scripts/security_log_investigation.py [csv_path] [--out reports]

Detection rules (thresholds are constants below):
  R1 Brute force           >= 5 failures from one IP against one account within 10 min
  R2 Password spraying     one IP failing against >= 5 distinct accounts within 30 min
  R3 Success after failures  a success from an IP with >= 5 failures in the previous 60 min (likely compromise)
  R4 Impossible travel     same account succeeds from two countries < 120 min apart
  R5 Post-compromise use   sensitive (/admin) endpoints used from an IP flagged by R3
"""
import argparse
import os
from collections import deque

import pandas as pd

BF_MIN_FAILS, BF_WINDOW = 5, pd.Timedelta(minutes=10)
SPRAY_MIN_ACCOUNTS, SPRAY_WINDOW = 5, pd.Timedelta(minutes=30)
SAF_MIN_FAILS, SAF_LOOKBACK = 5, pd.Timedelta(minutes=60)
TRAVEL_WINDOW = pd.Timedelta(minutes=120)
SENSITIVE_PREFIXES = ("/admin",)

FAIL_LABELS = {"FAIL", "FAILED", "FAILURE", "DENIED", "INVALID", "UNAUTHORIZED", "401", "403", "ERROR"}
OK_LABELS = {"SUCCESS", "OK", "PASSED", "ALLOW", "ALLOWED", "200"}


# ------------------------------------------------------------------ normalization
def pick(df, names):
    return next((c for c in names if c in df.columns), None)


def load_and_normalize(path):
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    n_raw = len(df)

    ts_col = pick(df, ["timestamp", "time", "datetime", "date"]) or df.columns[0]
    user_col = pick(df, ["username", "user", "account", "target_user"])
    ip_col = pick(df, ["source_ip", "ip", "ip_address", "client_ip"])
    res_col = pick(df, ["result", "status", "outcome", "response"])
    missing = [n for n, c in [("username", user_col), ("source_ip", ip_col), ("result", res_col)] if c is None]
    if missing:
        raise ValueError(f"Missing required column(s): {missing}. Found: {list(df.columns)}")

    # Timestamps -> timezone-aware UTC. Naive values are assumed to already be UTC.
    df["ts"] = pd.to_datetime(df[ts_col].astype(str).str.strip(), format="mixed", utc=True, errors="coerce")
    df["user"] = df[user_col].astype(str).str.strip().str.lower()
    df["ip"] = df[ip_col].astype(str).str.strip()
    label = df[res_col].astype(str).str.strip().str.upper()
    df["outcome"] = label.map(lambda v: "FAILURE" if v in FAIL_LABELS else "SUCCESS" if v in OK_LABELS else "UNKNOWN")
    df["country"] = df["country"].astype(str).str.strip().str.upper() if "country" in df.columns else "??"
    df["endpoint"] = df["endpoint"].astype(str).str.strip() if "endpoint" in df.columns else ""

    quality = {
        "rows_read": n_raw,
        "bad_timestamps_dropped": int(df["ts"].isna().sum()),
        "unknown_result_labels": int((df["outcome"] == "UNKNOWN").sum()),
        "distinct_raw_usernames": int(df[user_col].nunique()),
        "distinct_normalized_usernames": int(df["user"].nunique()),
        "distinct_raw_result_labels": int(df[res_col].nunique()),
    }
    df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)
    return df, quality


# ------------------------------------------------------------------ detection rules
def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def r1_brute_force(df):
    out = []
    fails = df[df.outcome == "FAILURE"]
    for (ip, user), g in fails.groupby(["ip", "user"]):
        times = list(g.ts)
        best, left = (0, 0, 0), 0
        for right in range(len(times)):
            while times[right] - times[left] > BF_WINDOW:
                left += 1
            if right - left + 1 > best[0]:
                best = (right - left + 1, left, right)
        if best[0] >= BF_MIN_FAILS:
            start, end = times[best[1]], times[best[2]]
            later = df[(df.ip == ip) & (df.user == user) & (df.outcome == "SUCCESS") & (df.ts > end)
                       & (df.ts <= end + pd.Timedelta(minutes=15))]
            out.append({"rule": "R1 Brute force", "ip": ip, "account": user, "failures": best[0],
                        "start": start, "end": end,
                        "followed_by_success": fmt(later.ts.iloc[0]) if len(later) else "no"})
    return out


def r2_password_spraying(df):
    out = []
    fails = df[df.outcome == "FAILURE"]
    for ip, g in fails.groupby("ip"):
        events = list(zip(g.ts, g.user))
        window, best = deque(), None
        for ts, user in events:
            window.append((ts, user))
            while ts - window[0][0] > SPRAY_WINDOW:
                window.popleft()
            accounts = {u for _, u in window}
            if len(accounts) >= SPRAY_MIN_ACCOUNTS and (best is None or (len(accounts), len(window)) > (len(best[0]), best[3])):
                best = (accounts, window[0][0], ts, len(window))
        if best:
            accounts, start, end, attempts = best
            succ = df[(df.ip == ip) & (df.outcome == "SUCCESS") & (df.ts >= start) & (df.ts <= end + pd.Timedelta(minutes=30))]
            out.append({"rule": "R2 Password spraying", "ip": ip, "accounts": sorted(accounts),
                        "attempts": attempts, "start": start, "end": end,
                        "avg_attempts_per_account": round(attempts / len(accounts), 1),
                        "accounts_with_success": sorted(set(succ.user))})
    return out


def r3_success_after_failures(df):
    out, seen = [], set()
    for _, row in df[df.outcome == "SUCCESS"].iterrows():
        prior = df[(df.ip == row.ip) & (df.outcome == "FAILURE") & (df.ts < row.ts) & (df.ts >= row.ts - SAF_LOOKBACK)]
        key = (row.ip, row.user)
        if len(prior) >= SAF_MIN_FAILS and key not in seen:
            seen.add(key)
            out.append({"rule": "R3 Success after failures", "ip": row.ip, "account": row.user, "success_time": row.ts,
                        "prior_failures_from_ip": len(prior),
                        "prior_failures_on_account": int((prior.user == row.user).sum())})
    return out


def r4_impossible_travel(df):
    out = []
    for user, g in df[(df.outcome == "SUCCESS") & (df.country != "??")].groupby("user"):
        rows = list(g.itertuples())
        for a, b in zip(rows, rows[1:]):
            if a.country != b.country and b.ts - a.ts < TRAVEL_WINDOW:
                out.append({"rule": "R4 Impossible travel", "account": user, "first": f"{a.country} ({a.ip})",
                            "second": f"{b.country} ({b.ip})", "start": a.ts, "end": b.ts,
                            "gap_minutes": round((b.ts - a.ts).total_seconds() / 60)})
    return out


def r5_post_compromise(df, r3):
    out = []
    for f in r3:
        acts = df[(df.ip == f["ip"]) & (df.user == f["account"]) & (df.ts >= f["success_time"])
                  & df.endpoint.str.startswith(SENSITIVE_PREFIXES)]
        for r in acts.itertuples():
            out.append({"rule": "R5 Post-compromise use", "ip": f["ip"], "account": f["account"],
                        "time": r.ts, "endpoint": r.endpoint})
    return out


# ------------------------------------------------------------------ reporting
def build_timeline(df, f1, f2, f3, f4, f5):
    ev = []
    for f in f2:
        ev.append((f["start"], f"Password spray begins from {f['ip']} ({f['avg_attempts_per_account']} guesses/account)"))
        ev.append((f["end"], f"Spray reaches {len(f['accounts'])} accounts, {f['attempts']} failed attempts"))
    for f in f3:
        ev.append((f["success_time"], f"SUCCESS: {f['account']} from {f['ip']} after {f['prior_failures_from_ip']} failures from that IP"))
    for f in f1:
        ev.append((f["start"], f"Brute force on '{f['account']}' from {f['ip']} starts"))
        ev.append((f["end"], f"Brute force ends: {f['failures']} failures in window; success follows: {f['followed_by_success']}"))
    for f in f5:
        ev.append((f["time"], f"Sensitive endpoint {f['endpoint']} used by {f['account']} from {f['ip']}"))
    for f in f4:
        ev.append((f["end"], f"Impossible travel: {f['account']} {f['first']} -> {f['second']} in {f['gap_minutes']} min"))
    return pd.DataFrame(sorted(ev), columns=["time_utc", "event"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default="data/synthetic_authentication_log.csv")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args()

    df, q = load_and_normalize(args.csv)
    print("=== DATA QUALITY / NORMALIZATION ===")
    for k, v in q.items():
        print(f"{k}: {v}")
    print(f"time range (UTC): {fmt(df.ts.min())} -> {fmt(df.ts.max())}")
    print(f"outcomes: {df.outcome.value_counts().to_dict()}")

    f1, f2, f3 = r1_brute_force(df), r2_password_spraying(df), r3_success_after_failures(df)
    f4, f5 = r4_impossible_travel(df), r5_post_compromise(df, f3)

    print("\n=== R1 BRUTE FORCE (>=%d failures / %s, same IP+account) ===" % (BF_MIN_FAILS, BF_WINDOW))
    for f in f1: print(f"{f['ip']} -> {f['account']}: {f['failures']} failures {fmt(f['start'])} to {fmt(f['end'])}; success after: {f['followed_by_success']}")
    print("\n=== R2 PASSWORD SPRAYING (>=%d accounts / %s, same IP) ===" % (SPRAY_MIN_ACCOUNTS, SPRAY_WINDOW))
    for f in f2:
        print(f"{f['ip']}: {len(f['accounts'])} accounts, {f['attempts']} attempts, {fmt(f['start'])} to {fmt(f['end'])}")
        print(f"  accounts: {', '.join(f['accounts'])}\n  accounts with success from this IP: {f['accounts_with_success'] or 'none'}")
    print("\n=== R3 SUCCESS AFTER FAILURES (likely compromised accounts) ===")
    for f in f3: print(f"{f['account']} from {f['ip']} at {fmt(f['success_time'])} ({f['prior_failures_from_ip']} prior failures from IP, {f['prior_failures_on_account']} on this account)")
    print("\n=== R4 IMPOSSIBLE TRAVEL ===")
    for f in f4: print(f"{f['account']}: {f['first']} -> {f['second']}, {f['gap_minutes']} min apart ({fmt(f['start'])} / {fmt(f['end'])})")
    print("\n=== R5 POST-COMPROMISE SENSITIVE ACTIVITY ===")
    for f in f5: print(f"{fmt(f['time'])} {f['account']} from {f['ip']} -> {f['endpoint']}")

    # tuning check: failure bursts that did NOT trigger anything
    flagged = {(f["ip"], f["account"]) for f in f1}
    near = df[df.outcome == "FAILURE"].groupby(["ip", "user"]).size()
    print("\n=== BENIGN / BELOW-THRESHOLD FAILURE BURSTS (3+ failures, not flagged) ===")
    for (ip, user), n in near.items():
        if n >= 3 and (ip, user) not in flagged:
            print(f"{ip} -> {user}: {n} failures (below threshold of {BF_MIN_FAILS})")

    timeline = build_timeline(df, f1, f2, f3, f4, f5)
    print("\n=== RECONSTRUCTED TIMELINE (UTC) ===")
    for r in timeline.itertuples(): print(f"{fmt(r.time_utc)}  {r.event}")

    os.makedirs(args.out, exist_ok=True)
    timeline.to_csv(os.path.join(args.out, "timeline.csv"), index=False)
    allf = [dict(x, finding_type=x["rule"]) for x in f1 + f2 + f3 + f4 + f5]
    pd.DataFrame(allf).to_csv(os.path.join(args.out, "findings.csv"), index=False)
    print(f"\n[+] Wrote {args.out}/timeline.csv and {args.out}/findings.csv")


if __name__ == "__main__":
    main()

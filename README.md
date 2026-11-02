# security-log-investigation

Security Log Investigation task: normalize a messy authentication log, detect brute force, password spraying and unusual access, and write up an incident report with a timeline.

## Deliverables
- **[Incident Report](./reports/incident_report.md)**: findings, methodology, timeline, evidence vs. assumptions, remediation.
- **[Analysis Script](./scripts/security_log_investigation.py)**: normalizes the log and runs five detection rules (brute force, password spraying, success-after-failures, impossible travel, post-compromise activity).
- **[Dataset](./data/synthetic_authentication_log.csv)**: 167 synthetic authentication events (fictional users, documentation-range IPs).
- **[Dataset Generator](./scripts/generate_synthetic_log.py)**: reproducible (fixed seed) script that created the dataset.
- **[Run Output](./reports/analysis_output.txt)**, **[findings.csv](./reports/findings.csv)**, **[timeline.csv](./reports/timeline.csv)**: results from running the script.

## Run
```bash
pip install pandas
python scripts/security_log_investigation.py data/synthetic_authentication_log.csv
```

## Key findings
- Password spraying from `198.51.100.77` (14 accounts, 27 attempts) compromised `m.patel`.
- Brute force from `192.0.2.45` (42 failures) compromised `admin`.
- `s.kumar` shows impossible travel (IN -> BR in 20 min), flagged for review.

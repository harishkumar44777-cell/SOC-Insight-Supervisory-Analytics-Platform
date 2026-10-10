# SOC Insight – Supervisory Analytics Platform (T1-PS4)

All files live in this one folder (no subfolders). Flask + SQLite dashboard that turns **synthetic** SOC incident records into SLA, workload and recommendation analytics for supervisors.
It is not connected to any real SOC/SIEM and does not detect attacks. There is **no login** (local demo only; do not expose it to a network).

## Run on Windows
1. Install Python 3 from python.org (tick "Add python.exe to PATH").
2. Open the `soc_insight` folder in VS Code, then Terminal → New Terminal.
3. `python -m venv .venv`
4. Activate: Command Prompt `.venv\Scripts\activate.bat` — PowerShell `.venv\Scripts\Activate.ps1`
   (if blocked: `Set-ExecutionPolicy -Scope Process Bypass`)
5. `python -m pip install -r requirements.txt`
6. `python app.py` then open http://127.0.0.1:5000
7. Tests: `python -m pytest -q`

The database `instance/soc_insight.db` (the `instance` folder is created automatically) and demo data are created automatically on first run. Reset: Settings → Reset Demo Data.
Bootstrap, Chart.js and icons load from CDNs, so charts/styling need internet; Flask pages and data work offline.

## Timestamps and SLA
All times are UTC. Ack time = acknowledged_at − created_at (unacknowledged: now − created_at). Breach = strictly greater than threshold
(Critical 5, High 15, Medium 30, Low 60 min — configurable demo values). "At risk" = ≥80% of threshold. No resolution SLA is defined.
Seeded data is relative to first launch time; use Reset Demo Data right before a demo so SOC-9001/9002/9003 are fresh.

## 3-minute demo
1. Dashboard: KPIs, severity chart. 2. Alerts → severity=Critical, tick "Overdue only". 3. Open SOC-9001 (unassigned, unacknowledged Critical).
4. Assign an analyst, click Acknowledge. 5. Analyst Performance: workload summary. 6. Recommendations: remaining rules (e.g. SOC-9002, SOC-9003).
7. Reports → Export CSV.

## Troubleshooting
- `python` not found: reinstall with PATH option or use `py`.
- Port 5000 busy: change `port=5000` at the bottom of `app.py`.
- Blank charts: no internet (CDN). Locked DB: close other copies of the app.

## Real alerts (Import / Real Alerts page)
SOC Insight analyses alerts produced by other tools; it does not sniff networks. Three ways in:
1. **Upload CSV/JSON** exported from a SIEM/EDR/firewall (see `sample_real_alerts.csv`). Only `title` is required; common column names are auto-mapped.
2. **Webhook**: `POST /api/ingest` with header `X-API-Key` (key shown on the Import page) and a JSON alert or list of alerts.
3. **Windows collector** (Windows only, run the terminal as Administrator): scans this PC's failed-logon events (4625) from the last 24 h and raises an alert for any IP with 5+ failures. Not tested on Windows by the author.

Real alerts are tagged with their source, get `RA-` codes, are de-duplicated on re-import, and start as Open with no acknowledgement time.
Filter them with Data source = Real on Security Alerts. Settings → "Remove demo incidents only" leaves just your real data.
The API key and pages have no login; keep the app on localhost.

## Auto-detection and live dashboard
Imported/pushed alerts are classified automatically (category column if present, otherwise keywords in the title) into 12 types, including
Reconnaissance, Denial of Service and Web Application Attack, with "Other" as the fallback. The dashboard defaults to All time, has a Data source filter,
lists every detected type as clickable chips, and refreshes itself every 15 seconds (toggle "Auto-refresh") with a toast when new alerts arrive.
Classification is keyword-based, not machine learning, so check unusual alerts manually. `alerts.csv` has no category column on purpose, to demo auto-detection.
The purple theme uses Google Fonts, Bootstrap, Font Awesome and Chart.js from CDNs (internet needed for the full look).

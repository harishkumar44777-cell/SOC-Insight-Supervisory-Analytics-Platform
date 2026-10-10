"""SOC Insight - Supervisory Analytics Platform (hackathon demo, synthetic data only).
Timestamp convention: all timestamps are naive UTC strings 'YYYY-MM-DDTHH:MM:SS'."""
import csv, hashlib, hmac, io, ipaddress, json, os, random, re, secrets, sqlite3, statistics, subprocess
from datetime import datetime, timedelta, timezone
from flask import (Flask, abort, send_from_directory, Response, flash, g, jsonify, redirect, render_template,
                   request, url_for, current_app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_FILES = {"style.css", "dashboard.js"}
SEVERITIES = ["Critical", "High", "Medium", "Low"]
STATUSES = ["Open", "Acknowledged", "In Progress", "Resolved", "Closed"]
ACTIVE = ("Open", "Acknowledged", "In Progress")
CATEGORIES = ["Brute-Force Login", "Phishing", "Malware Detection", "Suspicious Outbound Traffic",
              "Unauthorized Access", "Privilege Escalation", "Suspicious File Activity",
              "Multiple Failed Authentications", "Reconnaissance", "Denial of Service", "Web Application Attack", "Other"]
TRANSITIONS = {"Open": ["Acknowledged", "In Progress"], "Acknowledged": ["In Progress", "Resolved"],
               "In Progress": ["Resolved"], "Resolved": ["Closed", "In Progress"], "Closed": []}
DEFAULT_SLA = {"Critical": 5, "High": 15, "Medium": 30, "Low": 60}  # demo thresholds (minutes)
AT_RISK = 0.8  # "At risk" once 80% of the acknowledgement threshold has elapsed
FMT = "%Y-%m-%dT%H:%M:%S"
RULES = {
 "R1": "Any Critical incident that is still Open/Acknowledged/In Progress needs supervisor review.",
 "R2": "Critical incident whose acknowledgement SLA is breached (elapsed or actual ack time > threshold).",
 "R3": "Non-critical incident not acknowledged and older than its severity's acknowledgement threshold.",
 "R4": "Analyst open workload > max(1.5 x team median, median + 3).",
 "R5": "Category count in last 7 days >= 3 and >= 1.5 x previous 7 days. Simple ratio, not a statistical test.",
 "R6": "Unresolved incident has no assigned analyst.",
 "R7": "Five or more High-severity incidents are unresolved."}

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysts(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
 role TEXT NOT NULL, team TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, alert_code TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
 description TEXT, alert_type TEXT NOT NULL, source_ip TEXT, destination_ip TEXT,
 severity TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low')),
 status TEXT NOT NULL CHECK(status IN ('Open','Acknowledged','In Progress','Resolved','Closed')),
 assigned_analyst_id INTEGER REFERENCES analysts(id), created_at TEXT NOT NULL,
 acknowledged_at TEXT, resolved_at TEXT, updated_at TEXT NOT NULL,
 origin TEXT NOT NULL DEFAULT 'demo', external_id TEXT);
CREATE TABLE IF NOT EXISTS incident_log(id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
 actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT, timestamp TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents(status);
CREATE INDEX IF NOT EXISTS ix_inc_sev ON incidents(severity);
CREATE INDEX IF NOT EXISTS ix_inc_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS ix_inc_analyst ON incidents(assigned_analyst_id);
CREATE INDEX IF NOT EXISTS ix_log_inc ON incident_log(incident_id);
"""

# ---------- time helpers ----------
def utcnow(app=None):
    a = app or current_app
    return a.config.get("NOW") or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
def ts(d): return d.strftime(FMT) if d else None
def parse(s):
    try: return datetime.strptime(s, FMT) if s else None
    except (ValueError, TypeError): return None
def mins(a, b): return None if a is None or b is None else (b - a).total_seconds() / 60
def avg(v):
    v = [x for x in v if x is not None]
    return round(sum(v) / len(v), 1) if v else None
def dur(m):
    if m is None: return "—"
    return f"{m:.0f} min" if m < 60 else (f"{m/60:.1f} h" if m < 1440 else f"{m/1440:.1f} d")

# ---------- database ----------
def connect(path):
    c = sqlite3.connect(path); c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); return c

def log(conn, iid, actor, action, details, t):
    conn.execute("INSERT INTO incident_log(incident_id,actor,action,details,timestamp) VALUES(?,?,?,?,?)",
                 (iid, actor, action, details, t))

INFO = {
 "Brute-Force Login": ("Brute-force login attempts against {h}", "Hundreds of rapid login attempts from a single external address."),
 "Phishing": ("Phishing email reported by user on {h}", "User reported a credential-harvesting email with a spoofed sender."),
 "Malware Detection": ("Malware signature detected on {h}", "Endpoint agent quarantined a file matching a known malware family (synthetic)."),
 "Suspicious Outbound Traffic": ("Unusual outbound traffic from {h}", "Large outbound transfer to an unfamiliar external host."),
 "Unauthorized Access": ("Unauthorized access attempt on {h}", "Access to a restricted resource by an account without permission."),
 "Privilege Escalation": ("Privilege escalation detected on {h}", "Standard account added to an administrative group unexpectedly."),
 "Suspicious File Activity": ("Suspicious file activity on {h}", "Mass file rename/modify events within a short window."),
 "Multiple Failed Authentications": ("Multiple failed authentications for {h}", "Repeated failed sign-ins followed by a lockout.")}
HOSTS = ["WEB-01", "DB-02", "FILESRV-02", "HR-LAPTOP-14", "VPN-GW", "MAIL-01", "DEV-BOX-07", "AD-DC-01"]

def seed(conn, now):
    rng = random.Random(42)
    people = [("Aarav Menon", "Tier 1", "Alpha"), ("Diya Raman", "Tier 1", "Alpha"), ("Kabir Shah", "Tier 2", "Bravo"),
              ("Meera Iyer", "Tier 2", "Bravo"), ("Rohan Das", "Tier 3", "Charlie")]
    for n, r, t in (people if not conn.execute('SELECT 1 FROM analysts').fetchone() else []):
        conn.execute("INSERT INTO analysts(name,email,role,team,active,created_at) VALUES(?,?,?,?,1,?)",
                     (n, n.split()[0].lower() + "@demo-soc.example", r, t, ts(now - timedelta(days=200))))
    ids = [r[0] for r in conn.execute("SELECT id FROM analysts ORDER BY id")]
    def add(code, created, sev, cat, status, analyst, ack_d, res_d, title=None):
        host = rng.choice(HOSTS); t, d = INFO[cat]
        ack = created + timedelta(minutes=ack_d) if ack_d is not None else None
        res = ack + timedelta(minutes=res_d) if (ack and res_d is not None) else None
        last = res or ack or created
        src = f"203.0.113.{rng.randint(1, 254)}" if rng.random() < .7 else f"198.51.100.{rng.randint(1, 254)}"
        cur = conn.execute("""INSERT INTO incidents(alert_code,title,description,alert_type,source_ip,destination_ip,severity,status,
            assigned_analyst_id,created_at,acknowledged_at,resolved_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (code, title or t.format(h=host), "[DEMO DATA] " + d, cat, src, f"10.0.{rng.randint(0, 20)}.{rng.randint(2, 250)}",
             sev, status, analyst, ts(created), ts(ack), ts(res), ts(last)))
        iid = cur.lastrowid
        log(conn, iid, "System", "Incident created", f"Severity {sev}, category {cat}", ts(created))
        if analyst: log(conn, iid, "Supervisor", "Incident assigned", f"Assigned to analyst #{analyst}", ts(created + timedelta(minutes=1)))
        if ack: log(conn, iid, "Analyst", "Incident acknowledged", "Acknowledged", ts(ack))
        if res: log(conn, iid, "Analyst", "Incident resolved", "Resolved", ts(res))
        if status == "Closed": log(conn, iid, "Supervisor", "Incident closed", "Closed after review", ts(min(now, res + timedelta(minutes=30))))
    for i in range(120):
        created = now - timedelta(minutes=rng.randint(10, 30 * 24 * 60))
        sev = rng.choices(SEVERITIES, [10, 22, 40, 28])[0]; cat = rng.choice(CATEGORIES[:8])
        old = (now - created).total_seconds() > 3 * 3600
        status = rng.choices(STATUSES, [8, 4, 8, 45, 35])[0] if old else rng.choices(STATUSES[:3], [50, 30, 20])[0]
        analyst = None if (status == "Open" and rng.random() < .4) or rng.random() < .03 else rng.choices(ids, [30, 25, 20, 15, 10])[0]
        ack_d = DEFAULT_SLA[sev] * rng.uniform(.1, 1.5); res_d = rng.uniform(15, 720)
        if status == "Open" or created + timedelta(minutes=ack_d) > now: status, ack_d = "Open", None
        if status in ("Resolved", "Closed") and created + timedelta(minutes=ack_d + res_d) > now: status, res_d = "In Progress", None
        if status not in ("Resolved", "Closed"): res_d = None
        add(f"SOC-{1000 + i}", created, sev, cat, status, analyst, ack_d, res_d)
    # fixed, predictable demo incidents (relative to seed time)
    add("SOC-9001", now - timedelta(minutes=45), "Critical", "Malware Detection", "Open", None, None, None,
        "DEMO: Ransomware-like encryption activity on FILESRV-02")
    add("SOC-9002", now - timedelta(minutes=30), "Critical", "Privilege Escalation", "In Progress", ids[0], 12, None,
        "DEMO: Unexpected domain admin group change on AD-DC-01")
    add("SOC-9003", now - timedelta(minutes=40), "High", "Phishing", "Open", ids[1], None, None,
        "DEMO: Credential-harvesting email reported by finance team")

def init_db(app):
    conn = connect(app.config["DB"]); conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}  # migrate databases created before ingestion existed
    if "origin" not in cols: conn.execute("ALTER TABLE incidents ADD COLUMN origin TEXT NOT NULL DEFAULT 'demo'")
    if "external_id" not in cols: conn.execute("ALTER TABLE incidents ADD COLUMN external_id TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_inc_ext ON incidents(origin, external_id)")
    conn.execute("INSERT OR IGNORE INTO settings VALUES('api_key', ?)", (secrets.token_urlsafe(24),))
    for s, v in DEFAULT_SLA.items(): conn.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (f"sla_{s}", str(v)))
    if conn.execute("SELECT COUNT(*) FROM analysts").fetchone()[0] == 0: seed(conn, utcnow(app))
    conn.commit(); conn.close()

def get_thr(conn):
    thr = dict(DEFAULT_SLA)
    for r in conn.execute("SELECT key,value FROM settings WHERE key LIKE 'sla_%'"):
        try: thr[r["key"][4:]] = int(r["value"])
        except ValueError: pass
    return thr

# ---------- SLA + queries ----------
def enrich(r, thr, now):
    d = dict(r); c, a, z = parse(d["created_at"]), parse(d["acknowledged_at"]), parse(d["resolved_at"])
    t = thr[d["severity"]]; active = d["status"] in ACTIVE
    d.update(ack_min=mins(c, a), res_min=mins(c, z), threshold=t, overdue=False, unresolved=active, age_min=mins(c, now))
    if c is None: d["sla"] = "N/A"
    elif a: d["sla"] = "Breached" if d["ack_min"] > t else "Within SLA"   # boundary: equal to threshold is within SLA
    elif not active: d["sla"] = "N/A"
    else:
        el = d["age_min"]
        if el > t: d["sla"], d["overdue"] = "Breached", True
        elif el >= AT_RISK * t: d["sla"] = "At risk"
        else: d["sla"] = "Pending"
    return d

def vdate(s):
    try: return datetime.strptime(s, "%Y-%m-%d")
    except (ValueError, TypeError): return None

def build_where(args):
    w, p = [], []
    q = (args.get("q") or "").strip()[:80]
    if q: w.append("(i.alert_code LIKE ? OR i.title LIKE ?)"); p += [f"%{q}%"] * 2
    for key, col, allowed in (("severity", "severity", SEVERITIES), ("status", "status", STATUSES), ("category", "alert_type", CATEGORIES)):
        if args.get(key) in allowed: w.append(f"i.{col}=?"); p.append(args[key])
    if args.get("origin") == "demo": w.append("i.origin='demo'")
    elif args.get("origin") == "real": w.append("i.origin!='demo'")
    an = args.get("analyst")
    if an == "none": w.append("i.assigned_analyst_id IS NULL")
    elif an and an.isdigit(): w.append("i.assigned_analyst_id=?"); p.append(int(an))
    df, dt = vdate(args.get("date_from")), vdate(args.get("date_to"))
    if df: w.append("i.created_at>=?"); p.append(ts(df))
    if dt: w.append("i.created_at<?"); p.append(ts(dt + timedelta(days=1)))
    return (" WHERE " + " AND ".join(w)) if w else "", p

def fetch_items(conn, args, thr, now):
    where, p = build_where(args)
    rows = conn.execute("SELECT i.*, a.name AS analyst_name FROM incidents i LEFT JOIN analysts a ON a.id=i.assigned_analyst_id" + where, p).fetchall()
    items = [enrich(r, thr, now) for r in rows]
    if args.get("overdue") == "1": items = [i for i in items if i["overdue"]]
    sort = args.get("sort", "newest")
    items.sort(key=lambda i: i["created_at"], reverse=(sort != "oldest"))
    if sort == "severity": items.sort(key=lambda i: SEVERITIES.index(i["severity"]))
    return items

def summarize(items):
    within = sum(i["sla"] == "Within SLA" for i in items); br = sum(i["sla"] == "Breached" for i in items)
    cnt = lambda key, vals: {v: sum(i[key] == v for i in items) for v in vals}
    return dict(total=len(items), critical=sum(i["severity"] == "Critical" for i in items),
                open=sum(i["unresolved"] for i in items), resolved=sum(i["status"] in ("Resolved", "Closed") for i in items),
                breached=br, overdue=sum(i["overdue"] for i in items),
                avg_ack=avg(i["ack_min"] for i in items), avg_res=avg(i["res_min"] for i in items),
                compliance=round(100 * within / (within + br), 1) if within + br else None,
                severity=cnt("severity", SEVERITIES), status=cnt("status", STATUSES), category=cnt("alert_type", CATEGORIES))

def analyst_rows(analysts, items):
    out = []
    for a in analysts:
        m = [i for i in items if i["assigned_analyst_id"] == a["id"]]
        out.append(dict(id=a["id"], name=a["name"], team=a["team"], role=a["role"], total=len(m),
                        open=sum(i["unresolved"] for i in m), resolved=sum(i["status"] in ("Resolved", "Closed") for i in m),
                        critical=sum(i["severity"] == "Critical" for i in m), avg_ack=avg(i["ack_min"] for i in m),
                        avg_res=avg(i["res_min"] for i in m), overdue=sum(i["overdue"] for i in m)))
    return out

def imbalance(rows):
    if len(rows) < 2: return "Not enough analysts to compare workload."
    o = sorted(rows, key=lambda r: r["open"]); med = statistics.median(r["open"] for r in rows)
    hi, lo = o[-1], o[0]
    if hi["open"] - lo["open"] < 3: return f"Open workload looks balanced (range {lo['open']}–{hi['open']}, median {med:g})."
    return f"{hi['name']} has {hi['open']} open incidents vs {lo['name']} with {lo['open']} (team median {med:g}). Consider rebalancing."

def trend(items, days, now):
    start = (now - timedelta(days=days - 1)).date(); counts = {start + timedelta(d): 0 for d in range(days)}
    for i in items:
        c = parse(i["created_at"])
        if c and c.date() in counts: counts[c.date()] += 1
    return [[d.isoformat(), n] for d, n in counts.items()]

def next_action(d):
    if d["status"] == "Closed": return "No action required. Incident is closed."
    if d["status"] == "Resolved": return "Verify remediation, then close the incident."
    if not d["assigned_analyst_id"]: return "Assign an analyst immediately."
    if d["status"] == "Open" and d["overdue"]: return "Acknowledgement SLA breached: escalate and contact the assigned analyst."
    if d["status"] == "Open": return "Acknowledge the incident before the SLA threshold expires."
    return "Continue investigation; resolve once containment is confirmed."

def recommend(items, rows, now):
    recs, per = [], now.strftime("%Y-%m-%d %H:%M UTC (snapshot)")
    def add(rule, pr, title, reason, related, action):
        recs.append(dict(rule=rule, priority=pr, title=title, reason=reason, related=related, action=action, period=per, explanation=RULES[rule]))
    act = [i for i in items if i["unresolved"]]
    crit = sorted([i for i in act if i["severity"] == "Critical"], key=lambda i: -(i["age_min"] or 0))
    for i in crit[:10]:
        add("R1", "Critical", f"Review unresolved critical incident {i['alert_code']}", f"Status '{i['status']}', created {dur(i['age_min'])} ago.", i["alert_code"], "Supervisor review and prioritise now.")
    for i in [x for x in crit if x["sla"] == "Breached"][:10]:
        add("R2", "Critical", f"Escalate {i['alert_code']}: acknowledgement SLA breached", f"Threshold {i['threshold']} min for Critical was exceeded.", i["alert_code"], "Escalate to the on-call lead and confirm ownership.")
    for i in sorted([x for x in act if x["overdue"] and x["severity"] != "Critical"], key=lambda x: -(x["age_min"] or 0))[:10]:
        add("R3", "High", f"Overdue unacknowledged incident {i['alert_code']}", f"{i['severity']} incident unacknowledged for {dur(i['age_min'])} (threshold {i['threshold']} min).", i["alert_code"], "Acknowledge or reassign to an available analyst.")
    if len(rows) > 1:
        med = statistics.median(r["open"] for r in rows)
        for r in rows:
            if r["open"] > max(1.5 * med, med + 3):
                add("R4", "High", f"Workload review for {r['name']}", f"{r['open']} open incidents vs team median {med:g}.", r["name"], "Redistribute some incidents to analysts with lower load.")
    cur, prev = {}, {}
    for i in items:
        c = parse(i["created_at"])
        if not c: continue
        age = (now - c).total_seconds() / 86400
        if 0 <= age < 7: cur[i["alert_type"]] = cur.get(i["alert_type"], 0) + 1
        elif 7 <= age < 14: prev[i["alert_type"]] = prev.get(i["alert_type"], 0) + 1
    for cat in CATEGORIES:
        if cur.get(cat, 0) >= 3 and cur[cat] >= 1.5 * prev.get(cat, 0):
            add("R5", "Medium", f"Increase in '{cat}' alerts", f"{cur[cat]} alerts in last 7 days vs {prev.get(cat, 0)} in the previous 7 days.", cat, "Investigate for a common cause or campaign.")
    un = [i for i in act if not i["assigned_analyst_id"]]
    if un:
        add("R6", "High", f"{len(un)} unresolved incident(s) have no analyst", "Codes: " + ", ".join(i["alert_code"] for i in un[:10]), "Unassigned queue", "Assign each incident to an available analyst.")
    hi = [i for i in act if i["severity"] == "High"]
    if len(hi) >= 5:
        add("R7", "High", f"{len(hi)} High-severity incidents are unresolved", "High-severity queue is building up.", "High queue", "Review the queue and prioritise by age.")
    recs.sort(key=lambda r: ["Critical", "High", "Medium"].index(r["priority"]))
    return recs

def csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

# ---------- real-alert ingestion ----------
SEV_MAP = {"critical": "Critical", "crit": "Critical", "severe": "Critical", "fatal": "Critical", "high": "High", "error": "High",
           "major": "High", "medium": "Medium", "moderate": "Medium", "warning": "Medium", "warn": "Medium", "low": "Low",
           "info": "Low", "informational": "Low", "minor": "Low", "notice": "Low"}
CAT_KEYS = [("brute", "Brute-Force Login"), ("phish", "Phishing"), ("malware", "Malware Detection"), ("ransom", "Malware Detection"),
            ("virus", "Malware Detection"), ("trojan", "Malware Detection"), ("ddos", "Denial of Service"), ("denial", "Denial of Service"),
            ("flood", "Denial of Service"), ("sql", "Web Application Attack"), ("xss", "Web Application Attack"),
            ("injection", "Web Application Attack"), ("exploit", "Web Application Attack"), ("outbound", "Suspicious Outbound Traffic"),
            ("exfil", "Suspicious Outbound Traffic"), ("privilege", "Privilege Escalation"), ("escalat", "Privilege Escalation"),
            ("admin group", "Privilege Escalation"), ("group membership", "Privilege Escalation"), ("unauthor", "Unauthorized Access"),
            ("travel", "Unauthorized Access"), ("new country", "Unauthorized Access"), ("geoloc", "Unauthorized Access"),
            ("scan", "Reconnaissance"), ("recon", "Reconnaissance"), ("probe", "Reconnaissance"), ("enumerat", "Reconnaissance"),
            ("file", "Suspicious File Activity"), ("failed", "Multiple Failed Authentications"),
            ("authent", "Multiple Failed Authentications"), ("login", "Brute-Force Login")]
ALIASES = {"title": ("title", "name", "alert", "alert_name", "rule_name", "summary", "message"),
           "description": ("description", "details", "detail"), "severity": ("severity", "priority", "level"),
           "category": ("category", "alert_type", "type", "rule_category"), "source_ip": ("source_ip", "src_ip", "src", "source"),
           "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "dst", "destination"),
           "created_at": ("created_at", "timestamp", "time", "@timestamp", "event_time", "date"),
           "external_id": ("external_id", "id", "alert_id", "event_id"), "status": ("status", "state")}

def pick(rec, key):
    low = {str(k).lower().strip(): v for k, v in rec.items()}
    for a in ALIASES[key]:
        if low.get(a) not in (None, ""): return low[a]
    return None

def parse_time(v):
    if v is None: return None
    try:
        if isinstance(v, (int, float)) or str(v).replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(v), timezone.utc).replace(tzinfo=None, microsecond=0)
        d = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
        return d.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0) if d.tzinfo else d.replace(microsecond=0)
    except (ValueError, OverflowError, OSError): return None

def map_category(text):
    t = str(text or "").lower()
    for c in CATEGORIES:
        if t == c.lower(): return c
    for k, c in CAT_KEYS:
        if k in t: return c
    return "Other"

def clean_ip(v):
    try: return str(ipaddress.ip_address(str(v).strip())) if v else None
    except ValueError: return None

def normalize(rec, now):
    """Map one raw record to our schema. Returns (dict, None) or (None, reason)."""
    if not isinstance(rec, dict): return None, "not an object"
    title = str(pick(rec, "title") or "").strip()[:200]
    if not title: return None, "missing title"
    sev_raw = str(pick(rec, "severity") or "").strip().lower()
    sev = SEV_MAP.get(sev_raw) or ("Critical" if sev_raw.isdigit() and int(sev_raw) >= 9 else "High" if sev_raw.isdigit() and int(sev_raw) >= 7
          else "Medium" if sev_raw.isdigit() and int(sev_raw) >= 4 else "Low")
    created = parse_time(pick(rec, "created_at")) or now
    if created > now: created = now
    src, dst = clean_ip(pick(rec, "source_ip")), clean_ip(pick(rec, "destination_ip"))
    cat = map_category(pick(rec, "category") or title)
    ext = str(pick(rec, "external_id") or hashlib.sha1(f"{title}|{ts(created)}|{src}|{dst}".encode()).hexdigest())[:100]
    desc = str(pick(rec, "description") or "").strip()[:1000]
    if pick(rec, "status"): desc = (desc + f" [source status: {str(pick(rec, 'status'))[:30]}]").strip()
    return dict(title=title, severity=sev, category=cat, created_at=created, source_ip=src, destination_ip=dst, external_id=ext, description=desc), None

def insert_real(conn, n, origin):
    if conn.execute("SELECT 1 FROM incidents WHERE origin=? AND external_id=?", (origin, n["external_id"])).fetchone(): return False
    code = "RA-" + hashlib.sha1(f"{origin}|{n['external_id']}".encode()).hexdigest()[:8].upper(); t = ts(n["created_at"])
    cur = conn.execute("""INSERT INTO incidents(alert_code,title,description,alert_type,source_ip,destination_ip,severity,status,
        assigned_analyst_id,created_at,updated_at,origin,external_id) VALUES(?,?,?,?,?,?,?,'Open',NULL,?,?,?,?)""",
        (code, n["title"], n["description"], n["category"], n["source_ip"], n["destination_ip"], n["severity"], t, t, origin, n["external_id"]))
    log(conn, cur.lastrowid, "Ingest", "Incident created", f"Imported from source '{origin}'", t)
    return True

def ingest(conn, recs, origin, now):
    res = dict(created=0, duplicates=0, rejected=0, errors=[], types={})
    for r in recs[:5000]:
        n, err = normalize(r, now)
        if err: res["rejected"] += 1; res["errors"] = (res["errors"] + [err])[:5]; continue
        if insert_real(conn, n, origin): res["created"] += 1; res["types"][n["category"]] = res["types"].get(n["category"], 0) + 1
        else: res["duplicates"] += 1
    conn.commit(); return res

def parse_upload(filename, raw):
    name = (filename or "").lower()
    if name.endswith(".json"):
        try: data = json.loads(raw)
        except ValueError: raise ValueError("File is not valid JSON.")
        if isinstance(data, dict): data = data.get("alerts") or data.get("events") or [data]
        if not isinstance(data, list): raise ValueError("JSON must be a list of alerts.")
        return data
    if name.endswith(".csv"): return list(csv.DictReader(io.StringIO(raw)))
    raise ValueError("Upload a .csv or .json file.")

def windows_events_to_alerts(events, min_count=5):
    """Group Windows Security 4625 (failed logon) events by source IP into alert records."""
    groups = {}
    for e in events:
        msg = e.get("Message") or ""; m = re.search(r"Source Network Address:\s*(\S+)", msg)
        ip = m.group(1) if m else "-"
        if clean_ip(ip) is None or ip in ("127.0.0.1", "::1"): continue
        a = re.search(r"Account Name:\s*(\S+)", msg.split("Account For Which Logon Failed")[-1])
        g = groups.setdefault(ip, dict(n=0, acc=set(), times=[]))
        g["n"] += 1; g["times"].append(e.get("T") or ""); g["acc"].add(a.group(1) if a else "?")
    out = []
    for ip, g in groups.items():
        if g["n"] < min_count: continue
        first = min(g["times"])
        out.append(dict(title=f"{g['n']} failed Windows logons from {ip}", severity="High" if g["n"] >= 20 else "Medium",
                        category="Brute-Force Login", source_ip=ip, timestamp=first, external_id=f"win4625-{ip}-{first[:10]}",
                        description=f"Event 4625 in last 24h. Accounts targeted: {', '.join(sorted(g['acc'])[:5])}"))
    return out

# ---------- app factory ----------
def create_app(db_path=None, now=None):
    app = Flask(__name__, template_folder=BASE_DIR, static_folder=None)  # flat layout: all files in one folder
    app.secret_key = os.environ.get("SECRET_KEY", "demo-only-not-for-production")
    app.config["NOW"] = now
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    os.makedirs(app.instance_path, exist_ok=True)
    app.config["DB"] = db_path or os.path.join(app.instance_path, "soc_insight.db")
    init_db(app)
    app.jinja_env.filters["dur"] = dur

    @app.get("/static/<path:filename>", endpoint="static")
    def static_files(filename):  # only the two allow-listed assets are served
        if filename not in STATIC_FILES: abort(404)
        return send_from_directory(BASE_DIR, filename)

    def db():
        if "db" not in g: g.db = connect(app.config["DB"])
        return g.db
    @app.teardown_appcontext
    def close(_):
        c = g.pop("db", None)
        if c: c.close()
    @app.context_processor
    def ctx():
        n = db().execute("SELECT COUNT(*) FROM incidents WHERE severity='Critical' AND status IN ('Open','Acknowledged','In Progress')").fetchone()[0]
        return dict(crit_count=n, now_str=utcnow().strftime("%Y-%m-%d %H:%M UTC"), SEVERITIES=SEVERITIES, STATUSES=STATUSES, CATEGORIES=CATEGORIES)
    def analysts(active=True):
        return db().execute("SELECT * FROM analysts" + (" WHERE active=1" if active else "") + " ORDER BY name").fetchall()
    def items_for(args): return fetch_items(db(), args, get_thr(db()), utcnow())

    @app.get("/")
    def dashboard(): return render_template("dashboard.html")

    @app.get("/api/dashboard")
    def api_dashboard():
        now = utcnow(); dp = request.args.get("days", "all"); days = int(dp) if dp in ("7", "30", "90") else None
        args = {"severity": request.args.get("severity"), "origin": request.args.get("origin")}
        if days: args["date_from"] = (now - timedelta(days=days)).strftime("%Y-%m-%d")
        items = items_for(args); s = summarize(items); rows = analyst_rows(analysts(), items)
        s["active_analysts"] = len(analysts())
        recent = [{k: i[k] for k in ("id", "alert_code", "title", "severity", "status", "analyst_name", "created_at", "sla", "origin")} for i in items[:10]]
        return jsonify(summary=s, trend=trend(items, days or 30, now), analysts=rows, recent=recent, days=days or "all")

    @app.get("/alerts")
    def alerts():
        items = items_for(request.args); page = max(1, int(request.args.get("page", 1))) if request.args.get("page", "1").isdigit() else 1
        per = 15; pages = max(1, -(-len(items) // per)); page = min(page, pages)
        qs = {k: v for k, v in request.args.items() if k != "page" and v}
        return render_template("alerts.html", items=items[(page - 1) * per: page * per], total=len(items), page=page, pages=pages, qs=qs, analysts=analysts(False))

    def get_inc(iid):
        r = db().execute("SELECT i.*, a.name AS analyst_name FROM incidents i LEFT JOIN analysts a ON a.id=i.assigned_analyst_id WHERE i.id=?", (iid,)).fetchone()
        if not r: return None
        return enrich(r, get_thr(db()), utcnow())

    @app.get("/incident/<int:iid>")
    def incident(iid):
        d = get_inc(iid)
        if not d: return render_template("error.html", code=404, msg="Incident not found."), 404
        logs = db().execute("SELECT * FROM incident_log WHERE incident_id=? ORDER BY timestamp DESC, id DESC", (iid,)).fetchall()
        return render_template("incident_detail.html", d=d, logs=logs, analysts=analysts(), nexts=TRANSITIONS[d["status"]], action=next_action(d))

    def apply(iid, sets, action, details):
        t = ts(utcnow()); sets = dict(sets, updated_at=t)
        db().execute("UPDATE incidents SET " + ",".join(f"{k}=?" for k in sets) + " WHERE id=?", [*sets.values(), iid])
        log(db(), iid, "Supervisor", action, details, t); db().commit()

    def guard(iid):
        d = get_inc(iid)
        if not d: return None, (render_template("error.html", code=404, msg="Incident not found."), 404)
        if d["status"] == "Closed":
            flash("Closed incidents cannot be modified.", "danger"); return None, redirect(url_for("incident", iid=iid))
        return d, None

    @app.post("/incident/<int:iid>/assign")
    def assign(iid):
        d, err = guard(iid)
        if err: return err
        a = db().execute("SELECT * FROM analysts WHERE id=? AND active=1", (request.form.get("analyst_id", "0") if request.form.get("analyst_id", "").isdigit() else 0,)).fetchone()
        if not a: flash("Select a valid active analyst.", "danger")
        else:
            apply(iid, {"assigned_analyst_id": a["id"]}, "Incident assigned", f"Assigned to {a['name']}"); flash(f"Assigned to {a['name']}.", "success")
        return redirect(url_for("incident", iid=iid))

    @app.post("/incident/<int:iid>/status")
    def status(iid):
        d, err = guard(iid)
        if err: return err
        new = request.form.get("status")
        if new not in TRANSITIONS[d["status"]]:
            flash(f"Invalid transition: {d['status']} → {new}.", "danger"); return redirect(url_for("incident", iid=iid))
        t = ts(utcnow()); sets = {"status": new}
        if new in ("Acknowledged", "In Progress") and not d["acknowledged_at"]: sets["acknowledged_at"] = t
        if new == "Resolved": sets["resolved_at"] = t
        if new == "In Progress" and d["status"] == "Resolved": sets["resolved_at"] = None
        apply(iid, sets, {"Acknowledged": "Incident acknowledged", "Resolved": "Incident resolved", "Closed": "Incident closed"}.get(new, "Status updated"), f"{d['status']} → {new}")
        flash(f"Status changed to {new}.", "success"); return redirect(url_for("incident", iid=iid))

    @app.post("/incident/<int:iid>/severity")
    def severity(iid):
        d, err = guard(iid)
        if err: return err
        s = request.form.get("severity")
        if s not in SEVERITIES: flash("Invalid severity.", "danger")
        elif s != d["severity"]:
            apply(iid, {"severity": s}, "Severity changed", f"{d['severity']} → {s}"); flash("Severity updated.", "success")
        return redirect(url_for("incident", iid=iid))

    @app.post("/incident/<int:iid>/note")
    def note(iid):
        d, err = guard(iid)
        if err: return err
        n = (request.form.get("note") or "").strip()[:1000]
        if not n: flash("Note cannot be empty.", "danger")
        else:
            apply(iid, {}, "Investigation note", n); flash("Note added.", "success")
        return redirect(url_for("incident", iid=iid))

    @app.get("/analysts")
    def analyst_page():
        items = items_for({}); rows = analyst_rows(analysts(), items)
        return render_template("analyst_performance.html", rows=rows, summary=imbalance(rows))

    @app.get("/reports")
    def reports():
        items = items_for(request.args); s = summarize(items); rows = analyst_rows(analysts(), items)
        top = sorted(((c, sum(i["alert_type"] == c and i["unresolved"] for i in items)) for c in CATEGORIES), key=lambda x: -x[1])
        return render_template("reports.html", s=s, rows=rows, top=[t for t in top if t[1]][:5], qs=request.args.to_dict())

    @app.get("/reports/export.csv")
    def export_csv():
        items = items_for(request.args); out = io.StringIO(); w = csv.writer(out)
        w.writerow(["alert_code", "title", "category", "severity", "status", "analyst", "source_ip", "destination_ip", "created_at_utc",
                    "acknowledged_at_utc", "resolved_at_utc", "ack_minutes", "resolution_minutes", "sla_status"])
        for i in items:
            r = lambda x: "" if x is None else round(x, 1)
            w.writerow([csv_safe(v) for v in (i["alert_code"], i["title"], i["alert_type"], i["severity"], i["status"], i["analyst_name"],
                        i["source_ip"], i["destination_ip"], i["created_at"], i["acknowledged_at"], i["resolved_at"], r(i["ack_min"]), r(i["res_min"]), i["sla"])])
        fn = f"soc_incidents_{utcnow().strftime('%Y%m%d')}.csv"
        return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={fn}"})

    @app.get("/recommendations")
    def recommendations():
        items = items_for({}); return render_template("recommendations.html", recs=recommend(items, analyst_rows(analysts(), items), utcnow()))

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        if request.method == "POST":
            vals = {}
            for s in SEVERITIES:
                v = request.form.get(f"sla_{s}", "")
                if not v.isdigit() or not 1 <= int(v) <= 1440:
                    flash(f"{s} threshold must be a whole number between 1 and 1440 minutes.", "danger"); return redirect(url_for("settings"))
                vals[s] = int(v)
            for s, v in vals.items(): db().execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (f"sla_{s}", str(v)))
            db().commit(); flash("SLA thresholds saved.", "success"); return redirect(url_for("settings"))
        return render_template("settings.html", thr=get_thr(db()))

    @app.post("/settings/reset")
    def reset():
        if request.form.get("confirm") != "yes": flash("Reset not confirmed.", "danger"); return redirect(url_for("settings"))
        c = db()
        c.execute("DELETE FROM incidents WHERE origin='demo'")
        seed(c, utcnow()); c.commit(); flash("Demo data reset.", "success"); return redirect(url_for("dashboard"))

    @app.route("/import", methods=["GET", "POST"])
    def import_page():
        if request.method == "POST":
            f = request.files.get("file")
            if not f or not f.filename: flash("Choose a .csv or .json file first.", "danger"); return redirect(url_for("import_page"))
            try: res = ingest(db(), parse_upload(f.filename, f.read().decode("utf-8-sig", errors="replace")), "import", utcnow())
            except ValueError as e: flash(str(e), "danger"); return redirect(url_for("import_page"))
            types = ", ".join(f"{k} {v}" for k, v in sorted(res["types"].items(), key=lambda x: -x[1]))
            flash(f"Imported {res['created']} alert(s), {res['duplicates']} duplicate(s), {res['rejected']} rejected. Auto-detected types: {types or 'none'}", "success" if res["created"] else "warning")
            return redirect(url_for("dashboard", origin="real") if res["created"] else url_for("import_page"))
        key = db().execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]
        real = db().execute("SELECT origin, COUNT(*) FROM incidents WHERE origin!='demo' GROUP BY origin").fetchall()
        return render_template("import.html", key=key, real=real, is_windows=os.name == "nt")

    @app.post("/api/ingest")
    def api_ingest():
        stored = db().execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]
        if not hmac.compare_digest(request.headers.get("X-API-Key", "").encode(), stored.encode()):
            return jsonify(error="invalid or missing X-API-Key"), 401
        data = request.get_json(silent=True)
        recs = data if isinstance(data, list) else (data.get("alerts") or [data]) if isinstance(data, dict) else None
        if not recs: return jsonify(error="send a JSON object or list of alerts"), 400
        res = ingest(db(), recs, "webhook", utcnow()); return jsonify(res), 201 if res["created"] else 200

    @app.post("/collect/windows")
    def collect_windows():
        if os.name != "nt": flash("The Windows collector only runs on Windows.", "danger"); return redirect(url_for("import_page"))
        ps = ("Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 500 | "
              "Select-Object @{n='T';e={$_.TimeCreated.ToUniversalTime().ToString('s')}},Message | ConvertTo-Json")
        try: p = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e: flash(f"Could not run PowerShell: {e}", "danger"); return redirect(url_for("import_page"))
        if p.returncode != 0 or not p.stdout.strip():
            flash("No failed-logon events read. Either none occurred in 24h, or the terminal needs 'Run as administrator' to read the Security log.", "warning"); return redirect(url_for("import_page"))
        try: ev = json.loads(p.stdout)
        except ValueError: flash("Could not parse PowerShell output.", "danger"); return redirect(url_for("import_page"))
        ev = ev if isinstance(ev, list) else [ev]; recs = windows_events_to_alerts(ev)
        res = ingest(db(), recs, "windows", utcnow())
        flash(f"Read {len(ev)} failed-logon events; {res['created']} new alert(s), {res['duplicates']} already present (alerts need 5+ failures from one IP).", "success")
        return redirect(url_for("import_page"))

    @app.post("/settings/clear-demo")
    def clear_demo():
        if request.form.get("confirm") != "yes": flash("Not confirmed.", "danger"); return redirect(url_for("settings"))
        db().execute("DELETE FROM incidents WHERE origin='demo'"); db().commit(); flash("Demo incidents removed. Real alerts kept.", "success")
        return redirect(url_for("alerts"))

    @app.errorhandler(404)
    def e404(_): return render_template("error.html", code=404, msg="Page not found."), 404
    @app.errorhandler(500)
    def e500(_): return render_template("error.html", code=500, msg="Something went wrong on the server."), 500
    return app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)

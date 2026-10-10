import os, sys, sqlite3, tempfile, unittest
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as A

NOW = datetime(2026, 6, 1, 12, 0, 0)

class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.path = os.path.join(self.tmp.name, "t.db")
        self.app = A.create_app(self.path, now=NOW); self.c = self.app.test_client()
    def tearDown(self): self.tmp.cleanup()
    def conn(self): return A.connect(self.path)
    def add(self, code, sev="Low", status="Open", created=NOW - timedelta(minutes=1), ack=None, res=None, analyst=None, title="t", cat="Phishing"):
        c = self.conn(); f = A.ts
        cur = c.execute("INSERT INTO incidents(alert_code,title,alert_type,severity,status,assigned_analyst_id,created_at,acknowledged_at,resolved_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (code, title, cat, sev, status, analyst, f(created), f(ack), f(res), f(created)))
        c.commit(); i = cur.lastrowid; c.close(); return i
    def row(self, i):
        c = self.conn(); r = c.execute("SELECT * FROM incidents WHERE id=?", (i,)).fetchone(); c.close(); return r

class Tests(Base):
    def test_dashboard_loads(self):
        self.assertEqual(self.c.get("/").status_code, 200)
        for p in ("/alerts", "/analysts", "/reports", "/recommendations", "/settings", "/api/dashboard", "/reports/export.csv", "/import"):
            self.assertEqual(self.c.get(p).status_code, 200, p)
    def test_tables_exist(self):
        c = self.conn(); n = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"analysts", "incidents", "incident_log", "settings"} <= n)
    def test_seed_once(self):
        c = self.conn(); n = c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        self.assertTrue(100 <= n <= 150); self.assertEqual(c.execute("SELECT COUNT(*) FROM analysts").fetchone()[0], 5)
        A.create_app(self.path, now=NOW)
        self.assertEqual(self.conn().execute("SELECT COUNT(*) FROM incidents").fetchone()[0], n)
    def test_dashboard_metrics_from_db(self):
        d = self.c.get("/api/dashboard?days=90").get_json()["summary"]
        c = self.conn(); total = c.execute("SELECT COUNT(*) FROM incidents WHERE created_at>=?", (A.ts(NOW - timedelta(days=90)).split("T")[0] + "T00:00:00",)).fetchone()[0]
        self.assertEqual(d["total"], total)
        self.add("X-1", sev="Critical", created=NOW - timedelta(minutes=2))
        d2 = self.c.get("/api/dashboard?days=90").get_json()["summary"]
        self.assertEqual(d2["total"], total + 1); self.assertEqual(d2["critical"], d["critical"] + 1)
    def test_filters(self):
        c = self.conn(); thr = A.get_thr(c)
        its = A.fetch_items(c, {"severity": "Critical", "status": "Open"}, thr, NOW)
        self.assertTrue(its and all(i["severity"] == "Critical" and i["status"] == "Open" for i in its))
        self.assertEqual(len(its), c.execute("SELECT COUNT(*) FROM incidents WHERE severity='Critical' AND status='Open'").fetchone()[0])
        self.assertEqual(len(A.fetch_items(c, {"severity": "Bogus"}, thr, NOW)), c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])
    def test_assign(self):
        i = self.add("X-2"); self.c.post(f"/incident/{i}/assign", data={"analyst_id": "2"})
        self.assertEqual(self.row(i)["assigned_analyst_id"], 2)
        self.c.post(f"/incident/{i}/assign", data={"analyst_id": "999"})
        self.assertEqual(self.row(i)["assigned_analyst_id"], 2)
        self.assertTrue(self.conn().execute("SELECT 1 FROM incident_log WHERE incident_id=? AND action='Incident assigned'", (i,)).fetchone())
    def test_ack_and_resolve_timestamps(self):
        i = self.add("X-3"); self.c.post(f"/incident/{i}/status", data={"status": "Acknowledged"})
        r = self.row(i); self.assertEqual(r["acknowledged_at"], A.ts(NOW)); self.assertEqual(r["status"], "Acknowledged")
        self.c.post(f"/incident/{i}/status", data={"status": "Acknowledged"})  # duplicate rejected
        self.assertEqual(self.row(i)["acknowledged_at"], A.ts(NOW))
        self.c.post(f"/incident/{i}/status", data={"status": "Resolved"})
        r = self.row(i); self.assertEqual(r["resolved_at"], A.ts(NOW)); self.assertEqual(r["status"], "Resolved")
    def test_sla_boundary(self):
        thr = A.DEFAULT_SLA; base = NOW - timedelta(hours=1)
        def e(ack=None, el=None, st="Open"):
            created = base if ack is not None else NOW - timedelta(seconds=el)
            return A.enrich({"alert_code": "x", "severity": "Critical", "status": st, "created_at": A.ts(created),
                             "acknowledged_at": A.ts(created + timedelta(seconds=ack)) if ack is not None else None, "resolved_at": None}, thr, NOW)
        self.assertEqual(e(ack=300)["sla"], "Within SLA"); self.assertEqual(e(ack=301)["sla"], "Breached")
        self.assertEqual(e(el=300)["sla"], "At risk"); self.assertFalse(e(el=300)["overdue"])
        self.assertEqual(e(el=301)["sla"], "Breached"); self.assertTrue(e(el=301)["overdue"])
        self.assertEqual(e(el=10)["sla"], "Pending")
    def test_missing_timestamps(self):
        self.add("X-4", status="Resolved", sev="High")  # resolved without ack/resolved timestamps
        self.assertEqual(self.c.get("/api/dashboard").status_code, 200)
        self.assertEqual(self.c.get("/reports").status_code, 200)
    def test_recommendations(self):
        i = self.add("X-5", sev="Critical", created=NOW - timedelta(minutes=20))
        body = self.c.get("/recommendations").get_data(as_text=True)
        self.assertIn("X-5", body); self.assertIn("no analyst", body)
    def test_csv(self):
        self.add("X-6", title="=cmd()", sev="Low")
        r = self.c.get("/reports/export.csv?q=X-6")
        self.assertEqual(r.mimetype, "text/csv"); t = r.get_data(as_text=True)
        self.assertIn("alert_code,title", t); self.assertIn("X-6,'=cmd()", t); self.assertEqual(len(t.strip().splitlines()), 2)
    def test_invalid_transition(self):
        i = self.add("X-7"); self.c.post(f"/incident/{i}/status", data={"status": "Closed"})
        self.assertEqual(self.row(i)["status"], "Open")
        self.c.post(f"/incident/{i}/severity", data={"severity": "Nope"}); self.assertEqual(self.row(i)["severity"], "Low")
    def test_sql_injection(self):
        r = self.c.get("/alerts?q=' OR 1=1 --&severity=' OR '1'='1"); self.assertEqual(r.status_code, 200)
        c = self.conn(); self.assertEqual(len(A.fetch_items(c, {"q": "' OR 1=1 --"}, A.get_thr(c), NOW)), 0)
        self.assertGreater(c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 100)
    def test_settings_persist(self):
        self.c.post("/settings", data={"sla_Critical": "7", "sla_High": "15", "sla_Medium": "30", "sla_Low": "60"})
        self.assertEqual(A.get_thr(self.conn())["Critical"], 7); self.assertIn('value="7"', self.c.get("/settings").get_data(as_text=True))
        self.c.post("/settings", data={"sla_Critical": "abc", "sla_High": "15", "sla_Medium": "30", "sla_Low": "60"})
        self.assertEqual(A.get_thr(self.conn())["Critical"], 7)
    def test_reset(self):
        self.add("X-8"); self.c.post("/settings/reset", data={"confirm": "yes"})
        self.assertIsNone(self.conn().execute("SELECT 1 FROM incidents WHERE alert_code='X-8'").fetchone())

    def test_normalize_and_import_dedupe(self):
        n, e = A.normalize({"Name": "Phishing mail", "Priority": "7", "src": "203.0.113.5", "time": "2026-06-01T10:00:00+02:00"}, NOW)
        self.assertIsNone(e); self.assertEqual(n["severity"], "High"); self.assertEqual(n["category"], "Phishing")
        self.assertEqual(A.ts(n["created_at"]), "2026-06-01T08:00:00")
        self.assertIsNone(A.normalize({"severity": "high"}, NOW)[0])
        csvd = b"id,title,severity\nE1,Brute force login,critical\nE2,,low\n"
        import io
        for expect in (1, 0):
            r = self.c.post("/import", data={"file": (io.BytesIO(csvd), "a.csv")}, content_type="multipart/form-data")
            self.assertEqual(r.status_code, 302)
        c = self.conn(); rows = c.execute("SELECT severity, origin, status FROM incidents WHERE origin='import'").fetchall()
        self.assertEqual(len(rows), 1); self.assertEqual((rows[0][0], rows[0][2]), ("Critical", "Open"))
    def test_webhook_key(self):
        self.assertEqual(self.c.post("/api/ingest", json={"title": "x"}).status_code, 401)
        key = self.conn().execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]
        r = self.c.post("/api/ingest", json={"title": "Port scan", "severity": "low"}, headers={"X-API-Key": key})
        self.assertEqual(r.status_code, 201); self.assertEqual(r.get_json()["created"], 1)
        self.assertEqual(self.c.post("/api/ingest", json={"title": "Port scan", "severity": "low", "id": "z"}, headers={"X-API-Key": "bad"}).status_code, 401)
        self.assertIn("RA-", self.c.get("/alerts?origin=real").get_data(as_text=True))
    def test_windows_grouping(self):
        ev = [{"T": f"2026-06-01T10:0{i}:00", "Message": "Account For Which Logon Failed:\n Account Name: admin\n Source Network Address: 203.0.113.9"} for i in range(6)]
        ev += [{"T": "2026-06-01T10:00:00", "Message": "Source Network Address: 203.0.113.50"}]
        out = A.windows_events_to_alerts(ev); self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["source_ip"], "203.0.113.9"); self.assertEqual(out[0]["severity"], "Medium")
    def test_clear_demo_keeps_real(self):
        self.c.post("/api/ingest", json={"title": "Keep me"}, headers={"X-API-Key": self.conn().execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]})
        self.c.post("/settings/clear-demo", data={"confirm": "yes"})
        self.assertEqual(self.conn().execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)

    def test_auto_detect_types_and_dashboard(self):
        for title, cat in [("Possible SQL injection on web app", "Web Application Attack"), ("Port scan detected", "Reconnaissance"),
                           ("DDoS flood on gateway", "Denial of Service"), ("Admin group membership changed", "Privilege Escalation"),
                           ("VPN login from new country", "Unauthorized Access"), ("Something unusual", "Other")]:
            self.assertEqual(A.normalize({"title": title}, NOW)[0]["category"], cat, title)
        key = self.conn().execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]
        r = self.c.post("/api/ingest", json=[{"title": "Port scan detected", "timestamp": "2020-01-01T00:00:00Z"}, {"title": "DDoS flood"}], headers={"X-API-Key": key})
        self.assertEqual(r.get_json()["types"], {"Reconnaissance": 1, "Denial of Service": 1})
        s = self.c.get("/api/dashboard?days=all&origin=real").get_json()["summary"]
        self.assertEqual(s["total"], 2); self.assertEqual(s["category"]["Reconnaissance"], 1)
        self.assertEqual(self.c.get("/api/dashboard?days=7&origin=real").get_json()["summary"]["total"], 1)

if __name__ == "__main__": unittest.main()

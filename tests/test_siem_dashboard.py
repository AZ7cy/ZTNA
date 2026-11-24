"""Manager SIEM dashboard: the numbers it shows must equal what is in the audit chain (headless, no Tk needed)."""
import os, sys, tempfile, time, unittest
from pathlib import Path


class SiemDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-siem-"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import ztna_lab_v2 as z
        cls.z = z
        z.REQUESTED_MODE = "gui"; z.init_runtime("gui")
        cls.creds = {u: p for u, p, _r, _s in z.DEMO_BOOTSTRAP_CREDENTIALS}
        for user in list(cls.creds)[:4]:
            e = z.DesktopZTNA()
            ok, _ = e.login(user, cls.creds[user], e.demo_otp(user), f"laptop-{user}", "office")
            assert ok
            for res in z.RESOURCES: e.access(res)
            z.DesktopZTNA().login(user, "wrong-password", "000000", f"laptop-{user}", "office")

    @classmethod
    def tearDownClass(cls):
        # The deliberate bad-password logins above must not lock demo users out of tests that run later in the same process.
        with cls.z.LOCK:
            cls.z.FAILS.clear(); cls.z.USERFAIL.clear()

    def test_counts_match_the_raw_log(self):
        z = self.z; s = z.siem_snapshot(3600); log = list(z.LOG)
        access = [e for e in log if e["resource"] in z.RESOURCES and e["decision"] != "POLICY" and not z._is_exception_record(e)]   # extra-access workflow entries are not access decisions
        c = s["cur_agg"]
        self.assertEqual(c["events"], len(log))
        self.assertEqual(c["access"], len(access))
        self.assertEqual(c["allow"], sum(e["decision"] == "ALLOW" for e in access))
        self.assertEqual(c["deny"], sum(e["decision"] == "DENY" for e in access))
        self.assertEqual(c["failed_auth"], sum(e["resource"] == "login" and e["decision"] == "DENY" for e in log))
        self.assertEqual(sum(b["ev"] for b in s["buckets"]), len(s["cur"]))

    def test_window_excludes_old_events(self):
        s = self.z.siem_snapshot(900, now=time.time() + 7200)
        self.assertEqual(s["cur_agg"]["events"], 0)
        self.assertEqual(s["threat"]["score"], sum(f[1] for f in s["threat"]["factors"]))

    def test_iso_timestamps_are_parsed(self):
        z = self.z
        self.assertAlmostEqual(z._evt_epoch({"ts": "2026-01-01T00:00:00Z"}), 1767225600.0)
        self.assertEqual(z._evt_epoch({"ts": 12.5}), 12.5)
        self.assertEqual(z._evt_epoch({"ts": "garbage"}), 0.0)

    def test_categories_and_severity(self):
        z = self.z
        self.assertEqual(z.siem_category({"resource": "wiki", "decision": "ALLOW"}), "Access")
        self.assertEqual(z.siem_category({"resource": "login", "decision": "DENY"}), "Authentication")
        self.assertEqual(z.siem_category({"resource": "unknown:abc", "decision": "FALSE_ALARM"}), "Response")
        self.assertEqual(z.siem_category({"resource": "wiki", "decision": "POLICY"}), "Admin")
        self.assertEqual(z.siem_event_severity({"decision": "DENY", "risk": 90}, "Access"), "HIGH")
        self.assertEqual(z.siem_event_severity({"decision": "DENY", "risk": 10}, "Access"), "MEDIUM")
        self.assertEqual(z.siem_event_severity({"decision": "ALLOW", "risk": 10}, "Access"), "INFO")
        self.assertEqual(z.siem_event_severity({"decision": "REVOKE", "resource": "audit-reset"}, "Admin"), "HIGH")

    def test_threat_score_is_explained_and_capped(self):
        z = self.z
        quiet = z.siem_threat([], {"access": 0, "deny": 0, "avg_risk": 0.0})
        self.assertEqual((quiet["score"], quiet["level"], quiet["factors"]), (0, "LOW", []))
        many = [{"severity": "HIGH"}] * 10
        t = z.siem_threat(many, {"access": 10, "deny": 10, "avg_risk": 90.0}, integrity_ok=False)
        self.assertEqual(t["score"], 100); self.assertEqual(t["level"], "SEVERE")
        self.assertTrue(any("Audit chain" in f[0] for f in t["factors"]))

    def test_integrity_state_and_background_verifier(self):
        z = self.z; st = z.siem_integrity_state()
        self.assertTrue(st["linked"]); self.assertTrue(all(b["ok"] for b in st["blocks"]))
        self.assertEqual(st["entries"], z.AUDIT["entries"])
        v = z._Verifier(); self.assertTrue(v.start())
        deadline = time.time() + 20
        while v.running and time.time() < deadline: time.sleep(0.02)
        self.assertTrue(v.result[1]["ok"])

    def test_tampering_is_detected_by_the_verifier(self):
        z = self.z; path = z.AUDIT_FILE
        with open(path, "rb") as fh: original = fh.read()
        try:
            lines = original.split(b"\n"); i = next(n for n, l in enumerate(lines) if b'"ALLOW"' in l)
            lines[i] = lines[i].replace(b'"ALLOW"', b'"DENY"', 1)
            with open(path, "wb") as fh: fh.write(b"\n".join(lines))
            v = z._Verifier(); v.start()
            while v.running: time.sleep(0.02)
            self.assertFalse(v.result[1]["ok"])
        finally:
            with open(path, "wb") as fh: fh.write(original)
        self.assertTrue(z.verify_chain()["ok"])


if __name__ == "__main__":
    unittest.main()

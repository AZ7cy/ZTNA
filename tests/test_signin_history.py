"""Sign-in requests: every outcome is persisted with a reason and closed out in the audit chain; history survives restarts."""
import os, sys, sqlite3, tempfile, time, unittest
from pathlib import Path


class SigninHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-hist-"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import ztna as z
        cls.z = z
        z.REQUESTED_MODE = "gui"; z.init_runtime("gui")
        cls.creds = {u: p for u, p, _r, _s in z.DEMO_BOOTSTRAP_CREDENTIALS}

    def _request(self, user):
        # Other test classes in the same process use the same demo users: forget one-time-code replay and throttle state first.
        with self.z.LOCK:
            self.z.LAST_TOTP.pop(user, None); self.z.FAILS.clear(); self.z.USERFAIL.clear()
        e = self.z.DesktopZTNA()
        ok, rid = e.request_signin(user, self.creds[user], e.demo_otp(user), f"laptop-{user}", "office")
        self.assertTrue(ok, rid)
        return e, rid

    def _closeouts(self, user):
        return [e for e in list(self.z.LOG) if e["resource"] == "signin-request" and e["decision"] == "REVOKE" and e["user"] == user]

    def _age(self, rid, col, seconds):
        c = self.z._db_connection(); c.execute(f"UPDATE signin_requests SET {col}={col}-? WHERE id=?", (seconds, rid)); c.commit()

    def test_employee_cancel_is_persisted_and_audited(self):
        z = self.z; _e, rid = self._request("alice"); base = len(self._closeouts("alice"))
        self.assertTrue(z.cancel_signin_request(rid))
        row = z.get_signin_request(rid)
        self.assertEqual(row["status"], "cancelled"); self.assertTrue(row["closed_at"]); self.assertIn("employee", row["closed_reason"])
        self.assertEqual(z.signin_outcome(row), "Cancelled by the employee")
        self.assertEqual(len(self._closeouts("alice")), base + 1)
        self.assertFalse(z.cancel_signin_request(rid), "closing twice must be a no-op")
        self.assertEqual(len(self._closeouts("alice")), base + 1)

    def test_newer_request_supersedes_older_with_an_audit_entry(self):
        z = self.z; _e1, r1 = self._request("bob"); base = len(self._closeouts("bob")); _e2, r2 = self._request("bob")
        old, new = z.get_signin_request(r1), z.get_signin_request(r2)
        self.assertEqual(old["status"], "cancelled"); self.assertIn("newer", old["closed_reason"]); self.assertEqual(new["status"], "pending")
        self.assertEqual(len(self._closeouts("bob")), base + 1)
        self.assertGreaterEqual(z.count_pending_signins(), 1)

    def test_unanswered_request_expires_once_with_true_expiry_time(self):
        z = self.z; _e, rid = self._request("carol"); base = len(self._closeouts("carol"))
        self._age(rid, "ts", z.SIGNIN_REQUEST_TTL + 5)
        z.count_pending_signins(); z.list_signin_requests(10)            # repeated reads must not re-audit
        row = z.get_signin_request(rid)
        self.assertEqual(row["status"], "expired"); self.assertFalse(row["decided_by"])
        self.assertAlmostEqual(row["closed_at"], row["ts"] + z.SIGNIN_REQUEST_TTL, places=3)
        self.assertEqual(z.signin_outcome(row), "No manager response (expired)")
        self.assertEqual(len(self._closeouts("carol")), base + 1)

    def test_unused_approval_keeps_its_approval_record(self):
        z = self.z; _e, rid = self._request("dave"); base = len(self._closeouts("dave"))
        z.decide_signin_request(rid, True, "puja", "ok")
        self._age(rid, "decided_at", z.SIGNIN_APPROVAL_TTL + 5)
        row = z.get_signin_request(rid)
        self.assertEqual((row["status"], row["decided_by"], row["note"]), ("expired", "puja", "ok"))
        self.assertEqual(z.signin_outcome(row), "Approved by puja, but not used (expired)")
        self.assertEqual(len(self._closeouts("dave")), base + 1)
        self.assertFalse(z.claim_signin_request(rid), "an expired approval must not open a session")

    def test_used_approval_and_denial_are_recorded(self):
        z = self.z; e, rid = self._request("erin")
        z.decide_signin_request(rid, True, "puja", "ok"); ok, _ = e.complete_signin(rid); self.assertTrue(ok)
        row = z.get_signin_request(rid)
        self.assertEqual(z.signin_outcome(row), "Approved - session opened"); self.assertEqual(row["closed_reason"], "approval used: session opened")
        _e2, r2 = self._request("frank"); z.decide_signin_request(r2, False, "puja", "unknown device")
        d = z.get_signin_request(r2)
        self.assertEqual((d["status"], d["note"], d["closed_reason"]), ("denied", "unknown device", "denied by manager")); self.assertEqual(z.signin_outcome(d), "Denied by puja")

    def test_history_listing_and_chain_stays_valid(self):
        z = self.z
        hist = z.list_signin_requests(1000, status="history"); self.assertTrue(hist and all(r["status"] != "pending" for r in hist))
        pend = z.list_signin_requests(1000, status="pending"); self.assertTrue(all(r["status"] == "pending" for r in pend))
        self.assertTrue(z.verify_chain()["ok"])

    def test_closeout_entries_read_correctly_in_plain_language(self):
        z = self.z; _e, rid = self._request("grace"); z.cancel_signin_request(rid)
        entry = self._closeouts("grace")[0]; label, _tag, sentence = z.describe_audit_event(entry)
        self.assertEqual(label, "Closed"); self.assertIn("ended without a session", sentence); self.assertNotIn("denied", sentence)

    def test_retention_keeps_recent_history_and_never_deletes_pending(self):
        z = self.z; c = z._db_connection(); now = time.time(); day = 86400
        for rid, age, status, who in (("old-8d", 8, "denied", "ret1"), ("old-100d", 100, "denied", "ret2"), ("old-pending", 200, "pending", "ret3")):
            c.execute("INSERT INTO signin_requests(id,ts,user,device,location,status) VALUES(?,?,?,?,?,?)", (rid, now - age * day, who, "laptop-" + who, "office", status))
        c.commit()
        self.addCleanup(lambda: (c.execute("DELETE FROM signin_requests WHERE id IN ('old-8d','old-100d','old-pending')"), c.commit()))
        z.db_init()                                                        # runs the startup retention pass
        left = {r[0] for r in c.execute("SELECT id FROM signin_requests")}
        self.assertIn("old-8d", left, "history older than 7 days used to be wiped at every start")
        self.assertNotIn("old-100d", left); self.assertIn("old-pending", left)

    def test_existing_database_without_new_columns_is_migrated(self):
        z = self.z; old_file = z.DB_FILE; path = os.path.join(tempfile.mkdtemp(prefix="ztna-mig-"), "old.db")
        with sqlite3.connect(path) as c:
            c.execute("CREATE TABLE signin_requests (id TEXT PRIMARY KEY, ts REAL, user TEXT, device TEXT, location TEXT, status TEXT, decided_by TEXT, decided_at REAL, note TEXT, consumed INTEGER DEFAULT 0)")
            c.execute("INSERT INTO signin_requests(id,ts,user,device,location,status,decided_by) VALUES('legacy',?,'alice','laptop-alice','office','denied','puja')", (time.time(),))
        try:
            z.DB_FILE = path; z.db_init()
        finally:
            z.DB_FILE = old_file
        with sqlite3.connect(path) as c:
            cols = {r[1] for r in c.execute("PRAGMA table_info(signin_requests)")}
            self.assertTrue({"closed_at", "closed_reason"} <= cols)
            self.assertEqual(c.execute("SELECT status FROM signin_requests WHERE id='legacy'").fetchone()[0], "denied")
        self.assertEqual(self.z.signin_outcome({"status": "denied", "decided_by": "puja"}), "Denied by puja")


if __name__ == "__main__":
    unittest.main()

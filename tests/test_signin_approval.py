"""Sign-in approval queue: request -> manager decision -> one-time session."""
import os, sys, tempfile, unittest
from pathlib import Path

class SigninApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-signin-"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import ztna_lab_v2 as z
        cls.z = z
        z.REQUESTED_MODE = "gui"; z.init_runtime("gui")
        cls.creds = {u: p for u, p, _r, _s in z.DEMO_BOOTSTRAP_CREDENTIALS}

    def setUp(self):
        # A wrong-password test sets a 0.25 s per-user backoff; clear it so the next test never races that window.
        with self.z.LOCK:
            self.z.FAILS.clear(); self.z.USERFAIL.clear()

    def _request(self, user="alice"):
        e = self.z.DesktopZTNA()
        ok, rid = e.request_signin(user, self.creds[user], e.demo_otp(user), f"laptop-{user}", "office")
        self.assertTrue(ok, rid)
        return e, rid

    def test_pending_then_approved_opens_one_session(self):
        e, rid = self._request()
        self.assertEqual(self.z.get_signin_request(rid)["status"], "pending")
        self.assertIsNone(e.session)
        self.assertFalse(e.complete_signin(rid)[0])
        self.assertTrue(self.z.decide_signin_request(rid, True, "puja"))
        self.assertTrue(e.complete_signin(rid)[0])
        self.assertFalse(self.z.DesktopZTNA().complete_signin(rid)[0])   # approval is single-use

    def test_denied_never_opens_session(self):
        e, rid = self._request("bob")
        self.z.decide_signin_request(rid, False, "puja", "no")
        self.assertFalse(e.complete_signin(rid)[0])
        self.assertIsNone(self.z.decide_signin_request(rid, True, "puja"))  # already decided

    def test_bad_password_creates_no_request(self):
        e = self.z.DesktopZTNA()
        ok, _ = e.request_signin("alice", "wrong", e.demo_otp("alice"), "laptop-alice", "office")
        self.assertFalse(ok)

    def test_audit_chain_still_verifies(self):
        self.assertTrue(self.z.verify_chain()["ok"])

    def test_signin_request_publishes_gui_event(self):
        self.z.publish_gui_event("signin-created", request_id="test-request", user="alice", device="laptop-alice")
        events = []
        try:
            while True: events.append(self.z.GUI_EVENTS.get_nowait())
        except self.z.queue.Empty: pass
        self.assertTrue(any(x.get("kind") == "signin-created" and x.get("request_id") == "test-request" for x in events))

    def test_manager_can_force_stepup_on_next_resource_request(self):
        e = self.z.DesktopZTNA()
        ok, msg = e._open_session("carol", "laptop-carol", "office")
        self.assertTrue(ok, msg)
        self.z.STEPUP_REQUIRED_USERS.add("carol")
        result = e.access("wiki")
        self.assertEqual(result.get("decision"), "STEPUP")
        ok, msg = e.stepup(e.demo_otp("carol"))
        self.assertTrue(ok, msg)
        self.assertNotIn("carol", self.z.STEPUP_REQUIRED_USERS)
        e.logout()

if __name__ == "__main__":
    unittest.main()

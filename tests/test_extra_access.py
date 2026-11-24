"""Extra-access requests: an alert is raised for each request, tracked through the decision and the end of the access."""
import os, sys, tempfile, time, unittest
from pathlib import Path


class ExtraAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-xa-"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import ztna_lab_v2 as z
        cls.z = z
        z.REQUESTED_MODE = "gui"; z.init_runtime("gui")

    # ---- helpers
    def dev(self, user): return next(d for d, v in self.z.DEVICES.items() if v["owner"] == user)

    def outside_role(self, user, sensitive=None):
        z = self.z
        for r in z.RESOURCES:
            if z.rbac_allows(user, r) and z.segment_allows(user, r): continue
            if sensitive is None or (z.RESOURCES[r]["min_posture"] >= 80) == sensitive: return r
        self.skipTest(f"no suitable app outside {user}'s role")

    def alerts(self, kind="EXTRA_ACCESS_REQUEST", ref=None):
        with self.z.TELEMETRY_CACHE_LOCK: self.z.TELEMETRY_CACHE["alerts_ts"] = 0.0
        return [a for a in self.z.recent_alerts(500) if a["kind"] == kind and (ref is None or a["ref"] == ref)]

    def request(self, user, resource=None, reason="needed for a task"):
        resource = resource or self.outside_role(user)
        return self.z.create_access_exception_request(user, self.dev(user), resource, reason), resource

    def age(self, rid, col, seconds):
        c = self.z._db_connection(); c.execute(f"UPDATE access_exception_requests SET {col}={col}-? WHERE id=?", (seconds, rid)); c.commit()

    def closeouts(self, user):
        return [e for e in list(self.z.LOG) if e["user"] == user and e["decision"] == "REVOKE" and e["reasons"] and e["reasons"][0].startswith(self.z.EXTRA_ACCESS_PREFIX)]

    # ---- alert generation
    def test_a_request_raises_one_open_alert_linked_to_it(self):
        rid, res = self.request("alice", self.outside_role("alice", sensitive=False))
        (a,) = self.alerts(ref=rid)
        self.assertEqual((a["kind"], a["user"], a["status"]), ("EXTRA_ACCESS_REQUEST", "alice", 0))
        self.assertIn(res, a["details"]); self.assertIn("needed for a task", a["details"]); self.assertIn(rid, a["details"])
        self.assertEqual(a["severity"], "MEDIUM")

    def test_a_sensitive_application_is_high_severity(self):
        rid, _ = self.request("bob", self.outside_role("bob", sensitive=True))
        self.assertEqual(self.alerts(ref=rid)[0]["severity"], "HIGH")
        self.assertIn("sensitive application", self.alerts(ref=rid)[0]["details"])

    def test_a_weak_or_unmanaged_device_is_high_severity(self):
        z = self.z; dev = self.dev("leo"); old = dict(z.DEVICES[dev])
        try:
            z.DEVICES[dev]["corporate_managed"] = False
            rid, _ = self.request("leo", self.outside_role("leo", sensitive=False))
        finally:
            z.DEVICES[dev].update(old)
        a = self.alerts(ref=rid)[0]
        self.assertEqual(a["severity"], "HIGH"); self.assertIn("unmanaged device", a["details"])

    def test_repeating_a_pending_request_does_not_raise_another_alert(self):
        res = self.outside_role("dave", sensitive=False)
        rid, _ = self.request("dave", res); again, _ = self.request("dave", res, "asking twice")
        self.assertEqual(rid, again); self.assertEqual(len(self.alerts(ref=rid)), 1)

    def test_three_different_apps_in_an_hour_raise_a_pattern_alert(self):
        z = self.z; user = "erin"; before = len(self.alerts("EXTRA_ACCESS_PATTERN"))
        apps = [r for r in z.RESOURCES if not (z.rbac_allows(user, r) and z.segment_allows(user, r))][:3]
        self.assertEqual(len(apps), 3)
        for r in apps[:2]: self.request(user, r)
        self.assertEqual(len(self.alerts("EXTRA_ACCESS_PATTERN")), before, "two requests are not a pattern")
        self.request(user, apps[2])
        new = self.alerts("EXTRA_ACCESS_PATTERN"); self.assertEqual(len(new), before + 1)
        self.assertEqual(new[0]["severity"], "HIGH"); self.assertEqual(new[0]["user"], user)

    def test_no_alert_and_no_row_for_an_application_the_role_already_has(self):
        z = self.z; app = next(r for r in z.RESOURCES if z.rbac_allows("frank", r) and z.segment_allows("frank", r))
        with self.assertRaises(ValueError): z.create_access_exception_request("frank", self.dev("frank"), app, "x")

    # ---- tracking
    def test_each_listed_request_shows_its_alert_state(self):
        z = self.z; rid, _ = self.request("grace", self.outside_role("grace", sensitive=False))
        row = next(r for r in z.list_access_exception_requests() if r["id"] == rid)
        self.assertEqual((row["status"], row["alert_status"]), ("pending", 0))

    def test_approval_closes_the_alert_with_a_note_and_grants_access_until_the_end(self):
        z = self.z; rid, res = self.request("jack", self.outside_role("jack", sensitive=False))
        self.assertFalse(z.rbac_allows("jack", res))
        z.decide_access_exception_request(rid, True, "puja", 3600)
        (a,) = self.alerts(ref=rid)
        self.assertEqual(a["status"], 1); self.assertIn("approved by puja", a["details"])
        self.assertTrue(z.rbac_allows("jack", res))
        row = next(r for r in z.list_access_exception_requests() if r["id"] == rid)
        self.assertEqual(row["alert_status"], 1); self.assertTrue(z.exception_outcome(row).startswith("Approved by puja until"))

    def test_denial_closes_the_alert_and_grants_nothing(self):
        z = self.z; rid, res = self.request("kate", self.outside_role("kate", sensitive=False))
        z.decide_access_exception_request(rid, False, "puja")
        (a,) = self.alerts(ref=rid)
        self.assertEqual(a["status"], 1); self.assertIn("denied by puja", a["details"])
        self.assertFalse(z.rbac_allows("kate", res))
        self.assertEqual(z.exception_outcome(z.list_access_exception_requests()[0] | {"status": "denied", "decided_by": "puja"}), "Denied by puja")

    def test_a_decision_is_final_and_cannot_be_applied_twice(self):
        z = self.z; rid, _ = self.request("mia", self.outside_role("mia", sensitive=False))
        self.assertIsNotNone(z.decide_access_exception_request(rid, False, "puja"))
        self.assertIsNone(z.decide_access_exception_request(rid, True, "other-manager"))

    def test_approved_access_ends_on_time_with_an_audit_entry_and_a_note_on_the_alert(self):
        z = self.z; rid, res = self.request("nina", self.outside_role("nina", sensitive=False))
        z.decide_access_exception_request(rid, True, "puja", 3600); before = len(self.closeouts("nina"))
        c = z._db_connection(); c.execute("UPDATE access_exception_requests SET expires_at=? WHERE id=?", (time.time() - 5, rid)); c.commit()
        with z.LOCK: z.TEMP_RESOURCE_GRANTS[("nina", res)] = time.time() - 5       # what the in-memory grant looks like at that moment
        row = next(r for r in z.list_access_exception_requests() if r["id"] == rid)
        self.assertEqual(row["status"], "expired"); self.assertEqual(row["closed_reason"], "temporary access ended")
        self.assertFalse(z.rbac_allows("nina", res)); self.assertEqual(len(self.closeouts("nina")), before + 1)
        z.list_access_exception_requests(); self.assertEqual(len(self.closeouts("nina")), before + 1, "closing happens once")
        self.assertIn("access ended", self.alerts(ref=rid)[0]["details"])
        self.assertIn("has ended", z.exception_outcome(row))

    def test_an_unanswered_request_lapses_and_its_alert_is_closed(self):
        z = self.z; rid, _ = self.request("alice", self.outside_role("alice", sensitive=True)); before = len(self.closeouts("alice"))
        self.age(rid, "ts", z._exception_ttl() + 10)
        row = next(r for r in z.list_access_exception_requests() if r["id"] == rid)
        self.assertEqual((row["status"], row["decided_by"]), ("expired", None)); self.assertEqual(z.exception_outcome(row), "No manager response (expired)")
        self.assertEqual(self.alerts(ref=rid)[0]["status"], 1); self.assertIn("expired unanswered", self.alerts(ref=rid)[0]["details"])
        self.assertEqual(len(self.closeouts("alice")), before + 1)
        self.assertIsNone(z.decide_access_exception_request(rid, True, "puja"), "an expired request cannot be approved")

    # ---- these entries are manager workflow, not access attempts
    def test_exception_records_do_not_feed_access_telemetry_or_attack_detection(self):
        z = self.z; user = "bob"; events0 = z.telemetry_summary()["events"]; repeated0 = len(self.alerts("REPEATED_DENIALS")); seg0 = len(self.alerts("SEGMENT_VIOLATION"))
        apps = [r for r in z.RESOURCES if not (z.rbac_allows(user, r) and z.segment_allows(user, r))]
        for r in apps[:6]:
            rid, _ = self.request(user, r); z.decide_access_exception_request(rid, False, "puja")
        with z.TELEMETRY_CACHE_LOCK: z.TELEMETRY_CACHE["summary_ts"] = 0.0
        self.assertEqual(z.telemetry_summary()["events"], events0)
        self.assertEqual(len(self.alerts("REPEATED_DENIALS")), repeated0)
        self.assertEqual(len(self.alerts("SEGMENT_VIOLATION")), seg0)

    def test_audit_entries_read_correctly_and_the_dashboard_files_them_as_manager_response(self):
        z = self.z; rid, res = self.request("omar", self.outside_role("omar", sensitive=False)); z.decide_access_exception_request(rid, True, "puja")
        entries = [e for e in list(z.LOG)[:10] if e["user"] == "omar" and e["reasons"] and e["reasons"][0].startswith(z.EXTRA_ACCESS_PREFIX)]
        labels = {e["decision"]: z.describe_audit_event(e) for e in entries}
        self.assertEqual(labels["PENDING"][0], "Requested"); self.assertEqual(labels["ALLOW"][0], "Access granted")
        self.assertNotIn("opened", labels["ALLOW"][2])
        for e in entries: self.assertEqual(z.siem_category(e), "Response")

    def test_chain_stays_valid_and_alert_text_is_defined(self):
        z = self.z
        for kind in ("EXTRA_ACCESS_REQUEST", "EXTRA_ACCESS_PATTERN"):
            title, why, advice = z.describe_alert({"kind": kind, "severity": "HIGH"})
            self.assertTrue(title and why and advice); self.assertNotIn("Unrecognised", title)
        self.assertTrue(z.verify_chain()["ok"])

    # ---- audit failure must not leave a half-applied decision
    def test_audit_failure_leaves_the_request_pending_and_grants_nothing(self):
        z = self.z; rid, res = self.request("dave", self.outside_role("dave", sensitive=False)); real = z.audit
        def fail(**kw): raise z.AuditFull("audit full")
        z.audit = fail
        try:
            with self.assertRaises(z.AuditFull): z.decide_access_exception_request(rid, True, "puja")
        finally:
            z.audit = real
        row = next(r for r in z.list_access_exception_requests() if r["id"] == rid)
        self.assertEqual(row["status"], "pending"); self.assertFalse(z.rbac_allows("dave", res))
        self.assertEqual(self.alerts(ref=rid)[0]["status"], 0, "the alert stays open until a decision is really recorded")


if __name__ == "__main__":
    unittest.main()

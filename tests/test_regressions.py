"""Regression tests for bugs found in an audit of authentication, throttling, sessions, races and database errors.

Every test here failed on the previous version of the engine (see the 'before' notes) and passes now.
"""
import http.client, json, os, sys, tempfile, threading, time, unittest
from pathlib import Path


class RegressionBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-reg-"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import ztna as z
        cls.z = z
        z.REQUESTED_MODE = "gui"; z.init_runtime("gui")
        cls.creds = {u: p for u, p, _r, _s in z.DEMO_BOOTSTRAP_CREDENTIALS}

    def setUp(self):
        z = self.z
        with z.LOCK:
            z.FAILS.clear(); z.USERFAIL.clear(); z.LAST_TOTP.clear()
        z.BLOCKED_DEVICES.clear(); z.STEPUP_REQUIRED_USERS.clear()

    def dev(self, user): return next(d for d, v in self.z.DEVICES.items() if v["owner"] == user)

    def client(self): return self.z.DesktopZTNA()

    def audits(self): return self.z.AUDIT["entries"]


class OneTimeCodeOrderingTests(RegressionBase):
    """The code must be spent last, and only when password and device already checked out."""

    def test_wrong_device_does_not_burn_a_valid_code(self):                    # before: second attempt failed
        z = self.z; c = self.client(); code = c.demo_otp("alice")
        self.assertFalse(c._authenticate("alice", self.creds["alice"], code, self.dev("bob"))[0])
        with z.LOCK: z.FAILS.clear()
        self.assertTrue(c._authenticate("alice", self.creds["alice"], code, self.dev("alice"))[0])

    def test_wrong_password_does_not_burn_the_code(self):
        z = self.z; c = self.client(); code = c.demo_otp("bob")
        self.assertFalse(c._authenticate("bob", "wrong-password", code, self.dev("bob"))[0])
        with z.LOCK: z.FAILS.clear()
        self.assertTrue(c._authenticate("bob", self.creds["bob"], code, self.dev("bob"))[0])

    def test_a_spent_code_cannot_be_replayed(self):
        z = self.z; c = self.client(); code = c.demo_otp("carol")
        self.assertTrue(c._authenticate("carol", self.creds["carol"], code, self.dev("carol"))[0])
        with z.LOCK: z.FAILS.clear()
        self.assertFalse(c._authenticate("carol", self.creds["carol"], code, self.dev("carol"))[0])

    def test_storage_failure_fails_closed_and_spends_nothing(self):             # before: OSError escaped, counter advanced in memory only
        z = self.z; c = self.client(); code = c.demo_otp("dave"); real = z._atomic_json_replace
        def broken(*a, **k): raise OSError("disk full")
        z._atomic_json_replace = broken
        try:
            ok, msg = c._authenticate("dave", self.creds["dave"], code, self.dev("dave"))
        finally:
            z._atomic_json_replace = real
        self.assertFalse(ok); self.assertIn("unavailable", msg)
        self.assertNotIn("dave", z.LAST_TOTP, "a code must not be marked spent if the state could not be saved")
        self.assertEqual(z.FAILS.get(("dave", "desktop"), (0,))[0], 0, "a storage fault must not count against the employee")
        self.assertTrue(c._authenticate("dave", self.creds["dave"], code, self.dev("dave"))[0], "same code works once storage is back")

    def test_totp_ok_raises_state_store_error_and_spends_nothing(self):
        z = self.z; secret = z.USERS["erin"]["totp"]; code = z.demo_totp_code("erin"); real = z._atomic_json_replace
        def broken(*a, **k): raise OSError("read-only file system")
        z._atomic_json_replace = broken
        try:
            with self.assertRaises(z.StateStoreError): z.totp_ok("erin", secret, code)
        finally:
            z._atomic_json_replace = real
        self.assertTrue(z.totp_ok("erin", secret, code))


class ThrottlingTests(RegressionBase):
    def test_refund_keeps_an_active_hard_lock(self):                             # before: lock dropped to 0 s
        z = self.z
        with z.LOCK: z.FAILS[("alice", "desktop")] = (6, time.time() + 60, time.time())
        z.refund_auth_attempt("alice", "desktop")
        self.assertGreater(z.FAILS[("alice", "desktop")][1] - time.time(), 50)

    def test_refund_still_clears_a_plain_backoff(self):
        z = self.z
        with z.LOCK: z.FAILS[("alice", "desktop")] = (2, time.time() + 0.5, time.time())
        z.refund_auth_attempt("alice", "desktop")
        self.assertLessEqual(z.FAILS[("alice", "desktop")][1], time.time() + 0.01)

    def test_blocked_device_attempts_cannot_flood_the_audit_log(self):           # before: 300 attempts -> 300 audit entries
        z = self.z; z.BLOCKED_DEVICES.add(self.dev("bob")); before = self.audits()
        for _ in range(300):
            ok, msg = self.client()._authenticate("bob", "x", "000000", self.dev("bob"))
            self.assertFalse(ok); self.assertIn("blocked", msg)
        self.assertLessEqual(self.audits() - before, 3)

    def test_unexpected_error_does_not_leave_the_attempt_counted(self):
        z = self.z; c = self.client(); real = z.pw_verify
        def boom(*a, **k): raise RuntimeError("kdf exploded")
        z.pw_verify = boom
        try:
            with self.assertRaises(RuntimeError): c._authenticate("carol", self.creds["carol"], "000000", self.dev("carol"))
        finally:
            z.pw_verify = real
        self.assertEqual(z.FAILS.get(("carol", "desktop"), (0,))[0], 0)


class SessionHandlingTests(RegressionBase):
    def _approved(self, user):
        z = self.z; c = self.client()
        ok, rid = c.request_signin(user, self.creds[user], c.demo_otp(user), self.dev(user), "office"); self.assertTrue(ok, rid)
        z.decide_signin_request(rid, True, "puja", "ok"); return c, rid

    def test_approved_signin_is_refused_if_the_device_was_blocked_meanwhile(self):   # before: session opened on a blocked device
        z = self.z; c, rid = self._approved("frank"); z.BLOCKED_DEVICES.add(self.dev("frank"))
        ok, msg = c.complete_signin(rid)
        self.assertFalse(ok); self.assertIn("blocked", msg); self.assertIsNone(c.session)
        self.assertFalse(z.get_signin_request(rid)["consumed"], "the approval is not spent by a refused attempt")

    def test_approved_signin_still_works_for_a_healthy_device(self):
        c, rid = self._approved("grace"); self.assertTrue(c.complete_signin(rid)[0]); self.assertIsNotNone(c.session)

    def test_blocked_device_is_denied_before_step_up_is_offered(self):          # before: answered STEPUP
        z = self.z; c = self.client(); self.assertTrue(c.login("jack", self.creds["jack"], c.demo_otp("jack"), self.dev("jack"), "office")[0])
        z.STEPUP_REQUIRED_USERS.add("jack"); z.BLOCKED_DEVICES.add(self.dev("jack"))
        self.assertEqual(c.access("wiki")["decision"], "DENY")

    def test_step_up_storage_failure_spends_nothing(self):
        z = self.z; c = self.client(); self.assertTrue(c.login("kate", self.creds["kate"], c.demo_otp("kate"), self.dev("kate"), "office")[0])
        code = c.demo_otp("kate"); real = z._atomic_json_replace
        def broken(*a, **k): raise OSError("disk full")
        z._atomic_json_replace = broken
        try: ok, msg = c.stepup(code)
        finally: z._atomic_json_replace = real
        self.assertFalse(ok); self.assertIn("unavailable", msg)
        self.assertTrue(c.stepup(code)[0])

    def test_incident_sign_out_reports_a_database_failure(self):                # before: silent, database flag stayed 0
        z = self.z; c = self.client(); self.assertTrue(c.login("mia", self.creds["mia"], c.demo_otp("mia"), self.dev("mia"), "office")[0])
        sid = c.session[0]; conn = z._db_connection(); conn.execute("ALTER TABLE sessions RENAME TO sessions_broken"); conn.commit()
        try: n, err = z.revoke_user_sessions_report("mia")
        finally: conn.execute("ALTER TABLE sessions_broken RENAME TO sessions"); conn.commit()
        self.assertEqual(n, 1); self.assertTrue(err, "the failure must be reported to the caller")
        self.assertNotIn(sid, z.SESSIONS, "the live session is ended even if the database write failed")

    def test_incident_sign_out_persists_the_revocation(self):
        z = self.z; c = self.client(); self.assertTrue(c.login("nina", self.creds["nina"], c.demo_otp("nina"), self.dev("nina"), "office")[0])
        sid = c.session[0]; n, err = z.revoke_user_sessions_report("nina")
        self.assertEqual((n, err), (1, None))
        self.assertEqual(z._db_connection().execute("SELECT revoked FROM sessions WHERE sid=?", (sid,)).fetchone()[0], 1)

    def test_policy_engine_denies_a_blocked_device(self):
        z = self.z; sess = {"user": "alice", "device": self.dev("alice"), "location": "office", "mfa_at": time.time()}
        z.BLOCKED_DEVICES.add(self.dev("alice"))
        decision, reasons, _risk, _sig = z.evaluate(sess, self.dev("alice"), "wiki")
        self.assertEqual(decision, "DENY"); self.assertTrue(any("blocked" in r for r in reasons))


class GatewayTests(RegressionBase):
    """The real HTTP gateway handler, hosted in-process (so engine state can be changed between requests)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        z = cls.z
        cls.srv = z.PooledHTTPServer(("127.0.0.1", 0), z.H); cls.port = cls.srv.server_address[1]
        z.ALLOWED_HOSTS.add(f"127.0.0.1:{cls.port}")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def login(self, user, device, otp=None):
        z = self.z
        with z.LOCK: z.FAILS.clear()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        c.request("POST", "/api/login", json.dumps({"username": user, "password": self.creds[user], "otp": otp or z.demo_totp_code(user), "device_id": device, "location": "office"}), {"Content-Type": "application/json"})
        r = c.getresponse(); body = json.loads(r.read() or b"{}"); c.close(); return r.status, body

    def test_login_works(self):
        self.assertEqual(self.login("alice", self.dev("alice"))[0], 200)

    def test_blocked_device_cannot_sign_in_at_the_gateway(self):                 # before: 200 and a session token
        self.z.BLOCKED_DEVICES.add(self.dev("bob"))
        status, body = self.login("bob", self.dev("bob"))
        self.assertEqual(status, 403); self.assertNotIn("token", body)

    def test_wrong_device_does_not_burn_the_code_at_the_gateway(self):           # before: second request 401
        code = self.z.demo_totp_code("carol")
        self.assertEqual(self.login("carol", self.dev("alice"), code)[0], 401)
        self.assertEqual(self.login("carol", self.dev("carol"), code)[0], 200)

    def test_blocked_device_does_not_burn_the_code_either(self):
        z = self.z; code = z.demo_totp_code("dave"); z.BLOCKED_DEVICES.add(self.dev("dave"))
        self.assertEqual(self.login("dave", self.dev("dave"), code)[0], 403)
        z.BLOCKED_DEVICES.discard(self.dev("dave")); self.assertEqual(self.login("dave", self.dev("dave"), code)[0], 200)

    def _post(self, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        c.request("POST", path, json.dumps(body or {}), {"Content-Type": "application/json", **(headers or {})})
        r = c.getresponse(); out = (r.status, json.loads(r.read() or b"{}")); c.close(); return out

    def _request(self, method, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15); c.request(method, path, headers=headers or {})
        r = c.getresponse(); r.read(); out = (r.status, dict(r.getheaders())); c.close(); return out

    def test_manager_login_works_with_non_ascii_credentials(self):               # before: HTTP 500 for every attempt
        z = self.z; old = {k: os.environ.get(k) for k in ("ZTNA_MANAGER_USER", "ZTNA_MANAGER_PASSWORD")}
        os.environ["ZTNA_MANAGER_USER"] = "rené"; os.environ["ZTNA_MANAGER_PASSWORD"] = "pässwört-ok"
        z.MANAGER_LOGIN_FAILS.clear()
        try:
            self.assertEqual(self._post("/api/ui/manager-login", {"username": "rené", "password": "pässwört-ok"})[0], 200)
            self.assertEqual([e["user"] for e in list(z.LOG)[:3] if e["resource"] == "manager-login" and e["decision"] == "ALLOW"][:1], ["rené"],
                             "the audit entry must name the configured manager, not a hard-coded user")
            self.assertEqual(self._post("/api/ui/manager-login", {"username": "rené", "password": "wrong"})[0], 401)
            self.assertEqual(self._post("/api/ui/manager-login", {"username": "ünknown", "password": "ä"})[0], 401)
        finally:
            for k, v in old.items():
                if v is None: os.environ.pop(k, None)
                else: os.environ[k] = v
            z.MANAGER_LOGIN_FAILS.clear()

    def test_non_ascii_failed_manager_logins_are_counted_by_the_limiter(self):   # before: TypeError -> 500, never counted
        z = self.z; z.MANAGER_LOGIN_FAILS.clear()
        try:
            for _ in range(3): self.assertEqual(self._post("/api/ui/manager-login", {"username": "ä", "password": "ö"})[0], 401)
            self.assertEqual(len(z.MANAGER_LOGIN_FAILS), 3)
        finally: z.MANAGER_LOGIN_FAILS.clear()

    def test_metrics_endpoint_ignores_extra_access_workflow_entries(self):       # before: approvals/denials counted as allow/deny
        z = self.z; real = z.ADMIN_KEY; z.ADMIN_KEY = "k" * 40
        def metrics():
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15); c.request("GET", "/api/metrics", headers={"X-Admin-Key": "k" * 40})
            r = c.getresponse(); d = json.loads(r.read()); c.close(); return d
        try:
            before = metrics()
            user = "grace"; res = next(r for r in z.RESOURCES if not (z.rbac_allows(user, r) and z.segment_allows(user, r)))
            for approve in (False, True):
                rid = z.create_access_exception_request(user, self.dev(user), res, "metrics test"); z.decide_access_exception_request(rid, approve, "puja")
            after = metrics()
        finally: z.ADMIN_KEY = real
        self.assertEqual((after["allow"], after["deny"]), (before["allow"], before["deny"]))

    def test_put_is_405_and_other_unimplemented_methods_stay_501(self):        # documents intended behaviour (existing test_ztna asserts 501 for DELETE)
        self.assertEqual(self._request("PUT", "/api/state")[0], 405)
        self.assertEqual(self._request("DELETE", "/api/state")[0], 501)

    def test_gateway_storage_failure_is_a_503_not_a_crash(self):
        z = self.z; code = z.demo_totp_code("erin"); real = z._atomic_json_replace
        def broken(*a, **k): raise OSError("disk full")
        z._atomic_json_replace = broken
        try: status, _ = self.login("erin", self.dev("erin"), code)
        finally: z._atomic_json_replace = real
        self.assertEqual(status, 503)
        self.assertEqual(self.login("erin", self.dev("erin"), code)[0], 200)


class RaceTests(RegressionBase):
    def _race(self, fn, n=12):
        bar = threading.Barrier(n); out = []
        def go():
            try: bar.wait(); out.append(fn())
            except Exception as exc: out.append(exc)
        ts = [threading.Thread(target=go) for _ in range(n)]
        [t.start() for t in ts]; [t.join() for t in ts]
        return out

    def test_simultaneous_identical_extra_access_requests_create_one(self):      # before: 12 pending rows
        z = self.z; user = "mia"; res = next(r for r in z.RESOURCES if not z.rbac_allows(user, r)); dev = self.dev(user)
        out = self._race(lambda: z.create_access_exception_request(user, dev, res, "need it"))
        self.assertFalse([o for o in out if isinstance(o, Exception)], out)
        self.assertEqual(len(set(out)), 1)
        n = z._db_connection().execute("SELECT COUNT(*) FROM access_exception_requests WHERE user=? AND resource=? AND status='pending'", (user, res)).fetchone()[0]
        self.assertEqual(n, 1)

    def test_simultaneous_signin_requests_leave_exactly_one_pending(self):       # before: 12 pending rows
        z = self.z; out = self._race(lambda: z.create_signin_request("nina", self.dev("nina"), "office"))
        self.assertFalse([o for o in out if isinstance(o, Exception)], out)
        self.assertEqual(z._db_connection().execute("SELECT COUNT(*) FROM signin_requests WHERE user='nina' AND status='pending'").fetchone()[0], 1)

    def test_a_failed_statement_does_not_leave_the_database_locked(self):        # before: raw execute() left an open write transaction
        z = self.z; user = "kate"; res = next(r for r in z.RESOURCES if not z.rbac_allows(user, r)); dev = self.dev(user)
        self._race(lambda: z.create_access_exception_request(user, dev, res, "x"))
        done = []
        t = threading.Thread(target=lambda: done.append(z.create_signin_request("frank", self.dev("frank"), "office")))
        t.start(); t.join(10)
        self.assertEqual(len(done), 1, "another writer must not be blocked by an earlier failed insert")

    def test_unique_index_exists_and_old_duplicates_are_cleaned_on_upgrade(self):
        z = self.z; conn = z._db_connection()
        names = {r[1] for r in conn.execute("PRAGMA index_list(signin_requests)")} | {r[1] for r in conn.execute("PRAGMA index_list(access_exception_requests)")}
        self.assertTrue({"idx_signin_one_pending", "idx_exception_one_pending"} <= names)
        self.addCleanup(lambda: (conn.execute("DELETE FROM signin_requests WHERE user='zed'"), conn.commit()))
        conn.execute("DROP INDEX idx_signin_one_pending")
        for rid in ("dupA", "dupB", "dupC"):
            conn.execute("INSERT INTO signin_requests(id,ts,user,device,location,status) VALUES(?,?,'zed','laptop-zed','office','pending')", (rid, time.time()))
        conn.commit()
        z.db_init()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM signin_requests WHERE user='zed' AND status='pending'").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM signin_requests WHERE user='zed' AND closed_reason LIKE 'duplicate%'").fetchone()[0], 2)


class DatabaseErrorTests(RegressionBase):
    def _broken(self, table):
        conn = self.z._db_connection(); conn.execute(f"ALTER TABLE {table} RENAME TO {table}_broken"); conn.commit()
        self.addCleanup(lambda: (conn.execute(f"ALTER TABLE {table}_broken RENAME TO {table}"), conn.commit()))

    def test_extra_access_database_errors_are_state_store_errors(self):          # before: raw sqlite3.OperationalError
        z = self.z; user = "alice"; res = next(r for r in z.RESOURCES if not z.rbac_allows(user, r)); dev = self.dev(user)
        self._broken("access_exception_requests")
        with self.assertRaises(z.StateStoreError): z.create_access_exception_request(user, dev, res, "x")
        with self.assertRaises(z.StateStoreError): z.list_access_exception_requests()

    def test_signin_database_errors_are_state_store_errors(self):
        z = self.z; self._broken("signin_requests")
        for call in (z.list_signin_requests, z.count_pending_signins, lambda: z.get_signin_request("x"), lambda: z.create_signin_request("alice", self.dev("alice"), "office")):
            with self.assertRaises(z.StateStoreError): call()

    def test_failed_alert_insert_is_not_announced_and_does_not_block_the_next_one(self):   # before: reported True, then suppressed
        z = self.z; self._broken("security_alerts")
        self.assertFalse(z.db_alert_once("HIGH", "REG_PROBE", "zoe", "d", "first", window=300))
        self.assertIsNone(z.db_alert("HIGH", "REG_PROBE", "zoe", "d", "direct"))
        conn = z._db_connection(); conn.execute("ALTER TABLE security_alerts_broken RENAME TO security_alerts"); conn.commit()
        try:
            self.assertTrue(z.db_alert_once("HIGH", "REG_PROBE", "zoe", "d", "second", window=300), "a failed insert must not use up the dedupe window")
            rows = conn.execute("SELECT details FROM security_alerts WHERE kind='REG_PROBE'").fetchall()
            self.assertEqual([r[0] for r in rows], ["second"])
        finally:
            conn.execute("ALTER TABLE security_alerts RENAME TO security_alerts_broken"); conn.commit()


class RoundTwoTests(RegressionBase):
    def test_text_comparison_survives_non_ascii(self):                           # before: hmac.compare_digest(str, str) -> TypeError
        z = self.z
        self.assertTrue(z._ct_eq("pässwort", "pässwort")); self.assertFalse(z._ct_eq("pässwort", "passwort")); self.assertFalse(z._ct_eq("a", ""))

    def test_correct_password_is_not_refused_when_the_hash_upgrade_cannot_run(self):   # before: RuntimeError escaped the login
        import hashlib, secrets
        z = self.z; pw = "Correct-Horse-9"; salt = secrets.token_bytes(16)
        legacy = {"hash": hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, maxmem=128 * 1024 * 1024).hex(), "salt": salt.hex()}
        real = z.pw_hash
        def busy(*a, **k): raise RuntimeError("authentication capacity temporarily unavailable")
        z.pw_hash = busy
        try:
            record = dict(legacy); self.assertTrue(z.pw_verify(pw, record)); self.assertEqual(record, legacy, "no upgrade was possible, so the record is untouched")
            self.assertFalse(z.pw_verify("wrong", dict(legacy)))
        finally: z.pw_hash = real
        upgraded = dict(legacy); self.assertTrue(z.pw_verify(pw, upgraded)); self.assertEqual(upgraded.get("kdf"), "scrypt", "the upgrade still happens when capacity allows")

    def test_uppercase_stored_hash_still_verifies(self):
        import hashlib, secrets
        z = self.z; salt = secrets.token_bytes(16); rec = z.pw_hash("Abcdefgh1")
        stored = {"hash": rec[0].upper(), "salt": rec[1], "kdf": "scrypt", "n": z.SCRYPT_N, "r": z.SCRYPT_R, "p": z.SCRYPT_P}
        self.assertTrue(z.pw_verify("Abcdefgh1", stored))

    def test_totp_timestamp_zero_is_the_epoch_not_now(self):                      # before: `t or time.time()` treated 0 as missing
        z = self.z; secret = "JBSWY3DPEHPK3PXP"
        self.assertNotEqual(z.totp(secret, 0), z.totp(secret)); self.assertEqual(z.totp(secret, 0), z.totp(secret, 29))

    def test_display_helpers_never_raise(self):
        z = self.z
        for bad in (1e300, float("inf"), float("nan"), -1e300, None, "", "x"): z._fmt_ts(bad); z._fmt_ts(bad, "%H:%M")
        for bad in (float("inf"), float("nan"), 1e999, None, "x", [], {}): self.assertEqual(z._to_int(bad, 7), 7)
        self.assertEqual(z.posture("no-such-device"), 0)

    def test_daily_summary_counts_access_decisions_only(self):                    # before: every log line was an 'access event'
        z = self.z
        def stat(text, label): return int(next(l for l in text.splitlines() if l.startswith(label)).split(":")[1])
        base = z.daily_summary_text()
        c = self.client(); ok, _ = c.login("frank", self.creds["frank"], c.demo_otp("frank"), self.dev("frank"), "office"); self.assertTrue(ok)
        results = [c.access(r)["decision"] for r in list(z.RESOURCES)[:4]]
        now = z.daily_summary_text()
        self.assertEqual(stat(now, "Access events") - stat(base, "Access events"), 4, "the login itself is not an access event")
        self.assertEqual(stat(now, "Allowed") - stat(base, "Allowed"), results.count("ALLOW"))
        self.assertEqual(stat(now, "Denied") - stat(base, "Denied"), results.count("DENY"))
        z.DesktopZTNA()._fail_login("frank", self.dev("frank"))
        self.assertEqual(stat(z.daily_summary_text(), "Failed sign-ins") - stat(now, "Failed sign-ins"), 1)
        self.assertEqual(stat(z.daily_summary_text(), "Denied"), stat(now, "Denied"), "a failed login is not a denied access request")

    def test_requesting_an_app_you_already_hold_temporarily_says_so(self):
        z = self.z; user = "jack"; res = next(r for r in z.RESOURCES if not (z.rbac_allows(user, r) and z.segment_allows(user, r)))
        rid = z.create_access_exception_request(user, self.dev(user), res, "need it"); z.decide_access_exception_request(rid, True, "puja", 3600)
        with self.assertRaises(ValueError) as ctx: z.create_access_exception_request(user, self.dev(user), res, "again")
        self.assertIn("temporary access", str(ctx.exception)); self.assertNotIn("your role", str(ctx.exception))


class ReinitialisationTests(RegressionBase):
    def test_reinitialising_the_runtime_writes_audit_entries_to_the_new_data_dir(self):   # before: FileNotFoundError on every later audit write
        z = self.z; old_dir = os.environ["ZTNA_DATA_DIR"]
        try:
            for mode in ("server", "gui"):
                new_dir = tempfile.mkdtemp(prefix=f"ztna-reinit-{mode}-"); os.environ["ZTNA_DATA_DIR"] = new_dir
                z.REQUESTED_MODE = mode; z.init_runtime(mode)
                z.audit(user="reinit", device="d", resource="login", decision="DENY", reasons=[f"written after switching to {mode}"])
                self.assertEqual(os.path.dirname(z.AUDIT_FILE), new_dir)
                with open(z.AUDIT_FILE, encoding="utf-8") as fh: self.assertEqual(len(fh.readlines()), 1)
                self.assertEqual(z.AUDIT["entries"], 1); self.assertTrue(z.verify_chain()["ok"])
                self.assertEqual(os.path.realpath(z._db_connection().execute("PRAGMA database_list").fetchone()[2]), os.path.realpath(z.DB_FILE),
                                 "the cached connection must follow DB_FILE, not keep using the previous database")
        finally:
            os.environ["ZTNA_DATA_DIR"] = old_dir


class AlertStateTests(RegressionBase):
    def test_false_alarm_and_incident_states_are_stored(self):
        z = self.z
        ids = []
        for i in range(3): z.db_alert("MEDIUM", "REG_STATE", "zoe", "d", f"state {i}"); 
        with z._db_connection() as c: ids = [r[0] for r in c.execute("SELECT id FROM security_alerts WHERE kind='REG_STATE' ORDER BY id")]
        for i, status in zip(ids, (1, 2, 3)): z.acknowledge_alerts([i], status)
        with z.TELEMETRY_CACHE_LOCK: z.TELEMETRY_CACHE["alerts_ts"] = 0.0
        got = {a["id"]: a["status"] for a in z.recent_alerts(500) if a["kind"] == "REG_STATE"}
        self.assertEqual([got[i] for i in ids], [1, 2, 3])

    def test_bulk_acknowledge_never_closes_high_or_critical_alerts(self):
        z = self.z
        z.db_alert("HIGH", "REG_BULK", "zoe", "d", "h"); z.db_alert("CRITICAL", "REG_BULK", "zoe", "d", "c"); z.db_alert("LOW", "REG_BULK", "zoe", "d", "l")
        z.acknowledge_alerts(None, 1, include_high=False)
        with z._db_connection() as c: rows = dict(c.execute("SELECT severity, acknowledged FROM security_alerts WHERE kind='REG_BULK'").fetchall())
        self.assertEqual(rows, {"HIGH": 0, "CRITICAL": 0, "LOW": 1})


if __name__ == "__main__":
    unittest.main()

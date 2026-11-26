# Part 13 of ztna_lab_v2.py - DesktopZTNA, the engine adapter used by the desktop portals.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

class DesktopZTNA:
    """Small desktop-facing adapter around the hardened ZTNA """

    def __init__(self):
        self.session = None
        self.user = None
        self.device = None
        self.location = "office"

    def demo_otp(self, user):
        if not DEMO_OTP: raise RuntimeError("demo OTP generation disabled")
        return demo_totp_code(user)

    @staticmethod
    def _audit(**kw):
        """Audit without leaking AuditFull/AuditTamper into Tk callbacks; False means refuse the action."""
        try:
            audit(**kw); return True
        except (AuditFull, AuditTamper):
            return False

    def _fail_login(self, user, device, ip="desktop"):
        note_fail(user,ip)
        self._audit(user=user, device=device, resource="login", decision="DENY", reasons=["authentication failed"])
        n=recent_fails(user,ip)
        if n>=3 and user in USERS: db_alert_once("HIGH","BRUTE_FORCE_SUSPECTED",user,device,f"{n} recent failed authentication attempts",window=30.0)
        return False, "Authentication failed"

    def _authenticate(self, user, password, otp, device):
        """Password, then device ownership, then the one-time code LAST (so a code is only ever spent when everything else
        already checked out). Returns (ok, message); creates no session."""
        if device in BLOCKED_DEVICES:
            # A blocked device is refused outright, but its repeated attempts must not be able to flood the audit log.
            if audit_allowed(f"{user}|{device}","blocked-login",limit=3,window=60):
                self._audit(user=user, device=device, resource="login", decision="DENY", reasons=["device blocked by ZTNA manager"])
            return False, "This device has been blocked by the ZTNA manager"
        ip="desktop"
        if not reserve_auth_attempt(user,ip):
            n=recent_fails(user,"desktop")
            if n>=3 and user in USERS: db_alert_once("HIGH","BRUTE_FORCE_SUSPECTED",user,device,f"{n} failed attempts; further attempts are being throttled",window=30.0)
            return False, "Authentication temporarily unavailable"
        try:
            return self._authenticate_reserved(user,password,otp,device,ip)
        except StateStoreError:
            refund_auth_attempt(user,ip)                   # our storage failed, not the user's credentials
            return False, "Authentication state is unavailable; nothing was spent, try again shortly"
        except BaseException:
            refund_auth_attempt(user,ip); raise            # never leave an unexplained failure counted against the user

    def _authenticate_reserved(self, user, password, otp, device, ip):
        usr = USERS.get(user); dummy=next(iter(USERS.values())) if USERS else None
        pw_before = dict(usr["pw"]) if usr else None
        try: password_ok=pw_verify(password, usr["pw"] if usr else dummy["pw"] if dummy else {})
        except KdfBusy:
            refund_auth_attempt(user,ip)
            return False, "Authentication capacity temporarily unavailable"
        if usr and password_ok and usr["pw"] != pw_before:
            try: _persist_users()
            except Exception:
                logger.exception("could not persist upgraded password hash")
                refund_auth_attempt(user,ip)
                return False, "Account store unavailable; login refused"
        if not usr or not password_ok: return self._fail_login(user,device,ip)
        if device not in DEVICES or DEVICES[device]["owner"] != user: return self._fail_login(user,device,ip)
        if not totp_ok(user, usr["totp"], otp): return self._fail_login(user,device,ip)
        release_auth_attempt(user,ip)
        return True, "Credentials verified"

    def login(self, user, password, otp, device, location):
        ok, msg = self._authenticate(user, password, otp, device)
        if not ok: return False, msg
        try: return self._open_session(user, device, location)
        except StateStoreError: return False, "The session store is temporarily unavailable; sign in again shortly"

    def request_signin(self, user, password, otp, device, location):
        """Verify credentials, then send the sign-in to the manager queue. Returns (True, request_id) or (False, message)."""
        ok, msg = self._authenticate(user, password, otp, device)
        if not ok: return False, msg
        try:
            rid = create_signin_request(user, device, location if location in ("office","home") else "office")
        except (StateStoreError, AuditFull, AuditTamper):
            return False, "Sign-in request could not be recorded; nothing was sent"
        self.pending_request = rid
        return True, rid

    def complete_signin(self, rid):
        """Open the session once a manager approved the request. One approval = one session."""
        try: row = get_signin_request(rid)
        except StateStoreError: return False, "The sign-in service is temporarily unavailable; try again in a moment"
        if not row or row["status"] != "approved":
            return False, "This sign-in has not been approved"
        user, device = row["user"], row["device"]
        if user not in USERS or device not in DEVICES or DEVICES[device].get("owner") != user:
            return False, "This sign-in can no longer be completed"
        if device in BLOCKED_DEVICES:                         # blocked after the approval was given: refuse, keep nothing open
            if audit_allowed(f"{user}|{device}","blocked-login",limit=3,window=60):
                self._audit(user=user, device=device, resource="login", decision="DENY", reasons=["approved sign-in refused: device was blocked after approval"])
            return False, "This device has been blocked by the ZTNA manager"
        unavailable = (False, "The sign-in service is temporarily unavailable; try again in a moment")
        # Make room (session cap) BEFORE using the approval: that step may need the database, and a failure after the
        # claim used to leave an approval marked "used" with no session ("already used" on every retry).
        try:
            with LOCK: _prune_sessions_for_login_locked(user, time.time())
        except StateStoreError: return unavailable
        try: claimed = claim_signin_request(rid)
        except StateStoreError: return unavailable
        if not claimed:
            return False, "This approval was already used or has expired"
        try:
            ok, msg = self._open_session(row["user"], row["device"], row["location"],
                                         extra_reasons=[f"sign-in approved by manager {row['decided_by']}"])
        except StateStoreError:
            ok, msg = unavailable
        if not ok:                                           # nothing was opened: the approval stays usable until it expires
            try: release_signin_claim(rid)
            except StateStoreError: logger.error("sign-in approval %s could not be released after a failed sign-in", rid)
            return ok, msg
        self.pending_request = None
        return ok, msg

    def _open_session(self, user, device, location, extra_reasons=()):
        ip="desktop"
        now = time.time()
        previous = LASTLOC.get(user)
        travel = bool(previous and previous[0] != location and now - previous[1] < 300)
        if travel: db_alert_once("MEDIUM","IMPOSSIBLE_TRAVEL",user,device,f"{previous[0]} -> {location} in {int(now-previous[1])}s",window=60.0)
        sid = secrets.token_hex(12)
        pop_salt = _new_session_salt()
        key = _derive_session_key(sid, pop_salt)
        sess = {
            "user": user,
            "device": device,
            "location": location,
            "exp": now + TOKEN_TTL,
            "abs_exp": now + _env_int("ZTNA_SESSION_MAX",3600,1,30*86400),
            "mfa_at": now,
            "travel": travel,
            "auth_ip": "desktop",
            "location_at": now,
            "created": now,
            "key": key,
        }
        with LOCK:
            _prune_sessions_for_login_locked(user,now)
            SESSIONS[sid] = sess
            LASTLOC[user] = (location, now)
        db_exec("INSERT OR REPLACE INTO sessions(sid,user,device,location,created,expires,revoked,pop_key,mfa_at) VALUES(?,?,?,?,?,?,0,?,?)",(sid,user,device,location,now,sess["abs_exp"],pop_salt,now))
        if not self._audit(user=user, device=device, resource="login", decision="ALLOW",
                   reasons=["password + TOTP verified"] + list(extra_reasons) +
                           (["location change within 5 min"] if travel else [])):
            with LOCK: SESSIONS.pop(sid,None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            return False, "Audit unavailable; login refused"
        if device in DEVICES: DEVICES[device]["last_report"] = now   # the device checks in when its user signs in
        self.session = (sid, sess)
        self.user, self.device, self.location = user, device, location
        return True, "Login successful"


    def stepup(self, otp):
        if not self.session:
            return False, "Not logged in"
        sid, sess = self.session
        with LOCK:
            if sid not in SESSIONS:
                self._drop_session()
                return False, "session revoked"
        if sess["exp"] <= time.time() or sess["abs_exp"] <= time.time():
            with LOCK: SESSIONS.pop(sid,None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            self._drop_session()
            return False, "Session expired"
        if not reserve_auth_attempt(sess["user"], "desktop"):
            return False, "Authentication temporarily unavailable"
        try: code_ok = totp_ok(sess["user"], USERS[sess["user"]]["totp"], otp)
        except StateStoreError:
            refund_auth_attempt(sess["user"], "desktop")
            return False, "Authentication state is unavailable; nothing was spent, try again shortly"
        if not code_ok:
            note_fail(sess["user"], "desktop")
            self._audit(user=sess["user"], device=sess["device"], resource="stepup",
                       decision="DENY", reasons=["bad step-up code"])
            return False, "Authentication failed"
        release_auth_attempt(sess["user"], "desktop")
        # Record the event first so an unavailable audit log cannot grant fresh MFA.
        if not self._audit(user=sess["user"], device=sess["device"], resource="stepup",
                   decision="ALLOW", reasons=["MFA re-verified"]):
            return False, "Audit unavailable; step-up refused"
        with LOCK:
            sess["mfa_at"] = time.time(); sess["travel"] = False
            sess["exp"] = min(sess["mfa_at"] + TOKEN_TTL, sess["abs_exp"])
            STEPUP_REQUIRED_USERS.discard(sess["user"])
        db_exec("UPDATE sessions SET mfa_at=? WHERE sid=?",(sess["mfa_at"],sid))
        return True, "MFA re-verified"

    def access(self, resource):
        if not self.session:
            return {"decision": "DENY", "error": "authentication required"}
        sid, sess = self.session
        with LOCK:
            if sid not in SESSIONS:
                self._drop_session()
                return {"decision":"DENY","error":"session revoked"}
        if sess["exp"] <= time.time() or sess["abs_exp"] <= time.time():
            with LOCK: SESSIONS.pop(sid, None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            self._drop_session()
            return {"decision": "DENY", "error": "session expired"}
        if resource not in RESOURCES:
            return {"decision": "DENY", "error": "unknown resource"}
        if sess["device"] in BLOCKED_DEVICES:
            return {"decision": "DENY", "error": "device blocked by manager", "reasons": ["This device has been blocked by the ZTNA manager."]}
        if sess["user"] in STEPUP_REQUIRED_USERS:
            if not self._audit(user=sess["user"], device=sess["device"], resource=resource, decision="STEPUP", reasons=["manager requires fresh MFA before next application request"]):
                return {"decision": "DENY", "error": "audit unavailable; action refused"}
            return {"decision": "STEPUP", "error": "manager requires fresh MFA", "device": sess["device"], "risk": 0, "reasons": ["A manager requires you to verify your authenticator again."], "signals": [], "role": USERS[sess["user"]]["role"], "segment": SEGMENTS[resource], "segment_allowed": segment_allows(sess["user"], resource)}
        if sess["device"] in BLOCKED_DEVICES:
            return {"decision": "DENY", "error": "device blocked by manager", "reasons": ["This device has been blocked by the ZTNA manager."]}
        # Idle timeout, not a hard stop: activity keeps the session alive (up to its absolute lifetime), so MFA
        # windows longer than the token lifetime (e.g. 15 min) can actually apply instead of being cut off at 5 min.
        with LOCK: sess["exp"] = min(time.time() + TOKEN_TTL, sess["abs_exp"])
        decision, reasons, risk, signals = evaluate(sess, sess["device"], resource)
        if not self._audit(user=sess["user"], device=sess["device"], resource=resource,
                   decision=decision, reasons=reasons, risk=risk, signals=signals):
            return {"decision": "DENY", "error": "audit unavailable; action refused"}
        result = {"decision": decision, "device": sess["device"], "risk": risk, "reasons": reasons, "signals": signals, "role": USERS[sess["user"]]["role"], "segment": SEGMENTS[resource], "segment_allowed": segment_allows(sess["user"], resource)}
        if decision == "ALLOW":
            result["data"] = f"[simulated {resource} content]"
            result["preview"] = resource_preview(sess["user"], resource)
            upstream = RESOURCES[resource].get("upstream")
            if upstream:
                try:
                    result["upstream"] = fetch_upstream(upstream)
                except Exception:
                    result["upstream_error"] = "upstream unavailable"
        elif decision == "STEPUP":
            result["error"] = "step-up authentication required"
        else:
            result["error"] = "access denied"
        return result

    def _drop_session(self):
        """The session ended (revoked or expired): forget the identity too, so nothing more can be done in its name."""
        self.session = None
        self.user = self.device = None

    def logout(self):
        if self.session:
            sid, sess = self.session
            with LOCK: SESSIONS.pop(sid, None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            self._audit(user=sess["user"], device=sess["device"], resource="session",
                       decision="REVOKE", reasons=["user logout"])
        self.session = None
        self.user = self.device = None

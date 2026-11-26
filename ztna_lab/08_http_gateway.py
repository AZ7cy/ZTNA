# Part 08 of ztna_lab_v2.py - legacy stdlib HTTP/TLS gateway: request handler H and all of its routes.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ---------- HTTP ----------
class _DeadlineReader:
    def __init__(self, raw, sock, deadline): self.raw,self.sock,self.deadline=raw,sock,deadline
    def _timeout(self):
        remain=self.deadline-time.monotonic()
        if remain<=0: raise TimeoutError("request deadline exceeded")
        self.sock.settimeout(min(2.0,remain))
    def readline(self,*a,**k): self._timeout(); return self.raw.readline(*a,**k)
    def read(self,*a,**k): self._timeout(); return self.raw.read(*a,**k)
    def readinto(self,*a,**k): self._timeout(); return self.raw.readinto(*a,**k)
    def __getattr__(self,n): return getattr(self.raw,n)

def state_payload():
    """Least-privilege state snapshot shared by the API and regression tests."""
    with LOCK:
        safe_resources={r:{"roles":v["roles"],"min_posture":v["min_posture"],"managed":v["managed"],"hours":v["hours"],"mfa_age":v["mfa_age"],"locations":v["locations"]} for r,v in RESOURCES.items()}
        now=time.time()
        return {"users":{u:v["role"] for u,v in USERS.items()},
            "devices":{d:{"owner":v["owner"],"score":posture(d), **{k:bool(v.get(k,False)) for k in ("os_updated","disk_encrypted","firewall","antivirus","corporate_managed")}} for d,v in DEVICES.items()},
            "resources":safe_resources,"hour":now_hour(),"sim":SIM["hour"] is not None,
            "sessions":[{"sid":sid,"user":x["user"],"device":x["device"],"location":x["location"],"ttl":int(x["exp"]-now),"mfa":int(now-x["mfa_at"]),"travel":x.get("travel",False)} for sid,x in SESSIONS.items() if x["exp"]>now]}


# Size-capped throughput endpoints (/download/N, /upload). Parsed and validated in run_legacy_server().
LAB_MAX_TRANSFER = 16 * 1024 * 1024
SENSITIVE_HEADERS = frozenset({"authorization", "proxy-authorization", "x-device-proof", "x-admin-key", "cookie"})


class H(BaseHTTPRequestHandler):
    server_version = "ZTNA-Lab"
    LAB_TRANSFERS = threading.BoundedSemaphore(2)
    sys_version = ""
    CONNECTIONS=threading.BoundedSemaphore(32)
    protocol_version = "HTTP/1.1"
    timeout = 15.0
    def setup(self):
        if not self.CONNECTIONS.acquire(blocking=False):
            self.request.close(); raise ConnectionError("connection limit")
        try:
            self.request.settimeout(min(2.0,self.timeout))
            if hasattr(self.request,"do_handshake"): self.request.do_handshake()
            super().setup()
            self._request_deadline=time.monotonic()+self.timeout
            self.rfile=_DeadlineReader(self.rfile,self.request,self._request_deadline)
        except Exception: self.CONNECTIONS.release(); raise
    def finish(self):
        try: super().finish()
        finally:
            try: self.CONNECTIONS.release()
            except ValueError: pass
    def log_message(self, *a): pass
    def handle_error(self, request, client_address): pass
    def host_ok(self):
        raw=self.headers.get("Host","").strip().lower()
        return raw in ALLOWED_HOSTS
    def real_ip(self):
        host=self.client_address[0]
        try:
            ip=ipaddress.ip_address(host)
            return str(ip.ipv4_mapped) if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped else str(ip)
        except ValueError: return host
    def server_location(self):
        try: ip=ipaddress.ip_address(self.real_ip())
        except ValueError: return "unknown"
        if any(ip in n for n in OFFICE_NETS): return "office"
        if any(ip in n for n in HOME_NETS): return "home"
        return "unknown"
    def manager_session_ok(self):
        token = self.headers.get("X-Manager-Session", "")
        if not token or len(token) > 256:
            return False
        now = time.time()
        with MANAGER_LOGIN_LOCK:
            for key, record in list(MANAGER_SESSIONS.items()):
                if record.get("exp", 0) <= now:
                    MANAGER_SESSIONS.pop(key, None)
            record = MANAGER_SESSIONS.get(token)
            return bool(record and record.get("role") == "manager" and record.get("exp", 0) > now)

    def manager_login(self, data):
        # The requested puja/puja123 credential is deliberately demo-only. Production
        # deployments must use the normal administrator API key / enterprise identity.
        if not DEMO:
            return self.send(404, {"error": "demo manager login is disabled"})
        if not _is_loopback_bind(self.real_ip()) and not isinstance(self.connection, ssl.SSLSocket):
            return self.send(403, {"error": "HTTPS is required for remote manager sign-in"})
        now = time.time()
        with MANAGER_LOGIN_LOCK:
            while MANAGER_LOGIN_FAILS and now - MANAGER_LOGIN_FAILS[0] > 60:
                MANAGER_LOGIN_FAILS.popleft()
            if len(MANAGER_LOGIN_FAILS) >= 12:
                return self.send(429, {"error": "too many manager login attempts; wait a minute"})
        expected_user = os.environ.get("ZTNA_MANAGER_USER", "puja")
        expected_password = os.environ.get("ZTNA_MANAGER_PASSWORD", "puja123")
        user = str(data.get("username", ""))[:64]
        password = str(data.get("password", ""))[:256]
        if not (_ct_eq(user, expected_user) & _ct_eq(password, expected_password)):
            with MANAGER_LOGIN_LOCK:
                MANAGER_LOGIN_FAILS.append(now)
            if audit_allowed(self.real_ip(), "manager-login-deny", limit=20, window=60):
                audit(user=user or None, device=None, resource="manager-login", decision="DENY", reasons=["manager authentication failed"])
            return self.send(401, {"error": "invalid manager credentials"})
        token = secrets.token_urlsafe(32)
        with MANAGER_LOGIN_LOCK:
            if len(MANAGER_SESSIONS) >= 200:
                oldest = min(MANAGER_SESSIONS, key=lambda k: MANAGER_SESSIONS[k].get("created", 0))
                MANAGER_SESSIONS.pop(oldest, None)
            MANAGER_SESSIONS[token] = {"role": "manager", "created": now, "exp": now + 8 * 3600}
            MANAGER_LOGIN_FAILS.clear()
        audit(user=expected_user, device=None, resource="manager-login", decision="ALLOW", reasons=["ZTNA manager console login"])
        return self.send(200, {"token": token, "expires_in": 8 * 3600, "role": "manager"})

    def admin_ok(self):
        if self.manager_session_ok():
            return True
        if not ADMIN_KEY or len(ADMIN_KEY)<32: return False
        if os.environ.get("ZTNA_ADMIN_REQUIRE_MTLS", "0") == "1":
            try:
                if not os.environ.get("ZTNA_CLIENT_CA") or not self.connection.getpeercert(binary_form=True): return False
            except Exception: return False
        now=time.time(); ip=self.real_ip()
        with LOCK:
            # Cap memory use and discard stale source buckets before creating a new one.
            if len(ADMIN_FAILS) >= 10000:
                for old_ip, old_q in list(ADMIN_FAILS.items()):
                    while old_q and now-old_q[0] > 600: old_q.popleft()
                    if not old_q: ADMIN_FAILS.pop(old_ip, None)
                if len(ADMIN_FAILS) >= 10000 and ip not in ADMIN_FAILS:
                    # Do not let arbitrary new source addresses grow the table forever.
                    return False
            while ADMIN_FAIL_GLOBAL and now-ADMIN_FAIL_GLOBAL[0] > 60: ADMIN_FAIL_GLOBAL.popleft()
            q=ADMIN_FAILS.setdefault(ip,deque(maxlen=32))
            while q and now-q[0]>60: q.popleft()
            if len(q)>=10 or len(ADMIN_FAIL_GLOBAL)>=ADMIN_FAIL_GLOBAL_LIMIT: return False
            ok=bool(ADMIN_KEY) and hmac.compare_digest(self.headers.get("X-Admin-Key","").encode(),ADMIN_KEY.encode())
            if not ok:
                q.append(now); ADMIN_FAIL_GLOBAL.append(now)
            return ok
    def send(self, code, obj, ctype="application/json", extra_headers=None):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        if ctype == "text/html":
            nonce=secrets.token_urlsafe(18)
            body=body.replace(b"<script>",f'<script nonce="{nonce}">'.encode(),1)
            body=body.replace(b"<style>",f'<style nonce="{nonce}">'.encode(),1)
        self.close_connection=True; self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.send_header("Connection","close")
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}
        if os.environ.get("ZTNA_CERT") and os.environ.get("ZTNA_KEY"): headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
        for k, v in headers.items(): self.send_header(k, v)
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        if ctype == "text/html": self.send_header("Content-Security-Policy", f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; style-src-attr 'none'; connect-src 'self'")
        self.end_headers(); self.wfile.write(body)
    def body(self):
        te=self.headers.get("Transfer-Encoding","").strip()
        if te: self.close_connection=True; raise ValueError("transfer-encoding not supported")
        cls=self.headers.get_all("Content-Length") or []
        if len(cls)>1: self.close_connection=True; raise ValueError("duplicate content-length")
        try: n=int(cls[0] if cls else 0)
        except ValueError: self.close_connection=True; raise ValueError("bad length")
        if not 0 <= n <= MAX_BODY: self.close_connection=True; raise ValueError("bad length")
        raw=self.rfile.read(n) if n else b""; self._raw_body=raw
        d=json.loads(raw or b"{}") if n else {}
        if not isinstance(d,dict): raise ValueError("object required")
        return d
    def auth(self):
        h=self.headers.get("Authorization",""); dv=self.headers.get("X-Device-Id",""); proof=self.headers.get("X-Device-Proof","")
        claims=jwt_decode(h[7:]) if h.startswith("Bearer ") else None
        with LOCK: sess=SESSIONS.get(claims.get("sid")) if claims else None
        if not sess or sess["exp"]<=time.time() or sess["abs_exp"]<=time.time():
            if claims:
                with LOCK: SESSIONS.pop(claims.get("sid"),None)
            return claims,None,dv
        if dv != sess["device"]: return claims,None,dv
        if claims.get("dev")!=sess["device"] or not hmac.compare_digest(claims.get("cnf",""),sha_bytes(sess["key"])): return claims,None,dv
        if os.environ.get("ZTNA_CLIENT_CA"):
            try: cert=self.connection.getpeercert(binary_form=True)
            except Exception: cert=None
            fp=hashlib.sha256(cert).hexdigest() if cert else ""
            expected=os.environ.get("ZTNA_DEVICE_CERT_"+sess["device"].upper().replace("-","_"),"").lower()
            if not cert or not expected or not hmac.compare_digest(fp,expected): return claims,None,dv
        else:
            try:
                ts=float(self.headers.get("X-Device-Timestamp","")); nonce=self.headers.get("X-Device-Nonce","")
                declared=self.headers.get("X-Content-SHA256","")
                if not PROOF_NONCE_RE.fullmatch(nonce) or not PROOF_DIGEST_RE.fullmatch(declared) or not math.isfinite(ts) or abs(time.time()-ts)>30: return claims,None,dv
                now=time.time()
                with LOCK:
                    expected=hmac.new(sess["key"],proof_message(self.command,self.path,declared,ts,nonce),hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(proof,expected): return claims,None,dv
                    # The signature covers the *declared* digest; now bind it to the bytes actually received.
                    raw=getattr(self,"_raw_body",None); self._body_sha_pending=None
                    if raw is not None:
                        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),declared): return claims,None,dv
                    elif self.headers.get("Content-Length","0").strip() in ("","0"):
                        if declared!=EMPTY_SHA256: return claims,None,dv
                    else: self._body_sha_pending=declared      # streamed body (/upload) is checked by the handler
                    if not _nonce_accept(PROOF_NONCES,PROOF_NONCE_HEAP,nonce,35,now,limit=PROOF_NONCE_LIMIT,scope=claims.get("sid","unknown")): return claims,None,dv
            except (ValueError,TypeError): return claims,None,dv
        if not DEMO:
            loc=self.server_location(); old=sess.get("location"); now=time.time()
            if loc != old:
                with LOCK:
                    sess["travel"]=bool(old and old != "unknown" and loc != "unknown" and now-sess.get("location_at",now)<300)
                    sess["location"]=loc; sess["location_at"]=now
                    if old and old != loc: sess["ip_changed"]=True
        return claims,sess,dv

    def handle_one_request(self):
        try:
            return super().handle_one_request()
        except (ConnectionError,TimeoutError,ssl.SSLError):
            self.close_connection=True
        except Exception:
            self.close_connection=True
            try: self.send(500,{"error":"internal server error"})
            except Exception: pass
    def do_GET(self):
        if not self.host_ok(): return self.send(421,{"error":"bad host"})
        p = urlsplit(self.path).path
        if p in ("/", "/index.html"): return self.send(200, LANDING_HTML.encode(), "text/html")
        if p == "/employee": return self.send(200, EMPLOYEE_HTML.encode(), "text/html")
        if p == "/ztna": return self.send(200, MANAGER_LOGIN_HTML.encode(), "text/html")
        if p == "/ztna/console": return self.send(200, INDEX_HTML.encode(), "text/html")
        if p == "/api/ui/catalog":
            if not DEMO: return self.send(404, {"error": "demo catalog disabled"})
            return self.send(200, {"users": sorted(USERS.keys()), "devices": {d: {"owner": v.get("owner", "")} for d, v in DEVICES.items()}, "resources": sorted(RESOURCES.keys())})
        if p == "/baseline": return self.send(200, {"ok": True})
        if p.startswith("/netacl/"): return self.netacl(p[8:])
        if p == "/health": return self.send(200, {"status": "ok"})
        if p == "/inspect": return self.inspect()
        if p == "/headers": return self.headers_text()
        if p.startswith("/download/"): return self.download(p[10:])
        if p.startswith("/access/"): return self.access(p[8:])
        if not p.startswith("/api/"): return self.send(404, {"error": "not found"})
        if p == "/api/demo/totp" and DEMO_OTP:
            if not _is_loopback_bind(self.real_ip()): return self.send(403,{"error":"demo OTP helper is loopback-only"})
            from urllib.parse import parse_qs
            u=parse_qs(urlsplit(self.path).query).get("user",[""])[0]
            code=demo_totp_code(u) if u in USERS else None
            return self.send(200,{"code":code}) if code else self.send(409,{"error":"no OTP is currently usable; retry in the next window"}) if u in USERS else self.send(404,{})
        if not self.admin_ok(): return self.send(401, {"error": "admin key required"})
        if p == "/api/state":
            return self.send(200, state_payload())
        if p == "/api/logs": return self.send(200, list(LOG)[:100])
        if p == "/api/metrics":
            with LOCK:
                access_events=[e for e in LOG if e.get("resource") in RESOURCES and not _is_exception_record(e)]
                c = Counter(e["decision"] for e in access_events)
                rs = Counter(re.sub(r"\d+", "#", r) for e in access_events if e["decision"] == "DENY" for r in e["reasons"])
            return self.send(200, {"allow": c["ALLOW"], "deny": c["DENY"], "stepup": c["STEPUP"], "reasons": rs.most_common(6),
                "policy_us": {"p50": pct(LAT["policy_us"], .5), "p95": pct(LAT["policy_us"], .95)},
                "proxy_ms": {"p50": pct(LAT["proxy_ms"], .5), "p95": pct(LAT["proxy_ms"], .95)}, "series": list(LAT["proxy_ms"])[-60:]})
        if p == "/api/verify": return self.send(200, verify_chain())
        if p == "/api/firewall": return self.send(200, {"rules": firewall_rules()})
        if p == "/api/export":
            buf = io.StringIO(); w = csv.writer(buf); w.writerow(["time", "user", "device", "resource", "decision", "risk", "reasons", "hash"])
            for e in reversed(list(LOG)): w.writerow([safe(e.get("ts", "")), safe(e.get("user") or ""), safe(e.get("device") or ""), safe(e.get("resource", "")), safe(e.get("decision", "")), safe(e.get("risk", "")), safe("; ".join(e.get("reasons",[]))), safe(e.get("hash", "")[:16])])
            return self.send(200, buf.getvalue().encode(), "text/csv")
        self.send(404, {"error": "not found"})

    def do_PUT(self):
        if not self.host_ok(): return self.send(421,{"error":"bad host"})
        if urlsplit(self.path).path == "/upload": return self.upload()
        self.close_connection=True
        return self.send(405,{"error":"method not allowed"},extra_headers={"Allow":"GET, POST"})


    def do_POST(self):
        if not self.host_ok(): return self.send(421,{"error":"bad host"})
        p = urlsplit(self.path).path
        if p == "/upload": return self.upload()
        try: d = self.body()
        except Exception: return self.send(400, {"error": "bad request"})
        try:
            return self._post(p,d)
        except (AuditFull,AuditTamper):
            return self.send(503,{"error":"audit unavailable; action refused"})
        except StateStoreError:
            return self.send(503,{"error":"state store unavailable; action refused"})
        except Exception:
            self.close_connection=True
            try:
                if audit_allowed(self.real_ip(),"500",limit=20,window=60): audit(user=None,device=None,resource=p,decision="ERROR",reasons=["internal request error"])
            except Exception: pass
            return self.send(500,{"error":"internal server error"})

    def _post(self,p,d):
        if p == "/api/ui/manager-login": return self.manager_login(d)
        if p == "/api/ui/manager-logout":
            token = self.headers.get("X-Manager-Session", "")
            with MANAGER_LOGIN_LOCK: MANAGER_SESSIONS.pop(token, None)
            return self.send(200, {"ok": True})
        if p == "/api/login": return self.login(d)
        if p == "/api/stepup": return self.stepup(d)
        if p == "/api/posture/report": return self.posture_report(d)
        if p == "/api/logout": return self.logout(d)
        if p == "/api/refresh": return self.refresh_session()
        if not self.admin_ok(): return self.send(401, {"error": "admin key required"})
        if p == "/api/sim":
            if not DEMO: return self.send(403,{"error":"simulation disabled outside DEMO"})
            h=d.get("hour")
            if h is not None and (type(h) is not int or not 0 <= h <= 23): return self.send(400,{"error":"hour must be null or integer 0-23"})
            SIM["hour"]=h; audit(user="admin",device=None,resource="sim",decision="POLICY",reasons=[f"hour={h}"]); return self.send(200,{"hour":now_hour()})
        if p.startswith("/api/device/"):
            if not DEMO: return self.send(403,{"error":"manual posture controls disabled outside DEMO"})
            dev = p.split("/")[3]
            if dev in DEVICES and d.get("field") in POSTURE_W:
                if type(d.get("value")) is not bool: return self.send(400,{"error":"value must be boolean"})
                if d["field"] == "corporate_managed": return self.send(403,{"error":"corporate_managed is MDM/admin controlled"})
                DEVICES[dev][d["field"]] = d["value"]; DEVICES[dev]["last_report"] = time.time(); audit(user="admin",device=dev,resource="posture",decision="POLICY",reasons=[f"{d['field']}={d['value']}"]); return self.send(200,{"score":posture(dev),"stale":False})
        if p.startswith("/api/session/") and p.endswith("/revoke"):
            sid=p.split("/")[3]
            with LOCK: s = SESSIONS.pop(sid, None)   # takes effect in this process immediately
            try: db_exec_critical("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            except StateStoreError:
                try: audit(user=s and s["user"], device=s and s["device"], resource="-", decision="REVOKE", reasons=["admin revoked session; durable revocation FAILED"])
                except (AuditFull,AuditTamper): pass
                return self.send(503,{"error":"revocation applied in memory but could not be persisted","revoked":bool(s)})
            audit(user=s and s["user"], device=s and s["device"], resource="-", decision="REVOKE", reasons=["admin revoked session"])
            return self.send(200, {"revoked": bool(s)})
        if p.startswith("/api/policy/") and p.split("/")[3] in RESOURCES:
            res, r = p.split("/")[3], RESOURCES[p.split("/")[3]]
            try:
                merged=validate_policy_patch(res,d)
            except (TypeError,ValueError,IndexError,KeyError,OverflowError): return self.send(400,{"error":"invalid policy"})
            with LOCK: old={k:r[k] for k in POLICY_KEYS}; r.update(merged); save_policy()
            hist=None
            try:
                hist=db_exec_critical("INSERT INTO policy_changes(ts,actor,resource,policy_json) VALUES(?,?,?,?)",(time.time(),"admin",res,json.dumps(merged,sort_keys=True)))
                audit(user="admin", device=None, resource=res, decision="POLICY", reasons=["policy updated: " + json.dumps(merged, sort_keys=True, separators=(",", ":"))])
            except (AuditFull,AuditTamper,StateStoreError):
                # A policy change that cannot be recorded must not stay in effect: restore the previous policy.
                with LOCK: r.update(old); save_policy()
                if hist: db_exec("DELETE FROM policy_changes WHERE rowid=?",(hist,))
                return self.send(503,{"error":"policy change rolled back; audit or state store unavailable"})
            return self.send(200, {"policy": {k: r[k] for k in POLICY_KEYS}})
        self.send(404, {"error": "not found"})

    def login(self,d):
        if not _is_loopback_bind(self.real_ip()) and not isinstance(self.connection, ssl.SSLSocket):
            return self.send(403, {"error": "HTTPS is required for remote employee sign-in"})
        u,ip=str(d.get("username",""))[:64],self.real_ip()
        if not reserve_auth_attempt(u,ip): return self.send(429,{"error":"authentication temporarily unavailable"})
        usr=USERS.get(u); dummy=next(iter(USERS.values())) if USERS else None
        pw_before = dict(usr["pw"]) if usr else None
        try:
            pw_ok=pw_verify(str(d.get("password","")),usr["pw"] if usr else dummy["pw"] if dummy else {})
        except KdfBusy:
            refund_auth_attempt(u,ip)
            return self.send(503,{"error":"authentication capacity temporarily unavailable"},extra_headers={"Retry-After":"2"})
        if usr and pw_ok and usr["pw"] != pw_before:
            try: _persist_users()
            except Exception:
                logger.exception("could not persist upgraded password hash")
                refund_auth_attempt(u,ip)                # our storage failed, not the user's credentials
                return self.send(503,{"error":"account store unavailable; login refused"})
        dev=str(d.get("device_id",""))[:64]
        dev_ok=bool(usr and pw_ok and dev in DEVICES and DEVICES[dev]["owner"]==u)
        if dev_ok and dev in BLOCKED_DEVICES:           # manager blocks apply at the gateway too; checked before any code is spent
            if audit_allowed(f"{u}|{dev}","blocked-login",limit=3,window=60): audit(user=u,device=dev,resource="login",decision="DENY",reasons=["device blocked by ZTNA manager"])
            return self.send(403,{"error":"this device has been blocked by the ZTNA manager"})
        otp_okay=False
        if dev_ok:                                      # the one-time code is spent LAST, only when password and device already passed
            try: otp_okay=totp_ok(u,usr["totp"],str(d.get("otp","")),consume=True)
            except StateStoreError:
                refund_auth_attempt(u,ip)
                return self.send(503,{"error":"authentication state unavailable; nothing was spent, try again"})
        if not (usr and pw_ok and dev_ok and otp_okay):
            note_fail(u,ip)
            if audit_allowed(ip,"login-deny"): audit(user=u if u in USERS else None,device=dev,resource="login",decision="DENY",reasons=["authentication failed"])
            return self.send(401,{"error":"authentication failed"})
        loc=self.server_location()
        if DEMO and d.get("location") in ("office","home","unknown") and self.real_ip().startswith(("127.","::1")): loc=d["location"]
        with LOCK:
            new_dev=dev not in SEEN_DEV.setdefault(u,set()); SEEN_DEV[u].add(dev)
        now=time.time(); prev=LASTLOC.get(u); sid=secrets.token_hex(12); pop_salt=_new_session_salt(); key=_derive_session_key(sid,pop_salt)
        sess={"user":u,"device":dev,"location":loc,"exp":now+TOKEN_TTL,"abs_exp":now+_env_int("ZTNA_SESSION_MAX",3600,1,30*86400),"mfa_at":now,"travel":bool(prev and prev[0]!=loc and now-prev[1]<300),"auth_ip":ip,"location_at":now,"created":now,"key":key,"new_device":new_dev}
        try:
            with LOCK:
                _prune_sessions_for_login_locked(u,now)      # same expiry/cap rules as the desktop sign-in
                SESSIONS[sid]=sess; LASTLOC[u]=(loc,now); release_auth_attempt(u,ip)
        except StateStoreError:
            refund_auth_attempt(u,ip)
            return self.send(503,{"error":"state store unavailable; action refused"})
        try: db_exec_critical("INSERT OR REPLACE INTO sessions(sid,user,device,location,created,expires,revoked,pop_key,mfa_at) VALUES(?,?,?,?,?,?,0,?,?)",(sid,u,dev,loc,now,sess["abs_exp"],pop_salt,now))
        except StateStoreError:
            with LOCK: SESSIONS.pop(sid,None)
            return self.send(503,{"error":"state store unavailable; action refused"})
        try:
            audit(user=u,device=dev,resource="login",decision="ALLOW",reasons=["password + TOTP verified"]+( ["location change within 5 min"] if sess["travel"] else []))
        except (AuditFull,AuditTamper):
            with LOCK: SESSIONS.pop(sid,None)
            try: db_exec_critical("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            except StateStoreError: pass   # session is already gone from memory and no token was issued
            return self.send(503,{"error":"audit unavailable; action refused"})
        self.send(200,{"token":jwt_encode({"sid":sid,"sub":u,"dev":dev,"iat":int(now),"exp":sess["exp"],"cnf":sha_bytes(key)}),"device_key":b64(key),"expires_in":TOKEN_TTL})

    def stepup(self,d):
        claims,sess,dv=self.auth()
        if not sess: return self.send(401,{"error":"authentication required"})
        now=time.time(); ip=self.real_ip(); k=fkey(sess["user"],ip)
        if not reserve_auth_attempt(sess["user"],ip): return self.send(429,{"error":"authentication temporarily unavailable"})
        try: code_ok=totp_ok(sess["user"],USERS[sess["user"]]["totp"],str(d.get("otp","")))
        except StateStoreError:
            refund_auth_attempt(sess["user"],ip)
            return self.send(503,{"error":"authentication state unavailable; nothing was spent, try again"})
        if not code_ok:
            note_fail(sess["user"],ip); audit(user=sess["user"],device=dv,resource="stepup",decision="DENY",reasons=["bad step-up code"]); return self.send(401,{"error":"authentication failed"})
        release_auth_attempt(sess["user"],ip)
        with LOCK: prev_mfa,prev_travel=sess["mfa_at"],sess.get("travel",False); sess["mfa_at"]=time.time(); sess["travel"]=False
        try: db_exec_critical("UPDATE sessions SET mfa_at=? WHERE sid=?",(sess["mfa_at"],claims.get("sid")))
        except StateStoreError:
            with LOCK: sess["mfa_at"],sess["travel"]=prev_mfa,prev_travel
            return self.send(503,{"error":"state store unavailable; action refused"})
        audit(user=sess["user"],device=dv,resource="stepup",decision="ALLOW",reasons=["MFA re-verified"]); return self.send(200,{"ok":True})

    def refresh_session(self):
        claims,sess,dv=self.auth()
        if not sess: return self.send(401,{"error":"authentication required"})
        now=time.time(); new_exp=min(now+TOKEN_TTL,sess["abs_exp"])
        if new_exp<=now: return self.send(401,{"error":"absolute session lifetime reached"})
        with LOCK: sess["exp"]=new_exp
        token=jwt_encode({"sid":claims["sid"],"sub":sess["user"],"dev":sess["device"],"iat":int(now),"exp":new_exp,"cnf":sha_bytes(sess["key"])})
        return self.send(200,{"token":token,"expires_in":int(new_exp-now)})

    def logout(self,d):
        claims,sess,dv=self.auth()
        if not sess: return self.send(401,{"error":"authentication required"})
        with LOCK: SESSIONS.pop(claims["sid"],None)
        db_exec_critical("UPDATE sessions SET revoked=1 WHERE sid=?",(claims["sid"],))
        audit(user=sess["user"],device=sess["device"],resource="session",decision="REVOKE",reasons=["user logout"]); return self.send(200,{"ok":True})

    def posture_report(self,d):
        try:
            dev,checks,ts,nonce,sig=d["device"],d["checks"],float(d["ts"]),str(d["nonce"]),str(d["sig"])
            if not isinstance(dev,str) or not re.fullmatch(r"[a-z0-9-]{1,64}",dev) or not isinstance(checks,dict): raise ValueError
            if any(k not in ("os_updated","disk_encrypted","firewall","antivirus") or type(v) is not bool for k,v in checks.items()): raise ValueError
            required_checks={"os_updated","disk_encrypted","firewall","antivirus"}
            if set(checks) != required_checks: raise ValueError
            key=posture_key(dev); now=time.time()
            if key is None or not math.isfinite(ts) or abs(now-ts)>60: raise ValueError
            expected=sign_report(dev,checks,ts,nonce)
            if not hmac.compare_digest(sig,expected): raise ValueError
        except (KeyError,ValueError,TypeError):
            if audit_allowed(self.real_ip(),"posture-deny"):
                audit(user=None,device=str(d.get("device",""))[:40],resource="posture",decision="DENY",reasons=["invalid/stale/replayed posture report"])
            return self.send(403,{"error":"posture report rejected"})
        with LOCK:
            now=time.time()
            if not _nonce_accept(NONCES,NONCE_HEAP,nonce,75,now,limit=1024,scope="posture:"+dev): return self.send(403,{"error":"posture report replayed"})
            if dev not in DEVICES:
                owner=os.environ.get("ZTNA_DEVICE_OWNER_"+dev.upper().replace("-","_"))
                if not owner or owner not in USERS: return self.send(403,{"error":"device enrollment not authorized"})
                DEVICES[dev]={"owner":owner,"os_updated":False,"disk_encrypted":False,"firewall":False,"antivirus":False,"corporate_managed":False,"last_report":0.0}
            for k,v in checks.items():
                if k in ("os_updated","disk_encrypted","firewall","antivirus") and type(v) is bool: DEVICES[dev][k]=v
            if not DEMO: DEVICES[dev]["corporate_managed"]=managed_device(dev)
            DEVICES[dev]["last_report"]=time.time()
        if audit_allowed(self.real_ip(),"posture-info"): audit(user=None,device=dev,resource="posture",decision="INFO",reasons=["signed report applied",f"score {posture(dev)}"])
        return self.send(200,{"score":posture(dev)})

    def inspect(self):
        """Authenticated request inspector: shows what the gateway/proxy path delivered to this server.
        Credential-bearing headers are redacted; duplicate headers are preserved."""
        claims,sess,dv=self.auth()
        try:
            if not sess:
                if audit_allowed(self.real_ip(),"access-deny"): audit(user=None,device=dv[:64],resource="inspect",decision="DENY",reasons=["no valid token / session revoked"])
                return self.send(401,{"error":"authentication required"})
            headers=self.redacted_headers()
            tls=None
            if hasattr(self.connection,"cipher"):
                try:
                    c=self.connection.cipher(); tls={"version":self.connection.version(),"cipher":c[0] if c else None}
                except Exception: tls=None
            if audit_allowed(sess["user"],"inspect",limit=30,window=10): audit(user=sess["user"],device=sess["device"],resource="inspect",decision="ALLOW",reasons=["request inspector viewed"])
        except (AuditFull,AuditTamper): return self.send(503,{"error":"audit unavailable; action refused"})
        return self.send(200,{"client_ip":self.real_ip(),"method":self.command,"path":urlsplit(self.path).path,"http_version":self.request_version,
            "host":self.headers.get("Host",""),"tls":tls,"headers":headers,"session":{"user":sess["user"],"device":sess["device"],"location":sess["location"]}})

    def redacted_headers(self):
        """Every received header (duplicates preserved); credential-bearing values are redacted."""
        return [{"name":k,"value":"[redacted]" if k.lower() in SENSITIVE_HEADERS else v} for k,v in self.headers.items()]

    def _lab_session(self, resource):
        """Shared gate for the lab endpoints: a valid device-bound session is required, denials are audited."""
        claims,sess,dv=self.auth()
        if not sess:
            try:
                if audit_allowed(self.real_ip(),"access-deny"): audit(user=None,device=dv[:64],resource=resource,decision="DENY",reasons=["no valid token / session revoked"])
            except (AuditFull,AuditTamper): pass
            self.close_connection=True
            self.send(401,{"error":"authentication required"})
            return None
        return sess

    def _lab_audit(self, sess, resource, reason, decision="ALLOW"):
        try:
            if audit_allowed(sess["user"],"transfer",limit=30,window=10): audit(user=sess["user"],device=sess["device"],resource=resource,decision=decision,reasons=[reason])
        except (AuditFull,AuditTamper):
            self.send(503,{"error":"audit unavailable; action refused"}); return False
        return True

    def netacl(self,res):
        """Lab-only conventional baseline: access is decided by the SOURCE NETWORK alone (loopback/private = trusted).
        No identity, device, MFA, time or risk check. Exists only in demo mode so ZTNA can be compared against it."""
        if not DEMO or res not in RESOURCES: return self.send(404,{"error":"not found"})
        if not net_acl_trusted(self.real_ip()): return self.send(403,{"error":"source network not trusted"})
        return self.send(200,{"resource":res,"model":"network-acl","decision":"ALLOW"})

    def headers_text(self):
        """Plain-text, curl-friendly header dump (credentials redacted). Same gate as /inspect."""
        sess=self._lab_session("headers")
        if not sess: return
        if not self._lab_audit(sess,"headers","plain header dump viewed"): return
        lines=[f"client_ip: {self.real_ip()}",f"method: {self.command}",f"path: {urlsplit(self.path).path}",f"http_version: {self.request_version}",""]
        lines+=[f"{h['name']}: {h['value']}" for h in self.redacted_headers()]
        return self.send(200,("\n".join(lines)+"\n").encode("utf-8","replace"),"text/plain; charset=utf-8")

    def download(self,spec):
        """GET /download/N: stream N pseudo-random bytes. N is capped (ZTNA_LAB_MAX_TRANSFER) and concurrency is bounded."""
        sess=self._lab_session("download")
        if not sess: return
        if not re.fullmatch(r"[0-9]{1,12}",spec): return self.send(400,{"error":"size must be a non-negative integer"})
        n=int(spec)
        if n>LAB_MAX_TRANSFER: return self.send(413,{"error":"size exceeds limit","max_bytes":LAB_MAX_TRANSFER})
        if not self.LAB_TRANSFERS.acquire(blocking=False):
            return self.send(429,{"error":"too many concurrent transfers"},extra_headers={"Retry-After":"1"})
        try:
            if not self._lab_audit(sess,"download",f"download {n} bytes"): return
            self.close_connection=True
            self.send_response(200)
            for k,v in (("Content-Type","application/octet-stream"),("Content-Length",str(n)),("Cache-Control","no-store"),("X-Content-Type-Options","nosniff"),("Connection","close")): self.send_header(k,v)
            self.end_headers()
            block=secrets.token_bytes(65536); sent=0
            while sent<n:
                chunk=block[:min(len(block),n-sent)]; self.wfile.write(chunk); sent+=len(chunk)
        finally:
            self.LAB_TRANSFERS.release()

    def upload(self):
        """POST|PUT /upload: discard the body (never stored) and report how many bytes arrived and how fast."""
        sess=self._lab_session("upload")
        if not sess: return
        self.close_connection=True
        if self.headers.get("Transfer-Encoding","").strip(): return self.send(400,{"error":"transfer-encoding not supported"})
        cls=self.headers.get_all("Content-Length") or []
        if len(cls)!=1 or not re.fullmatch(r"[0-9]{1,12}",cls[0].strip()): return self.send(400,{"error":"exactly one numeric Content-Length required"})
        n=int(cls[0])
        if n>LAB_MAX_TRANSFER: return self.send(413,{"error":"size exceeds limit","max_bytes":LAB_MAX_TRANSFER})
        if not self.LAB_TRANSFERS.acquire(blocking=False):
            return self.send(429,{"error":"too many concurrent transfers"},extra_headers={"Retry-After":"1"})
        try:
            t0=time.perf_counter(); remaining=n; body_hash=hashlib.sha256()
            try:
                while remaining:
                    chunk=self.rfile.read(min(65536,remaining))
                    if not chunk: break
                    body_hash.update(chunk); remaining-=len(chunk)
            except (TimeoutError,OSError): pass
            got=n-remaining; dt=max(time.perf_counter()-t0,1e-9)
            def refused(reason,payload):
                try: audit_allowed(sess["user"],"transfer",limit=30,window=10) and audit(user=sess["user"],device=sess["device"],resource="upload",decision="DENY",reasons=[reason])
                except (AuditFull,AuditTamper): pass
                return self.send(400,payload)
            if remaining: return refused("upload incomplete body",{"error":"incomplete body","received":got})
            pending=getattr(self,"_body_sha_pending",None)
            if pending is not None and not hmac.compare_digest(body_hash.hexdigest(),pending):
                return refused("upload body digest mismatch",{"error":"body digest mismatch"})
            # ALLOW is recorded only after the whole body was received and its digest verified.
            if not self._lab_audit(sess,"upload",f"upload {got} bytes verified"): return
            return self.send(200,{"received":got,"seconds":round(dt,4),"mbps":round(got*8/dt/1e6,3)})
        finally:
            self.LAB_TRANSFERS.release()

    def access(self,res):
        t0=time.perf_counter(); claims,sess,dv=self.auth()
        if not sess:
            if audit_allowed(self.real_ip(),"access-deny"): audit(user=None,device=dv[:64],resource=audit_resource(res),decision="DENY",reasons=["no valid token / session revoked"])
            return self.send(401,{"error":"authentication required"})
        if res not in RESOURCES: return self.send(404,{"error":"not found"})
        if claims.get("dev")!=sess["device"] or dv!=sess["device"]: audit(user=sess["user"],device=dv[:64],resource=audit_resource(res),decision="DENY",reasons=["token/device binding mismatch"]); return self.send(403,{"error":"access denied"})
        t1=time.perf_counter(); dec,why,risk,sig=evaluate(sess,claims["dev"],res); LAT["policy_us"].append((time.perf_counter()-t1)*1e6)
        audit_kw=dict(user=sess["user"],device=claims["dev"],resource=res,decision=dec,reasons=why,risk=risk,signals=sig)
        if dec!="ALLOW":
            try:
                if audit_allowed(sess["user"],"access-deny",limit=60,window=10): audit(**audit_kw)
            except (AuditFull,AuditTamper): return self.send(503,{"error":"audit unavailable; action refused"})
            return self.send(401 if dec=="STEPUP" else 403,{"error":"step-up authentication required" if dec=="STEPUP" else "access denied","stepup":dec=="STEPUP"})
        try: audit(**audit_kw)
        except (AuditFull,AuditTamper): return self.send(503,{"error":"audit unavailable; action refused"})
        up,out=RESOURCES[res]["upstream"],{"resource":res,"data":f"[simulated {res} content]","user":sess["user"]}
        if up:
            try: out["upstream"]=fetch_upstream(up)
            except Exception: out["upstream_error"]="upstream unavailable"
        LAT["proxy_ms"].append((time.perf_counter()-t0)*1000); return self.send(200,{**out,"signals":sig})

# Part 04 of ztna_lab_v2.py - resource catalogue, in-memory state, GUI event bus, SQLite store, security alerts, session revocation.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

def _res(desc, roles, min_posture, managed, hours, mfa_age, locations, segment, env=None):
    return {"desc": desc, "roles": roles, "min_posture": min_posture, "managed": managed, "hours": hours, "mfa_age": mfa_age,
            "locations": locations, "segment": segment, "upstream": os.environ.get(env) if env else None}
OFC, ANY = ["office"], ["office", "home"]
RESOURCES = {  # mfa_age = max seconds since last MFA before step-up is demanded
    "wiki":           _res("Company knowledge base and how-to pages",           ["engineer","devops","security","hr","finance","sales","support","legal","executive","admin"], 40, False, [0, 24], 300,  ANY, "SEG-WIKI", "UP_WIKI"),
    "hr-db":          _res("Employee records, salaries and reviews",            ["hr","admin"],                                   70, True,  [9, 18], 900,  OFC, "SEG-HR", "UP_HR"),
    "admin-panel":    _res("IT admin console: users, devices, sessions",        ["admin"],                                        90, True,  [9, 18], 120,  OFC, "SEG-ADMIN", "UP_ADMIN"),
    "source-code":    _res("Git repositories and pull requests",                ["engineer","devops","security","admin"],         70, True,  [7, 21], 900,  ANY, "SEG-CODE"),
    "ci-cd":          _res("Build and deploy pipelines",                        ["devops","admin"],                               80, True,  [8, 20], 600,  OFC, "SEG-CICD"),
    "crm":            _res("Customer accounts and sales pipeline",              ["sales","support","executive","admin"],          50, False, [7, 20], 1800, ANY, "SEG-CRM"),
    "finance-ledger": _res("General ledger, invoices and payments",             ["finance","executive","admin"],                  80, True,  [9, 18], 600,  OFC, "SEG-FIN"),
    "support-desk":   _res("Customer tickets and live chat queue",              ["support","security","admin"],                   40, False, [0, 24], 3600, ANY, "SEG-SUPPORT"),
    "legal-vault":    _res("Contracts, NDAs and compliance documents",          ["legal","executive","admin"],                    80, True,  [9, 18], 600,  OFC, "SEG-LEGAL"),
    "siem-console":   _res("Security alerts and incident response",             ["security","admin"],                             85, True,  [0, 24], 300,  OFC, "SEG-SEC"),
    "exec-reports":   _res("Board packs and company KPIs",                      ["executive","finance","admin"],                  75, True,  [8, 19], 600,  OFC, "SEG-EXEC"),
}
POLICY_KEYS = ("min_posture", "managed", "hours", "mfa_age")
POLICY_DEFAULTS = {r: {k: (list(v[k]) if isinstance(v[k], list) else v[k]) for k in POLICY_KEYS} for r, v in RESOURCES.items()}
SESSIONS, LOG, FAILS, USERFAIL, LASTLOC, NONCES, PROOF_NONCES, AUDIT_RATE = {}, deque(maxlen=500), {}, {}, {}, {}, {}, {}
# In-process GUI event bus: state changes wake desktop consoles immediately; DB refresh remains a safety net.
GUI_EVENTS = queue.Queue(maxsize=1000)
TEMP_RESOURCE_GRANTS = {}  # (username, resource) -> unix expiry
BLOCKED_DEVICES = set()
STEPUP_REQUIRED_USERS = set()

def publish_gui_event(kind, **payload):
    event = {"kind": str(kind), "ts": time.time(), **payload}
    try: GUI_EVENTS.put_nowait(event)
    except queue.Full:
        try: GUI_EVENTS.get_nowait()
        except queue.Empty: pass
        try: GUI_EVENTS.put_nowait(event)
        except queue.Full: pass

def set_device_blocked(device, blocked=True, actor="manager"):
    if blocked: BLOCKED_DEVICES.add(device)
    else: BLOCKED_DEVICES.discard(device)
    if blocked:
        with LOCK:
            sids = [sid for sid, sess in SESSIONS.items() if sess.get("device") == device]
            for sid in sids: SESSIONS.pop(sid, None)
        for sid in sids: db_exec("UPDATE sessions SET revoked=1 WHERE sid=?", (sid,))
    try: audit(user=actor, device=device, resource="device-control", decision="REVOKE" if blocked else "POLICY", reasons=["device blocked by manager" if blocked else "device unblocked by manager"])
    except (AuditFull, AuditTamper):
        if blocked: BLOCKED_DEVICES.discard(device)
        else: BLOCKED_DEVICES.add(device)
        raise
    publish_gui_event("device-control", device=device, blocked=blocked)
    return True
NONCE_HEAP=[]
PROOF_NONCE_HEAP=[]
PROOF_NONCE_LIMIT=1024
_NONCE_SCOPE_COUNTS={}
TELEMETRY_CACHE={"summary_ts":0.0,"alerts_ts":0.0,"summary":None,"alerts":None}
TELEMETRY_CACHE_LOCK=threading.RLock()

def _nonce_accept(store,heap,nonce,ttl,now,limit=1024,scope="global"):
    # Capacity is scoped to a session/device, so one authenticated principal
    # cannot exhaust a global nonce cache.
    key=(str(scope),str(nonce)); counter_key=(id(store),str(scope))
    while heap and heap[0][0]<=now:
        exp,k=heapq.heappop(heap)
        if store.get(k)==exp:
            store.pop(k,None)
            ck=(id(store),k[0]); remaining=max(0,_NONCE_SCOPE_COUNTS.get(ck,0)-1)
            if remaining: _NONCE_SCOPE_COUNTS[ck]=remaining
            else: _NONCE_SCOPE_COUNTS.pop(ck,None)
    if key in store: return False
    used=_NONCE_SCOPE_COUNTS.get(counter_key,0)
    if used>=limit: return False
    exp=now+ttl; store[key]=exp; _NONCE_SCOPE_COUNTS[counter_key]=used+1
    heapq.heappush(heap,(exp,key)); return True
LAT = {"policy_us": deque(maxlen=2000), "proxy_ms": deque(maxlen=2000)}
SIM = {"hour": None}
AUDIT = {"prev": "0" * 64, "fh": None, "entries": 0}

# Persistent telemetry database for the desktop SIEM-style dashboard.
def db_init():
    with sqlite3.connect(DB_FILE, timeout=5) as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS access_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user TEXT, device TEXT, resource TEXT, decision TEXT, risk INTEGER, reasons TEXT, signals TEXT);
        CREATE TABLE IF NOT EXISTS security_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, severity TEXT, kind TEXT, user TEXT, device TEXT, details TEXT, acknowledged INTEGER DEFAULT 0, ref TEXT);
        CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, user TEXT, device TEXT, location TEXT, created REAL, expires REAL, revoked INTEGER DEFAULT 0, mfa_at REAL);
        CREATE TABLE IF NOT EXISTS policy_changes (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, resource TEXT, policy_json TEXT);
        CREATE TABLE IF NOT EXISTS signin_requests (id TEXT PRIMARY KEY, ts REAL, user TEXT, device TEXT, location TEXT, status TEXT, decided_by TEXT, decided_at REAL, note TEXT, consumed INTEGER DEFAULT 0, closed_at REAL, closed_reason TEXT);
        CREATE TABLE IF NOT EXISTS access_exception_requests (id TEXT PRIMARY KEY, ts REAL, user TEXT, device TEXT, resource TEXT, reason TEXT, status TEXT, decided_by TEXT, decided_at REAL, expires_at REAL, closed_at REAL, closed_reason TEXT);
        CREATE INDEX IF NOT EXISTS idx_signin_status ON signin_requests(status, ts);
        CREATE INDEX IF NOT EXISTS idx_exception_status ON access_exception_requests(status, ts);
        CREATE INDEX IF NOT EXISTS idx_access_ts ON access_events(ts);
        CREATE INDEX IF NOT EXISTS idx_alert_ts ON security_alerts(ts);
        """)
        try: c.execute("ALTER TABLE sessions ADD COLUMN pop_key TEXT")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE sessions ADD COLUMN mfa_at REAL")
        except sqlite3.OperationalError: pass
        for col, typ in (("closed_at", "REAL"), ("closed_reason", "TEXT")):      # sign-in history: when/why a request ended
            try: c.execute(f"ALTER TABLE signin_requests ADD COLUMN {col} {typ}")
            except sqlite3.OperationalError: pass
        for col, typ in (("closed_at", "REAL"), ("closed_reason", "TEXT")):      # extra-access requests: same close-out tracking
            try: c.execute(f"ALTER TABLE access_exception_requests ADD COLUMN {col} {typ}")
            except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE security_alerts ADD COLUMN ref TEXT")        # links an alert to the request that caused it
        except sqlite3.OperationalError: pass
        c.execute("CREATE INDEX IF NOT EXISTS idx_alert_ref ON security_alerts(ref)")
        # One pending request per employee (and per employee+app) is an invariant the database now enforces itself, so two
        # simultaneous submissions cannot both win. Duplicates left behind by the old check-then-insert race are closed first.
        c.execute("UPDATE signin_requests SET status='cancelled', closed_at=?, closed_reason='duplicate pending request closed during upgrade' WHERE status='pending' AND rowid NOT IN (SELECT MAX(rowid) FROM signin_requests WHERE status='pending' GROUP BY user)", (time.time(),))
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_signin_one_pending ON signin_requests(user) WHERE status='pending'")
        c.execute("UPDATE access_exception_requests SET status='cancelled', closed_at=?, closed_reason='duplicate pending request closed during upgrade' WHERE status='pending' AND rowid NOT IN (SELECT MAX(rowid) FROM access_exception_requests WHERE status='pending' GROUP BY user, resource)", (time.time(),))
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_exception_one_pending ON access_exception_requests(user, resource) WHERE status='pending'")
    try:
        with sqlite3.connect(DB_FILE, timeout=5) as c:
            c.execute("DELETE FROM signin_requests WHERE status!='pending' AND ts < ?", (time.time()-_env_int("ZTNA_SIGNIN_HISTORY_DAYS", 90, 7, 3650)*86400,))
            c.execute("DELETE FROM access_exception_requests WHERE status!='pending' AND ts < ?", (time.time()-_env_int("ZTNA_SIGNIN_HISTORY_DAYS", 90, 7, 3650)*86400,))
            for user, resource, expires in c.execute("SELECT user,resource,expires_at FROM access_exception_requests WHERE status='approved' AND expires_at>?", (time.time(),)).fetchall():
                TEMP_RESOURCE_GRANTS[(user, resource)] = float(expires)
    except sqlite3.Error: pass
    prune_telemetry()
def _prune_sessions_for_login_locked(user, now):
    """Prune expired sessions and enforce per-user session caps; caller holds LOCK."""
    for old_sid,v in list(SESSIONS.items()):
        if v.get("exp",0)<=now or v.get("abs_exp",0)<=now:
            SESSIONS.pop(old_sid,None)
            db_exec_critical("UPDATE sessions SET revoked=1 WHERE sid=?",(old_sid,))
    own=sorted(((sid,v.get("created",0)) for sid,v in SESSIONS.items() if v.get("user")==user),key=lambda x:x[1])
    while len(own)>=max(1,MAX_SESSIONS_PER_USER):
        old_sid,_=own.pop(0)
        SESSIONS.pop(old_sid,None)
        db_exec_critical("UPDATE sessions SET revoked=1 WHERE sid=?",(old_sid,))


def _db_connection():
    c=getattr(DB_LOCAL,"conn",None)
    if c is not None and getattr(DB_LOCAL,"path",None)!=DB_FILE:
        # The database file changed (runtime initialised again on another data directory): never keep using the old one.
        try: c.close()
        except sqlite3.Error: pass
        c=None
    if c is None:
        c=sqlite3.connect(DB_FILE,timeout=5,check_same_thread=True)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=5000")
        DB_LOCAL.conn=c; DB_LOCAL.path=DB_FILE
    return c

def db_exec(sql,args=()):
    """BEST-EFFORT write for telemetry only (access events, alerts). Failures are logged and swallowed.
    Security state (sessions, revocation, policy history) must use db_exec_critical()."""
    try:
        c=_db_connection(); c.execute(sql,args); c.commit(); return True
    except sqlite3.Error as exc:
        logger.warning("telemetry database write failed: %s",exc); return False

class StateStoreError(RuntimeError):
    """A mandatory security-state write failed; callers must fail closed."""

def db_exec_critical(sql,args=()):
    """MANDATORY write: errors propagate as StateStoreError so the caller can refuse or roll back. Returns lastrowid."""
    try:
        c=_db_connection(); cur=c.execute(sql,args); c.commit(); return cur.lastrowid
    except sqlite3.Error as exc:
        try: _db_connection().rollback()
        except sqlite3.Error: pass
        logger.error("security-state database write failed: %s",exc)
        raise StateStoreError(str(exc)) from None
def db_access(user,device,resource,decision,risk,reasons,signals):
    db_exec("INSERT INTO access_events(ts,user,device,resource,decision,risk,reasons,signals) VALUES(?,?,?,?,?,?,?,?)",(time.time(),user,device,resource,decision,int(risk or 0),json.dumps(reasons),json.dumps(signals)))
def db_alert(severity,kind,user=None,device=None,details="",ref=None):
    """Store an alert. Returns the new alert id, or None if it could not be stored (nothing is announced in that case)."""
    # Serialize the insert and invalidation with cache misses so a reader cannot
    # publish a stale pre-insert snapshot after the invalidation.
    with TELEMETRY_CACHE_LOCK:
        try:
            c=_db_connection(); cur=c.execute("INSERT INTO security_alerts(ts,severity,kind,user,device,details,ref) VALUES(?,?,?,?,?,?,?)",(time.time(),severity,kind,user,device,details,ref)); c.commit(); aid=cur.lastrowid
        except sqlite3.Error as exc:
            logger.warning("alert could not be stored (%s): %s",kind,exc); return None
        # Hard retention cap independent of time-based cleanup: sustained alerting cannot grow the DB forever.
        db_exec("DELETE FROM security_alerts WHERE id NOT IN (SELECT id FROM security_alerts ORDER BY id DESC LIMIT 5000)")
        TELEMETRY_CACHE["alerts_ts"]=0.0
        TELEMETRY_CACHE["summary_ts"]=0.0
    publish_gui_event("alert-raised", severity=severity, alert_kind=kind, user=user, device=device)
    return aid

_ALERT_DEDUPE={}
_ALERT_GLOBAL=deque()
def db_alert_once(severity,kind,user=None,device=None,details="",window=60.0,key=None):
    """Insert an alert unless the same (kind,user) alert was raised within `window` seconds (prevents flooding the queue)."""
    now=time.time(); k=(kind,user,key)
    with TELEMETRY_CACHE_LOCK:
        if now-_ALERT_DEDUPE.get(k,0.0)<window: return False
        # Global flood guard: check before appending, so rejected attempts cannot grow this deque.
        while _ALERT_GLOBAL and now-_ALERT_GLOBAL[0]>60: _ALERT_GLOBAL.popleft()
        if len(_ALERT_GLOBAL)>=120: return False
        _ALERT_GLOBAL.append(now)
        _ALERT_DEDUPE[k]=now
        if len(_ALERT_DEDUPE)>2000:
            for kk,tt in sorted(_ALERT_DEDUPE.items(),key=lambda kv:kv[1])[:len(_ALERT_DEDUPE)-1500]: _ALERT_DEDUPE.pop(kk,None)
    if db_alert(severity,kind,user,device,details) is None:
        with TELEMETRY_CACHE_LOCK:                      # a failed insert must not use up the dedupe window or the flood budget
            _ALERT_DEDUPE.pop(k,None)
            if _ALERT_GLOBAL: _ALERT_GLOBAL.pop()
        return False
    return True

RECENT_DENIES={}   # user -> deque of recent DENY timestamps
def detect_alerts(kw):
    """Turn an audited access decision into security alerts. Plain denials stay in the audit log only;
    alerts are raised for attack-like patterns: segment/lateral-movement attempts, repeated denials, elevated risk."""
    try:
        decision=kw.get("decision"); user=kw.get("user"); dev=kw.get("device"); res=kw.get("resource")
        reasons=[str(x) for x in (kw.get("reasons") or [])]; risk=int(kw.get("risk",0) or 0)
        if decision=="DENY" and risk>=80:
            db_alert_once("HIGH","HIGH_RISK_ACCESS_DENIED",user,dev,"; ".join(reasons),window=30.0)
        elif decision in ("DENY","STEPUP") and risk>=60:
            db_alert_once("MEDIUM","ELEVATED_RISK_REQUEST",user,dev,f"{res}: risk {risk}; "+"; ".join(reasons),window=60.0)
        if decision=="DENY" and any(x.startswith("micro-segmentation") for x in reasons):
            db_alert_once("MEDIUM","SEGMENT_VIOLATION",user,dev,f"{user} tried to reach {res} ({SEGMENTS.get(res,'?')}), a segment closed to their role (possible lateral movement)",window=30.0,key=res)
        if decision=="DENY" and user:
            now=time.time(); q=RECENT_DENIES.setdefault(user,deque(maxlen=50)); q.append(now)
            n=sum(1 for t in q if now-t<120)
            if n>=5: db_alert_once("MEDIUM","REPEATED_DENIALS",user,dev,f"{n} denied requests in 2 minutes (last: {res})",window=120.0)
    except Exception as exc:
        logger.warning("alert detection failed: %s",exc)

def recent_alerts(limit=80):
    with TELEMETRY_CACHE_LOCK:
        now=time.time()
        cached=TELEMETRY_CACHE["alerts"]
        if cached is not None and now-TELEMETRY_CACHE["alerts_ts"]<1.0:
            return cached[:max(0,int(limit))]
        try:
            with closing(sqlite3.connect(DB_FILE,timeout=5)) as c:
                rows=c.execute("SELECT ts,severity,kind,user,device,details,acknowledged,id,ref FROM security_alerts ORDER BY id DESC LIMIT 500").fetchall()
            out=[dict(ts=x[0],severity=x[1],kind=x[2],user=x[3],device=x[4],details=x[5],acknowledged=bool(x[6]),status=int(x[6] or 0),id=x[7],ref=x[8]) for x in rows]
            TELEMETRY_CACHE["alerts"]=out; TELEMETRY_CACHE["alerts_ts"]=time.time()
            return out[:max(0,int(limit))]
        except sqlite3.Error: return []
def telemetry_summary():
    now=time.time()
    if TELEMETRY_CACHE["summary"] is not None and now-TELEMETRY_CACHE["summary_ts"]<1.0: return TELEMETRY_CACHE["summary"]
    try:
        with closing(sqlite3.connect(DB_FILE,timeout=5)) as c:
            a=c.execute("SELECT COUNT(*),SUM(decision='ALLOW'),SUM(decision='STEPUP'),SUM(decision='DENY'),AVG(risk) FROM access_events WHERE ts>?",(now-3600,)).fetchone(); n=c.execute("SELECT COUNT(*) FROM security_alerts WHERE ts>? AND acknowledged=0",(now-3600,)).fetchone()[0]
        out={"events":a[0] or 0,"allow":a[1] or 0,"stepup":a[2] or 0,"deny":a[3] or 0,"avg_risk":round(a[4] or 0,1),"alerts":n}; TELEMETRY_CACHE["summary"]=out; TELEMETRY_CACHE["summary_ts"]=now; return out
    except sqlite3.Error: return {"events":0,"allow":0,"stepup":0,"deny":0,"avg_risk":0,"alerts":0}
def prune_telemetry():
    days=max(1,int(os.environ.get("ZTNA_TELEMETRY_RETENTION_DAYS","30"))); cutoff=time.time()-days*86400
    try:
        c=_db_connection(); c.execute("DELETE FROM access_events WHERE ts<?",(cutoff,)); c.execute("DELETE FROM security_alerts WHERE ts<?",(cutoff,)); c.execute("DELETE FROM policy_changes WHERE ts<?",(cutoff,)); c.commit()
    except sqlite3.Error as exc: logger.warning("telemetry retention failed: %s",exc)

def acknowledge_alerts(ids=None, status=1, include_high=True):
    """Mark alerts handled. status: 1 reviewed, 2 false alarm, 3 incident confirmed. ids=None means every open alert;
    include_high=False leaves HIGH-severity alerts open (they need an individual decision)."""
    sql="UPDATE security_alerts SET acknowledged=? WHERE acknowledged=0"; args=[int(status)]
    if ids is not None:
        ids=[int(i) for i in ids]
        if not ids: return
        sql+=" AND id IN (%s)"%",".join("?"*len(ids)); args+=ids
    if not include_high: sql+=" AND severity NOT IN ('HIGH','CRITICAL')"
    db_exec(sql,tuple(args))
    TELEMETRY_CACHE["alerts_ts"]=0.0
    TELEMETRY_CACHE["summary_ts"]=0.0

ALERT_STATUS = {0: "Needs a decision", 1: "Reviewed", 2: "False alarm", 3: "Incident confirmed"}
ALERT_INFO = {
    "EXTRA_ACCESS_REQUEST": ("Employee asked for access beyond their role",
        "An employee requested temporary access to an application their role does not include. Nothing is granted until a manager approves it.",
        "Open 'App exceptions' and read the reason. Approve only for a real, current task (the shortest time that works); otherwise deny. Your decision closes this alert automatically."),
    "EXTRA_ACCESS_PATTERN": ("Employee keeps asking for extra access",
        "The same employee asked for temporary access to three or more different applications within an hour. Genuine needs are usually one app at a time.",
        "Speak to the employee before approving anything further. If it looks like probing, use 'Confirm incident'."),
    "BRUTE_FORCE_SUSPECTED": ("Possible password guessing",
        "Several failed sign-ins for this account in a short time. Either someone is guessing the password, or the user keeps mistyping it.",
        "Ask the user. If it was them: 'False alarm'. If not: 'Confirm incident' (signs them out everywhere), then reset their password and authenticator."),
    "SEGMENT_VIOLATION": ("Blocked attempt to enter a closed network segment",
        "A user asked for a system in a micro-segment their role is not allowed to reach. This is what lateral movement looks like.",
        "Check Audit & Integrity. 'Reviewed' if it was a mis-click; 'Confirm incident' if the user has no reason to touch that system."),
    "REPEATED_DENIALS": ("Many denied requests in a row",
        "The same user was refused five or more times within two minutes, which looks like probing for something they can reach.",
        "Ask the user what they were doing. 'False alarm' if it was testing; 'Confirm incident' to sign them out."),
    "ELEVATED_RISK_REQUEST": ("Risky request was stopped or challenged",
        "A request scored 60-79 on the risk scale (weak device, unusual place, failed logins, request bursts) and was denied or needed extra verification.",
        "Open Audit & Integrity to see the signals, then choose an outcome."),
    "IMPOSSIBLE_TRAVEL": ("Sign-in from a new location within minutes",
        "The same account signed in from two different locations less than five minutes apart.",
        "Confirm with the user. 'Confirm incident' signs them out everywhere."),
    "HIGH_RISK_ACCESS_DENIED": ("Very risky request was blocked",
        "A request scored 80 or more on the risk scale (weak device, unusual location, repeated failed logins, request bursts...). It was already stopped.",
        "Open Audit & Integrity to see the reasons. 'Reviewed' if you have looked at it; 'Confirm incident' if the user did not do this."),
}
def describe_alert(a):
    title, why, advice = ALERT_INFO.get(a.get("kind"), (str(a.get("kind", "alert")).replace("_", " ").title(), str(a.get("details", "")), "Review it, then choose an outcome."))
    return title, why, advice

def revoke_user_sessions_report(user):
    """Sign a user out everywhere. -> (sessions ended, error or None). Live sessions are always ended in memory; the error
    says the revocation could NOT be written to the database (the gateway reads that flag), so the caller can warn."""
    with LOCK:
        sids=[k for k,v in SESSIONS.items() if v.get("user")==user]
        for k in sids: SESSIONS.pop(k,None)
    try: db_exec_critical("UPDATE sessions SET revoked=1 WHERE user=?",(user,))
    except StateStoreError as exc: return len(sids), str(exc)
    return len(sids), None

def revoke_user_sessions(user):
    """Sign a user out everywhere (used when an incident is confirmed). Returns the number of sessions ended."""
    n,_err=revoke_user_sessions_report(user)
    return n

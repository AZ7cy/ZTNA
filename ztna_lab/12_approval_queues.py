# Part 12 of ztna_lab_v2.py - sign-in approval queue and temporary application exceptions.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

SIGNIN_REQUEST_TTL = 600     # seconds a request may wait for a manager
SIGNIN_APPROVAL_TTL = 300    # seconds an approval stays usable

def _signin_write(sql, args=()):
    try:
        c=_db_connection(); cur=c.execute(sql,args); c.commit(); return cur.rowcount
    except sqlite3.Error as exc:
        try: _db_connection().rollback()
        except sqlite3.Error: pass
        logger.error("sign-in request database write failed: %s",exc)
        raise StateStoreError(str(exc)) from None

def _state_read(sql, args=()):
    """Read that reports database trouble as StateStoreError (callers already handle it), never a raw sqlite3 error."""
    try: return _db_connection().execute(sql,args).fetchall()
    except sqlite3.Error as exc:
        try: _db_connection().rollback()
        except sqlite3.Error: pass
        logger.error("state database read failed: %s",exc)
        raise StateStoreError(str(exc)) from None

_SIGNIN_LOCK=threading.Lock()
_SIGNIN_COLS = ("id","ts","user","device","location","status","decided_by","decided_at","note","consumed","closed_at","closed_reason")

def _signin_closed_audit(user, device, reason):
    """Close-out entry so the audit chain never leaves a request looking PENDING forever. Closing is always safe, so an
    unavailable audit log is reported but never stops a request from closing (a stale approval must not stay usable)."""
    try: audit(user=user,device=device,resource="signin-request",decision="REVOKE",reasons=[reason])
    except (AuditFull,AuditTamper) as exc: logger.error("sign-in close-out could not be audited: %s",exc)

def _expire_signin_requests():
    now=time.time()
    for rid,user,device,ts in _state_read("SELECT id,user,device,ts FROM signin_requests WHERE status='pending' AND ts<?",(now-SIGNIN_REQUEST_TTL,)):
        why=f"no manager response within {SIGNIN_REQUEST_TTL//60} minutes"          # closed_at is when it really lapsed, not when we noticed
        if _signin_write("UPDATE signin_requests SET status='expired',closed_at=?,closed_reason=? WHERE id=? AND status='pending'",(ts+SIGNIN_REQUEST_TTL,why,rid))==1:
            _signin_closed_audit(user,device,f"sign-in request expired: {why}")
    for rid,user,device,by,at in _state_read("SELECT id,user,device,decided_by,decided_at FROM signin_requests WHERE status='approved' AND consumed=0 AND decided_at<?",(now-SIGNIN_APPROVAL_TTL,)):
        why=f"approval by {by} was not used within {SIGNIN_APPROVAL_TTL//60} minutes"
        if _signin_write("UPDATE signin_requests SET status='expired',closed_at=?,closed_reason=? WHERE id=? AND status='approved' AND consumed=0",(at+SIGNIN_APPROVAL_TTL,why,rid))==1:
            _signin_closed_audit(user,device,f"sign-in approval expired unused: {why}")

def create_signin_request(user, device, location):
    rid=secrets.token_hex(6); why="replaced by a newer sign-in request"; replaced=[]
    with _SIGNIN_LOCK:
        for attempt in range(6):
            now=time.time()
            older=_state_read("SELECT id,device FROM signin_requests WHERE user=? AND status='pending'",(user,))
            replaced+=[(o,d) for o,d in older if _signin_write("UPDATE signin_requests SET status='cancelled',closed_at=?,closed_reason=? WHERE id=? AND status='pending'",(now,why,o))==1]
            try: _signin_write("INSERT INTO signin_requests(id,ts,user,device,location,status) VALUES(?,?,?,?,?,'pending')",(rid,now,user,device,location)); break
            except StateStoreError as exc:
                if "UNIQUE" not in str(exc) or attempt==5: raise     # another process inserted first: replace that one too
    try:
        audit(user=user,device=device,resource="signin-request",decision="PENDING",reasons=["employee sign-in awaiting manager approval"])
    except (AuditFull,AuditTamper):
        _signin_write("UPDATE signin_requests SET status='cancelled',closed_at=?,closed_reason=? WHERE id=?",(time.time(),"request could not be recorded in the audit log",rid)); raise
    for _o,d in replaced: _signin_closed_audit(user,d,f"sign-in request superseded: {why}")
    publish_gui_event("signin-created", request_id=rid, user=user, device=device)
    return rid

def get_signin_request(rid):
    _expire_signin_requests()
    r=_state_read("SELECT %s FROM signin_requests WHERE id=?"%",".join(_SIGNIN_COLS),(rid,))
    return dict(zip(_SIGNIN_COLS,r[0])) if r else None

def list_signin_requests(limit=100, status=None):
    """Newest first with pending on top. status: None = all, 'pending', or 'history' (everything already closed or decided)."""
    _expire_signin_requests()
    where={"pending":"WHERE status='pending'","history":"WHERE status!='pending'"}.get(status,"")
    rows=_state_read("SELECT %s FROM signin_requests %s ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, ts DESC LIMIT ?"%(",".join(_SIGNIN_COLS),where),(int(limit),))
    return [dict(zip(_SIGNIN_COLS,r)) for r in rows]

def count_pending_signins():
    _expire_signin_requests()
    return _state_read("SELECT COUNT(*) FROM signin_requests WHERE status='pending'")[0][0]

def signin_outcome(r):
    """One plain-language line describing how a sign-in request ended (or where it stands)."""
    st, by, why = r.get("status"), r.get("decided_by") or "a manager", r.get("closed_reason") or ""
    if st == "pending": return "Waiting for a manager"
    if st == "approved": return "Approved - session opened" if r.get("consumed") else "Approved - waiting for the employee to finish signing in"
    if st == "denied": return f"Denied by {by}"
    if st == "expired": return f"Approved by {by}, but not used (expired)" if r.get("decided_by") else "No manager response (expired)"
    if st == "cancelled": return why[:1].upper() + why[1:] if why else "Cancelled"
    return str(st or "").title()

def cancel_signin_request(rid):
    found=_state_read("SELECT user,device FROM signin_requests WHERE id=? AND status='pending'",(rid,)); row=found[0] if found else None
    changed = _signin_write("UPDATE signin_requests SET status='cancelled',closed_at=?,closed_reason=? WHERE id=? AND status='pending'",(time.time(),"cancelled by the employee",rid))==1
    if changed:
        if row: _signin_closed_audit(row[0],row[1],"sign-in request cancelled by the employee")
        publish_gui_event("signin-cancelled", request_id=rid)
    return changed

def claim_signin_request(rid):
    now=time.time()
    return _signin_write("UPDATE signin_requests SET consumed=1,closed_at=?,closed_reason='approval used: session opened' WHERE id=? AND status='approved' AND consumed=0 AND decided_at>=?",(now,rid,now-SIGNIN_APPROVAL_TTL))==1

def release_signin_claim(rid):
    """Undo claim_signin_request() when no session could be opened after all, so the record does not claim a session
    that never existed and the employee can retry while the approval is still valid."""
    return _signin_write("UPDATE signin_requests SET consumed=0,closed_at=NULL,closed_reason=NULL WHERE id=? AND status='approved' AND consumed=1",(rid,))==1

def decide_signin_request(rid, approve, manager, note=""):
    """Manager decision. Returns the request row, or None if it was no longer pending. Audited; reverts if audit fails."""
    status="approved" if approve else "denied"; now=time.time()
    # A request past its lifetime is closed as expired (and audited), not approved late: the manager's list may be
    # up to a refresh old, and an approval given after the 10 minutes used to open a session.
    _expire_signin_requests()
    if _signin_write("UPDATE signin_requests SET status=?,decided_by=?,decided_at=?,note=?,closed_at=?,closed_reason=? WHERE id=? AND status='pending' AND ts>=?",
                     (status,manager,now,(note or "")[:200],None if approve else now,None if approve else "denied by manager",rid,now-SIGNIN_REQUEST_TTL))!=1:
        return None
    row=get_signin_request(rid)
    try:
        audit(user=row["user"],device=row["device"],resource="signin-request",decision="ALLOW" if approve else "DENY",
              reasons=[f"sign-in {status} by manager {manager}"]+([f"note: {note[:200]}"] if note else []))
    except (AuditFull,AuditTamper):
        _signin_write("UPDATE signin_requests SET status='pending',decided_by=NULL,decided_at=NULL,closed_at=NULL,closed_reason=NULL WHERE id=?",(rid,)); raise
    publish_gui_event("signin-decided", request_id=rid, status=status, user=row.get("user"), device=row.get("device"))
    return row

EXTRA_ACCESS_PREFIX="temporary application exception"
_EXC_LOCK=threading.Lock()
_EXC_COLS=("id","ts","user","device","resource","reason","status","decided_by","decided_at","expires_at","closed_at","closed_reason")

def _is_exception_record(kw):
    """True for audit entries that record a request for / decision on extra access. They name an application, but they are
    manager workflow, not access attempts: they must not feed access telemetry or the attack-detection rules."""
    rs=kw.get("reasons") or []
    return bool(rs) and str(rs[0]).startswith(EXTRA_ACCESS_PREFIX)

def _exception_ttl(): return _env_int("ZTNA_EXCEPTION_REQUEST_TTL",86400,60,30*86400)

def _exception_write(sql, args=()):
    try:
        c=_db_connection(); cur=c.execute(sql,args); c.commit(); return cur.rowcount
    except sqlite3.Error as exc:
        try: _db_connection().rollback()
        except sqlite3.Error: pass
        logger.error("access-exception database write failed: %s",exc)
        raise StateStoreError(str(exc)) from None

def _exception_closed_audit(user, device, resource, reason):
    try: audit(user=user,device=device,resource=resource,decision="REVOKE",reasons=[reason])
    except (AuditFull,AuditTamper) as exc: logger.error("access-exception close-out could not be audited: %s",exc)

def _note_alert(ref, note, resolve=True):
    """Keep the alert tied to a request in step with it: append what happened and (resolve=True) mark it handled."""
    if resolve: ok=db_exec("UPDATE security_alerts SET acknowledged=1, details=substr(details || ' | ' || ?,1,600) WHERE ref=? AND acknowledged=0",(note,ref))
    else: ok=db_exec("UPDATE security_alerts SET details=substr(details || ' | ' || ?,1,600) WHERE ref=?",(note,ref))
    with TELEMETRY_CACHE_LOCK:
        TELEMETRY_CACHE["alerts_ts"]=0.0; TELEMETRY_CACHE["summary_ts"]=0.0
    if ok: publish_gui_event("alert-updated", ref=ref)

def _extra_access_profile(device, resource):
    """-> (severity, risk flags, device score, managed). Higher scrutiny for sensitive apps and weak or unmanaged devices."""
    managed=bool(DEVICES.get(device,{}).get("corporate_managed")); score=posture(device) if device in DEVICES else 0
    flags=[]
    if RESOURCES[resource]["min_posture"]>=80: flags.append("sensitive application")
    if not managed: flags.append("unmanaged device")
    if score<70: flags.append(f"weak device health ({score}/100)")
    return ("HIGH" if flags else "MEDIUM"), flags, score, managed

def _raise_extra_access_alerts(rid, user, device, resource, reason):
    severity, flags, score, managed = _extra_access_profile(device, resource)
    name=_person(user)[0] if "_person" in globals() else user; role=USERS.get(user,{}).get("role","?")
    details=(f"{name} ({role}) asked for temporary access to {resource}: \"{reason}\". Device {device}: health {score}/100, "
             f"{'company-managed' if managed else 'not company-managed'}." + (f" Flags: {', '.join(flags)}." if flags else "") + f" Request {rid}.")
    if db_alert(severity,"EXTRA_ACCESS_REQUEST",user,device,details,ref=rid) is None:
        logger.error("extra-access alert for request %s could not be stored",rid)
    try:
        asked=_state_read("SELECT DISTINCT resource FROM access_exception_requests WHERE user=? AND ts>?",(user,time.time()-3600))
        if len(asked)>=3:
            db_alert_once("HIGH","EXTRA_ACCESS_PATTERN",user,device,f"{name} asked for temporary access to {len(asked)} different applications within an hour: {', '.join(sorted(r[0] for r in asked))}. Possible privilege probing.",window=3600.0)
    except StateStoreError: pass

def _expire_access_exceptions():
    """Close requests nobody answered, and end approved access whose time has run out, each with an audit entry."""
    now=time.time(); ttl=_exception_ttl()
    for rid,user,device,resource,ts in _state_read("SELECT id,user,device,resource,ts FROM access_exception_requests WHERE status='pending' AND ts<?",(now-ttl,)):
        why=f"no manager response within {ttl//3600 if ttl>=3600 else ttl//60} {'hours' if ttl>=3600 else 'minutes'}"
        if _exception_write("UPDATE access_exception_requests SET status='expired',closed_at=?,closed_reason=? WHERE id=? AND status='pending'",(ts+ttl,why,rid))==1:
            _exception_closed_audit(user,device,resource,f"{EXTRA_ACCESS_PREFIX} request expired: {why}")
            _note_alert(rid,"request expired unanswered")
    for rid,user,device,resource,by,exp in _state_read("SELECT id,user,device,resource,decided_by,expires_at FROM access_exception_requests WHERE status='approved' AND expires_at<?",(now,)):
        if _exception_write("UPDATE access_exception_requests SET status='expired',closed_at=?,closed_reason='temporary access ended' WHERE id=? AND status='approved'",(exp,rid))==1:
            with LOCK:
                if TEMP_RESOURCE_GRANTS.get((user,resource),0)<=now: TEMP_RESOURCE_GRANTS.pop((user,resource),None)
            _exception_closed_audit(user,device,resource,f"{EXTRA_ACCESS_PREFIX} ended: access approved by {by} has run out")
            _note_alert(rid,f"access ended {_fmt_ts(exp)}",resolve=False)

def create_access_exception_request(user, device, resource, reason):
    if user not in USERS or device not in DEVICES or DEVICES[device].get("owner") != user or resource not in RESOURCES:
        raise ValueError("unknown identity, device, or application")
    if rbac_allows(user, resource) and segment_allows(user, resource):
        raise ValueError("you already have temporary access to this application" if _temporary_resource_grant(user, resource) else "this application is already assigned to your role")
    why=(str(reason or "").strip() or "business need")[:240]; rid=secrets.token_hex(6)
    with _EXC_LOCK:                       # in-process serialisation; the unique index covers other processes
        found=_state_read("SELECT id FROM access_exception_requests WHERE user=? AND resource=? AND status='pending'",(user,resource))
        if found: return found[0][0]
        try: _exception_write("INSERT INTO access_exception_requests(id,ts,user,device,resource,reason,status) VALUES(?,?,?,?,?,?,'pending')",(rid,time.time(),user,device,resource,why))
        except StateStoreError as exc:
            if "UNIQUE" in str(exc):
                found=_state_read("SELECT id FROM access_exception_requests WHERE user=? AND resource=? AND status='pending'",(user,resource))
                if found: return found[0][0]
            raise
    try: audit(user=user, device=device, resource=resource, decision="PENDING", reasons=[f"{EXTRA_ACCESS_PREFIX} requested", why])
    except (AuditFull, AuditTamper):
        try: _exception_write("DELETE FROM access_exception_requests WHERE id=?",(rid,))
        except StateStoreError: pass
        raise
    _raise_extra_access_alerts(rid,user,device,resource,why)
    publish_gui_event("exception-created", request_id=rid, user=user, resource=resource)
    return rid

def list_access_exception_requests(limit=200):
    """Newest first, pending on top. Each row carries alert_status (None = no alert, 0 = needs a decision, 1-3 = handled)."""
    _expire_access_exceptions()
    rows=_state_read("SELECT %s FROM access_exception_requests ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, ts DESC LIMIT ?"%",".join(_EXC_COLS),(int(limit),))
    out=[dict(zip(_EXC_COLS,r)) for r in rows]
    states={}
    try:
        ids=[r["id"] for r in out]
        for i in range(0,len(ids),400):
            chunk=ids[i:i+400]
            for ref,ack in _state_read("SELECT ref,acknowledged FROM security_alerts WHERE kind='EXTRA_ACCESS_REQUEST' AND ref IN (%s)"%",".join("?"*len(chunk)),tuple(chunk)): states[ref]=int(ack or 0)
    except StateStoreError: pass
    for r in out: r["alert_status"]=states.get(r["id"])
    return out

def exception_outcome(r):
    st,by,why=r.get("status"),r.get("decided_by") or "a manager",r.get("closed_reason") or ""
    if st=="pending": return "Waiting for a manager"
    if st=="approved": return f"Approved by {by} until {_fmt_ts(r['expires_at'],'%H:%M')}" if r.get("expires_at") else f"Approved by {by}"
    if st=="denied": return f"Denied by {by}"
    if st=="expired": return f"Approved by {by}; access has ended" if r.get("decided_by") else "No manager response (expired)"
    if st=="cancelled": return why[:1].upper()+why[1:] if why else "Cancelled"
    return str(st or "").title()

def decide_access_exception_request(rid, approve, manager, duration_seconds=3600):
    _expire_access_exceptions()
    found=_state_read("SELECT %s FROM access_exception_requests WHERE id=?"%",".join(_EXC_COLS),(rid,))
    row=dict(zip(_EXC_COLS,found[0])) if found else None
    if not row or row["status"] != "pending": return None
    now = time.time(); status = "approved" if approve else "denied"; expiry = now + max(60, min(int(duration_seconds), 8*3600)) if approve else None
    if _exception_write("UPDATE access_exception_requests SET status=?,decided_by=?,decided_at=?,expires_at=?,closed_at=?,closed_reason=? WHERE id=? AND status='pending'",
                        (status, manager, now, expiry, None if approve else now, None if approve else "denied by manager", rid)) != 1: return None
    try:
        audit(user=row["user"], device=row["device"], resource=row["resource"], decision="ALLOW" if approve else "DENY",
              reasons=[f"{EXTRA_ACCESS_PREFIX} {status} by {manager}"] + ([f"expires at {_fmt_ts(expiry)}"] if expiry else []))
    except (AuditFull, AuditTamper):
        try: _exception_write("UPDATE access_exception_requests SET status='pending',decided_by=NULL,decided_at=NULL,expires_at=NULL,closed_at=NULL,closed_reason=NULL WHERE id=?",(rid,))
        except StateStoreError: pass
        raise
    if approve:                                         # the grant only exists once the approval is durably recorded
        with LOCK: TEMP_RESOURCE_GRANTS[(row["user"], row["resource"])] = expiry
    _note_alert(rid, f"approved by {manager} until {_fmt_ts(expiry,'%H:%M')}" if approve else f"denied by {manager}")
    publish_gui_event("exception-decided", request_id=rid, status=status, user=row["user"], resource=row["resource"])
    return row

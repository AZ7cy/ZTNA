# Part 19 of ztna_lab_v2.py - built-in self-test (python ztna_lab_v2.py selftest).
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

def selftest():
    """Focused regression checks without mutating live security or telemetry state."""
    global _RUNTIME_MODE, DEMO, DATA_DIR, AUDIT_FILE, AUDIT_ANCHOR_FILE, AUDIT_EXTERNAL_ANCHOR_FILE, AUDIT_ANCHOR_KEY
    global ENTERPRISE_DB_URL, enterprise_engine, EnterpriseSession, ENTERPRISE_RATE_PRUNE_LAST, AUTH_PRUNE_LAST
    import tempfile, shutil
    results=[]
    old_mode=_RUNTIME_MODE
    old_last=dict(LAST_TOTP)
    old_fails=dict(FAILS)
    old_userfail={k:deque(v, maxlen=v.maxlen) for k,v in USERFAIL.items()}
    old_lastloc=dict(LASTLOC)
    old_nonces=type(NONCES)(NONCES)
    old_proof_nonces=type(PROOF_NONCES)(PROOF_NONCES)
    old_heap=list(NONCE_HEAP)
    old_proof_heap=list(PROOF_NONCE_HEAP)
    old_scope_counts=dict(_NONCE_SCOPE_COUNTS)
    old_auth_prune_last=AUTH_PRUNE_LAST
    old_sessions=dict(SESSIONS)
    old_telemetry_cache=dict(TELEMETRY_CACHE)
    old_db_file=DB_FILE
    old_db_conn_present=hasattr(DB_LOCAL, "conn")
    old_db_conn=getattr(DB_LOCAL, "conn", None)
    selftest_db_dir=tempfile.mkdtemp(prefix="ztna-selftest-db-")
    try:
        # Database-writing tests, including alert-cache refresh and eviction tests,
        # run against an isolated DB even when selftest() is called in-process.
        globals()["DB_FILE"]=os.path.join(selftest_db_dir,"selftest.sqlite3")
        DB_LOCAL.conn=None
        with TELEMETRY_CACHE_LOCK:
            TELEMETRY_CACHE["alerts"]=None; TELEMETRY_CACHE["summary"]=None
            TELEMETRY_CACHE["alerts_ts"]=0.0; TELEMETRY_CACHE["summary_ts"]=0.0
        db_init()
        # H2: exercise the real verifier in a client mode and confirm it does not persist.
        if USERS:
            before=Path(TOTP_STATE_FILE).read_bytes() if os.path.exists(TOTP_STATE_FILE) else None
            _RUNTIME_MODE="attack"
            u=next(iter(USERS)); secret=USERS[u]["totp"]; nowctr=int(time.time())//30
            sentinel=object(); saved_counter=LAST_TOTP.get(u,sentinel)
            try:
                # Isolate the verifier from persisted replay history, while explicitly
                # disabling persistence as client modes must do.
                LAST_TOTP[u]=nowctr-2
                candidate=totp(secret,(nowctr-1)*30)
                passed=totp_ok(u,secret,candidate,consume=True,persist=False)
                after=Path(TOTP_STATE_FILE).read_bytes() if os.path.exists(TOTP_STATE_FILE) else None
                results.append(("H2",passed and before==after))
            finally:
                if saved_counter is sentinel: LAST_TOTP.pop(u,None)
                else: LAST_TOTP[u]=saved_counter
        else:
            results.append(("H2",None))
        # H3: generated demo OTP must match one of the server's accepted future/current windows.
        if DEMO and USERS:
            u=next(iter(USERS)); prior=LAST_TOTP.get(u,-1); LAST_TOTP[u]=int(time.time())//30-1
            c=demo_totp_code(u); nowctr=int(time.time())//30
            ok=c is not None and any(c==totp(USERS[u]["totp"],(nowctr+w)*30) for w in (-1,0,1))
            results.append(("H3",ok)); LAST_TOTP[u]=prior
        else:
            results.append(("H3",None))
        # H5: independent source addresses should not globally lock the user;
        # a fifth failed attempt must hard-block only that source/user pair.
        FAILS.clear()
        pair_a=reserve_auth_attempt("alice","198.51.100.10")
        pair_b=reserve_auth_attempt("alice","203.0.113.20")
        k=fkey("alice","198.51.100.10"); FAILS[k]=(5,time.time()+60,time.time()); note_fail("alice","198.51.100.10")
        hard_block=not reserve_auth_attempt("alice","198.51.100.10")
        release_auth_attempt("alice","203.0.113.20")
        other_ip=reserve_auth_attempt("alice","203.0.113.20")
        # Inactivity decay must clear an old pair and allow a new attempt.
        FAILS[k]=(6, time.time()+60, time.time()-601)
        decayed=reserve_auth_attempt("alice","198.51.100.10")
        results.append(("H5",pair_a and pair_b and hard_block and other_ip and decayed))
        # H6: enforce per-scope capacity, isolation, expiry and >32 requests/session.
        NONCES.clear(); NONCE_HEAP.clear(); _NONCE_SCOPE_COUNTS.clear()
        now=time.time()
        many=all(_nonce_accept(NONCES,NONCE_HEAP,f"many-{i}",75,now,limit=1024,scope="large-session") for i in range(40))
        ok=all(_nonce_accept(NONCES,NONCE_HEAP,f"n{i}",75,now,limit=2,scope="a") for i in range(2))
        blocked=not _nonce_accept(NONCES,NONCE_HEAP,"n2",75,now,limit=2,scope="a")
        other=_nonce_accept(NONCES,NONCE_HEAP,"n0",75,now,limit=2,scope="b")
        exp1=_nonce_accept(NONCES,NONCE_HEAP,"expiry-1",1,now,limit=1,scope="expiry")
        exp2=_nonce_accept(NONCES,NONCE_HEAP,"expiry-2",1,now+2,limit=1,scope="expiry")
        results.append(("H6",many and ok and blocked and other and exp1 and exp2 and PROOF_NONCE_LIMIT>32))
        # Scope counters must disappear after all entries in that scope expire.
        only=_nonce_accept(NONCES,NONCE_HEAP,"scope-zero",1,now,limit=1,scope="zero-after-expiry")
        _nonce_accept(NONCES,NONCE_HEAP,"trigger-expiry",1,now+2,limit=1,scope="other-scope")
        counter_removed=(id(NONCES),"zero-after-expiry") not in _NONCE_SCOPE_COUNTS
        results.append(("NONCE_COUNTER_CLEANUP",only and counter_removed))
        NONCES.clear(); NONCE_HEAP.clear(); _NONCE_SCOPE_COUNTS.clear()
        # Enterprise device IDs must treat missing/empty as absent and reject, not truncate, oversized IDs.
        if FASTAPI_AVAILABLE:
            try:
                missing_ok=enterprise_device_id(None) is None and enterprise_device_id("") is None
                try: enterprise_device_id("a"*65); too_long=False
                except HTTPException as exc: too_long=getattr(exc,"status_code",None)==400
                results.append(("ENTERPRISE_DEVICE_ID",missing_ok and too_long))
            except Exception: results.append(("ENTERPRISE_DEVICE_ID",False))
        else: results.append(("ENTERPRISE_DEVICE_ID",None))
        # Session eviction must revoke the database row, not merely drop memory state.
        eviction_ok=None
        if _RUNTIME_READY and os.path.exists(DB_FILE) and USERS:
            old_max=MAX_SESSIONS_PER_USER; sentinel=secrets.token_hex(12); now_test=time.time()
            old_session=SESSIONS.pop(sentinel,None)
            try:
                globals()["MAX_SESSIONS_PER_USER"]=1
                salt=_new_session_salt()
                SESSIONS[sentinel]={"user":"alice","device":"laptop-alice","location":"office","exp":now_test+600,"abs_exp":now_test+600,"created":now_test-10,"mfa_at":now_test,"key":b"test-key"}
                db_exec("INSERT OR REPLACE INTO sessions(sid,user,device,location,created,expires,revoked,pop_key,mfa_at) VALUES(?,?,?,?,?,?,0,?,?)",(sentinel,"alice","laptop-alice","office",now_test-10,now_test+600,salt,now_test))
                with LOCK: _prune_sessions_for_login_locked("alice",now_test)
                with closing(sqlite3.connect(DB_FILE,timeout=5)) as c:
                    row=c.execute("SELECT revoked FROM sessions WHERE sid=?",(sentinel,)).fetchone()
                eviction_ok=sentinel not in SESSIONS and bool(row and row[0]==1)
            finally:
                SESSIONS.pop(sentinel,None); db_exec("DELETE FROM sessions WHERE sid=?",(sentinel,)); globals()["MAX_SESSIONS_PER_USER"]=old_max
                if old_session is not None: SESSIONS[sentinel]=old_session
        results.append(("SESSION_EVICTION_REVOKES_DB",eviction_ok))
        # Desktop adapter expiration must mark the persistent session row revoked.
        desktop_expiry_ok=None
        if _RUNTIME_READY and os.path.exists(DB_FILE) and USERS:
            expired_sid=secrets.token_hex(12); now_exp=time.time(); salt=_new_session_salt()
            expired_session={"user":"alice","device":"laptop-alice","location":"office",
                             "exp":now_exp-1,"abs_exp":now_exp-1,"created":now_exp-120,
                             "mfa_at":now_exp-120,"key":b"selftest-expired-session-key"}
            try:
                SESSIONS[expired_sid]=expired_session
                db_exec("INSERT OR REPLACE INTO sessions(sid,user,device,location,created,expires,revoked,pop_key,mfa_at) VALUES(?,?,?,?,?,?,0,?,?)",
                        (expired_sid,"alice","laptop-alice","office",now_exp-120,now_exp-1,salt,now_exp-120))
                desktop=DesktopZTNA(); desktop.session=(expired_sid,expired_session)
                outcome=desktop.access("wiki")
                with closing(sqlite3.connect(DB_FILE,timeout=5)) as c:
                    row=c.execute("SELECT revoked FROM sessions WHERE sid=?",(expired_sid,)).fetchone()
                desktop_expiry_ok=(outcome.get("error")=="session expired" and expired_sid not in SESSIONS and bool(row and row[0]==1))
            finally:
                SESSIONS.pop(expired_sid,None); db_exec("DELETE FROM sessions WHERE sid=?",(expired_sid,))
        results.append(("DESKTOP_EXPIRED_SESSION_REVOKED_DB",desktop_expiry_ok))
        # Run crash-window tests in a separate temporary audit directory, never against live audit state.
        crash_ok=False; tamper_ok=False
        try:
            td=tempfile.mkdtemp(prefix="ztna-audit-selftest-")
            old_paths=(DATA_DIR,AUDIT_FILE,AUDIT_ANCHOR_FILE,AUDIT_EXTERNAL_ANCHOR_FILE,AUDIT_ANCHOR_KEY,DEMO,dict(AUDIT),list(LOG))
            try:
                globals()["DATA_DIR"]=td; globals()["AUDIT_FILE"]=os.path.join(td,"audit.jsonl"); globals()["AUDIT_ANCHOR_FILE"]=os.path.join(td,"audit.anchor"); globals()["AUDIT_EXTERNAL_ANCHOR_FILE"]=os.path.join(td,"audit.monotonic"); globals()["AUDIT_ANCHOR_KEY"]=b"selftest-audit-key-material-32bytes"; globals()["DEMO"]=False
                # Keep the caller's audit file handle open; the copied audit dict
                # below is restored after this isolated test.
                AUDIT.clear(); AUDIT.update({"prev":"0"*64,"fh":None,"entries":0,"size":0}); LOG.clear()
                audit(user="selftest",device=None,resource="login",decision="ALLOW",reasons=["event 1"])
                audit(user="selftest",device=None,resource="login",decision="ALLOW",reasons=["event 2"])
                old_local=Path(AUDIT_ANCHOR_FILE).read_bytes(); old_external=Path(AUDIT_EXTERNAL_ANCHOR_FILE).read_bytes()
                audit(user="selftest",device=None,resource="login",decision="ALLOW",reasons=["event 3"])
                full_log=Path(AUDIT_FILE).read_bytes(); lines=full_log.splitlines(keepends=True)
                # local checkpoint exactly one behind
                Path(AUDIT_ANCHOR_FILE).write_bytes(old_local)
                local_repaired=(not verify_chain()["ok"])
                resume_chain(); local_repaired=local_repaired and verify_chain()["ok"]
                # external checkpoint exactly one behind
                Path(AUDIT_EXTERNAL_ANCHOR_FILE).write_bytes(old_external)
                ext_repaired=(not verify_chain()["ok"])
                resume_chain(); ext_repaired=ext_repaired and verify_chain()["ok"]
                # both checkpoints exactly one behind
                Path(AUDIT_ANCHOR_FILE).write_bytes(old_local); Path(AUDIT_EXTERNAL_ANCHOR_FILE).write_bytes(old_external)
                resume_chain(); both_repaired=verify_chain()["ok"]
                crash_ok=local_repaired and ext_repaired and both_repaired
                # Positive control: reject the run as inconclusive unless the untouched log verifies.
                Path(AUDIT_FILE).write_bytes(full_log)
                baseline=verify_chain()["ok"]
                if not baseline:
                    raise RuntimeError("untouched audit log failed verification before tamper tests")
                if len(lines)<3:
                    raise RuntimeError("tamper test needs at least 3 audit entries")
                # Deleted tail must fail verification.
                Path(AUDIT_FILE).write_bytes(b"".join(lines[:-1])); truncated=not verify_chain()["ok"]
                Path(AUDIT_FILE).write_bytes(full_log)
                # Edit a parsed middle record while retaining its old hash.
                rec=json.loads(lines[1])
                rec["decision"]="DENY" if rec.get("decision")!="DENY" else "ALLOW"
                mutated=list(lines); mutated[1]=(json.dumps(rec,separators=(",",":"))+"\n").encode("utf-8")
                Path(AUDIT_FILE).write_bytes(b"".join(mutated)); middle=not verify_chain()["ok"]
                Path(AUDIT_FILE).write_bytes(full_log)
                first=json.loads(lines[0])
                with LOCK: _write_anchor_locked(1,first["hash"])
                two_behind=not verify_chain()["ok"]
                with LOCK: _write_anchor_locked(4,"a"*64)
                local_ahead=not verify_chain()["ok"]
                last_hash=json.loads(lines[-1])["hash"]
                with LOCK: _write_anchor_locked(3,last_hash)  # valid local anchor for the independent external-ahead check
                ext_mac=hmac.new(AUDIT_ANCHOR_KEY,f"4:{'b'*64}".encode(),hashlib.sha256).hexdigest()
                Path(AUDIT_EXTERNAL_ANCHOR_FILE).write_text(f"4:{'b'*64}:{ext_mac}",encoding="ascii")
                external_ahead=not verify_chain()["ok"]
                tamper_ok=baseline and truncated and middle and two_behind and local_ahead and external_ahead
            finally:
                if AUDIT.get("fh") is not None:
                    try: AUDIT["fh"].close()
                    except Exception: pass
                DATA_DIR,AUDIT_FILE,AUDIT_ANCHOR_FILE,AUDIT_EXTERNAL_ANCHOR_FILE,AUDIT_ANCHOR_KEY,DEMO,old_audit,old_log=old_paths
                AUDIT.clear(); AUDIT.update(old_audit); LOG.clear(); LOG.extend(old_log)
                shutil.rmtree(td,ignore_errors=True)
        except Exception:
            logger.exception("audit crash/tamper self-test failed")
            # Keep the two outcomes independent: a tamper-test exception must not
            # overwrite a crash-recovery result that was already completed.
        results.append(("AUDIT_CRASH_RECOVERY",crash_ok))
        results.append(("AUDIT_TAMPER_REJECTION",tamper_ok))
        # H13: exported resource names must be normalized and bounded.
        results.append(("H13",audit_resource("=SUM(A1:A2)").startswith("unknown:") and len(audit_resource("x"*1000))<=24))
        # State payload must include every posture signal.
        posture_keys={"os_updated","disk_encrypted","firewall","antivirus","corporate_managed"}
        st=state_payload(); devs=st.get("devices",{})
        results.append(("STATE_POSTURE_FIELDS", None if not devs else all(posture_keys.issubset(d.keys()) for d in devs.values())))
        # Alert cache must invalidate when a new alert is inserted. This runs in
        # the temporary DB created at selftest entry, never the user's real DB.
        if _RUNTIME_READY and os.path.exists(DB_FILE):
            kind="SELFTEST_CACHE_"+secrets.token_hex(4)
            db_alert("LOW",kind,details="selftest")
            results.append(("ALERT_CACHE_REFRESH",any(x.get("kind")==kind for x in recent_alerts(100))))
        else:
            results.append(("ALERT_CACHE_REFRESH",None))
        # Shared enterprise rate-limit storage needs every SQLAlchemy symbol.
        if FASTAPI_AVAILABLE and all(name in globals() for name in ("create_engine","sessionmaker","ThreadPoolExecutor","EnterpriseBase")):
            rate_db_dir=tempfile.mkdtemp(prefix="ztna-rate-selftest-")
            old_engine,old_session,old_url,old_prune=enterprise_engine,EnterpriseSession,ENTERPRISE_DB_URL,ENTERPRISE_RATE_PRUNE_LAST
            test_engine=None
            try:
                rate_db_path=os.path.join(rate_db_dir,"rate.sqlite3")
                test_engine=create_engine("sqlite:///"+rate_db_path,connect_args={"check_same_thread":False,"timeout":30},pool_pre_ping=True)
                enterprise_engine=test_engine
                ENTERPRISE_DB_URL="sqlite:///"+rate_db_path
                EnterpriseSession=sessionmaker(autocommit=False,autoflush=False,bind=test_engine)
                ENTERPRISE_RATE_PRUNE_LAST=0.0
                EnterpriseBase.metadata.create_all(bind=test_engine)
                rate_now=time.time(); sequential=[_enterprise_rate_allow("192.0.2.10",rate_now,3,60) for _ in range(5)]
                with ThreadPoolExecutor(max_workers=8) as pool:
                    concurrent=list(pool.map(lambda _: _enterprise_rate_allow("192.0.2.11",rate_now,3,60),range(12)))
                window_reset=_enterprise_rate_allow("192.0.2.10",rate_now+60,3,60)
                results.append(("ENTERPRISE_SHARED_RATE_LIMIT",sequential==[True,True,True,False,False] and sum(concurrent)==3 and window_reset))
            except Exception:
                logger.exception("shared enterprise rate-limit self-test failed")
                results.append(("ENTERPRISE_SHARED_RATE_LIMIT",False))
            finally:
                ENTERPRISE_RATE_PRUNE_LAST=old_prune
                EnterpriseSession=old_session; ENTERPRISE_DB_URL=old_url; enterprise_engine=old_engine
                if test_engine is not None:
                    try: test_engine.dispose()
                    except Exception: pass
                shutil.rmtree(rate_db_dir,ignore_errors=True)
        else:
            results.append(("ENTERPRISE_SHARED_RATE_LIMIT",None))
    finally:
        _RUNTIME_MODE=old_mode
        LAST_TOTP.clear(); LAST_TOTP.update(old_last)
        FAILS.clear(); FAILS.update(old_fails)
        USERFAIL.clear(); USERFAIL.update(old_userfail)
        LASTLOC.clear(); LASTLOC.update(old_lastloc)
        SESSIONS.clear(); SESSIONS.update(old_sessions)
        NONCES.clear(); NONCES.update(old_nonces)
        PROOF_NONCES.clear(); PROOF_NONCES.update(old_proof_nonces)
        NONCE_HEAP.clear(); NONCE_HEAP.extend(old_heap)
        PROOF_NONCE_HEAP.clear(); PROOF_NONCE_HEAP.extend(old_proof_heap)
        _NONCE_SCOPE_COUNTS.clear(); _NONCE_SCOPE_COUNTS.update(old_scope_counts)
        AUTH_PRUNE_LAST=old_auth_prune_last
        with TELEMETRY_CACHE_LOCK:
            TELEMETRY_CACHE.clear(); TELEMETRY_CACHE.update(old_telemetry_cache)
        # Close only the selftest thread's temporary DB connection; restore the
        # prior connection and file path untouched.
        test_conn=getattr(DB_LOCAL,"conn",None)
        if test_conn is not None and test_conn is not old_db_conn:
            try: test_conn.close()
            except Exception: pass
        globals()["DB_FILE"]=old_db_file
        if old_db_conn_present: DB_LOCAL.conn=old_db_conn
        else:
            try: del DB_LOCAL.conn
            except AttributeError: pass
        shutil.rmtree(selftest_db_dir,ignore_errors=True)
    results=[(k,None if v is None else bool(v)) for k,v in results]
    print("\n".join(f"{k}: {'SKIP' if v is None else ('PASS' if v else 'FAIL')}" for k,v in results))
    passed=sum(v is True for _,v in results); skipped=sum(v is None for _,v in results)
    failed=sum(v is False for _,v in results)
    print(f"Summary: {passed} passed, {skipped} skipped, {failed} failed")
    return failed==0

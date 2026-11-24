# Part 06 of ztna_lab_v2.py - tamper-evident audit log: HMAC hash chain, anchors, verification, recovery, plain-English text, export.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ---------- tamper-evident audit log (SHA-256 hash chain, persisted) ----------
class AuditFull(Exception): pass
class AuditTamper(Exception): pass

def _audit_segment_files():
    files=[]
    for name in os.listdir(DATA_DIR):
        if not name.startswith(os.path.basename(AUDIT_FILE)+"."): continue
        suffix=name.rsplit(".",1)[-1]
        if suffix.isdigit(): files.append((int(suffix),os.path.join(DATA_DIR,name)))
    files.sort(reverse=True)
    return [p for _,p in files]+([AUDIT_FILE] if os.path.exists(AUDIT_FILE) else [])

def _rotate_audit_locked():
    prefix=os.path.basename(AUDIT_FILE)+"."
    existing=[int(n[len(prefix):]) for n in os.listdir(DATA_DIR) if n.startswith(prefix) and n[len(prefix):].isdigit()]
    if len(existing)>=_env_int("ZTNA_MAX_AUDIT_SEGMENTS",32,1,100000,error_type=AuditFull): raise AuditFull("audit segment limit reached; archive segments before continuing")
    if AUDIT["fh"] is not None:
        AUDIT["fh"].close(); AUDIT["fh"]=None
    nums=[]
    prefix=os.path.basename(AUDIT_FILE)+"."
    for name in os.listdir(DATA_DIR):
        if name.startswith(prefix) and name[len(prefix):].isdigit(): nums.append(int(name[len(prefix):]))
    # Highest number first, so an interrupted rotation still leaves the segments in chain order.
    for i in sorted(nums,reverse=True): _replace_file(f"{AUDIT_FILE}.{i}",f"{AUDIT_FILE}.{i+1}")
    if os.path.exists(AUDIT_FILE): _replace_file(AUDIT_FILE,AUDIT_FILE+".1")
    try:
        fd=os.open(DATA_DIR,os.O_RDONLY); os.fsync(fd); os.close(fd)
    except OSError: pass
    AUDIT["size"]=0

def _audit_hash(prev, event):
    # surrogatepass: a lone surrogate (legal in JSON, e.g. "\ud800" in a request body) would otherwise raise here and
    # the entry could not be written at all. Every other string encodes to exactly the same bytes as before.
    payload=json.dumps(event,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8","surrogatepass")
    return hmac.new(AUDIT_ANCHOR_KEY, prev.encode()+b"|"+payload, hashlib.sha256).hexdigest()

def _anchor_value(entries,last_hash):
    msg=f"{entries}:{last_hash}".encode()
    return hmac.new(AUDIT_ANCHOR_KEY,msg,hashlib.sha256).hexdigest()

def _write_anchor_locked(entries,last_hash):
    tmp=AUDIT_ANCHOR_FILE+f".tmp.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}"
    data={"entries":entries,"hash":last_hash,"mac":_anchor_value(entries,last_hash)}
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(data,f,separators=(",",":")); f.flush(); os.fsync(f.fileno())
        _replace_file(tmp,AUDIT_ANCHOR_FILE); _fsync_dir(AUDIT_ANCHOR_FILE)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def _verify_anchor_locked(entries,last_hash):
    try:
        with open(AUDIT_ANCHOR_FILE,encoding="utf-8") as f: a=json.load(f)
    except FileNotFoundError:
        return entries==0 and last_hash=="0"*64
    except (OSError,ValueError,TypeError): return False
    return (type(a.get("entries")) is int and type(a.get("hash")) is str and type(a.get("mac")) is str
            and a["entries"]==entries and hmac.compare_digest(a["hash"],last_hash)
            and hmac.compare_digest(a["mac"],_anchor_value(entries,last_hash)))

AUDIT_EXTERNAL_ANCHOR_FILE=os.environ.get("ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE",os.path.join(str(Path(DATA_DIR).parent),"ztna_audit_monotonic.anchor"))
def _external_anchor_update(entries,last_hash):
    if not AUDIT_ANCHOR_KEY: return
    try:
        path=AUDIT_EXTERNAL_ANCHOR_FILE; Path(path).parent.mkdir(parents=True,exist_ok=True)
        current=-1
        if os.path.exists(path):
            with open(path,encoding="ascii") as f: current=int(f.read().strip().split(":",1)[0])
        if entries < current: raise AuditTamper("audit monotonic counter rollback")
        if entries == current:
            if os.path.exists(path):
                raw=Path(path).read_text(encoding="ascii").strip().split(":")
                if len(raw)==3 and hmac.compare_digest(raw[1],last_hash) and hmac.compare_digest(raw[2],hmac.new(AUDIT_ANCHOR_KEY,f"{entries}:{last_hash}".encode(),hashlib.sha256).hexdigest()):
                    return
            raise AuditTamper("audit external anchor hash mismatch")
        tmp=path+f".tmp.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}"
        mac=hmac.new(AUDIT_ANCHOR_KEY,f"{entries}:{last_hash}".encode(),hashlib.sha256).hexdigest()
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            with os.fdopen(fd,"w",encoding="ascii") as f: f.write(f"{entries}:{last_hash}:{mac}"); f.flush(); os.fsync(f.fileno())
            _replace_file(tmp,path); _fsync_dir(path)
        except BaseException:
            try: os.unlink(tmp)
            except OSError: pass
            raise
    except (OSError,ValueError) as exc:
        if not DEMO: raise AuditTamper(f"external audit anchor unavailable: {exc}")

def _verify_external_anchor(entries,last_hash):
    try:
        if not os.path.exists(AUDIT_EXTERNAL_ANCHOR_FILE): return DEMO
        raw=Path(AUDIT_EXTERNAL_ANCHOR_FILE).read_text(encoding="ascii").strip().split(":")
        if len(raw)!=3: return False
        counter,h,mac=raw
        counter=int(counter)
        if counter != entries: return False
        if not hmac.compare_digest(h,last_hash): return False
        return hmac.compare_digest(mac,hmac.new(AUDIT_ANCHOR_KEY,f"{counter}:{h}".encode(),hashlib.sha256).hexdigest())
    except Exception: return False

def audit_allowed(source,kind,limit=60,window=10):
    now=time.time(); key=(str(source)[:80],kind)
    with LOCK:
        if len(AUDIT_RATE)>10000:
            for k,v in list(AUDIT_RATE.items()):
                if not v or now-v[-1]>window: AUDIT_RATE.pop(k,None)
        q=AUDIT_RATE.setdefault(key,deque(maxlen=limit))
        while q and now-q[0]>window: q.popleft()
        if len(q)>=limit: return False
        q.append(now); return True

def _discard_failed_audit_write_locked():
    """After a failed append: drop the writer WITHOUT flushing what it still buffers, then cut the file back to the
    last complete entry. Otherwise a partial line (or a line whose hash never became AUDIT["prev"]) stays in the
    file and every later entry breaks the chain for good."""
    fh, AUDIT["fh"] = AUDIT.get("fh"), None
    if fh is not None:
        try: fh.buffer.raw.close()       # closes the descriptor; the buffered bytes can no longer reach the file
        except Exception: pass
    try:
        with open(AUDIT_FILE, "r+b") as f:
            if os.fstat(f.fileno()).st_size > AUDIT.get("size", 0): f.truncate(AUDIT.get("size", 0))
    except OSError as exc:
        logger.error("could not roll back a failed audit write: %s", exc)

def _sync_audit_anchors_locked():
    """Bring both anchors up to the last durable entry (after an earlier anchor write failed)."""
    try:
        _external_anchor_update(AUDIT["entries"], AUDIT["prev"])
        _write_anchor_locked(AUDIT["entries"], AUDIT["prev"])
    except OSError as exc:
        raise AuditFull(f"audit anchor unavailable: {exc}") from None
    AUDIT["anchor_lag"] = False

def audit(**kw):
    kw["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    kw["hour"] = now_hour(); kw["resource"] = audit_resource(kw.get("resource"))
    with LOCK:
        # The anchors may trail the log by at most one entry (that is what startup recovery repairs), so an entry
        # whose anchor update failed must be anchored before anything else is appended.
        if AUDIT.get("anchor_lag"): _sync_audit_anchors_locked()
        kw["prev"] = AUDIT["prev"]
        kw["hash_alg"] = "HMAC-SHA256"
        kw["hash"] = _audit_hash(kw["prev"], {k:v for k,v in kw.items() if k!="hash"})
        line = json.dumps(kw,separators=(",",":"))+"\n"
        # Everything up to the write raises AuditFull/AuditTamper only: callers roll back on exactly those, and a raw
        # OSError (Windows refusing to rotate a segment that the verifier has open, disk errors) used to skip that.
        try:
            # size 0 with no file is the moment right after a rotation (or a restart that followed one), not tampering.
            if AUDIT["entries"] and AUDIT.get("size",0) and (not os.path.exists(AUDIT_FILE) or os.path.getsize(AUDIT_FILE) < AUDIT.get("size",0)):
                raise AuditTamper("audit log changed while running")
            if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) >= MAX_AUDIT_BYTES:
                _rotate_audit_locked()
            if AUDIT["fh"] is None:
                fd=os.open(AUDIT_FILE,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
                try: os.chmod(AUDIT_FILE,0o600)
                except OSError: pass
                AUDIT["fh"]=os.fdopen(fd,"a",encoding="utf-8")
        except OSError as exc:
            raise AuditFull(f"audit log unavailable: {exc}") from None
        try:
            AUDIT["fh"].write(line); AUDIT["fh"].flush(); os.fsync(AUDIT["fh"].fileno())
            size=os.path.getsize(AUDIT_FILE)
        except OSError as exc:
            _discard_failed_audit_write_locked()
            raise AuditFull(f"audit write failed: {exc}") from None
        AUDIT["size"]=size
        AUDIT["prev"]=kw["hash"]; AUDIT["entries"] += 1; LOG.appendleft(kw)
        # The entry is durable from here on, so the caller's action stands. A failed anchor update is repaired by the
        # next audit() before it appends (or by startup recovery, which accepts a one-entry lag), not reported as
        # "not recorded" for an action that the log already holds.
        try:
            _external_anchor_update(AUDIT["entries"],AUDIT["prev"])
            _write_anchor_locked(AUDIT["entries"],AUDIT["prev"])
        except OSError as exc:
            AUDIT["anchor_lag"]=True
            logger.error("audit entry %s is recorded but its anchor could not be updated (%s); the next entry waits until it is", AUDIT["entries"], exc)
        if kw.get("resource") in RESOURCES and not _is_exception_record(kw):
            db_access(kw.get("user"),kw.get("device"),kw.get("resource"),kw.get("decision"),kw.get("risk",0),kw.get("reasons",[]),kw.get("signals",[]))
            detect_alerts(kw)

def _read_anchor_snapshot(path):
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return b"!UNREADABLE!"

def _local_anchor_snapshot_matches(raw,entries,last_hash):
    if raw is None: return entries==0 and last_hash=="0"*64
    try:
        a=json.loads(raw.decode("utf-8"))
        return (type(a.get("entries")) is int and type(a.get("hash")) is str and type(a.get("mac")) is str
                and a["entries"]==entries and hmac.compare_digest(a["hash"],last_hash)
                and hmac.compare_digest(a["mac"],_anchor_value(entries,last_hash)))
    except Exception: return False

def _external_anchor_snapshot_matches(raw,entries,last_hash):
    if raw is None: return DEMO
    try:
        parts=raw.decode("ascii").strip().split(":")
        if len(parts)!=3: return False
        counter,h,mac=parts; counter=int(counter)
        if counter!=entries: return False
        if not hmac.compare_digest(h,last_hash): return False
        expected=hmac.new(AUDIT_ANCHOR_KEY,f"{counter}:{h}".encode(),hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac,expected)
    except Exception: return False

def _open_shared_read(path):
    """Open for binary reading. On Windows also allow the file to be renamed while it is open (FILE_SHARE_DELETE), as
    POSIX always does: the verifier keeps every segment open during its scan, and segment rotation must not fail
    because of that. Falls back to a plain open() if the Windows call is unavailable."""
    if os.name == "nt":
        try:
            import _winapi, msvcrt
            handle = _winapi.CreateFile(os.fspath(path), _winapi.GENERIC_READ, 0x1 | 0x2 | 0x4, 0, _winapi.OPEN_EXISTING, 0, 0)
        except (ImportError, AttributeError):
            return open(path, "rb")
        except OSError as exc:
            if exc.winerror == 2: raise FileNotFoundError(2, "No such file or directory", path) from None   # ERROR_FILE_NOT_FOUND
            raise
        return open(msvcrt.open_osfhandle(handle, os.O_RDONLY), "rb")
    return open(path, "rb")

def _open_audit_snapshot_locked():
    handles=[]
    try:
        for path in _audit_segment_files():
            fh=_open_shared_read(path)
            size=os.fstat(fh.fileno()).st_size
            handles.append((path,fh,size))
        local_raw=_read_anchor_snapshot(AUDIT_ANCHOR_FILE)
        external_raw=_read_anchor_snapshot(AUDIT_EXTERNAL_ANCHOR_FILE)
        inmem_entries=AUDIT.get("entries",0); inmem_prev=AUDIT.get("prev","0"*64)
        current_size=os.path.getsize(AUDIT_FILE) if os.path.exists(AUDIT_FILE) else 0
        return handles,local_raw,external_raw,inmem_entries,inmem_prev,current_size
    except BaseException:
        for _,fh,_ in handles:
            try: fh.close()
            except Exception: pass
        raise

def _scan_audit_handles(handles,tail_limit=0):
    """Verify a stable descriptor snapshot one line at a time; never read all logs into RAM."""
    prev="0"*64; seen_hmac=False; count=0; previous_hash="0"*64
    tail=deque(maxlen=tail_limit) if tail_limit else None
    for path,fh,size in handles:
        fh.seek(0); consumed=0
        while consumed<size:
            raw=fh.readline(size-consumed)
            if not raw or not raw.endswith(b"\n"):
                return {"ok":False,"broken_at":count,"entries":count,"reason":"partial audit line","last_hash":prev,"previous_hash":previous_hash,"tail":tail or []}
            consumed+=len(raw)
            try:
                event=json.loads(raw.decode("utf-8"))
                if not isinstance(event,dict): raise ValueError("audit entry is not a JSON object")   # e.g. a tampered "0"
                h=event.pop("hash")
                if event.get("prev")!=prev:
                    return {"ok":False,"broken_at":count,"entries":count+1,"last_hash":prev,"previous_hash":previous_hash,"tail":tail or []}
                if event.get("hash_alg")=="HMAC-SHA256": expected=_audit_hash(prev,event); seen_hmac=True
                else:
                    if seen_hmac: return {"ok":False,"broken_at":count,"entries":count+1,"last_hash":prev,"previous_hash":previous_hash,"tail":tail or []}
                    expected=sha(prev+json.dumps(event,sort_keys=True,separators=(",",":")))
                if not hmac.compare_digest(str(expected),str(h)):
                    return {"ok":False,"broken_at":count,"entries":count+1,"last_hash":prev,"previous_hash":previous_hash,"tail":tail or []}
                previous_hash=prev; prev=h; count+=1
                if tail is not None:
                    event["hash"]=h; tail.append(event)
            except (ValueError,KeyError,TypeError,UnicodeDecodeError,RecursionError):      # RecursionError: deeply nested JSON
                return {"ok":False,"broken_at":count,"entries":count+1,"last_hash":prev,"previous_hash":previous_hash,"tail":tail or []}
    return {"ok":True,"entries":count,"last_hash":prev,"previous_hash":previous_hash,"tail":tail or []}

def _verify_chain_snapshot():
    with LOCK:
        handles,local_raw,external_raw,inmem_entries,inmem_prev,current_size=_open_audit_snapshot_locked()
    try:
        scan=_scan_audit_handles(handles)
        if not scan["ok"]: return scan
        count=scan["entries"]; last=scan["last_hash"]
        if not _local_anchor_snapshot_matches(local_raw,count,last):
            return {"ok":False,"broken_at":max(0,count-1),"entries":count,"anchor":True}
        if not _external_anchor_snapshot_matches(external_raw,count,last):
            return {"ok":False,"broken_at":max(0,count-1),"entries":count,"external_anchor":True}
        return {"ok":True,"entries":count}
    finally:
        for _,fh,_ in handles:
            try: fh.close()
            except Exception: pass

def verify_chain():
    # Only descriptor/anchor snapshotting is serialized. The potentially huge
    # chain scan happens outside LOCK and consumes bounded per-line memory.
    try: return _verify_chain_snapshot()
    except OSError: return {"ok":False,"broken_at":0,"entries":0,"anchor":True}

def _one_behind_recovery_snapshot():
    with LOCK:
        handles,local_raw,external_raw,_,_,current_size=_open_audit_snapshot_locked()
    try:
        scan=_scan_audit_handles(handles)
        if not scan.get("ok"): return None
        count=scan["entries"]; last=scan["last_hash"]; before=scan["previous_hash"]
        return {"count":count,"last":last,"before":before,"local_raw":local_raw,"external_raw":external_raw}
    finally:
        for _,fh,_ in handles:
            try: fh.close()
            except Exception: pass

def _local_anchor_one_behind(raw,count,before):
    if count<1: return False
    if raw is None: return count==1 and before=="0"*64
    try:
        a=json.loads(raw.decode("utf-8")); n=a.get("entries")
        return type(n) is int and n==count-1 and hmac.compare_digest(str(a.get("hash","")),before) and hmac.compare_digest(str(a.get("mac","")),_anchor_value(n,before))
    except Exception: return False

def _external_anchor_one_behind(raw,count,before):
    if raw is None or count<1: return False
    try:
        parts=raw.decode("ascii").strip().split(":")
        if len(parts)!=3: return False
        n,h,mac=parts; n=int(n)
        expected=hmac.new(AUDIT_ANCHOR_KEY,f"{n}:{h}".encode(),hashlib.sha256).hexdigest()
        return n==count-1 and hmac.compare_digest(h,before) and hmac.compare_digest(mac,expected)
    except Exception: return False

def resume_chain():
    v=verify_chain()
    if not v["ok"]:
        snap=_one_behind_recovery_snapshot()
        if snap:
            count,last,before=snap["count"],snap["last"],snap["before"]
            try:
                # Repair only a valid anchor that is exactly one event behind a
                # fully verified log. Never repair two-behind or ahead-of-log states.
                if _local_anchor_one_behind(snap["local_raw"],count,before):
                    with LOCK: _write_anchor_locked(count,last)
                v=verify_chain()
                if not v["ok"] and v.get("external_anchor") and _external_anchor_one_behind(snap["external_raw"],count,before):
                    _external_anchor_update(count,last)
                    v=verify_chain()
            except Exception: pass
    if not v["ok"]: raise SystemExit(f"audit chain corrupt at entry {v.get('broken_at',0)}: refusing to start")
    with LOCK:
        AUDIT["fh"] = AUDIT.get("fh")
        # Tail hydration is bounded; use descriptors under the lock, then scan outside it.
        handles,_,_,_,_,current_size=_open_audit_snapshot_locked()
    try:
        scan=_scan_audit_handles(handles,tail_limit=500)
        if not scan.get("ok"): raise SystemExit("audit chain changed during startup recovery")
        with LOCK:
            LOG.clear()
            for event in scan["tail"]: LOG.appendleft(event)
            AUDIT["prev"]=scan["last_hash"]; AUDIT["entries"]=scan["entries"]; AUDIT["size"]=current_size
    finally:
        for _,fh,_ in handles:
            try: fh.close()
            except Exception: pass


# ---------- audit log in plain English, integrity report and recovery ----------
_FIELD_WORDS = {"os_updated": "OS-update check", "disk_encrypted": "disk-encryption check", "firewall": "firewall check",
                "antivirus": "antivirus check", "corporate_managed": "company-managed flag"}

def describe_audit_event(e):
    """-> (label, tag, sentence): the audit entry as a human-readable statement. tag is ok|bad|warn|info|dim."""
    res = str(e.get("resource", "")); dec = str(e.get("decision", "")); user = e.get("user") or "someone"
    dev = e.get("device") or ""; on = f" on {dev}" if dev else ""
    reasons = [str(x) for x in (e.get("reasons") or [])]; r0 = reasons[0] if reasons else ""; risk = e.get("risk", 0)
    labels = {"ALLOW": ("Allowed", "ok"), "DENY": ("Blocked", "bad"), "STEPUP": ("Needs MFA", "warn"), "POLICY": ("Admin change", "info"), "REVOKE": ("Signed out", "dim")}
    label, tag = labels.get(dec, (dec.title() or "Event", "dim"))
    if r0.startswith(EXTRA_ACCESS_PREFIX):
        if dec == "PENDING": return "Requested", "warn", f"{user} asked for temporary access to {res}{on}: {reasons[1] if len(reasons) > 1 else 'no reason given'}."
        if dec == "ALLOW": return "Access granted", "ok", f"A manager granted {user} temporary access to {res}{on} ({r0[len(EXTRA_ACCESS_PREFIX):].strip()}; {reasons[1] if len(reasons) > 1 else 'time-limited'})."
        if dec == "DENY": return "Request denied", "bad", f"A manager denied {user}'s request for temporary access to {res}{on}."
        return "Access ended", "dim", f"{user}'s temporary access request for {res}{on} ended: {r0.split(': ',1)[-1]}."
    if res == "signin-request":
        if dec == "PENDING": return "Waiting", "warn", f"{user} asked to sign in{on} and is waiting for a manager to approve it."
        if dec == "ALLOW": return label, tag, f"A manager approved {user}'s sign-in request{on}."
        if dec == "REVOKE": return "Closed", "dim", f"{user}'s sign-in request{on} ended without a session: {r0 or 'closed'}."
        return label, tag, f"A manager denied {user}'s sign-in request{on}."
    if res == "login":
        if dec == "ALLOW":
            extra = " Location changed within 5 minutes, so the session is flagged as riskier." if any("location change" in r for r in reasons) else ""
            return label, tag, f"{user} signed in{on}; password and one-time code were correct.{extra}"
        return label, tag, f"Sign-in refused for '{user}'{on}: wrong password, wrong one-time code, or a device that is not theirs (the system deliberately does not say which)."
    if res == "stepup":
        return (label, tag, f"{user} proved their identity again with a fresh one-time code.") if dec == "ALLOW" else (label, tag, f"{user} entered a wrong code during re-verification.")
    if res == "session":
        return label, tag, (f"{user} signed out." if r0 == "user logout" else f"{user}'s session was ended ({r0 or 'revoked'}).")
    if res == "posture":
        if "=" in r0:
            f, v = r0.split("=", 1)
            word = _FIELD_WORDS.get(f, f)
            return label, tag, f"Admin set the {word} on {dev or 'a device'} to {'PASS' if v == 'True' else 'FAIL'}."
        return label, tag, f"Device health change on {dev or 'a device'}: {r0 or 'updated'}."
    if res == "sim":
        h = r0.split("=", 1)[-1]
        return label, tag, "Admin switched the policy clock back to the real time." if h == "None" else f"Admin set the simulated clock to {h}:00 (to test hours rules)."
    if res in RESOURCES and dec == "POLICY":
        try:
            payload = r0.split("policy updated: ", 1)[1]
            if len(payload.encode("utf-8")) > 4096: raise ValueError("policy audit record too large")
            d = json.loads(payload)
            if not isinstance(d, dict) or not {"min_posture", "managed", "hours", "mfa_age"}.issubset(d): raise ValueError("invalid policy audit record")
            return label, tag, (f"Admin changed the rules for {res}: device score at least {d['min_posture']}, "
                                f"{'company-managed devices only' if d['managed'] else 'any enrolled device'}, "
                                f"open {_fmt_hours({'hours': d['hours']})}, MFA every {d['mfa_age'] / 60:g} min.")
        except Exception:
            return label, tag, f"Admin changed the rules for {res}: {r0}"
    if res in RESOURCES:
        if dec == "ALLOW": return label, tag, f"{user} opened {res}{on} (risk {risk}/100)."
        if dec == "STEPUP": return label, tag, f"{user} was asked to re-verify with MFA before opening {res}."
        role = USERS.get(user, {}).get("role", "?")
        _v, _h, lines, _t = explain_decision(res, {"decision": dec, "reasons": reasons, "role": role, "risk": risk, "signals": e.get("signals", []), "device": dev, "hour": e.get("hour", now_hour())})
        third = " ".join(lines[:2]).replace("Your ", "Their ").replace("your ", "their ").replace("yours", "theirs")
        return label, tag, f"{user} was blocked from {res}{on}. " + third
    if res.startswith("unknown:"):
        return label, tag, f"A request for a system that does not exist was rejected ({user})."
    return label, tag, ("Admin action: " if dec == "POLICY" else "") + ("; ".join(reasons) or res)

def verify_report(v):
    """-> (ok, headline, [explanation lines]) for a verify_chain() result."""
    if v.get("ok"):
        return True, f"INTACT - all {v.get('entries', 0)} entries verified", ["Every entry matches its cryptographic seal and the anchor files agree.", "Nothing was edited, removed or inserted."]
    n = int(v.get("broken_at", 0)) + 1
    if v.get("external_anchor"):
        why = ["The log is consistent with itself, but the separate 'monotonic anchor' disagrees with it.",
               "Typical causes: the log was rolled back to an older copy, the anchor file was replaced, or the app stopped halfway through a write."]
    elif v.get("anchor"):
        why = ["The log is consistent with itself, but it disagrees with the local anchor file (audit.anchor).",
               "Typical causes: the last lines were deleted, the anchor file was replaced, or the app stopped halfway through a write (that last case is repaired by 'Safe repair')."]
    elif v.get("reason") == "partial audit line":
        why = [f"Entry #{n} is cut off (incomplete). This usually means a crash or a full disk while it was being written."]
    else:
        why = [f"Entry #{n} no longer matches its cryptographic seal.", "That line was edited, or a line before it was removed or inserted."]
    return False, f"PROBLEM FOUND at entry #{n}", why

def repair_chain_safe():
    """Fix the ONE harmless failure that can be repaired automatically: the log is valid but an anchor file is exactly one
    entry behind (crash right after writing an entry). Anything else is never 'repaired': that would hide tampering."""
    v = verify_chain()
    if v.get("ok"): return True, "Nothing to repair: the audit log is intact."
    snap = _one_behind_recovery_snapshot()
    if not snap:
        return False, ("This cannot be repaired automatically, on purpose. The log's own seals do not match, which means entries were changed, "
                       "removed or cut off. Save an evidence copy, then investigate or archive the damaged log.")
    try:
        count, last, before = snap["count"], snap["last"], snap["before"]
        if _local_anchor_one_behind(snap["local_raw"], count, before):
            with LOCK: _write_anchor_locked(count, last)
        v = verify_chain()
        if not v["ok"] and v.get("external_anchor") and _external_anchor_one_behind(snap["external_raw"], count, before):
            _external_anchor_update(count, last); v = verify_chain()
    except Exception as exc:
        return False, f"Repair failed: {exc}"
    if not v["ok"]:
        return False, "The anchors are not simply one entry behind, so nothing was changed. Save an evidence copy and investigate."
    try: audit(user="admin", device=None, resource="audit-repair", decision="POLICY", reasons=["anchor files re-synchronised after a one-entry lag (safe repair)"])
    except (AuditFull, AuditTamper): pass
    return True, "Repaired: the log was valid and the anchor was one entry behind. The anchor is now in sync."

def export_audit_evidence():
    """Copy every audit file plus a short report into a new folder (never modifies the originals). Returns the folder."""
    stamp = time.strftime("%Y%m%d-%H%M%S"); dest = os.path.join(DATA_DIR, f"audit_evidence_{stamp}")
    os.makedirs(dest, mode=0o700, exist_ok=True)
    for pth in list(_audit_segment_files()) + [AUDIT_ANCHOR_FILE, AUDIT_EXTERNAL_ANCHOR_FILE]:
        if os.path.exists(pth): shutil.copy2(pth, os.path.join(dest, os.path.basename(pth)))
    ok, head, lines = verify_report(verify_chain())
    with open(os.path.join(dest, "REPORT.txt"), "w", encoding="utf-8") as f:
        f.write(f"Audit evidence copy made {datetime.now().isoformat(timespec='seconds')}\nResult: {head}\n" + "\n".join(lines) + "\n")
    return dest

def archive_and_reset_audit():
    """Demo-mode recovery from a confirmed integrity failure: move every audit file into a timestamped archive folder
    (nothing is deleted) and start a brand-new chain whose first entry records what happened."""
    if not DEMO: raise RuntimeError("only available in local demo mode; in production restore from backup and investigate")
    with LOCK:
        if AUDIT.get("fh") is not None:
            try: AUDIT["fh"].close()
            except Exception: pass
            AUDIT["fh"] = None
        arch = os.path.join(DATA_DIR, "audit_archive_" + time.strftime("%Y%m%d-%H%M%S")); os.makedirs(arch, mode=0o700, exist_ok=True)
        for pth in list(_audit_segment_files()) + [AUDIT_ANCHOR_FILE, AUDIT_EXTERNAL_ANCHOR_FILE]:
            if os.path.exists(pth): shutil.move(pth, os.path.join(arch, os.path.basename(pth)))
        AUDIT["prev"] = "0" * 64; AUDIT["entries"] = 0; AUDIT["size"] = 0; AUDIT["anchor_lag"] = False; LOG.clear()
    audit(user="admin", device=None, resource="audit-reset", decision="POLICY", reasons=[f"damaged audit log archived to {os.path.basename(arch)}; new chain started"])
    return arch

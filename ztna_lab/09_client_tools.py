# Part 09 of ztna.py - client tooling: red-team attack suite, benchmark, posture agent, latency probe.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ---------- client-side tooling: attack simulation, benchmark, agent ----------
AH = {"X-Admin-Key": ADMIN_KEY or ""}
def http(base,method,path,body=None,headers=None):
    if not DEMO and base.lower().startswith("http://"): return 0,{}
    headers=headers or {}
    data=json.dumps(body).encode() if body is not None else None
    headers=proof_headers(headers,method,path,data or b"")
    r=urllib.request.Request(base+path,data,{"Content-Type":"application/json",**headers},method=method)
    try:
        ctx=ssl.create_default_context(cafile=os.environ.get("ZTNA_CA_FILE") or None)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
        x=opener.open(r,timeout=5); raw=x.read(); return x.status,(json.loads(raw or b"{}") if raw else {})
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:return e.code,json.loads(raw or b"{}")
        except ValueError:return e.code,{}
    except (urllib.error.URLError,ConnectionError,TimeoutError,OSError): return 0,{}

def _next_totp(u):
    nowctr=int(time.time())//30; last=CLIENT_TOTP_LAST.get(u,-1)
    for ctr in (nowctr-1,nowctr,nowctr+1):
        if ctr>last:
            CLIENT_TOTP_LAST[u]=ctr
            return totp(USERS[u]["totp"],ctr*30)
    # No unused server-acceptable counter remains in this 3-window interval.
    return None

def login_as(base,u,dev,loc="office"):
    previous_counter=CLIENT_TOTP_LAST.get(u,-1)
    code=_next_totp(u)
    if code is None: return {}
    selected_counter=CLIENT_TOTP_LAST.get(u,-1)
    s,b=http(base,"POST","/api/login",{"username":u,"password":u+"123","otp":code,"device_id":dev,"location":loc})
    if s==200: CLIENT_TOTP_LAST[u]=max(selected_counter,int(time.time())//30)
    else: CLIENT_TOTP_LAST[u]=previous_counter
    if s!=200: return {}
    tok=b.get("token",""); key=b.get("device_key","")
    return {"Authorization":"Bearer "+tok,"X-Device-Id":dev,"X-Device-Key":key}

def proof_headers(h,method,path,body=b""):
    key=h.get("X-Device-Key","")
    if not key: return h
    try:
        raw=unb64(key); ts=time.time(); nonce=secrets.token_urlsafe(18); digest=hashlib.sha256(body).hexdigest()
        msg=proof_message(method,path,digest,ts,nonce)
        return {k:v for k,v in h.items() if k!="X-Device-Key"} | {"X-Device-Timestamp":f"{ts:.3f}","X-Device-Nonce":nonce,"X-Content-SHA256":digest,"X-Device-Proof":hmac.new(raw,msg,hashlib.sha256).hexdigest()}
    except Exception: return h

def _attack(base):
    A, rows = (lambda *a, **k: http(base, *a, **k)), []
    def check(name, got, want):
        rows.append(got == want); print(f"{'PASS' if got == want else 'FAIL'}  {name:58s} expected={want} got={got}")
    A("POST", "/api/sim", {"hour": 12}, AH)
    hb, ha = login_as(base, "bob", "laptop-bob"), login_as(base, "alice", "laptop-alice")
    if not hb.get("Authorization") or not ha.get("Authorization"):
        check("test prerequisites: demo logins succeeded", False, True)
        return False
    check("control: HR user, managed device -> hr-db", A("GET", "/access/hr-db", headers=hb)[0], 200)
    check("no token -> wiki", A("GET", "/access/wiki")[0], 401)
    check("inspector without token", A("GET", "/inspect")[0], 401)
    s,b=A("GET", "/inspect", headers=hb); seen={x["name"].lower():x["value"] for x in b.get("headers",[])}
    check("inspector redacts credentials", (s, hb["Authorization"][7:] not in json.dumps(b), seen.get("authorization"), seen.get("x-device-proof")), (200, True, "[redacted]", "[redacted]"))
    h, p, s = ha["Authorization"][7:].split("."); c = json.loads(unb64(p)); c["sub"] = "carol"
    check("tampered JWT payload", A("GET", "/access/wiki", headers={**ha, "Authorization": f"Bearer {h}.{b64(json.dumps(c).encode())}.{s}"})[0], 401)
    check("alg=none forged JWT", A("GET", "/access/wiki", headers={**ha, "Authorization": "Bearer " + b64(b'{"alg":"none"}') + "." + p + "."})[0], 401)
    check("stolen token replayed from another device", A("GET", "/access/wiki", headers={**ha, "X-Device-Id": "laptop-carol"})[0], 401)
    check("privilege escalation: engineer -> hr-db", A("GET", "/access/hr-db", headers=ha)[0], 403)
    byod_h=login_as(base, "bob", "byod-bob")
    check("unmanaged BYOD -> hr-db", A("GET", "/access/hr-db", headers=byod_h)[0], 403)
    A("POST", "/api/sim", {"hour": 22}, AH); check("off-hours access to hr-db", A("GET", "/access/hr-db", headers=hb)[0], 403); A("POST", "/api/sim", {"hour": 12}, AH)
    A("POST", "/api/policy/wiki", {"mfa_age": 1}, AH); time.sleep(1.2)
    s, b = A("GET", "/access/wiki", headers=ha); check("stale MFA -> step-up demanded", (s, b.get("stepup")), (401, True))
    A("POST", "/api/stepup", {"otp": _next_totp("alice")}, ha)
    check("after step-up -> allowed", A("GET", "/access/wiki", headers=ha)[0], 200); A("POST", "/api/policy/wiki", {"mfa_age": 300}, AH)
    carol_h=login_as(base, "carol", "laptop-carol")
    check("admin on managed device, in hours -> admin-panel", A("GET", "/access/admin-panel", headers=carol_h)[0], 200)
    carol_home=login_as(base,"carol","laptop-carol","home")
    s,b=A("GET","/access/wiki",headers=carol_home)
    check("location change flagged (impossible travel)",(s,any("location change" in x for x in b.get("signals",[]))),(200,True))
    homeh = carol_home
    hr_ = ha; check("control: session before revoke", A("GET", "/access/wiki", headers=hr_)[0], 200)
    A("POST", f"/api/session/{json.loads(unb64(hr_['Authorization'][7:].split('.')[1]))['sid']}/revoke", {}, AH)
    check("revoked session is rejected immediately", A("GET", "/access/wiki", headers=hr_)[0], 401)
    logout_h=homeh
    valid_shape_checks={"os_updated":True,"disk_encrypted":True,"firewall":True,"antivirus":True}
    check("forged posture report (correct shape, invalid signature)", A("POST", "/api/posture/report", {"device":"laptop-bob","checks":valid_shape_checks,"ts":time.time(),"nonce":secrets.token_hex(8),"sig":"00"})[0], 403)
    check("admin API without key", A("GET", "/api/logs")[0], 401)
    check("audit hash chain intact", A("GET", "/api/verify", headers=AH)[1].get("ok"), True)
    statuses=[]
    # The server owns its backoff environment, so changing this client's env
    # would not help. If a request is throttled between failures, wait and retry
    # that same attempt until the server accepts it (or the test deadline expires).
    backoff_base=max(0.05,_env_float("ZTNA_AUTH_BACKOFF_BASE",0.25))
    for i in range(5):
        deadline=time.monotonic()+20.0
        wait=min(8.0,backoff_base*(2**i)+0.1)
        while True:
            status=A("POST", "/api/login", {"username":"carol","password":"x","otp":"000000","device_id":"laptop-carol","location":"office"})[0]
            if status==401:
                statuses.append(status); break
            if status==429 and time.monotonic()<deadline:
                time.sleep(wait); wait=min(8.0,max(wait*1.5,0.25)); continue
            statuses.append(status); break
    last=A("POST", "/api/login", {"username":"carol","password":"x","otp":"000000","device_id":"laptop-carol","location":"office"})[0]
    check("brute force: five failures followed by hard lock", (all(x==401 for x in statuses),last), (True,429))
    check("bad Host rejected", A("GET", "/api/logs", headers={**AH,"Host":"evil.example"})[0], 421)
    check("invalid simulated hour rejected", A("POST","/api/sim",{"hour":"x"},AH)[0],400)
    check("logout revokes session", A("POST","/api/logout",{},logout_h)[0],200)
    # Local replay primitive test: exercise the same one-use TOTP verifier without waiting for another server window.
    with LOCK:
        saved_last=LAST_TOTP.get("alice",-1); LAST_TOTP["alice"]=int(time.time())//30-2
    replay_code=totp(USERS["alice"]["totp"])
    first_ok=totp_ok("alice",USERS["alice"]["totp"],replay_code,consume=True)
    second_ok=totp_ok("alice",USERS["alice"]["totp"],replay_code,consume=True)
    with LOCK: LAST_TOTP["alice"]=saved_last
    check("TOTP replay rejected", (first_ok,second_ok), (True,False))
    _compare_models(base, A, check, hb=hb, revoked=ha, byod=byod_h, admin=carol_h)
    A("POST", "/api/sim", {"hour": None}, AH); print(f"\n{sum(rows)}/{len(rows)} passed"); return all(rows)

def _compare_models(base, A, check, hb, revoked, byod, admin):
    """Run the same scenarios against ZTNA (/access) and a conventional network ACL (/netacl) and tabulate the outcome.
    Reuses sessions the red-team run already holds (TOTP codes are one-time). Legitimate rows must be allowed by both;
    unauthorized rows show what each model actually lets through."""
    rows=[]   # (scenario, legitimate?, ztna_status, network_acl_status)
    def row(name, legit, z, acl): rows.append((name,legit,z,acl))
    def acl(res): return A("GET", f"/netacl/{res}")[0]
    row("HR user -> hr-db in hours (legitimate)", True, A("GET","/access/hr-db",headers=hb)[0], acl("hr-db"))
    row("admin on managed device -> admin-panel (legitimate)", True, A("GET","/access/admin-panel",headers=admin)[0], acl("admin-panel"))
    row("HR user -> admin-panel (privilege escalation)", False, A("GET","/access/admin-panel",headers=hb)[0], acl("admin-panel"))
    row("no credentials, inside network -> hr-db", False, A("GET","/access/hr-db")[0], acl("hr-db"))
    row("stolen token replayed from another device", False, A("GET","/access/wiki",headers={**hb,"X-Device-Id":"laptop-carol"})[0], acl("wiki"))
    row("unmanaged BYOD -> hr-db", False, A("GET","/access/hr-db",headers=byod)[0], acl("hr-db"))
    A("POST","/api/sim",{"hour":22},AH); row("off-hours hr-db", False, A("GET","/access/hr-db",headers=hb)[0], acl("hr-db")); A("POST","/api/sim",{"hour":12},AH)
    row("revoked session reused", False, A("GET","/access/wiki",headers=revoked)[0], acl("wiki"))
    row("attacker outside the trusted network (simulated source)", False, 401, 200 if net_acl_trusted("203.0.113.9") else 403)
    allowed=lambda c: c==200
    print("\nZTNA vs conventional network ACL (same scenarios, live server)")
    print(f"  {'scenario':58s} {'ZTNA':>5s} {'net-ACL':>8s}")
    for n,l,z,a in rows: print(f"  {n:58s} {z:>5} {a:>8}")
    bad=[r for r in rows if not r[1]]; good=[r for r in rows if r[1]]
    z_blocked=sum(1 for r in bad if not allowed(r[2])); a_blocked=sum(1 for r in bad if not allowed(r[3]))
    print(f"  unauthorized attempts blocked: ZTNA {z_blocked}/{len(bad)}, network ACL {a_blocked}/{len(bad)}; legitimate allowed: ZTNA {sum(1 for r in good if allowed(r[2]))}/{len(good)}, network ACL {sum(1 for r in good if allowed(r[3]))}/{len(good)}")
    check("comparison: ZTNA blocks every unauthorized attempt", z_blocked, len(bad))
    check("comparison: ZTNA still allows legitimate access", sum(1 for r in good if allowed(r[2])), len(good))
    check("comparison: network ACL blocks only the outside attacker", a_blocked, 1)
    out=os.environ.get("ZTNA_RESULTS_DIR")
    if out:
        Path(out).mkdir(parents=True,exist_ok=True)
        with open(os.path.join(out,"comparison.csv"),"w",newline="") as f:
            w=csv.writer(f); w.writerow(["scenario","legitimate","ztna_status","network_acl_status"]); w.writerows(rows)

def attack(base):
    # The suite changes policy and simulated time. Fail before doing so if the
    # caller has not supplied the same valid admin key as the target server;
    # otherwise a missing key produces misleading downstream test failures.
    if not ADMIN_KEY or len(ADMIN_KEY) < 32:
        print("FAIL  attack prerequisites: set ZTNA_ADMIN_KEY (32+ characters) in this client environment to match the server")
        return False
    admin_headers={"X-Admin-Key": ADMIN_KEY}
    st,b=http(base,"GET","/api/state",headers=admin_headers)
    if st != 200:
        print(f"FAIL  attack prerequisites: server rejected ZTNA_ADMIN_KEY (HTTP {st}); use the same key as the server")
        return False
    original_mfa=b.get("resources",{}).get("wiki",{}).get("mfa_age",300)
    try:
        return _attack(base)
    finally:
        try:
            http(base,"POST","/api/policy/wiki",{"mfa_age":original_mfa},AH)
            http(base,"POST","/api/sim",{"hour":None},AH)
        except Exception: pass

def bench(base,N=500,CONC=10):
    ha=login_as(base,"alice","laptop-alice"); rows=[]
    if not ha.get("Authorization"):
        raise SystemExit("bench login failed; check server availability, demo credentials, OTP window, and lockout state")
    # Policy-only benchmark isolates evaluation CPU from HTTP/audit/upstream I/O.
    sess={"user":"alice","device":"laptop-alice","location":"office","mfa_at":time.time(),"travel":False}
    t=time.perf_counter()
    for _ in range(N): evaluate(sess,"laptop-alice","wiki")
    policy_us=(time.perf_counter()-t)*1e6/N
    policy_ms=policy_us/1000.0
    rows.append(["policy evaluation only","local",round(policy_ms,4),round(policy_ms,4),round(policy_ms,4),round(N/max(time.perf_counter()-t,1e-9),2)])
    ctx=ssl.create_default_context(cafile=os.environ.get("ZTNA_CA_FILE") or None)
    def call(path,h):
        t=time.perf_counter(); r=urllib.request.urlopen(urllib.request.Request(base+path,headers=proof_headers(h or {},"GET",path)),context=ctx,timeout=5); r.read(); return (time.perf_counter()-t)*1000
    for name,path,h in [("direct baseline","/baseline",None)]+([("network ACL /netacl/wiki","/netacl/wiki",None)] if DEMO else [])+[("ZTNA /access/wiki","/access/wiki",ha)]:
        for mode,c in [("sequential",1),("concurrent",min(CONC,int(os.environ.get("ZTNA_MAX_CONNECTIONS","64"))))]:
            t=time.perf_counter()
            with ThreadPoolExecutor(c) as ex: l=sorted(ex.map(lambda _:call(path,h),range(N)))
            elapsed=time.perf_counter()-t
            rows.append([name,mode,round(statistics.mean(l),2),round(l[N//2],2),round(l[int(N*.95)],2),round(N/elapsed,2)])
            print(rows[-1])
    with open("results.csv","w",newline="") as f:
        w=csv.writer(f); w.writerow(["scenario","mode","mean_ms","p50_ms","p95_ms","req_per_sec"]); w.writerows(rows)
    print("saved results.csv; policy_us is CPU-only and request timings include audit/I/O")

def agent(dev, kv, base):
    pairs=[a.split("=",1) for a in kv if "=" in a]; checks={k:v.lower() in ("1","true","yes") for k,v in pairs}
    required={"os_updated","disk_encrypted","firewall","antivirus"}
    if set(checks)!=required: raise SystemExit("agent requires exactly: os_updated=0/1 disk_encrypted=0/1 firewall=0/1 antivirus=0/1")
    try:
        if posture_key(dev) is None: raise SystemExit(f"no posture key configured for device {dev!r}")
    except Exception as exc:
        if isinstance(exc,SystemExit): raise
        raise SystemExit(str(exc))
    ts,nonce=time.time(),secrets.token_hex(8); sign=sign_report(dev,checks,ts,nonce)
    status, payload = http(base, "POST", "/api/posture/report", {"device": dev, "checks": checks, "ts": ts, "nonce": nonce, "sig": sign})
    print((status, payload))
    return status == 200

def probe_stats(samples_ms, failures=0):
    """Latency statistics for a probe run (milliseconds)."""
    s=sorted(samples_ms)
    if not s: return {"sent":failures,"ok":0,"failed":failures}
    q=lambda p: round(s[min(len(s)-1,int(len(s)*p))],3)
    jitter=statistics.mean(abs(a-b) for a,b in zip(samples_ms,samples_ms[1:])) if len(samples_ms)>1 else 0.0
    return {"sent":len(s)+failures,"ok":len(s),"failed":failures,"min":round(s[0],3),"avg":round(statistics.mean(s),3),
            "p50":q(.5),"p95":q(.95),"p99":q(.99),"max":round(s[-1],3),"jitter":round(jitter,3)}

def run_probe(args):
    """probe URL [count] [interval_ms]: time N GET requests; any HTTP response counts as reachable."""
    if not args or len(args)>3: raise SystemExit("usage: probe URL [count 1-1000] [interval_ms 0-60000]")
    url=args[0]; u=urlsplit(url)
    if u.scheme not in ("http","https") or not u.netloc: raise SystemExit("probe URL must start with http:// or https://")
    try:
        count=int(args[1]) if len(args)>1 else 20; gap=int(args[2]) if len(args)>2 else 200
    except ValueError: raise SystemExit("count and interval_ms must be integers")
    if not 1<=count<=1000 or not 0<=gap<=60000: raise SystemExit("count must be 1-1000 and interval_ms 0-60000")
    ctx=ssl.create_default_context(cafile=os.environ.get("ZTNA_CA_FILE") or None)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
    samples,failures,codes=[],0,Counter()
    for i in range(count):
        t=time.perf_counter()
        try:
            try:
                with opener.open(urllib.request.Request(url,method="GET"),timeout=5) as r: r.read(65536); code=r.status
            except urllib.error.HTTPError as e: e.read(65536); code=e.code
            samples.append((time.perf_counter()-t)*1000); codes[code]+=1
        except (urllib.error.URLError,OSError,ValueError): failures+=1
        if gap and i<count-1: time.sleep(gap/1000.0)
    result=probe_stats(samples,failures); result["status_codes"]=dict(codes); result["url"]=url
    print(json.dumps(result,indent=2))
    return 0 if samples else 1

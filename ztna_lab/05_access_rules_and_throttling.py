# Part 05 of ztna.py - RBAC and micro-segments, temporary grants, policy load/save, device posture score, login throttling.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

SEGMENTS={r:v["segment"] for r,v in RESOURCES.items()}
SEGMENT_ALLOW={role:{v["segment"] for v in RESOURCES.values() if role in v["roles"]} for role in ROLES}
def _temporary_resource_grant(user, resource):
    expiry = TEMP_RESOURCE_GRANTS.get((user, resource), 0)
    if expiry > time.time(): return True
    if expiry: TEMP_RESOURCE_GRANTS.pop((user, resource), None)
    return False

def rbac_allows(user,resource):
    return bool(user in USERS and resource in RESOURCES and (USERS[user].get("role") in RESOURCES[resource]["roles"] or _temporary_resource_grant(user, resource)))
def segment_allows(user,resource):
    return bool(user in USERS and resource in RESOURCES and (SEGMENTS[resource] in SEGMENT_ALLOW.get(USERS[user].get("role"),set()) or _temporary_resource_grant(user, resource)))
def validate_policy_data(data):
    if not isinstance(data,dict): raise ValueError("policy must be object")
    for r,v in data.items():
        if r not in RESOURCES or not isinstance(v,dict): continue
        if "min_posture" in v and (type(v["min_posture"]) is not int or not 0 <= v["min_posture"] <= 100): raise ValueError("bad min_posture")
        if "mfa_age" in v and (type(v["mfa_age"]) is not int or v["mfa_age"] < 0): raise ValueError("bad mfa_age")
        if "managed" in v and type(v["managed"]) is not bool: raise ValueError("bad managed")
        if "hours" in v and (not isinstance(v["hours"],list) or len(v["hours"]) != 2 or any(type(x) is not int for x in v["hours"]) or not all(0 <= x <= 24 for x in v["hours"]) or v["hours"][0] == v["hours"][1]): raise ValueError("bad hours")

def validate_policy_patch(resource,data):
    if resource not in RESOURCES or not isinstance(data,dict): raise ValueError("unknown resource")
    current=RESOURCES[resource]
    merged={k:current[k] for k in POLICY_KEYS}
    for k in POLICY_KEYS:
        if k in data: merged[k]=data[k]
    validate_policy_data({resource:merged})
    return merged

def save_policy():
    data={r:{k:v[k] for k in POLICY_KEYS} for r,v in RESOURCES.items()}
    with LOCK: _atomic_json_replace(POLICY_FILE,data)

def load_policy():
    try:
        with open(POLICY_FILE,encoding="utf-8") as f: data=json.load(f)
    except FileNotFoundError: return
    except (OSError,ValueError,TypeError): raise SystemExit("policy.json is corrupt: refusing to start with defaults")
    validate_policy_data(data)
    for r,v in data.items():
        if r in RESOURCES: RESOURCES[r].update({k:v[k] for k in POLICY_KEYS if k in v})

POSTURE_TTL=300
def posture(dev):
    d=DEVICES.get(dev)
    if d is None: return 0                      # an unknown device has no posture (callers used to get a KeyError)
    if POSTURE_TTL>0 and time.time()-d.get("last_report",0)>POSTURE_TTL: return 0
    return sum(w for k,w in POSTURE_W.items() if d.get(k))
now_hour = lambda: SIM["hour"] if SIM["hour"] is not None else datetime.now(LOCAL_TZ).hour
def recent_fails(u,ip=None):
    n=time.time(); key=fkey(u,ip) if ip is not None else (u,None)
    return sum(1 for t in list(USERFAIL.get(key,())) if n-t<600)
fkey = lambda u, ip: (u if u in USERS else "?", ip)
def note_fail(u, ip):
    now=time.time()
    with LOCK:
        k=fkey(u,ip)
        USERFAIL.setdefault(k,deque(maxlen=50)).append(now)
        if u in USERS: USERFAIL.setdefault((u,None),deque(maxlen=100)).append(now)
        count,until,last=FAILS.get(k,(0,0,now))
        # A failed fifth attempt triggers a fixed hard cooldown for this source/user
        # pair; it does not lock the account globally and leak account existence.
        if count>=5:
            FAILS[k]=(count,now+_env_float("ZTNA_AUTH_HARD_LOCK_SECONDS",60.0),now)

AUTH_PRUNE_LAST=0.0

def reserve_auth_attempt(u, ip):
    global AUTH_PRUNE_LAST
    now=time.time(); k=fkey(u,ip)
    with LOCK:
        # Expensive whole-table cleanup runs at most once per 10 seconds.
        if now-AUTH_PRUNE_LAST>=10.0:
            for key,(count,until,last) in list(FAILS.items()):
                if (now-last > 600 and now >= until) or count <= 0: FAILS.pop(key,None)     # never drop an active lock
            for key,q in list(USERFAIL.items()):
                while q and now-q[0]>=600: q.popleft()
                if not q: USERFAIL.pop(key,None)
            for user,(loc,ts) in list(LASTLOC.items()):
                if now-ts>3600: LASTLOC.pop(user,None)
            AUTH_PRUNE_LAST=now
        count,until,last=FAILS.get(k,(0,0,now))
        # Ten quiet minutes reset the counter, but not while a hard lock is still running: a ZTNA_AUTH_HARD_LOCK_SECONDS
        # above 600 used to be cut short to 600 s.
        if now-last>600 and now>=until:
            count=0
            FAILS.pop(k,None)
            until=0
        if now<until: return False
        if now-last > 600: count=0
        # Reserve the attempt before password verification. Exponential backoff
        # prevents parallel guesses from racing through the five-attempt limit.
        next_count=count+1
        # The exponent is capped: 2.0**1024 raises OverflowError, which after ~1,000 throttled guesses turned every
        # further attempt (including the real user's) into an internal error.
        base=max(0.05,_env_float("ZTNA_AUTH_BACKOFF_BASE",0.25)); backoff=min(8.0,base*(2.0**min(max(0,next_count-1),16)))
        FAILS[k]=(next_count,now+backoff,now)
        return True

def release_auth_attempt(u, ip):
    with LOCK:
        k=fkey(u,ip)
        FAILS.pop(k,None)

def refund_auth_attempt(u, ip):
    """Undo only the current reservation after KDF saturation, preserving history."""
    now=time.time(); k=fkey(u,ip)
    with LOCK:
        count,until,last=FAILS.get(k,(0,0,now))
        count=max(0,count-1)
        if count==0:
            FAILS.pop(k,None)
        else:
            # Drop only the short backoff this reservation set; an active hard lock (longer than any backoff) stays.
            FAILS[k]=(count,until if until-now>8.0 else now,now)

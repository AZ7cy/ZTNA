# Part 02 of ztna.py - crypto helpers, JWT, TOTP, password hashing, device posture keys, device-proof message format.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ---------- crypto helpers ----------
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
sha_bytes = lambda b: hashlib.sha256(b).hexdigest()

def _ensure_demo_jwt_key():
    global JWT_KEY, JWT_KEYS
    if os.environ.get("ZTNA_JWT_KEYS") or os.environ.get("ZTNA_JWT_KEY"): return
    path=os.path.join(DATA_DIR,"demo_jwt.key")
    try:
        raw=Path(path).read_bytes()
        if len(raw)==32:
            JWT_KEY=raw; JWT_KEYS={"default": raw}; return
    except FileNotFoundError: pass
    candidate=secrets.token_bytes(32)
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except FileExistsError:
        # Another process initialized the shared demo data directory first.
        raw=Path(path).read_bytes()
        if len(raw)!=32: raise SystemExit("demo JWT key file is corrupt")
        JWT_KEY=raw; JWT_KEYS={"default": raw}
        return
    with os.fdopen(fd,"wb") as f: f.write(candidate); f.flush(); os.fsync(f.fileno())
    _fsync_dir(path)
    JWT_KEY=candidate; JWT_KEYS={"default": candidate}

def _session_master_key():
    """Load a dedicated session PoP master key; never reuse the JWT signing key in production."""
    wk=os.environ.get("ZTNA_SESSION_WRAP_KEY")
    if not wk:
        if not DEMO: raise RuntimeError("production requires ZTNA_SESSION_WRAP_KEY")
        return hmac.new(JWT_KEY,b"ztna-session-pop-master",hashlib.sha256).digest()
    try: key=bytes.fromhex(wk)
    except ValueError: raise RuntimeError("ZTNA_SESSION_WRAP_KEY must be 64 hex characters")
    if len(key)!=32: raise RuntimeError("ZTNA_SESSION_WRAP_KEY must be 64 hex characters")
    return key

def _new_session_salt():
    return b64(secrets.token_bytes(16))

def _derive_session_key(sid, salt):
    raw_salt=unb64(salt) if isinstance(salt,str) else bytes(salt)
    if len(raw_salt)!=16: raise ValueError("invalid session salt")
    return hmac.new(_session_master_key(),b"pop|"+str(sid).encode()+b"|"+raw_salt,hashlib.sha256).digest()

def jwt_encode(claims):
    kid = JWT_ACTIVE_KID
    key = JWT_KEYS.get(kid, JWT_KEY)
    h, p = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}, separators=(",", ":")).encode()), b64(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64(hmac.new(key, f'{h}.{p}'.encode(), hashlib.sha256).digest())}"

def jwt_decode(tok):
    if not _RUNTIME_READY:
        return None
    if not DEMO and not (os.environ.get("ZTNA_JWT_KEYS") or len(os.environ.get("ZTNA_JWT_KEY", "")) >= 64):
        return None
    try:
        h, p, sig = tok.split(".")
        header = json.loads(unb64(h))
        if header.get("alg") != "HS256": return None
        kid = header.get("kid", "default")
        key = JWT_KEYS.get(kid)
        # No fallback for an unknown kid: this prevents key-ID downgrade behavior.
        if key is None: return None
        expected = b64(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected): return None
        c = json.loads(unb64(p))
        return c if isinstance(c, dict) and isinstance(c.get("exp"), (int, float)) and c["exp"] > time.time() else None
    except Exception:
        return None

def _ct_eq(a, b):
    """Constant-time equality for text. hmac.compare_digest on str raises TypeError for any non-ASCII character, which made
    passwords such as "pässwort" impossible to confirm and turned a non-ASCII manager login into an HTTP 500."""
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))

def totp(secret_b32, t=None, step=30):
    raw=str(secret_b32).strip().replace(" ","").upper(); raw += "="*((8-len(raw)%8)%8)
    ctr=struct.pack(">Q",int((time.time() if t is None else t)//step))
    d=hmac.new(base64.b32decode(raw,casefold=True),ctr,hashlib.sha1).digest(); o=d[-1]&15
    return f"{(struct.unpack('>I',d[o:o+4])[0]&0x7fffffff)%10**6:06d}"

def totp_ok(user,secret,code,consume=True,persist=None):
    code=str(code)
    if not re.fullmatch(r"[0-9]{6}",code): return False
    ctr=int(time.time())//30
    if persist is None: persist = _RUNTIME_MODE not in {"attack","bench","agent"}
    with LOCK:
        last=LAST_TOTP.get(user,-1); matched=None
        for w in (-1,0,1):
            c=ctr+w
            if c>last and hmac.compare_digest(totp(secret,c*30),code): matched=c; break
        if matched is None: return False
        if consume:
            if persist:
                # Save first: a code must never be spent in memory only, or a crash/restart would make it replayable.
                try: _atomic_json_replace(TOTP_STATE_FILE,{**LAST_TOTP,user:matched})
                except OSError as exc:
                    logger.error("TOTP replay state could not be saved; refusing the code: %s",exc)
                    raise StateStoreError("authentication state store unavailable") from None
            LAST_TOTP[user]=matched
        return True

def demo_totp_code(user):
    if not DEMO_OTP: raise RuntimeError("demo OTP generation disabled")
    nowctr=int(time.time())//30
    last=LAST_TOTP.get(user,-1)
    for c in (nowctr,nowctr+1):
        if c>last and c >= nowctr-1 and c <= nowctr+1:
            return totp(USERS[user]["totp"],c*30)
    return None

def _load_totp_state():
    try:
        with open(TOTP_STATE_FILE,encoding="utf-8") as f: raw=json.load(f)
        if not isinstance(raw,dict) or any(not isinstance(k,str) or type(v) is not int for k,v in raw.items()): raise ValueError
        return raw
    except FileNotFoundError: return {}
    except (OSError,ValueError,TypeError): raise SystemExit("TOTP state is corrupt: refusing to start")

LAST_TOTP={}

def _fsync_dir(path):
    try:
        fd=os.open(os.path.dirname(os.path.abspath(path)) or ".",os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    except OSError: pass

def _replace_file(src, dst, attempts=40, delay=0.025):
    """os.replace() that survives a short-lived reader on Windows. There, renaming onto (or away from) a file that
    another handle has open (the audit verifier, an antivirus or backup scan) fails with PermissionError instead of
    replacing it underneath the reader, so retry for up to about a second before giving up."""
    for attempt in range(attempts):
        try:
            os.replace(src, dst); return
        except PermissionError:
            if os.name != "nt" or attempt == attempts - 1: raise
            time.sleep(delay)

def _save_totp_state_locked():
    _atomic_json_replace(TOTP_STATE_FILE,LAST_TOTP)

SCRYPT_N = 2**15  # 32 MiB per operation; bounded by PBKDF_SEM to limit memory pressure.
SCRYPT_R = 8
SCRYPT_P = 1

def pw_hash(pw, salt=None, *, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    salt = salt or secrets.token_bytes(16)
    if not PBKDF_SEM.acquire(timeout=_env_float("ZTNA_KDF_WAIT_SECONDS",2.0)):
        raise RuntimeError("authentication capacity temporarily unavailable")
    try:
        if hasattr(hashlib,"scrypt"):
            got=hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=128*1024*1024).hex()
        else:
            got=hashlib.pbkdf2_hmac("sha256",pw.encode(),salt,600000).hex()
    finally:
        PBKDF_SEM.release()
    return got,salt.hex()

def _pw_record(password):
    digest, salt = pw_hash(password)
    return {"hash": digest, "salt": salt, "kdf": "scrypt" if hasattr(hashlib, "scrypt") else "pbkdf2_sha256",
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P} if hasattr(hashlib, "scrypt") else {"hash": digest, "salt": salt, "kdf": "pbkdf2_sha256", "iterations": 600000}

class KdfBusy(RuntimeError):
    """KDF worker capacity is temporarily exhausted; credentials were not checked."""

def pw_verify(pw, stored):
    try:
        if not isinstance(stored, dict): return False
        salt = bytes.fromhex(stored["salt"]); expected = stored["hash"]
        if not isinstance(expected, str) or len(expected) not in (64, 128) or not re.fullmatch(r"[0-9a-fA-F]+", expected): return False
        kdf = stored.get("kdf", "scrypt")
        legacy = "kdf" not in stored or "n" not in stored
        if not PBKDF_SEM.acquire(timeout=_env_float("ZTNA_KDF_WAIT_SECONDS",2.0)):
            raise KdfBusy("authentication capacity temporarily unavailable")
        try:
            if kdf == "scrypt" and hasattr(hashlib,"scrypt"):
                n = int(stored.get("n", 2**14)); r = int(stored.get("r", 8)); p = int(stored.get("p", 1))
                if n < 2**14 or n > 2**18 or n & (n-1) or not 1 <= r <= 16 or not 1 <= p <= 4: return False
                got=hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=128*1024*1024).hex()
            elif kdf == "pbkdf2_sha256":
                iterations=int(stored.get("iterations",600000))
                if not 100000 <= iterations <= 2000000: return False
                got=hashlib.pbkdf2_hmac("sha256",pw.encode(),salt,iterations).hex()
            else: return False
        finally:
            PBKDF_SEM.release()
        if not hmac.compare_digest(got, expected.lower()): return False
        # Transparently upgrade legacy scrypt (N=2**14) records after a valid login.
        if hasattr(hashlib, "scrypt") and (legacy or kdf != "scrypt" or int(stored.get("n",0)) < SCRYPT_N):
            try: fresh_hash, fresh_salt = pw_hash(pw)
            except RuntimeError: return True              # the upgrade is optional: a correct password must never fail for lack of KDF capacity
            stored.update({"hash": fresh_hash, "salt": fresh_salt, "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P})
        return True
    except (KeyError, ValueError, TypeError, OverflowError): return False

POSTURE_KEYS = {}
def _demo_posture_keys():
    path=os.path.join(DATA_DIR,"device_keys.json")
    # The cross-process lock ensures two client/server processes cannot replace
    # each other's freshly generated keyset.
    with _file_lock(path):
        try:
            with open(path,encoding="utf-8") as f:
                data=json.load(f)
            if not isinstance(data,dict): raise SystemExit("demo device key file is corrupt")
        except FileNotFoundError:
            data={}
        missing=[d for d in FIXTURE_DEVICES if d not in data]       # first run, or an older 4-device key file
        if missing or not os.path.exists(path):
            data.update({d:secrets.token_hex(32) for d in missing})
            _atomic_json_replace(path,data)
        return {k:bytes.fromhex(v) for k,v in data.items()}

def managed_device(dev):
    allowed={x.strip() for x in os.environ.get("ZTNA_MANAGED_DEVICES","").split(",") if x.strip()}
    return dev in allowed

def posture_key(dev):
    if not re.fullmatch(r"[a-z0-9-]{1,64}",str(dev)): return None
    if DEMO:
        if not POSTURE_KEYS: POSTURE_KEYS.update(_demo_posture_keys())
        return POSTURE_KEYS.get(dev)
    k=os.environ.get("ZTNA_POSTURE_KEY_"+dev.upper().replace("-","_"))
    if not k: return None
    try:
        raw=bytes.fromhex(k)
        return raw if len(raw)>=32 else None
    except ValueError: return None

def sign_report(dev,checks,ts,nonce):
    key=posture_key(dev)
    if key is None: raise ValueError("no per-device posture key configured")
    return hmac.new(key,f"{dev}|{ts}|{nonce}|{json.dumps(checks,sort_keys=True)}".encode(),hashlib.sha256).hexdigest()

# ---------- device proof canonical input ----------
EMPTY_SHA256=hashlib.sha256(b"").hexdigest()
PROOF_NONCE_RE=re.compile(r"[A-Za-z0-9_-]{8,128}")
PROOF_DIGEST_RE=re.compile(r"[0-9a-f]{64}")
def proof_message(method,target,body_sha256,ts,nonce):
    """Canonical device-proof input (v2): method, FULL request target (path + query exactly as sent), SHA-256 of the
    body, timestamp and nonce, newline-separated. Neither method, target nor the validated digest/nonce can contain a
    newline, so fields cannot be shifted into one another."""
    return "\n".join(("ztna-pop-v2",method,target,body_sha256,f"{ts:.3f}",nonce)).encode()

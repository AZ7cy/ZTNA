# Part 03 of ztna.py - roles and demo roster, file locks, atomic JSON writes, TOTP secret encryption, user and device stores.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ---------- roster: roles, people, devices (demo) ----------
ROLES = {  # role -> plain-English description (what the role is for)
    "engineer":  "Builds the product. Reads and writes source code; uses the wiki.",
    "devops":    "Runs build/release pipelines and infrastructure; also reads source code.",
    "security":  "Security team. Monitors the SIEM, supports tickets, reviews source code.",
    "hr":        "People team. Owns employee records (HR database).",
    "finance":   "Finance team. Owns the general ledger and sees executive reports.",
    "sales":     "Sells to customers. Works in the CRM.",
    "support":   "Customer support. Works the support desk and can look up CRM accounts.",
    "legal":     "Legal team. Owns contracts in the legal vault.",
    "executive": "Leadership. Reads executive reports, finance, legal and CRM data.",
    "admin":     "IT administrator. Full access to every system.",
}
# (username, role, display name, job title, department)
ROSTER = (
    ("alice", "engineer",  "Alice Nguyen",    "Senior Software Engineer", "Engineering"),
    ("bob",   "hr",        "Bob Martins",     "HR Business Partner",      "People"),
    ("carol", "admin",     "Carol Diaz",      "IT Administrator",         "IT"),
    ("mia",   "sales",     "Mia Rossi",       "Account Executive",        "Sales"),
    ("dave",  "devops",    "Dave Okafor",     "Platform Engineer",        "Infrastructure"),
    ("erin",  "security",  "Erin Walsh",      "Security Analyst",         "Security"),
    ("frank", "finance",   "Frank Mueller",   "Financial Controller",     "Finance"),
    ("grace", "legal",     "Grace Kim",       "Corporate Counsel",        "Legal"),
    ("henry", "executive", "Henry Adler",     "Chief Operating Officer",  "Leadership"),
    ("ivy",   "support",   "Ivy Chen",        "Support Lead",             "Customer Support"),
    ("jack",  "engineer",  "Jack Patel",      "Backend Engineer",         "Engineering"),
    ("kate",  "sales",     "Kate O'Brien",    "Sales Manager",            "Sales"),
    ("leo",   "devops",    "Leo Fernandez",   "Site Reliability Engineer","Infrastructure"),
    ("nina",  "finance",   "Nina Petrova",    "Accounts Payable Analyst", "Finance"),
    ("omar",  "security",  "Omar Haddad",     "SOC Engineer",             "Security"),
    ("priya", "hr",        "Priya Sharma",    "Talent Acquisition Lead",  "People"),
    ("quinn", "support",   "Quinn Baker",     "Support Agent",            "Customer Support"),
    ("raj",   "engineer",  "Raj Menon",       "Frontend Engineer",        "Engineering"),
    ("sara",  "admin",     "Sara Lindqvist",  "Systems Administrator",    "IT"),
    ("tom",   "sales",     "Tom Becker",      "Sales Development Rep",    "Sales"),
)
USER_PROFILE = {u: {"name": n, "title": t, "dept": d} for u, _r, n, t, d in ROSTER}
SEED_USERS = tuple((u, r) for u, r, *_ in ROSTER)

def _fixture_devices():
    """Demo endpoints: one laptop per employee plus a few personal (BYOD) devices with weaker health, so the
    demo shows different outcomes for different people."""
    ok = dict.fromkeys(("os_updated", "disk_encrypted", "firewall", "antivirus", "corporate_managed"), True)
    out = {f"laptop-{u}": {"owner": u, **ok} for u, *_ in ROSTER}
    out["laptop-kate"]["antivirus"] = False                      # score 85: fine for most, not for 90+ systems
    out["laptop-tom"]["os_updated"] = False                      # score 75
    out["laptop-nina"]["disk_encrypted"] = False                 # score 75
    out["laptop-quinn"]["corporate_managed"] = False             # healthy but not company-managed
    out["byod-bob"] = {"owner": "bob", **ok, "disk_encrypted": False, "antivirus": False, "corporate_managed": False}
    out["byod-ivy"] = {"owner": "ivy", **ok, "firewall": False, "antivirus": False, "corporate_managed": False}
    out["byod-jack"] = {"owner": "jack", **ok, "os_updated": False, "corporate_managed": False}
    out["byod-mia"] = {"owner": "mia", **ok, "disk_encrypted": False, "corporate_managed": False}
    return out
FIXTURE_DEVICES = _fixture_devices()
DEMO_PASSWORD_HINT = "random password printed once during demo account provisioning"

# ---------- data model ----------
@contextmanager
def _file_lock(path, timeout=None):
    """Cross-process advisory lock for read/modify/replace file updates.
    timeout=None blocks (original behaviour); a number of seconds raises TimeoutError instead of waiting forever."""
    lock_path = path + ".lock"
    Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            # LK_LOCK is not a blocking lock: it retries 10 times, once a second, then raises OSError ("Resource
            # deadlock avoided"). Poll LK_NBLCK instead; with timeout=None there is no deadline.
            deadline = None if timeout is None else time.monotonic() + timeout
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out waiting for lock {lock_path}") from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            if timeout is None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError(f"timed out waiting for lock {lock_path}") from None
                        time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _atomic_json_replace(path, data):
    tmp = path + f".tmp.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        _replace_file(tmp, path)
        _fsync_dir(path)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def _totp_wrap_key():
    """Dedicated AES-GCM key. Production uses ZTNA_SESSION_WRAP_KEY; demo mode uses a 0600 local key file."""
    configured = os.environ.get("ZTNA_SESSION_WRAP_KEY", "").strip()
    if configured:
        try: key = bytes.fromhex(configured)
        except ValueError: raise RuntimeError("ZTNA_SESSION_WRAP_KEY must be 64 hex characters") from None
        if len(key) != 32: raise RuntimeError("ZTNA_SESSION_WRAP_KEY must be 64 hex characters")
        return key
    if not DEMO: raise RuntimeError("production requires ZTNA_SESSION_WRAP_KEY to encrypt TOTP secrets")
    path = os.path.join(DATA_DIR, "totp_wrap.key")
    try:
        key = Path(path).read_bytes()
        if len(key) != 32: raise SystemExit("TOTP wrapping key is corrupt")
        return key
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = Path(path).read_bytes()
            if len(key) != 32: raise SystemExit("TOTP wrapping key is corrupt")
            return key
        with os.fdopen(fd, "wb") as f: f.write(key); f.flush(); os.fsync(f.fileno())
        _fsync_dir(path)
        return key

CRYPTOGRAPHY_MISSING = ("the 'cryptography' package is required: it encrypts the stored authenticator (TOTP) secrets. "
                        "Install it with:  python -m pip install cryptography")

def _cryptography_available():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except ImportError:
        return False

def _encrypt_totp(secret):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError(CRYPTOGRAPHY_MISSING) from None
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(_totp_wrap_key()).encrypt(nonce, str(secret).encode(), b"ztna-totp-v1")
    return "v1:" + base64.urlsafe_b64encode(nonce + cipher).decode().rstrip("=")

def _decrypt_totp(value):
    if not isinstance(value, str): raise ValueError("invalid TOTP secret")
    if not value.startswith("v1:"): return value  # one-time migration of legacy plaintext files
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:            # used to be reported as a wrong wrapping key
        raise SystemExit(f"cannot decrypt TOTP secrets: {CRYPTOGRAPHY_MISSING}") from None
    try:
        blob = base64.urlsafe_b64decode(value[3:] + "=" * ((4-len(value[3:])%4)%4))
        if len(blob) < 29: raise ValueError
        return AESGCM(_totp_wrap_key()).decrypt(blob[:12], blob[12:], b"ztna-totp-v1").decode()
    except Exception:
        raise SystemExit("cannot decrypt TOTP secret: check ZTNA_SESSION_WRAP_KEY / local wrapping key") from None

def _decode_user_records(raw):
    if not isinstance(raw, dict): raise SystemExit("users file is corrupt")
    decoded = {}
    migrated = False
    for username, rec in raw.items():
        if not isinstance(rec, dict): raise SystemExit("users file is corrupt")
        item = dict(rec)
        if "totp_enc" in item:
            item["totp"] = _decrypt_totp(item.pop("totp_enc"))
        elif "totp" in item:
            item["totp"] = _decrypt_totp(item["totp"])
            migrated = True
        decoded[username] = item
    return decoded, migrated

def _encode_user_records(raw):
    encoded = {}
    for username, rec in raw.items():
        item = dict(rec)
        secret = item.pop("totp", None)
        if secret is None and "totp_enc" in item:
            encoded[username] = item
            continue
        if secret is not None: item["totp_enc"] = _encrypt_totp(secret)
        encoded[username] = item
    return encoded

DEMO_BOOTSTRAP_CREDENTIALS = []

def _load_or_create_demo_users():
    path=os.path.join(DATA_DIR,"demo_users.json")
    with _file_lock(path):
        try:
            with open(path,encoding="utf-8") as f: stored=json.load(f)
            data, migrated = _decode_user_records(stored)
            added=False
            for u,role in SEED_USERS:
                # Rotate accounts provisioned by the old predictable username+123 scheme.
                pwrec = data.get(u, {}).get("pw", {}) if isinstance(data.get(u), dict) else {}
                old_demo_password = not pwrec.get("kdf") or int(pwrec.get("n", 0) or 0) < SCRYPT_N
                if u not in data or (old_demo_password and os.environ.get("ZTNA_DEMO_FIXED_CREDENTIALS") != "1"):
                    password = (u + "123") if os.environ.get("ZTNA_DEMO_FIXED_CREDENTIALS") == "1" else secrets.token_urlsafe(18)
                    data[u]={"pw":_pw_record(password),"role":role,"totp":data.get(u,{}).get("totp",base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))}
                    if os.environ.get("ZTNA_DEMO_FIXED_CREDENTIALS") != "1":
                        DEMO_BOOTSTRAP_CREDENTIALS.append((u, password, role, data[u]["totp"]))
                    added=True
            if added or migrated: _atomic_json_replace(path,_encode_user_records(data))
            return data
        except FileNotFoundError:
            pass
        data={}
        fixed = os.environ.get("ZTNA_DEMO_FIXED_CREDENTIALS") == "1"
        for u,role in SEED_USERS:
            password = (u + "123") if fixed else secrets.token_urlsafe(18)
            data[u]={"pw":_pw_record(password),"role":role,"totp":base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")}
            if not fixed:
                DEMO_BOOTSTRAP_CREDENTIALS.append((u, password, role, data[u]["totp"]))
        _atomic_json_replace(path,_encode_user_records(data))
        return data

def load_users():
    if DEMO:
        raw=_load_or_create_demo_users()
        for u,v in raw.items():
            try: base64.b32decode(v["totp"]+"="*((8-len(v["totp"])%8)%8),casefold=True)
            except Exception: raise SystemExit("demo users file is corrupt")
        return raw
    try:
        with open(USERS_FILE,encoding="utf-8") as f: raw=json.load(f)
        raw, migrated_totp = _decode_user_records(raw)
        if migrated_totp: _atomic_json_replace(USERS_FILE, _encode_user_records(raw))
    except FileNotFoundError:
        bu=os.environ.get("ZTNA_BOOTSTRAP_USER"); br=os.environ.get("ZTNA_BOOTSTRAP_ROLE","admin"); bp=os.environ.get("ZTNA_BOOTSTRAP_PASSWORD"); bt=os.environ.get("ZTNA_BOOTSTRAP_TOTP")
        if not (bu and bp and bt): raise SystemExit("production requires ZTNA_USERS_FILE or complete bootstrap credentials")
        if len(bp)<8: raise SystemExit("bootstrap password must be at least 8 characters")
        if br not in ROLES: raise SystemExit("invalid bootstrap role")
        pwrec=_pw_record(bp); secret=bt.strip().replace(" ","").upper().rstrip("=")
        try: base64.b32decode(secret+"="*((8-len(secret)%8)%8),casefold=True)
        except Exception: raise SystemExit("invalid bootstrap TOTP secret")
        raw={bu:{"pw":pwrec,"role":br,"totp":secret}}
        Path(USERS_FILE).parent.mkdir(parents=True,exist_ok=True)
        _atomic_json_replace(USERS_FILE,_encode_user_records(raw))
    except (OSError,ValueError): raise SystemExit("users file is corrupt: refusing to start")
    out={}
    for u,v in raw.items():
        if not isinstance(u,str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}",u) or not isinstance(v,dict): raise SystemExit("invalid users file")
        if not isinstance(v.get("pw"),dict) or not isinstance(v.get("role"),str) or not isinstance(v.get("totp"),str): raise SystemExit("invalid users file")
        out[u]={"pw":v["pw"],"role":v["role"],"totp":v["totp"]}
    return out

USERS = {}

POSTURE_LABELS = {"os_updated": "Operating system up to date", "disk_encrypted": "Disk is encrypted", "firewall": "Firewall is on",
                  "antivirus": "Antivirus running", "corporate_managed": "Company-managed device (MDM)"}
POSTURE_W = {"os_updated": 25, "disk_encrypted": 25, "firewall": 15, "antivirus": 15, "corporate_managed": 20}
_ok = dict.fromkeys(POSTURE_W, True)
DEVICES = {d: {**v, "last_report": 0.0} for d, v in FIXTURE_DEVICES.items()} if DEMO else {}   # no report until a login from that device


def _device_store_path():
    return os.path.join(DATA_DIR, "devices.json")

def _device_keys_path():
    return os.path.join(DATA_DIR, "device_keys.json")

def load_persisted_devices():
    """Load locally enrolled demo devices without replacing built-in lab fixtures."""
    path = _device_store_path()
    try:
        with open(path, encoding="utf-8") as f:
            records = json.load(f)
    except FileNotFoundError:
        return
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"device registry is corrupt: {exc}") from None
    if not isinstance(records, dict):
        raise RuntimeError("device registry is corrupt: expected an object")
    for device_id, item in records.items():
        if not re.fullmatch(r"[a-z0-9-]{1,64}", str(device_id)) or not isinstance(item, dict):
            continue
        owner = item.get("owner")
        if not isinstance(owner, str) or owner not in USERS:
            continue
        record = {"owner": owner, "last_report": float(item.get("last_report", time.time()))}
        for field in POSTURE_W:
            record[field] = bool(item.get(field, False))
        DEVICES[device_id] = record

def save_persisted_devices():
    """Persist only custom devices; built-in lab devices remain source-defined fixtures."""
    builtins = set(FIXTURE_DEVICES)
    records = {}
    for device_id, item in DEVICES.items():
        if device_id in builtins:
            continue
        records[device_id] = {"owner": item["owner"], **{k: bool(item.get(k, False)) for k in POSTURE_W},
                              "last_report": float(item.get("last_report", time.time()))}
    _atomic_json_replace(_device_store_path(), records)

def _persist_users():
    path = os.path.join(DATA_DIR, "demo_users.json") if DEMO else USERS_FILE
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    _atomic_json_replace(path, _encode_user_records(USERS))

def _persist_demo_device_keys():
    if not DEMO:
        raise RuntimeError("GUI device enrollment is currently supported only in local demo mode")
    path = _device_keys_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with _file_lock(path):
        try:
            with open(path, encoding="utf-8") as f:
                current = json.load(f)
            if not isinstance(current, dict):
                raise RuntimeError("device key registry is corrupt")
        except FileNotFoundError:
            current = {}
        current.update({k: v.hex() for k, v in POSTURE_KEYS.items()})
        _atomic_json_replace(path, current)

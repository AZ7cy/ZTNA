# Part 01 of ztna.py - imports, optional Tk stub, logging, settings parsing, JWT keyring, runtime configuration, init_runtime().
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# `sys` is imported by ztna.py itself, before its Python version check.
# pyright: reportUndefinedVariable=false

import base64, csv, random, shutil, fnmatch, hashlib, hmac, io, ipaddress, json, math, os, re, secrets, ssl, sqlite3, statistics, struct, threading, time, uuid, logging, subprocess, heapq, queue, asyncio, signal, socket
import urllib.error, urllib.request, http.client

# Import-safe: command-line parsing and environment mutation happen only in main().
# This is required for `uvicorn module:enterprise_app`, gunicorn workers and pytest.
REQUESTED_MODE = None
VALID_MODES = {"gui", "server", "enterprise", "attack", "bench", "agent", "iptables", "compose", "verify", "adduser", "selftest", "probe", "dns", "cli", "systemd"}
USAGE = "usage: python ztna.py [gui|server|enterprise|api|attack|bench|agent|iptables|compose|verify|adduser|selftest|probe|dns|cli|systemd]"
from collections import Counter, OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, quote
from datetime import datetime, timezone
from pathlib import Path
from contextlib import asynccontextmanager, closing, contextmanager
# Python 3.10+ is enforced above, so zoneinfo is part of the standard library.
# Missing IANA database entries (common on Windows without `tzdata`) are
# handled at the lookup site in init_runtime().
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except ImportError:
    class _TkStub:
        # Common tkinter constants remain import-safe on headless/minimal Python
        # installations. GUI construction itself is rejected by main() when ttk
        # is unavailable, so these values do not pretend to implement Tk widgets.
        END = "end"
        INSERT = "insert"
        SEL = "sel"
        LEFT = "left"
        RIGHT = "right"
        TOP = "top"
        BOTTOM = "bottom"
        BOTH = "both"
        X = "x"
        Y = "y"
        N = "n"
        S = "s"
        E = "e"
        W = "w"
        CENTER = "center"
        WORD = "word"
        DISABLED = "disabled"
        NORMAL = "normal"
        VERTICAL = "vertical"
        HORIZONTAL = "horizontal"
        SUNKEN = "sunken"
        RAISED = "raised"
        GROOVE = "groove"
        RIDGE = "ridge"
        FLAT = "flat"
        NSEW = "nsew"
        NS = "ns"
        EW = "ew"
        NW = "nw"
        NE = "ne"
        SW = "sw"
        SE = "se"
        YES = 1
        NO = 0
        ACTIVE = "active"
        ALL = "all"
        TRUE = 1
        FALSE = 0

        class Tk:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("tkinter is not available (install python3-tk)")
        class TclError(Exception):
            pass
        class StringVar:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("tkinter is not available (install python3-tk)")
        IntVar = StringVar
        BooleanVar = StringVar
        class Frame:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("tkinter is not available (install python3-tk)")
        Canvas = Frame
        Toplevel = Tk
        class Text:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("tkinter is not available (install python3-tk)")
    tk = _TkStub()
    ttk = None
    messagebox = None

logger = logging.getLogger("ztna")


def _configure_logging():
    raw = os.environ.get("LOG_LEVEL", "INFO").strip()
    if raw.isdecimal():
        level = int(raw)
    else:
        candidate = logging.getLevelName(raw.upper())
        level = candidate if isinstance(candidate, int) else logging.INFO
    # NOTSET (0) would enable all messages on the root logger; invalid values
    # safely fall back to INFO instead.
    if level < 1 or level > 100:
        level = logging.INFO

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
    else:
        # Respect a host application's root logger (uvicorn, gunicorn, pytest).
        # Only adjust this project's named logger.
        logger.setLevel(level)


def _env_int(name, default, minimum=1, maximum=None, *, error_type=SystemExit):
    """Parse a bounded integer setting, treating blank values as the default.

    CLI startup uses SystemExit for concise configuration errors. ASGI lifespan
    initialization passes RuntimeError so uvicorn reports a conventional startup
    failure instead of surfacing SystemExit from asynchronous lifecycle code.
    """
    if isinstance(default, bool):
        raise ValueError(f"programmer error: default for {name} must be an integer")
    try:
        default_value = int(default)
    except (TypeError, ValueError):
        raise ValueError(f"programmer error: default for {name} must be an integer") from None
    if default_value < minimum or (maximum is not None and default_value > maximum):
        raise ValueError(f"programmer error: default for {name} is outside configured bounds")

    def config_error(message):
        if error_type is SystemExit:
            raise SystemExit(message) from None
        raise error_type(message) from None

    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default_value
    try:
        value = int(raw.strip())
    except ValueError:
        config_error(f"{name} must be an integer (got {raw!r})")
    if value < minimum or (maximum is not None and value > maximum):
        bounds = f"at least {minimum}" + (f" and at most {maximum}" if maximum is not None else "")
        config_error(f"{name} must be {bounds} (got {value})")
    return value


def _env_float(name, default, minimum=0.0, *, error_type=SystemExit):
    """Parse a finite float setting; blank means default, bad values fail with a config error."""
    raw=os.environ.get(name)
    if raw is None or not raw.strip(): return float(default)
    try: value=float(raw.strip())
    except ValueError: raise error_type(f"{name} must be a number (got {raw!r})") from None
    if not math.isfinite(value) or value<minimum:
        raise error_type(f"{name} must be a finite number >= {minimum} (got {raw!r})")
    return value


def _parse_cidrs(name, default="", *, error_type=SystemExit):
    out = []
    for item in os.environ.get(name, default).split(","):
        item = item.strip()
        if not item:
            continue
        try:
            # Don't silently widen an allowlist when a host address is used
            # where a canonical network address was intended.
            out.append(ipaddress.ip_network(item, strict=True))
        except ValueError as exc:
            message = (
                f"invalid {name} entry {item!r}: {exc} "
                "(host bits set? use the network address, e.g. 10.0.0.0/8)"
            )
            raise error_type(message) from None
    return out


def _is_loopback_bind(host):
    h = str(host).strip().strip("[]").lower()
    if h in {"localhost", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


_configured_jwt_key = os.environ.get("ZTNA_JWT_KEY")
JWT_KEY = _configured_jwt_key.encode() if _configured_jwt_key else secrets.token_bytes(32)
JWT_KEYS = {}
JWT_ACTIVE_KID = "default"

def _load_jwt_keyring(error_type=RuntimeError):
    """Load an optional rotating HS256 keyring; legacy ZTNA_JWT_KEY remains supported."""
    global JWT_KEYS, JWT_ACTIVE_KID, JWT_KEY
    raw = os.environ.get("ZTNA_JWT_KEYS", "").strip()
    active = os.environ.get("ZTNA_JWT_ACTIVE_KID", "default").strip() or "default"
    if raw:
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or not parsed:
                raise ValueError
            keys = {str(k): str(v).encode() for k, v in parsed.items()
                    if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(k)) and isinstance(v, str) and len(v) >= 64}
            if len(keys) != len(parsed) or active not in keys:
                raise ValueError
        except (ValueError, TypeError):
            raise error_type("ZTNA_JWT_KEYS must be a JSON object of key IDs to secrets (each 64+ chars), and ZTNA_JWT_ACTIVE_KID must name one") from None
        JWT_KEYS, JWT_ACTIVE_KID = keys, active
        JWT_KEY = keys[active]
    else:
        configured = os.environ.get("ZTNA_JWT_KEY")
        if configured:
            if len(configured) < 64 and os.environ.get("ZTNA_DEMO", "0") != "1":
                raise error_type("ZTNA_JWT_KEY must be at least 64 characters")
            JWT_KEYS, JWT_ACTIVE_KID, JWT_KEY = {"default": configured.encode()}, "default", configured.encode()
        else:
            JWT_KEYS, JWT_ACTIVE_KID = {"default": JWT_KEY}, "default"

ADMIN_KEY = os.environ.get("ZTNA_ADMIN_KEY")
TOKEN_TTL = 300
MAX_BODY = 65536
MAX_AUDIT_BYTES = 50 * 1024 * 1024
DATA_DIR = os.path.abspath(os.environ.get("ZTNA_DATA_DIR", str(Path(__file__).resolve().parent / "ztna_data")))
AUDIT_FILE = os.path.join(DATA_DIR, "audit.jsonl")
TOTP_STATE_FILE = os.path.join(DATA_DIR, "totp_state.json")
POLICY_FILE = os.path.join(DATA_DIR, "policy.json")
DB_FILE = os.path.join(DATA_DIR, "ztna_lab.sqlite3")
USERS_FILE = os.environ.get("ZTNA_USERS_FILE", os.path.join(DATA_DIR, "users.json"))
DEMO = os.environ.get("ZTNA_DEMO", "0") == "1"
DEMO_OTP = DEMO and os.environ.get("ZTNA_DEMO_OTP", "0") == "1"
AUDIT_ANCHOR_FILE = os.path.join(DATA_DIR, "audit.anchor")
AUDIT_ANCHOR_KEY = os.environ.get("ZTNA_AUDIT_ANCHOR_KEY")
AUDIT_ANCHOR_KEY = AUDIT_ANCHOR_KEY.encode() if AUDIT_ANCHOR_KEY else None
HOST_ENV = os.environ.get("ZTNA_HOST", "127.0.0.1")
PORT = 8443
ALLOWED_HOSTS = {x.strip().lower() for x in os.environ.get("ZTNA_ALLOWED_HOSTS", f"127.0.0.1:{PORT},localhost:{PORT},[::1]:{PORT},::1:{PORT}").split(",") if x.strip()}
OFFICE_NETS = []
HOME_NETS = []
ZTNA_TZ = os.environ.get("ZTNA_TZ", "Asia/Kolkata")
LOCAL_TZ = None
LOCK = threading.RLock()
# Demo-only browser console sessions. Manager authentication is separate from employee identity.
MANAGER_SESSIONS = {}
MANAGER_LOGIN_FAILS = deque(maxlen=500)
MANAGER_LOGIN_LOCK = threading.RLock()
DB_LOCAL = threading.local()
PBKDF_SEM = threading.BoundedSemaphore(4)
ADMIN_FAILS = {}
ADMIN_FAIL_GLOBAL = deque(maxlen=5000)
ADMIN_FAIL_GLOBAL_LIMIT = 300
MAX_SESSIONS_PER_USER = 4
# ---------- runtime initialization ----------
_RUNTIME_READY=False
_RUNTIME_MODE=None
CLIENT_TOTP_LAST={}

def _ensure_demo_anchor():
    global AUDIT_ANCHOR_KEY
    if AUDIT_ANCHOR_KEY: return
    path=os.path.join(DATA_DIR,"audit_anchor.key")
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w",encoding="ascii") as f:
            f.write(secrets.token_hex(32)); f.flush(); os.fsync(f.fileno())
    except FileExistsError:
        pass
    with open(path,"r",encoding="ascii") as f: AUDIT_ANCHOR_KEY=f.read().strip().encode()

def _configure_runtime_paths(mode):
    global DATA_DIR,AUDIT_FILE,TOTP_STATE_FILE,POLICY_FILE,DB_FILE,USERS_FILE,AUDIT_ANCHOR_FILE
    # Tests must never mutate a running lab's policy, telemetry, or audit state.
    # When a parent data directory is explicitly provided, isolate tests beneath it.
    if mode == "selftest":
        if "ZTNA_DATA_DIR" in os.environ:
            target=os.path.join(os.path.abspath(os.environ["ZTNA_DATA_DIR"]), "selftest_data")
        else:
            target=os.path.abspath(str(Path(__file__).resolve().parent / "selftest_data"))
    elif "ZTNA_DATA_DIR" in os.environ:
        target=os.path.abspath(os.environ["ZTNA_DATA_DIR"])
    else:
        dirname = {"gui": "desktop_data_gui"}.get(mode, "ztna_data")
        target=os.path.abspath(str(Path(__file__).resolve().parent / dirname))
    DATA_DIR=target
    os.makedirs(DATA_DIR,exist_ok=True)
    AUDIT_FILE=os.path.join(DATA_DIR,"audit.jsonl")
    TOTP_STATE_FILE=os.path.join(DATA_DIR,"totp_state.json")
    POLICY_FILE=os.path.join(DATA_DIR,"policy.json")
    DB_FILE=os.path.join(DATA_DIR,"ztna_lab.sqlite3")
    if "ZTNA_USERS_FILE" not in os.environ: USERS_FILE=os.path.join(DATA_DIR,"users.json")
    AUDIT_ANCHOR_FILE=os.path.join(DATA_DIR,"audit.anchor")

def _validate_external_anchor_location(anchor_path, protected_dirs, error_type=RuntimeError):
    """Production check: the external audit anchor must live outside the mutable data/database directories.

    Paths are fully resolved (symlinks, ``..``) before comparison. The anchor's parent directory must also not be
    world-writable. Operate the anchor directory with a separate OS user or mount: the app account gets write on the
    anchor file only (0600/0700), while operators/verifiers get read-only access to it.
    """
    anchor=Path(os.path.realpath(anchor_path))
    for d in protected_dirs:
        if not d: continue
        root=Path(os.path.realpath(d))
        if anchor==root or root in anchor.parents:
            raise error_type(f"external audit anchor {anchor} must be outside the mutable data/database directory {root}")
    parent=anchor.parent
    try:
        if os.name=="posix" and parent.exists() and (parent.stat().st_mode & 0o002):
            raise error_type(f"external audit anchor directory {parent} must not be world-writable")
    except OSError: pass

def init_runtime(mode, *, asgi=False):
    global _RUNTIME_READY,_RUNTIME_MODE,USERS,AUDIT_ANCHOR_KEY,DEMO,DEMO_OTP,POSTURE_TTL,LAST_TOTP,HOST_ENV,PORT,ALLOWED_HOSTS,OFFICE_NETS,HOME_NETS,LOCAL_TZ,AUDIT_EXTERNAL_ANCHOR_FILE,AH
    global TOKEN_TTL,MAX_AUDIT_BYTES,PBKDF_SEM,MAX_SESSIONS_PER_USER,PROOF_NONCE_LIMIT,JWT_KEY,JWT_KEYS,JWT_ACTIVE_KID,ADMIN_KEY,MAX_UPSTREAM_BODY
    if _RUNTIME_READY and _RUNTIME_MODE==mode: return
    with LOCK:
        # Initialising again in the same process (another mode or data directory): forget the previous runtime's audit writer
        # and counters, or every later entry would still be appended to the OLD file while AUDIT_FILE points at the new one.
        if AUDIT.get("fh") is not None:
            try: AUDIT["fh"].close()
            except OSError: pass
        AUDIT.clear(); AUDIT.update({"prev": "0" * 64, "fh": None, "entries": 0, "size": 0}); LOG.clear()
    error_type = RuntimeError if asgi else SystemExit
    _configure_runtime_paths(mode)
    HOST_ENV=os.environ.get("ZTNA_HOST","127.0.0.1")
    PORT=_env_int("ZTNA_PORT",8443,1,65535,error_type=RuntimeError if asgi else SystemExit)
    TOKEN_TTL=_env_int("ZTNA_TOKEN_TTL",300,1,86400,error_type=RuntimeError if asgi else SystemExit)
    MAX_AUDIT_BYTES=_env_int("ZTNA_MAX_AUDIT_BYTES",50*1024*1024,1024,error_type=RuntimeError if asgi else SystemExit)
    PBKDF_SEM=threading.BoundedSemaphore(_env_int("ZTNA_PBKDF_CONCURRENCY",4,1,128,error_type=RuntimeError if asgi else SystemExit))
    MAX_SESSIONS_PER_USER=_env_int("ZTNA_MAX_SESSIONS_PER_USER",4,1,1000,error_type=RuntimeError if asgi else SystemExit)
    PROOF_NONCE_LIMIT=max(64,_env_int("ZTNA_PROOF_NONCE_LIMIT",1024,1,1000000,error_type=RuntimeError if asgi else SystemExit))
    MAX_UPSTREAM_BODY=_env_int("ZTNA_MAX_UPSTREAM_BODY",1048576,1024,100*1024*1024,error_type=RuntimeError if asgi else SystemExit)
    # Fail fast on bad tunables instead of returning a 500 on every login later.
    _env_int("ZTNA_SESSION_MAX",3600,1,30*86400,error_type=error_type)
    _env_float("ZTNA_KDF_WAIT_SECONDS",2.0,error_type=error_type)
    _env_float("ZTNA_AUTH_HARD_LOCK_SECONDS",60.0,error_type=error_type)
    _env_float("ZTNA_AUTH_BACKOFF_BASE",0.25,error_type=error_type)
    # These are read again where they are used (policy engine, exception queue, audit rotation, telemetry pruning);
    # a bad value used to fail only there: every access decision raised, or a Tk callback raised SystemExit.
    _env_int("ZTNA_RISK_BURST_N",40,1,100000,error_type=error_type)
    _env_int("ZTNA_EXCEPTION_REQUEST_TTL",86400,60,30*86400,error_type=error_type)
    _env_int("ZTNA_MAX_AUDIT_SEGMENTS",32,1,100000,error_type=error_type)
    _env_int("ZTNA_TELEMETRY_RETENTION_DAYS",30,0,36500,error_type=error_type)
    if "H" in globals():
        H.CONNECTIONS=threading.BoundedSemaphore(_env_int("ZTNA_MAX_CONNECTIONS",32,1,10000,error_type=RuntimeError if asgi else SystemExit))
        try:
            H.timeout=float(os.environ.get("ZTNA_REQUEST_DEADLINE","15"))
        except ValueError:
            raise error_type("ZTNA_REQUEST_DEADLINE must be a positive finite number") from None
        if H.timeout<=0 or not math.isfinite(H.timeout):
            raise error_type("ZTNA_REQUEST_DEADLINE must be a positive finite number")
    ADMIN_KEY=os.environ.get("ZTNA_ADMIN_KEY")
    # Keep CLI red-team/admin requests aligned with runtime configuration even
    # when a test harness imports the module before setting environment values.
    if "AH" in globals(): AH={"X-Admin-Key": ADMIN_KEY or ""}
    _load_jwt_keyring(error_type=error_type)
    DEMO = os.environ.get("ZTNA_DEMO","0")=="1"
    DEMO_OTP=DEMO and (os.environ.get("ZTNA_DEMO_OTP","0")=="1" or mode == "selftest")
    demo_bind = os.environ.get("ZTNA_API_HOST", HOST_ENV) if mode == "enterprise" else HOST_ENV
    if DEMO_OTP and not _is_loopback_bind(demo_bind):
        raise error_type("refusing to enable ZTNA_DEMO_OTP on a non-loopback bind; demo OTP helper is loopback-only")
    if DEMO and not _is_loopback_bind(demo_bind):
        if os.environ.get("ZTNA_ALLOW_REMOTE_DEMO","0") != "1":
            raise error_type("refusing DEMO mode on a non-loopback bind; set ZTNA_ALLOW_REMOTE_DEMO=1 only for an isolated lab")
        logger.warning("REMOTE DEMO OVERRIDE enabled: demo credentials and OTP helper may be exposed")
    allowed_raw = os.environ.get("ZTNA_ALLOWED_HOSTS")
    if not DEMO and not allowed_raw and not _is_loopback_bind(HOST_ENV):
        raise error_type("production non-loopback binds require explicit ZTNA_ALLOWED_HOSTS")
    ALLOWED_HOSTS={x.strip().lower() for x in (allowed_raw if allowed_raw is not None else f"127.0.0.1:{PORT},localhost:{PORT},[::1]:{PORT},::1:{PORT}").split(",") if x.strip()}
    OFFICE_NETS=_parse_cidrs("ZTNA_OFFICE_CIDRS","127.0.0.0/8,::1/128",error_type=error_type)
    HOME_NETS=_parse_cidrs("ZTNA_HOME_CIDRS","",error_type=error_type)
    tz_key = os.environ.get("ZTNA_TZ", "Asia/Kolkata").strip() or "Asia/Kolkata"
    try:
        LOCAL_TZ = ZoneInfo(tz_key)
    except (ZoneInfoNotFoundError, ValueError):
        logger.warning(
            "Timezone %s unavailable or invalid; falling back to system local time. "
            "Install the tzdata package on Windows for IANA zones.",
            tz_key,
        )
        LOCAL_TZ = datetime.now().astimezone().tzinfo
    if DEMO:
        _ensure_demo_anchor(); _ensure_demo_jwt_key()
        # DEVICES is filled at import time only if ZTNA_DEMO was already set then. `python ztna.py` (gui) turns demo
        # mode on later, in main(), and used to get just 4 hard-coded laptops: 17 of the 20 demo employees had no device.
        for device_id, fixture in FIXTURE_DEVICES.items():
            DEVICES.setdefault(device_id, {**fixture, "last_report": 0.0})
    if mode=="gui" and not DEMO:
        # Standalone desktop mode has no HTTP listener. It gets a local-only
        # audit key, but does not silently provision demo users or demo OTPs.
        _ensure_demo_anchor()
    AUDIT_EXTERNAL_ANCHOR_FILE=os.environ.get("ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE",os.path.join(DATA_DIR,"audit.monotonic"))
    if not DEMO and mode in {"server","verify"} and "ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE" not in os.environ:
        raise error_type("production requires ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE outside the mutable data directory")
    if not DEMO and mode in {"server","verify"}: _validate_external_anchor_location(AUDIT_EXTERNAL_ANCHOR_FILE,[DATA_DIR],error_type)
    if not DEMO and mode == "server":
        if os.environ.get("ZTNA_ADMIN_REQUIRE_MTLS", "0") == "1" and not os.environ.get("ZTNA_CLIENT_CA"):
            raise error_type("ZTNA_ADMIN_REQUIRE_MTLS=1 requires ZTNA_CLIENT_CA")
        if not (os.environ.get("ZTNA_JWT_KEYS") or (os.environ.get("ZTNA_JWT_KEY") and len(os.environ.get("ZTNA_JWT_KEY","")) >= 64)): raise error_type("production requires ZTNA_JWT_KEY (64+ chars) or ZTNA_JWT_KEYS keyring")
        wrap_key=os.environ.get("ZTNA_SESSION_WRAP_KEY","")
        if len(wrap_key) != 64:
            raise error_type("production requires ZTNA_SESSION_WRAP_KEY as 64 hex characters")
        try: bytes.fromhex(wrap_key)
        except ValueError: raise error_type("ZTNA_SESSION_WRAP_KEY must contain 64 hexadecimal characters") from None
        if not os.environ.get("ZTNA_AUDIT_ANCHOR_KEY") or len(os.environ.get("ZTNA_AUDIT_ANCHOR_KEY","")) < 32:
            raise error_type("production requires ZTNA_AUDIT_ANCHOR_KEY of at least 32 characters")
        if not ADMIN_KEY or len(ADMIN_KEY)<32:
            raise error_type("production requires ZTNA_ADMIN_KEY of at least 32 characters")
    if not DEMO and mode == "verify":
        anchor_key = os.environ.get("ZTNA_AUDIT_ANCHOR_KEY", "")
        if len(anchor_key) < 32:
            raise error_type("production verify requires ZTNA_AUDIT_ANCHOR_KEY of at least 32 characters")
    if mode not in {"attack","bench","agent","enterprise"}:
        LAST_TOTP=_load_totp_state()
    else:
        LAST_TOTP={}
    if mode not in {"iptables","compose","adduser","attack","bench","agent","selftest","enterprise","gui"} and not DEMO:
        key=os.environ.get("ZTNA_AUDIT_ANCHOR_KEY")
        if not key: raise error_type("production requires ZTNA_AUDIT_ANCHOR_KEY")
        AUDIT_ANCHOR_KEY=key.encode()
    if mode in {"attack","bench","agent","selftest"} and DEMO:
        USERS=load_users()
    elif mode=="gui" and not DEMO and not (os.path.isfile(USERS_FILE) or (os.environ.get("ZTNA_BOOTSTRAP_USER") and os.environ.get("ZTNA_BOOTSTRAP_PASSWORD") and os.environ.get("ZTNA_BOOTSTRAP_TOTP"))):
        # Secure GUI default: start without demo accounts when no production user store is configured.
        USERS={}
    elif mode not in {"iptables","compose","verify","adduser","selftest","attack","bench","agent"} and not (mode=="enterprise" and not DEMO and os.environ.get("OIDC_ALLOW_LOCAL","false").lower()!="true"):
        USERS=load_users()
    else:
        USERS={}
    POSTURE_TTL=0 if DEMO else _env_int("ZTNA_POSTURE_TTL",300,0,86400,error_type=RuntimeError if asgi else SystemExit)
    if mode not in {"iptables","compose","verify","enterprise","adduser"}: db_init()
    if mode in {"gui","server"}:
        load_policy()
        if mode=="server" or any(os.path.exists(p) for p in (AUDIT_FILE,AUDIT_ANCHOR_FILE,AUDIT_EXTERNAL_ANCHOR_FILE)):
            resume_chain()
    elif mode in {"attack","bench","agent","selftest"}:
        load_policy()
    _RUNTIME_READY=True; _RUNTIME_MODE=mode

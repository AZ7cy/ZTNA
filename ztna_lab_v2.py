#!/usr/bin/env python3
"""ZTNA Enterprise Lab - single-file stdlib legacy server + Tkinter GUI + optional FastAPI enterprise API.
Importing the module does not create data directories, configure root logging, parse CLI args, or load persistent state. Runtime configuration is validated when main() or the ASGI lifespan starts.
Production managed devices use ZTNA_MANAGED_DEVICES after signed posture verification. Default access decision = DENY.

  python3 ztna_lab_v2.py                       GUI (prompts before enabling demo mode when ZTNA_DEMO is unset; demo OTP is separately opt-in)
  python3 ztna_lab_v2.py server                stdlib HTTP/TLS server
  python3 ztna_lab_v2.py enterprise (or api)   FastAPI/OIDC API
  python3 ztna_lab_v2.py attack [URL]          red-team self-test
  python3 ztna_lab_v2.py bench [URL]           benchmark -> results.csv
  python3 ztna_lab_v2.py agent DEVICE key=value ... [URL]
  python3 ztna_lab_v2.py iptables              print segmentation rules (dry run)
  python3 ztna_lab_v2.py compose               write docker-compose.yml
  python3 ztna_lab_v2.py verify                verify the audit chain (exit status for CI)
  python3 ztna_lab_v2.py adduser               add a new local user securely (existing users are refused)
  python3 ztna_lab_v2.py selftest              run isolated regression tests
  python3 ztna_lab_v2.py probe URL [N] [MS]    latency probe: N GETs, MS ms apart; min/avg/p50/p95/p99/max/jitter
  python3 ztna_lab_v2.py dns serve             lab DNS server (UDP, loopback:5353 by default, A/CNAME records)
  python3 ztna_lab_v2.py dns list|add|cname|remove|query ...   manage records / query a DNS server
  python3 ztna_lab_v2.py cli [COMMAND ...]     remote admin console for a running server (REPL or one-shot)
  python3 ztna_lab_v2.py systemd [server|dns]  print a hardened systemd unit (dry run)

Authenticated GET /inspect shows what the gateway delivered to the server (client IP, headers, TLS); credentials are redacted.
Authenticated lab endpoints: GET /headers (plain-text header dump), GET /download/N and PUT|POST /upload (size-capped
throughput tests). Unauthenticated: GET /health. See README.md for the DNS/CLI settings (ZTNA_DNS_*, ZTNA_LAB_*).

Legacy-server production configuration includes ZTNA_ADMIN_KEY (32+ chars), ZTNA_JWT_KEY (64+ chars),
ZTNA_SESSION_WRAP_KEY (64 hex chars), ZTNA_AUDIT_ANCHOR_KEY (32+ chars),
ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE (outside mutable app data), ZTNA_USERS_FILE or bootstrap variables,
ZTNA_CERT and ZTNA_KEY, and ZTNA_ALLOWED_HOSTS. Enterprise OIDC production instead requires
OIDC_AUDIENCE, AUDIT_SECRET (32+ chars), ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE, TLS certificates,
and PyJWT[crypto]; it does not use the legacy admin or HS256 signing keys. ZTNA_CLIENT_CA is required only when mTLS is desired.
Demo mode generates random per-user bootstrap passwords on first provisioning; save the one-time startup output. Never expose demo mode to untrusted networks.
Enterprise demo local-token fallback reads legacy login sessions from the same ZTNA_DATA_DIR used by the legacy server; to use local lab tokens, share that directory and start the legacy server to issue sessions.
For a clean demo reset, stop all processes first and remove the selected demo data directory, including
audit.jsonl and rotated segments, audit.anchor, audit_anchor.key, audit.monotonic (if inside it),
demo_jwt.key, demo_users.json, totp_state.json, policy.json, and ztna_lab.sqlite3. If an external
monotonic anchor path was configured, reset it only together with the matching demo audit log.
"""
import sys
if sys.version_info < (3, 10):
    _version_error = "Python 3.10+ is required by this single-file build"
    if __name__ == "__main__":
        raise SystemExit(_version_error)
    raise ImportError(_version_error)

import base64, csv, random, shutil, fnmatch, hashlib, hmac, io, ipaddress, json, math, os, re, secrets, ssl, sqlite3, statistics, struct, threading, time, uuid, logging, subprocess, heapq, queue, asyncio, signal, socket
import urllib.error, urllib.request, http.client

# Import-safe: command-line parsing and environment mutation happen only in main().
# This is required for `uvicorn module:enterprise_app`, gunicorn workers and pytest.
REQUESTED_MODE = None
VALID_MODES = {"gui", "server", "enterprise", "attack", "bench", "agent", "iptables", "compose", "verify", "adduser", "selftest", "probe", "dns", "cli", "systemd"}
USAGE = "usage: python ztna_lab_v2.py [gui|server|enterprise|api|attack|bench|agent|iptables|compose|verify|adduser|selftest|probe|dns|cli|systemd]"
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
        if not DEVICES:
            DEVICES.update({"laptop-alice":{"owner":"alice","os_updated":True,"disk_encrypted":True,"firewall":True,"antivirus":True,"corporate_managed":True,"last_report":time.time()},"laptop-bob":{"owner":"bob","os_updated":True,"disk_encrypted":True,"firewall":True,"antivirus":True,"corporate_managed":True,"last_report":time.time()},"laptop-carol":{"owner":"carol","os_updated":True,"disk_encrypted":True,"firewall":True,"antivirus":True,"corporate_managed":True,"last_report":time.time()},"byod-bob":{"owner":"bob","os_updated":True,"disk_encrypted":False,"firewall":True,"antivirus":False,"corporate_managed":False,"last_report":time.time()}})
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
            if timeout is None:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
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
        os.replace(tmp, path)
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

def _encrypt_totp(secret):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError("TOTP encryption requires cryptography; install requirements-enterprise.txt") from None
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(_totp_wrap_key()).encrypt(nonce, str(secret).encode(), b"ztna-totp-v1")
    return "v1:" + base64.urlsafe_b64encode(nonce + cipher).decode().rstrip("=")

def _decrypt_totp(value):
    if not isinstance(value, str): raise ValueError("invalid TOTP secret")
    if not value.startswith("v1:"): return value  # one-time migration of legacy plaintext files
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
                if now-last > 600 or count <= 0: FAILS.pop(key,None)
            for key,q in list(USERFAIL.items()):
                while q and now-q[0]>=600: q.popleft()
                if not q: USERFAIL.pop(key,None)
            for user,(loc,ts) in list(LASTLOC.items()):
                if now-ts>3600: LASTLOC.pop(user,None)
            AUTH_PRUNE_LAST=now
        count,until,last=FAILS.get(k,(0,0,now))
        if now-last>600:
            count=0
            FAILS.pop(k,None)
            until=0
        if now<until: return False
        if now-last > 600: count=0
        # Reserve the attempt before password verification. Exponential backoff
        # prevents parallel guesses from racing through the five-attempt limit.
        next_count=count+1
        base=max(0.05,_env_float("ZTNA_AUTH_BACKOFF_BASE",0.25)); backoff=min(8.0,base*(2.0**max(0,next_count-1)))
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
    if len(existing)>=int(os.environ.get("ZTNA_MAX_AUDIT_SEGMENTS","32")): raise AuditFull("audit segment limit reached; archive segments before continuing")
    if AUDIT["fh"] is not None:
        AUDIT["fh"].close(); AUDIT["fh"]=None
    nums=[]
    prefix=os.path.basename(AUDIT_FILE)+"."
    for name in os.listdir(DATA_DIR):
        if name.startswith(prefix) and name[len(prefix):].isdigit(): nums.append(int(name[len(prefix):]))
    for i in sorted(nums,reverse=True): os.replace(f"{AUDIT_FILE}.{i}",f"{AUDIT_FILE}.{i+1}")
    if os.path.exists(AUDIT_FILE): os.replace(AUDIT_FILE,AUDIT_FILE+".1")
    try:
        fd=os.open(DATA_DIR,os.O_RDONLY); os.fsync(fd); os.close(fd)
    except OSError: pass
    AUDIT["size"]=0

def _audit_hash(prev, event):
    payload=json.dumps(event,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
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
        os.replace(tmp,AUDIT_ANCHOR_FILE); _fsync_dir(AUDIT_ANCHOR_FILE)
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
            os.replace(tmp,path); _fsync_dir(path)
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

def audit(**kw):
    kw["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    kw["hour"] = now_hour(); kw["resource"] = audit_resource(kw.get("resource"))
    with LOCK:
        kw["prev"] = AUDIT["prev"]
        kw["hash_alg"] = "HMAC-SHA256"
        kw["hash"] = _audit_hash(kw["prev"], {k:v for k,v in kw.items() if k!="hash"})
        if AUDIT["entries"] and (not os.path.exists(AUDIT_FILE) or os.path.getsize(AUDIT_FILE) < AUDIT.get("size",0)):
            raise AuditTamper("audit log changed while running")
        if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) >= MAX_AUDIT_BYTES:
            _rotate_audit_locked()
        if AUDIT["fh"] is None:
            fd=os.open(AUDIT_FILE,os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
            try: os.chmod(AUDIT_FILE,0o600)
            except OSError: pass
            AUDIT["fh"]=os.fdopen(fd,"a",encoding="utf-8")
        try:
            AUDIT["fh"].write(json.dumps(kw,separators=(",",":"))+"\n"); AUDIT["fh"].flush(); os.fsync(AUDIT["fh"].fileno())
        except OSError as exc:
            raise AuditFull(f"audit write failed: {exc}")
        AUDIT["size"]=os.path.getsize(AUDIT_FILE)
        AUDIT["prev"]=kw["hash"]; AUDIT["entries"] += 1; LOG.appendleft(kw)
        _external_anchor_update(AUDIT["entries"],AUDIT["prev"])
        _write_anchor_locked(AUDIT["entries"],AUDIT["prev"])
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

def _open_audit_snapshot_locked():
    handles=[]
    try:
        for path in _audit_segment_files():
            fh=open(path,"rb")
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
                event=json.loads(raw.decode("utf-8")); h=event.pop("hash")
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
            except (ValueError,KeyError,TypeError,UnicodeDecodeError):
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
        AUDIT["prev"] = "0" * 64; AUDIT["entries"] = 0; AUDIT["size"] = 0; LOG.clear()
    audit(user="admin", device=None, resource="audit-reset", decision="POLICY", reasons=[f"damaged audit log archived to {os.path.basename(arch)}; new chain started"])
    return arch

# ---------- adaptive policy engine ----------
REQ_TIMES={}      # "user|device" -> recent request timestamps (suspicious request frequency signal)
SEEN_DEV={}       # user -> devices that have completed a login for that account since start
def _burst_signal(sess,dev):
    """Return extra risk (0/15/30) and a signal text for an unusually high request rate on this user+device."""
    n_lim=max(1,int(os.environ.get("ZTNA_RISK_BURST_N","40") or 40)); now=time.time()
    q=REQ_TIMES.setdefault(f"{sess.get('user')}|{dev}",deque(maxlen=max(500,n_lim*4))); q.append(now)
    n=sum(1 for t in q if now-t<10)
    if n>3*n_lim: return 30,f"request burst ({n} in 10s)"
    if n>n_lim: return 15,f"request burst ({n} in 10s)"
    return 0,None

def evaluate(sess, dev, res):
    """-> (ALLOW|DENY|STEPUP, reasons, risk 0-100, signals). Runs on EVERY request (continuous evaluation)."""
    r, why, sig, d = RESOURCES[res], [], [], DEVICES.get(dev)
    role, ps = USERS[sess["user"]]["role"], (posture(dev) if dev in DEVICES else 0)
    if not rbac_allows(sess["user"], res): why.append(f"RBAC: role '{role}' not permitted")
    if not segment_allows(sess["user"], res): why.append(f"micro-segmentation: {SEGMENTS[res]} blocked for role '{role}'")
    if dev in BLOCKED_DEVICES: why.append("device blocked by manager")
    if not d: why.append("unknown device")
    else:
        if d["owner"] != sess["user"]: why.append("device not owned by user")
        if ps < r["min_posture"]: why.append(f"posture {ps} < required {r['min_posture']}")
        if r["managed"] and not d["corporate_managed"]: why.append("corporate-managed device required")
    lo, hi = r["hours"]; h=now_hour(); inh = (lo <= h < hi) if lo < hi else (h >= lo or h < hi)
    if not inh: why.append(f"outside allowed hours {lo}:00-{hi}:00")
    if sess["location"] not in r["locations"]: why.append(f"location '{sess['location']}' not allowed")
    risk = 100 - ps + {"office": 0, "home": 5}.get(sess["location"], 25) + (0 if inh else 10)
    if recent_fails(sess["user"],sess.get("auth_ip")): n=recent_fails(sess["user"],sess.get("auth_ip")); risk += min(30,10*n); sig.append(f"{n} recent failed logins")
    if sess.get("travel"): risk += 30; sig.append("location change within 5 min")
    if sess.get("new_device"): risk += 10; sig.append("device first seen for this account")
    extra,txt=_burst_signal(sess,dev)
    if extra: risk += extra; sig.append(txt)
    risk = min(risk, 100)
    if why: return "DENY", why, risk, sig
    if risk >= 80: return "DENY", [f"risk score {risk} >= 80"], risk, sig
    max_age = min(r["mfa_age"], 60) if risk >= 50 else r["mfa_age"]      # risky context -> fresher MFA
    if time.time() - sess["mfa_at"] > max_age: return "STEPUP", [f"MFA older than {max_age}s"], risk, sig
    return "ALLOW", ["all policy checks passed"], risk, sig

SEG = {"wiki": "10.10.1.10", "hr-db": "10.10.2.10", "admin-panel": "10.10.3.10", "source-code": "10.10.4.10", "ci-cd": "10.10.5.10",
       "crm": "10.10.6.10", "finance-ledger": "10.10.7.10", "support-desk": "10.10.8.10", "legal-vault": "10.10.9.10",
       "siem-console": "10.10.10.10", "exec-reports": "10.10.11.10"}   # one micro-segment per protected resource
def firewall_rules(proxy="10.10.0.2"):
    return (["# dry run - review before applying on a gateway", "iptables -P FORWARD DROP",
             "iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP",
             "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
            + [f"iptables -A FORWARD -s {proxy} -d {ip} -p tcp --dport 80 -j ACCEPT  # ZTNA proxy -> {r} only" for r, ip in SEG.items()]
            + ["# no segment-to-segment rule exists => lateral movement is dropped", "iptables -A FORWARD -m limit --limit 5/min --limit-burst 20 -j LOG --log-prefix 'ZTNA-DROP '",
               "# IPv6 must use an equivalent ip6tables default-deny policy; do not leave IPv6 enabled without it."])

def net_acl_trusted(ip):
    """Conventional perimeter rule: anything on a trusted (private/loopback) network is allowed."""
    try: a=ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError: return False
    return a.is_loopback or any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))

pct = lambda v, p: (lambda s: round(s[min(len(s) - 1, int(len(s) * p))], 3) if s else 0)(sorted(list(v)))
AUDIT_SYSTEM_RESOURCES={"identity-create","device-enrollment","audit-repair","audit-reset","audit-export","alert-review","login","stepup","posture","session","sim","firewall","policy","inspect","headers","download","upload","manager-login","signin-request","manager-logout","-"}
def audit_resource(resource):
    if resource in RESOURCES or resource in AUDIT_SYSTEM_RESOURCES: return str(resource)
    raw=str(resource or "")[:512]
    return "unknown:"+sha(raw)[:16]

def safe(x):
    s=str(x)
    return "'"+s if s[:1] in ("=","+","-","@","\t","\r") else s

# ---------- upstream safety ----------
MAX_UPSTREAM_BODY=1048576
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise urllib.error.HTTPError(req.full_url,code,"redirects disabled",headers,fp)

class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that uses a previously validated IP instead of resolving the hostname again."""
    def __init__(self, host, connect_ip, **kwargs):
        self._connect_ip = connect_ip
        super().__init__(host, **kwargs)
    def connect(self):
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host: self._tunnel()

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated IP while retaining hostname SNI/certificate checks."""
    def __init__(self, host, connect_ip, **kwargs):
        self._connect_ip = connect_ip
        super().__init__(host, **kwargs)
    def connect(self):
        raw = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = raw
            self._tunnel()
            raw = self.sock
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)

class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, connect_ip): super().__init__(); self.connect_ip = connect_ip
    def http_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedHTTPConnection(host, self.connect_ip, **kw), req)

class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connect_ip): super().__init__(); self.connect_ip = connect_ip
    def https_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedHTTPSConnection(host, self.connect_ip, **kw), req,
                            context=self._context, check_hostname=self._check_hostname)

def fetch_upstream(url):
    """Fetch only explicitly allowlisted public upstreams; reject private, loopback, link-local and reserved IPs."""
    u=urlsplit(url or "")
    if u.scheme not in ("http","https") or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError("unsupported upstream URL")
    host = u.hostname.rstrip(".").lower()
    if not host or len(host) > 253: raise ValueError("invalid upstream host")
    allow = {x.strip().lower().rstrip(".") for x in os.environ.get("ZTNA_UPSTREAM_ALLOWLIST", "").split(",") if x.strip()}
    if not allow or host not in allow:
        raise ValueError("upstream host is not allowlisted")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError: raise ValueError("invalid upstream port") from None
    if not 1 <= port <= 65535: raise ValueError("invalid upstream port")
    try:
        addresses = {x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except OSError: raise ValueError("upstream DNS lookup failed") from None
    if not addresses: raise ValueError("upstream host did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%",1)[0])
        if not ip.is_global or ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("upstream resolved to a non-public address")
    # Pin the actual socket to the IP we validated, preventing DNS rebinding between validation and connect.
    pinned_ip = sorted(addresses)[0]
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect,
                                       _PinnedHTTPHandler(pinned_ip), _PinnedHTTPSHandler(pinned_ip))
    req=urllib.request.Request(url,method="GET",headers={"Connection":"close"})
    with opener.open(req,timeout=3) as r:
        data=r.read(MAX_UPSTREAM_BODY+1)
        if len(data)>MAX_UPSTREAM_BODY: raise ValueError("upstream response too large")
        return json.loads(data)

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
        with LOCK:
            for old_key,v in list(SESSIONS.items()):
                if v["exp"]<=now or v["abs_exp"]<=now:
                    SESSIONS.pop(old_key,None)
                    db_exec_critical("UPDATE sessions SET revoked=1 WHERE sid=?",(old_key,))
            own=sorted(((k,v.get("created",0)) for k,v in SESSIONS.items() if v["user"]==u),key=lambda x:x[1])
            while len(own)>=max(1,MAX_SESSIONS_PER_USER):
                old_sid,_=own.pop(0); SESSIONS.pop(old_sid,None)
                db_exec_critical("UPDATE sessions SET revoked=1 WHERE sid=?",(old_sid,))
            SESSIONS[sid]=sess; LASTLOC[u]=(loc,now); release_auth_attempt(u,ip)
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

COMPOSE = """services:
  init-data:
    image: python:3.12-slim
    user: "0:0"
    volumes: ["ztna_data:/data", "ztna_anchor:/anchor"]
    command: ["sh", "-c", "mkdir -p /data /anchor && chown -R 65532:65532 /data /anchor"]
  ztna:
    image: python:3.12-slim
    depends_on:
      init-data:
        condition: service_completed_successfully
    working_dir: /app
    volumes: [".:/app:ro", "ztna_data:/data", "ztna_anchor:/anchor", "./certs:/certs:ro"]
    init: true
    command: ["python", "%SCRIPT%", "server"]
    ports: ["127.0.0.1:8443:8443"]
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    environment:
      ZTNA_HOST: 0.0.0.0
      ZTNA_DEMO: "0"
      ZTNA_DATA_DIR: /data
      ZTNA_ADMIN_KEY: "${ZTNA_ADMIN_KEY:?set a 32+ character ZTNA_ADMIN_KEY}"
      ZTNA_USERS_FILE: /data/users.json
      ZTNA_BOOTSTRAP_USER: "${ZTNA_BOOTSTRAP_USER:?set ZTNA_BOOTSTRAP_USER}"
      ZTNA_BOOTSTRAP_ROLE: "${ZTNA_BOOTSTRAP_ROLE:-admin}"
      ZTNA_BOOTSTRAP_PASSWORD: "${ZTNA_BOOTSTRAP_PASSWORD:?set ZTNA_BOOTSTRAP_PASSWORD}"
      ZTNA_BOOTSTRAP_TOTP: "${ZTNA_BOOTSTRAP_TOTP:?set ZTNA_BOOTSTRAP_TOTP}"
      ZTNA_POSTURE_KEY_LAPTOP_ALICE: "${ZTNA_POSTURE_KEY_LAPTOP_ALICE:?set ZTNA_POSTURE_KEY_LAPTOP_ALICE}"
      ZTNA_POSTURE_KEY_LAPTOP_BOB: "${ZTNA_POSTURE_KEY_LAPTOP_BOB:?set ZTNA_POSTURE_KEY_LAPTOP_BOB}"
      ZTNA_POSTURE_KEY_LAPTOP_CAROL: "${ZTNA_POSTURE_KEY_LAPTOP_CAROL:?set ZTNA_POSTURE_KEY_LAPTOP_CAROL}"
      ZTNA_DEVICE_OWNER_LAPTOP_ALICE: "${ZTNA_DEVICE_OWNER_LAPTOP_ALICE:?set ZTNA_DEVICE_OWNER_LAPTOP_ALICE}"
      ZTNA_DEVICE_OWNER_LAPTOP_BOB: "${ZTNA_DEVICE_OWNER_LAPTOP_BOB:?set ZTNA_DEVICE_OWNER_LAPTOP_BOB}"
      ZTNA_DEVICE_OWNER_LAPTOP_CAROL: "${ZTNA_DEVICE_OWNER_LAPTOP_CAROL:?set ZTNA_DEVICE_OWNER_LAPTOP_CAROL}"
      ZTNA_MANAGED_DEVICES: "${ZTNA_MANAGED_DEVICES:-}"
      ZTNA_OFFICE_CIDRS: "${ZTNA_OFFICE_CIDRS:?set ZTNA_OFFICE_CIDRS}"
      ZTNA_CERT: /certs/server.crt
      ZTNA_KEY: /certs/server.key
      ZTNA_AUDIT_ANCHOR_KEY: "${ZTNA_AUDIT_ANCHOR_KEY:?set ZTNA_AUDIT_ANCHOR_KEY}"
      ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE: /anchor/audit.monotonic
      ZTNA_JWT_KEY: "${ZTNA_JWT_KEY:?set a 64+ character ZTNA_JWT_KEY}"
      ZTNA_SESSION_WRAP_KEY: "${ZTNA_SESSION_WRAP_KEY:?set 32-byte hex session wrap key}"
      ZTNA_ALLOWED_HOSTS: "${ZTNA_ALLOWED_HOSTS:-localhost:8443,127.0.0.1:8443}"
      UP_WIKI: "http://wiki/"
      UP_HR: "http://hr/"
      UP_ADMIN: "http://admin/"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('https://127.0.0.1:8443/baseline', context=__import__('ssl')._create_unverified_context(), timeout=3)"]
      interval: 15s
      timeout: 5s
      retries: 3
    networks: [seg_wiki, seg_hr, seg_admin, edge]
  wiki:  {image: hashicorp/http-echo, command: ["-listen=:80", '-text={\"svc\":\"wiki\"}'], networks: [seg_wiki]}
  hr:    {image: hashicorp/http-echo, command: ["-listen=:80", '-text={\"svc\":\"hr-db\"}'], networks: [seg_hr]}
  admin: {image: hashicorp/http-echo, command: ["-listen=:80", '-text={\"svc\":\"admin\"}'], networks: [seg_admin]}
networks:
  edge: {}
  seg_wiki: {internal: true}
  seg_hr: {internal: true}
  seg_admin: {internal: true}
volumes:
  ztna_data:
  ztna_anchor:
"""

# ---------- GUI (embedded) ----------
INDEX_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZTNA Lab · Manager Console</title>
<style>
:root{--bg:#0d1117;--pn:#151b23;--ln:#262e3a;--tx:#d5dbe3;--mu:#7d8896;--ok:#3ddc97;--no:#ff5c6c;--am:#f2b94b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding:14px 22px;border-bottom:1px solid var(--ln)}
h1{font-size:15px;margin:0;letter-spacing:.14em;text-transform:uppercase}h1 b{color:var(--am)}.hk{display:flex;gap:8px;align-items:center}.hk input{width:190px}
.tag{color:var(--mu);font-size:12px}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:14px;padding:14px 22px}
.pn{background:var(--pn);border:1px solid var(--ln);border-radius:6px;padding:14px;min-width:0}.pn h2{margin:0 0 10px;font-size:12px;color:var(--mu);letter-spacing:.12em;text-transform:uppercase}
.wide{grid-column:1/-1}label{display:block;color:var(--mu);font-size:11px;margin:8px 0 3px}
input,select,button{background:#0d1117;color:var(--tx);border:1px solid var(--ln);border-radius:4px;padding:6px 8px;font:inherit;width:100%}
button{cursor:pointer;width:auto;border-color:#3b4656}button:hover{border-color:var(--am)}button.p{background:var(--am);color:#111;border-color:var(--am);font-weight:700}
.row{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.row>*{flex:1}.row>button{flex:0 0 auto}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:4px 6px;border-bottom:1px solid var(--ln);text-align:left;vertical-align:top}th{color:var(--mu);font-weight:400}
.A{color:var(--ok)}.D{color:var(--no)}.R{color:var(--am)}pre{margin:8px 0 0;background:#0d1117;padding:8px;border-radius:4px;overflow:auto;max-height:170px;font-size:12px}
.dev{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:8px;padding-bottom:8px;border-bottom:1px dashed var(--ln)}
.chip{border:1px solid var(--ln);border-radius:3px;padding:1px 7px;font-size:11px;cursor:pointer;user-select:none}.chip.on{color:var(--ok);border-color:var(--ok)}.chip.off{color:var(--no);border-color:var(--no)}
.sc{font-size:20px;font-weight:700;min-width:44px}.big{font-size:26px;font-weight:700}.kpi{display:flex;gap:22px;margin-bottom:10px;flex-wrap:wrap}.kpi small{display:block;color:var(--mu);font-size:11px}
canvas{width:100%;height:110px;display:block}.mt6{margin-top:6px}.w44{width:44%}.bar progress{width:100%;height:8px;vertical-align:middle}.bar{position:relative;background:#0d1117;margin:3px 0;border-radius:3px;overflow:hidden}.bar i{position:absolute;inset:0 auto 0 0;background:#3a2530}.bar span{position:relative;padding:2px 6px;font-size:12px;display:block}
.pol{display:grid;grid-template-columns:90px repeat(4,1fr);gap:6px;align-items:center;margin-bottom:6px}.pol input[type=checkbox]{width:auto}
</style></head><body>
<header><h1>ZTNA <b>Lab</b> · Manager Console</h1><div class="hk"><span class="tag">Authenticated manager</span><button data-action="manager-logout">Log out</button><span class="tag" id="clock"></span></div></header>
<main>
<section class="pn"><h2>1 · Access console (client simulator)</h2>
 <div class="row"><div><label>User</label><select id="u"></select></div><div><label>Device</label><select id="d"></select></div><div><label>Location</label><select id="loc"><option>office</option><option>home</option><option>unknown</option></select></div></div>
 <div class="row"><div><label>Demo bootstrap password</label><input id="pw" type="password"></div><div><label>TOTP code</label><input id="otp" maxlength="6"></div><button data-action="demo-otp">fill OTP</button></div>
 <p class="row"><button class="p" data-action="login">Authenticate</button><button data-action="stepup">Step-up MFA</button><button data-action="logout">Logout</button><span id="who" class="tag"></span></p>
 <div class="row">%%RESOURCE_BUTTONS%%</div>
 <pre id="out">Not authenticated. Default policy: deny.</pre></section>
<section class="pn"><h2>2 · Device posture &amp; clock (admin simulation)</h2><div id="devs"></div>
 <label>Simulated clock hour <span id="hv"></span></label>
 <input type="range" id="hr" min="0" max="23" data-action="set-hour"> <button class="mt6" data-action="real-clock">use real clock</button></section>
<section class="pn"><h2>3 · Active sessions</h2><table id="ses"></table></section>
<section class="pn"><h2>4 · Policy editor (live)</h2><div id="pol"></div><div class="tag">min posture · MFA max age (s) · hours from–to · managed device</div></section>
<section class="pn"><h2>5 · Performance &amp; top deny reasons</h2><div class="kpi" id="kpi"></div><canvas id="cv" width="700" height="110"></canvas><div id="rs"></div></section>
<section class="pn"><h2>6 · Generated segmentation rules (dry run)</h2><pre id="fw"></pre></section>
<section class="pn wide"><h2>7 · Decision log (hash-chained audit trail) <button data-action="verify">verify chain</button> <button data-action="export">export CSV</button> <span id="vr" class="tag"></span></h2><table id="log"></table></section>
</main>
<script>
let tok=null,dev=null,deviceKey=null,pollTimer=null;const $=i=>document.getElementById(i),esc=s=>String(s??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');
const j=async(p,m='GET',b)=>{const h={'Content-Type':'application/json'};if(p.startsWith('/api/')&&!['/api/login','/api/stepup','/api/logout','/api/refresh','/api/demo/totp','/api/ui/manager-login'].includes(p))h['X-Manager-Session']=sessionStorage.getItem('ztnaManagerSession')||'';
 if(tok&&(p.startsWith('/access')||p=='/api/stepup'||p=='/api/logout'||p=='/api/refresh')){h.Authorization='Bearer '+tok;h['X-Device-Id']=dev;if(deviceKey){if(!window.isSecureContext&&!['localhost','127.0.0.1','::1'].includes(location.hostname)){throw new Error('Secure context required for device proof');}const raw=Uint8Array.from(atob(deviceKey.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(deviceKey.length/4)*4,'=')),c=>c.charCodeAt(0));const k=await crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']);const ts=Date.now()/1000;const nonce=crypto.randomUUID();const bodyText=b?JSON.stringify(b):'';const dig=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(bodyText))),x=>x.toString(16).padStart(2,'0')).join('');const u=new URL(p,location.href);const data=new TextEncoder().encode(['ztna-pop-v2',m,u.pathname+u.search,dig,ts.toFixed(3),nonce].join(String.fromCharCode(10)));const sig=new Uint8Array(await crypto.subtle.sign('HMAC',k,data));h['X-Device-Timestamp']=ts.toFixed(3);h['X-Device-Nonce']=nonce;h['X-Content-SHA256']=dig;h['X-Device-Proof']=Array.from(sig,b=>b.toString(16).padStart(2,'0')).join('')}}
 const r=await fetch(p,{method:m,headers:h,body:b?JSON.stringify(b):undefined});return{s:r.status,d:await r.json().catch(()=>({}))}};
async function demoOtp(){$('otp').value=(await j('/api/demo/totp?user='+$('u').value)).d.code||''}
async function login(){if(!window.isSecureContext && !['localhost','127.0.0.1','::1'].includes(location.hostname)){ $('out').textContent='Secure context required: use HTTPS for the ZTNA web console.'; return; }const r=await j('/api/login','POST',{username:$('u').value,password:$('pw').value,otp:$('otp').value,device_id:$('d').value,location:$('loc').value});
 if(r.s==200){tok=r.d.token;dev=$('d').value;deviceKey=r.d.device_key;$('who').textContent='✔ '+$('u').value+' @ '+dev}else{tok=null;deviceKey=null;$('who').textContent='✘ '+(r.d.error||r.s)}$('out').textContent=JSON.stringify(r.d,null,1).slice(0,300);refresh()}
async function acc(x){if(!tok){$('out').textContent='401 – authenticate first';return}const r=await j('/access/'+x);$('out').textContent=r.s+' '+(r.s==200?'ALLOW':r.d.stepup?'STEP-UP (fill OTP, click Step-up MFA)':'DENY')+'\n'+JSON.stringify(r.d,null,1);refresh()}
async function logout(){if(!tok)return;const r=await j('/api/logout','POST',{});tok=null;deviceKey=null;dev=null;$('who').textContent='logged out';$('out').textContent=JSON.stringify(r.d);refresh()}
async function stepup(){if(!tok)return;const r=await j('/api/stepup','POST',{otp:$('otp').value});$('out').textContent=r.s+' '+JSON.stringify(r.d);refresh()}
async function tgl(d,f,v){await j('/api/device/'+d+'/posture','POST',{field:f,value:v});refresh()}
async function setHour(h){await j('/api/sim','POST',{hour:h==null?null:+h});refresh()}
async function rev(s){await j('/api/session/'+s+'/revoke','POST',{});refresh()}
async function pol(r){await j('/api/policy/'+r,'POST',{min_posture:+$('mp_'+r).value,mfa_age:+$('ma_'+r).value,hours:[+$('lo_'+r).value,+$('hi_'+r).value],managed:$('mg_'+r).checked});refresh()}
async function ver(){const r=await j('/api/verify');$('vr').textContent=r.d.ok?'✔ chain intact ('+r.d.entries+' entries)':'✘ TAMPERED at entry '+r.d.broken_at}
async function exp(){const r=await fetch('/api/export',{headers:{'X-Manager-Session':sessionStorage.getItem('ztnaManagerSession')||''}});const a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download='ztna_audit.csv';a.click()}
async function managerLogout(){try{await j('/api/ui/manager-logout','POST',{})}catch(e){}sessionStorage.removeItem('ztnaManagerSession');location.href='/ztna'}
async function refresh(){if(!sessionStorage.getItem('ztnaManagerSession')){$('clock').textContent='manager login required';return}const [s,l,m,f]=await Promise.all([j('/api/state'),j('/api/logs'),j('/api/metrics'),j('/api/firewall')]);const st=s.d;
 if(s.s==401){$('clock').textContent='enter admin key';if(pollTimer){clearInterval(pollTimer);pollTimer=null}return}
 if(!pollTimer)pollTimer=setInterval(refresh,2500);
 $('clock').textContent='policy clock '+String(st.hour).padStart(2,'0')+':00'+(st.sim?' (simulated)':'');$('hv').textContent=st.hour;if(document.activeElement!==$('hr'))$('hr').value=st.hour;
 if(!$('u').options.length){$('u').innerHTML=Object.keys(st.users).map(u=>`<option>${esc(u)}</option>`).join('');$('d').innerHTML=Object.keys(st.devices).map(u=>`<option>${esc(u)}</option>`).join('')}
 $('devs').innerHTML=Object.entries(st.devices).map(([n,d])=>`<div class="dev"><span class="sc ${d.score>=70?'A':d.score>=40?'R':'D'}">${d.score}</span><b>${esc(n)}</b>`+['os_updated','disk_encrypted','firewall','antivirus'].map(f=>`<span class="chip ${d[f]?'on':'off'}" data-action="toggle-posture" data-device="${esc(n)}" data-field="${f}" data-value="${!d[f]}">${f}</span>`).join('')+`<span class="chip ${d.corporate_managed?'on':'off'}">corporate_managed (MDM)</span>`+'</div>').join('');
 $('ses').innerHTML='<tr><th>sid<th>user<th>device<th>loc<th>ttl<th>MFA age<th></tr>'+st.sessions.map(x=>`<tr><td>${esc(x.sid)}<td>${esc(x.user)}<td>${esc(x.device)}<td>${esc(x.location)}${x.travel?' ⚠':''}<td>${x.ttl}s<td>${x.mfa}s<td><button data-action="revoke" data-sid="${esc(x.sid)}">revoke</button></tr>`).join('');
 if(!$('pol').contains(document.activeElement))$('pol').innerHTML=Object.entries(st.resources).map(([r,v])=>`<div class="pol"><b>${esc(r)}</b><input id="mp_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.min_posture}"><input id="ma_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.mfa_age}"><span><input id="lo_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.hours[0]}" class="w44">–<input id="hi_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="number" value="${v.hours[1]}" class="w44"></span><input id="mg_${esc(r)}" data-action="policy" data-resource="${esc(r)}" type="checkbox" ${v.managed?'checked':''}></div>`).join('');
 $('log').innerHTML='<tr><th>time<th>user<th>device<th>resource<th>decision<th>risk<th>reasons / signals</tr>'+l.d.map(e=>`<tr><td>${esc(e.ts.slice(11))}<td>${esc(e.user||'-')}<td>${esc(e.device||'-')}<td>${esc(e.resource)}<td class="${e.decision=='ALLOW'?'A':e.decision=='DENY'?'D':'R'}">${esc(e.decision)}<td>${e.risk??''}<td>${esc(e.reasons.concat(e.signals||[]).join('; '))}</tr>`).join('');
 const k=m.d;$('kpi').innerHTML=`<div><div class="big A">${k.allow}</div><small>allowed</small></div><div><div class="big R">${k.stepup}</div><small>step-ups</small></div><div><div class="big D">${k.deny}</div><small>denied</small></div><div><div class="big">${k.policy_us.p50}µs</div><small>policy eval p50</small></div><div><div class="big">${k.proxy_ms.p95}ms</div><small>request p95</small></div>`;
 const mx2=Math.max(1,...k.reasons.map(r=>r[1]));$('rs').innerHTML=k.reasons.map(([t,n])=>`<div class="bar"><progress max="${mx2}" value="${n}"></progress><span>${esc(t)} · ${n}</span></div>`).join('');
 $('fw').textContent=f.d.rules.join('\n');
 const c=$('cv').getContext('2d');c.clearRect(0,0,700,110);const v=k.series,mx=Math.max(1,...v);c.strokeStyle='#f2b94b';c.beginPath();v.forEach((y,i)=>{const X=i*700/Math.max(1,v.length-1),Y=105-y/mx*92;i?c.lineTo(X,Y):c.moveTo(X,Y)});c.stroke();c.fillStyle='#7d8896';c.fillText('request latency (ms), last '+v.length+' · max '+mx.toFixed(2),6,12)}
document.addEventListener('click',e=>{const b=e.target.closest('[data-action]');if(!b)return;const a=b.dataset.action;if(a==='demo-otp')demoOtp();else if(a==='login')login();else if(a==='stepup')stepup();else if(a==='logout')logout();else if(a==='access')acc(b.dataset.resource);else if(a==='real-clock')setHour(null);else if(a==='manager-logout')managerLogout();else if(a==='verify')ver();else if(a==='export')exp();else if(a==='revoke')rev(b.dataset.sid);else if(a==='toggle-posture')tgl(b.dataset.device,b.dataset.field,b.dataset.value==='true')});
document.addEventListener('change',e=>{const a=e.target.dataset.action;if(a==='policy')pol(e.target.dataset.resource)});
let hourTimer=null;document.addEventListener('input',e=>{if(e.target.dataset.action==='set-hour'){clearTimeout(hourTimer);hourTimer=setTimeout(()=>setHour(e.target.value),250)}});
refresh();
</script></body></html>
"""
INDEX_HTML = INDEX_HTML.replace("%%RESOURCE_BUTTONS%%", "".join(f'<button data-action="access" data-resource="{r}">{r}</button>' for r in RESOURCES))

LANDING_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZTNA Access Portal</title><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--line:#283653;--text:#edf3ff;--muted:#9aa9c5;--accent:#79a8ff;--green:#55d6a2}*{box-sizing:border-box}body{margin:0;min-height:100vh;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--text);background:radial-gradient(circle at 20% 0%,#1b2b50,transparent 40%),var(--bg);display:grid;place-items:center;padding:24px}.wrap{width:min(980px,100%)}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:12px}.title{font-size:clamp(32px,5vw,52px);line-height:1.05;margin:12px 0}.sub{color:var(--muted);max-width:650px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:18px;margin-top:32px}.card{display:flex;flex-direction:column;gap:12px;background:rgba(18,26,44,.94);border:1px solid var(--line);border-radius:22px;padding:26px;box-shadow:0 24px 70px #0003}.icon{width:48px;height:48px;border-radius:14px;display:grid;place-items:center;background:#21345a;color:var(--accent);font-size:24px}.card h2{margin:0;font-size:22px}.card p{margin:0;color:var(--muted);flex:1}.btn{display:inline-flex;justify-content:center;align-items:center;text-decoration:none;background:var(--accent);color:#071126;font-weight:800;border-radius:12px;padding:13px 16px;margin-top:10px}.foot{color:var(--muted);font-size:12px;margin-top:24px}
</style></head><body><main class="wrap"><div class="eyebrow">Zero Trust Network Access</div><h1 class="title">Secure access.<br>Clear decisions.</h1><p class="sub">Choose the workspace that matches your role. Employee access requests are evaluated by the same ZTNA policy engine and appear in the manager console in near real time.</p><div class="cards"><section class="card"><div class="icon">↗</div><h2>Employee access</h2><p>Sign in with your employee account, verify MFA, and request access to approved company resources. See the policy decision and reason.</p><a class="btn" href="/employee">Employee sign in</a></section><section class="card"><div class="icon">▦</div><h2>ZTNA manager</h2><p>Review access requests, active sessions, device posture, policy settings, audit logs, and system health from a dedicated console.</p><a class="btn" href="/ztna">Manager sign in</a></section></div><div class="foot">Demo lab · Requests and logs are shared through the server, so both workspaces can be used from separate laptops on the same network.</div></main></body></html>"""

MANAGER_LOGIN_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZTNA Manager Sign In</title><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--line:#283653;--text:#edf3ff;--muted:#9aa9c5;--accent:#79a8ff}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(circle at 15% 0%,#1b2b50,transparent 42%),var(--bg);font:16px/1.5 system-ui,sans-serif;color:var(--text)}.card{width:min(440px,100%);padding:30px;background:var(--panel);border:1px solid var(--line);border-radius:22px;box-shadow:0 24px 70px #0004}.eyebrow{font-size:12px;color:var(--accent);letter-spacing:.14em;text-transform:uppercase;font-weight:800}h1{font-size:30px;margin:10px 0 4px}p{color:var(--muted);margin:0 0 24px}label{display:block;font-size:13px;color:var(--muted);margin:15px 0 6px}input,button{width:100%;padding:13px 14px;border-radius:11px;border:1px solid var(--line);font:inherit}input{background:#0b1020;color:var(--text)}button{margin-top:22px;background:var(--accent);color:#071126;font-weight:800;border:0;cursor:pointer}#msg{min-height:24px;color:#ff9aa8;margin-top:14px;font-size:14px}.back{display:inline-block;color:var(--muted);margin-top:12px;text-decoration:none;font-size:14px}
</style></head><body><main class="card"><div class="eyebrow">ZTNA · Operations</div><h1>Manager sign in</h1><p>Authenticate to monitor requests, sessions, policy decisions, and audit records.</p><form id="form"><label for="username">Manager name</label><input id="username" autocomplete="username" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><button type="submit">Sign in to console</button></form><div id="msg" role="status"></div><a class="back" href="/">← Back to workspace selection</a></main><script>
document.getElementById('form').addEventListener('submit',async e=>{e.preventDefault();const msg=document.getElementById('msg');msg.textContent='Signing in…';try{const r=await fetch('/api/ui/manager-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Sign-in failed');sessionStorage.setItem('ztnaManagerSession',d.token);location.href='/ztna/console'}catch(err){msg.textContent=err.message}});
</script></body></html>"""

EMPLOYEE_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Employee · ZTNA Access</title><style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--line:#283653;--text:#edf3ff;--muted:#9aa9c5;--accent:#79a8ff;--good:#55d6a2;--bad:#ff8190;--warn:#ffc86b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0%,#1b2b50,transparent 40%),var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:18px clamp(16px,4vw,48px);border-bottom:1px solid var(--line)}.brand{font-weight:850;letter-spacing:.05em}.brand span{color:var(--accent)}.top a{color:var(--muted);text-decoration:none}.layout{width:min(1080px,100%);margin:auto;padding:clamp(16px,4vw,40px);display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr);gap:22px}.panel{background:rgba(18,26,44,.95);border:1px solid var(--line);border-radius:20px;padding:clamp(18px,3vw,28px);min-width:0}.eyebrow{font-size:12px;color:var(--accent);font-weight:800;letter-spacing:.13em;text-transform:uppercase}h1{font-size:clamp(28px,4vw,38px);line-height:1.1;margin:12px 0}h2{font-size:20px;margin:0 0 14px}p{color:var(--muted)}label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}input,select,button{font:inherit;border-radius:10px;padding:12px;border:1px solid var(--line);width:100%}input,select{background:#0b1020;color:var(--text)}button{background:var(--accent);color:#071126;font-weight:800;border:0;cursor:pointer}button.secondary{background:#1a2740;color:var(--text);border:1px solid var(--line)}button:disabled{opacity:.5;cursor:not-allowed}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}.muted{font-size:12px;color:var(--muted)}.status{padding:14px;border:1px solid var(--line);border-radius:12px;background:#0b1020;white-space:pre-wrap;overflow-wrap:anywhere;margin-top:16px}.resources{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}.resource{background:#17233a;color:var(--text);border:1px solid var(--line);padding:15px;text-align:left}.resource strong{display:block}.resource small{display:block;color:var(--muted);font-weight:400;margin-top:4px}.resource:hover{border-color:var(--accent)}.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:4px 10px;font-size:12px;color:var(--muted)}.hidden{display:none!important}.decision{font-weight:850}.allow{color:var(--good)}.deny{color:var(--bad)}.step{color:var(--warn)}@media(max-width:760px){.layout{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.grid2{grid-template-columns:1fr}}
</style></head><body><header class="top"><div class="brand">ZTNA <span>ACCESS</span> · EMPLOYEE</div><a href="/">← Switch workspace</a></header><main class="layout"><section class="panel" id="loginPanel"><div class="eyebrow">Identity verification</div><h1>Welcome back.</h1><p>Sign in to request access. Your identity, device, MFA, and current policy are checked before resources open.</p><form id="loginForm"><label for="user">Employee account</label><select id="user" required></select><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><label for="otp">Authenticator code (TOTP)</label><input id="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="6-digit code" required><label for="device">Device</label><select id="device" required></select><div class="muted" style="margin-top:8px">Use the authenticator code registered for your employee account. For remote devices, use HTTPS.</div><button style="margin-top:20px" type="submit">Sign in securely</button></form><div id="loginMsg" class="status" role="status">Not signed in.</div></section><section class="panel hidden" id="accessPanel"><div class="eyebrow">Employee workspace</div><h1>Request resource access</h1><p id="welcome">Choose a resource below. Each request is checked by the live ZTNA policy engine and recorded in the manager's audit console.</p><div class="grid2"><div><span class="pill" id="userPill">Employee</span></div><div style="text-align:right"><button class="secondary" id="logout" type="button">Sign out</button></div></div><h2 style="margin-top:24px">Available systems</h2><div id="resources" class="resources"></div><div id="result" class="status" aria-live="polite">Choose a system to request access.</div><p class="muted">A denied request is still recorded for security review. A request does not override policy.</p></section></main><script>
const $=id=>document.getElementById(id),esc=s=>String(s??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');let token=null,device=null,deviceKey=null,user=null,catalog=null;
async function req(path,method='GET',body=null,auth=false){const headers={'Content-Type':'application/json'};let raw=body===null?'':JSON.stringify(body);if(auth&&token){headers.Authorization='Bearer '+token;headers['X-Device-Id']=device;const bytes=Uint8Array.from(atob(deviceKey.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(deviceKey.length/4)*4,'=')),c=>c.charCodeAt(0));const key=await crypto.subtle.importKey('raw',bytes,{name:'HMAC',hash:'SHA-256'},false,['sign']);const ts=(Date.now()/1000).toFixed(3),nonce=crypto.randomUUID(),digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw))),x=>x.toString(16).padStart(2,'0')).join('');const u=new URL(path,location.href);const msg=new TextEncoder().encode(['ztna-pop-v2',method,u.pathname+u.search,digest,ts,nonce].join(String.fromCharCode(10)));const sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,msg));headers['X-Device-Timestamp']=ts;headers['X-Device-Nonce']=nonce;headers['X-Content-SHA256']=digest;headers['X-Device-Proof']=Array.from(sig,b=>b.toString(16).padStart(2,'0')).join('')};const r=await fetch(path,{method,headers,body:body===null?undefined:raw});return {status:r.status,data:await r.json().catch(()=>({}))}}
async function loadCatalog(){try{const r=await fetch('/api/ui/catalog');catalog=await r.json();if(!r.ok)throw Error(catalog.error||'Demo catalog unavailable');$('user').innerHTML=catalog.users.map(u=>`<option value="${esc(u)}">${esc(u)}</option>`).join('');setDevices();$('user').addEventListener('change',setDevices);$('resources').innerHTML=catalog.resources.map(r=>`<button class="resource" data-resource="${esc(r)}"><strong>${esc(r)}</strong><small>Request access →</small></button>`).join('')}catch(e){$('loginMsg').textContent='Could not load employee directory: '+e.message}}
function setDevices(){const u=$('user').value;const ds=Object.entries(catalog.devices).filter(([name,d])=>d.owner===u).map(([name])=>name);$('device').innerHTML=ds.map(d=>`<option>${esc(d)}</option>`).join('')}
$('loginForm').addEventListener('submit',async e=>{e.preventDefault();$('loginMsg').textContent='Verifying credentials and MFA…';if(!window.isSecureContext&&!['localhost','127.0.0.1','::1'].includes(location.hostname)){$('loginMsg').textContent='Use HTTPS when connecting from another laptop.';return}try{const selectedUser=$('user').value,selectedDevice=$('device').value;const r=await req('/api/login','POST',{username:selectedUser,password:$('password').value,otp:$('otp').value,device_id:selectedDevice});if(r.status!==200)throw Error(r.data.error||'Sign in failed');token=r.data.token;device=selectedDevice;deviceKey=r.data.device_key;user=selectedUser;$('loginPanel').classList.add('hidden');$('accessPanel').classList.remove('hidden');$('userPill').textContent=user+' · '+device;$('welcome').textContent='Signed in as '+user+'. Every request below is evaluated and appears in the manager console.';$('loginMsg').textContent='Signed in';}catch(err){$('loginMsg').textContent=err.message}});
$('resources').addEventListener('click',async e=>{const b=e.target.closest('[data-resource]');if(!b||!token)return;const res=b.dataset.resource;$('result').textContent='Checking '+res+'…';try{const r=await req('/access/'+encodeURIComponent(res),'GET',null,true);const decision=r.status===200?'ALLOW':r.data.stepup?'STEP-UP REQUIRED':'DENY';$('result').innerHTML=`<div class="decision ${decision==='ALLOW'?'allow':decision.startsWith('STEP')?'step':'deny'}">${esc(decision)}</div><div style="margin-top:8px">${esc(res)}</div><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(JSON.stringify(r.data,null,2))}</pre><div class="muted">The request and decision have been sent to the shared audit log.</div>`}catch(err){$('result').textContent='Request failed: '+err.message}});
$('logout').addEventListener('click',async()=>{try{await req('/api/logout','POST',{},true)}catch(e){}token=null;device=null;deviceKey=null;user=null;$('accessPanel').classList.add('hidden');$('loginPanel').classList.remove('hidden');$('password').value='';$('otp').value='';$('loginMsg').textContent='Signed out.'});loadCatalog();
</script></body></html>"""

class PooledHTTPServer(HTTPServer):
    if ":" in HOST_ENV:
        address_family=socket.AF_INET6
    daemon_threads=True
    def handle_error(self, request, client_address):
        # Client disconnects and TLS handshake failures are routine; do not dump
        # tracebacks that can leak request details or flood stderr.
        logger.debug("request handling failed for %s", client_address)
    request_queue_size=128
    def __init__(self,*args,max_workers=32,**kwargs):
        super().__init__(*args,**kwargs)
        self.max_workers=max_workers
        self.slots=threading.BoundedSemaphore(max_workers)
        self.executor=ThreadPoolExecutor(max_workers=max_workers,thread_name_prefix="ztna-http")
    def get_request(self):
        request,client_address=self.socket.accept()
        if getattr(self,"ssl_context",None): request=self.ssl_context.wrap_socket(request,server_side=True,do_handshake_on_connect=False)
        return request,client_address
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            request.close(); return
        try:
            self.executor.submit(self._process_request,request,client_address)
        except Exception:
            self.slots.release(); request.close(); raise
    def _process_request(self,request,client_address):
        try: self.finish_request(request,client_address)
        except Exception: self.handle_error(request,client_address)
        finally:
            self.shutdown_request(request); self.slots.release()
    def server_close(self):
        super().server_close()
        if hasattr(self,"executor"): self.executor.shutdown(wait=True,cancel_futures=True)



# ---------- plain-English decisions and per-employee resource previews (demo content) ----------
def _seeded(user, resource):
    return random.Random(int(hashlib.sha256(f"{user}|{resource}".encode()).hexdigest()[:12], 16))

_P_REPOS = ["payments-api", "web-frontend", "mobile-app", "auth-service", "data-pipeline", "search-index", "billing-engine", "notifications", "design-system", "infra-modules"]
_P_COMMITS = ["Fix race condition in retry logic", "Add pagination to list endpoint", "Bump dependencies (security patch)", "Refactor config loader", "Improve error messages", "Add unit tests for edge cases", "Cache expensive lookups", "Remove dead feature flag"]
_P_PIPES = ["build-main", "deploy-staging", "deploy-prod", "nightly-tests", "terraform-plan", "container-scan", "db-migrate", "rollback-check"]
_P_CUST = ["Acme Corp", "Globex", "Initech", "Umbrella Ltd", "Hooli", "Stark Industries", "Wayne Enterprises", "Soylent Co", "Vandelay Imports", "Pied Piper", "Cyberdyne", "Wonka Foods"]
_P_ACCT = ["Accounts payable", "Accounts receivable", "Payroll clearing", "Cloud hosting", "Travel & expenses", "Software licences", "Office lease", "Marketing spend"]
_P_TICKET = ["Cannot reset password", "Invoice shows wrong amount", "App crashes on login", "Export to CSV is empty", "Need to change account owner", "Slow dashboard loading", "Two-factor code not arriving", "Refund request"]
_P_DOCS = ["Master services agreement", "Mutual NDA", "Data processing addendum", "Vendor contract", "Office lease renewal", "Employment template", "Partner agreement", "Privacy policy v4"]
_P_RULES = ["Impossible travel", "Brute-force login", "Unusual data download", "New admin created", "Malware signature hit", "Port scan from guest Wi-Fi", "Disabled endpoint protection", "Off-hours VPN login"]
_P_KPIS = [("Monthly recurring revenue", "$4.82M", "+3.1%"), ("Active customers", "12,480", "+1.4%"), ("Gross margin", "71.2%", "+0.6 pt"), ("Cash runway", "27 months", "no change"), ("Net revenue retention", "112%", "+2 pt"), ("Support CSAT", "94%", "-1 pt"), ("Hiring plan filled", "68%", "+5 pt"), ("Security incidents (30d)", "3", "-2")]
_P_WIKI = {
    "engineer": ["Coding standards", "How to review a pull request", "On-call handbook", "Architecture decision records", "Local dev environment setup"],
    "devops": ["Runbook: failed deploy", "Kubernetes cluster map", "Terraform conventions", "Incident command guide", "Backup and restore drill"],
    "security": ["Incident response plan", "Phishing triage guide", "Vulnerability SLAs", "Zero Trust rollout plan", "Log retention policy"],
    "hr": ["Onboarding checklist", "Performance review calendar", "Leave and holiday policy", "Interview scorecards", "Benefits FAQ"],
    "finance": ["Month-end close checklist", "Expense policy", "Vendor payment terms", "Audit preparation", "Budget calendar"],
    "sales": ["Pricing and discount rules", "Competitor battlecards", "Demo script", "Deal desk process", "Territory map"],
    "support": ["Escalation matrix", "Macro library", "Refund policy", "Known issues", "Tone-of-voice guide"],
    "legal": ["Contract review checklist", "Data protection guide", "IP assignment policy", "Regulatory calendar", "Outside counsel panel"],
    "executive": ["Quarterly priorities", "Board calendar", "Org chart", "Strategy one-pager", "Company values"],
    "admin": ["Joiner / mover / leaver process", "Device enrolment guide", "Backup schedule", "License inventory", "Access review procedure"],
}

def resource_preview(user, resource):
    """A small, believable preview of what `user` sees inside `resource`. Deterministic per user, different for every
    employee. Demo content only (nothing here is real data)."""
    prof = USER_PROFILE.get(user, {}); role = USERS.get(user, {}).get("role", "?")
    who = prof.get("name", user); rnd = _seeded(user, resource)
    pick = lambda pool, n: rnd.sample(pool, min(n, len(pool)))
    if resource == "wiki":
        rows = [(t, rnd.choice(["Team space", "Company", "Handbook"]), f"{rnd.randint(1, 28)} days ago") for t in _P_WIKI.get(role, _P_WIKI["engineer"])[:4]]
        return {"title": f"Wiki pages recommended for {who}", "summary": f"Pages for the '{role}' role.", "columns": ("Page", "Space", "Last edited"), "rows": rows}
    if resource == "hr-db":
        others = [u for u in sorted(USER_PROFILE) if u != user]
        rows = [(USER_PROFILE[u]["name"], USER_PROFILE[u]["dept"], USER_PROFILE[u]["title"], rnd.choice(["Active", "Active", "Active", "On leave"])) for u in pick(others, 5)]
        return {"title": f"Employee records opened by {who}", "summary": "Showing 5 of %d employee records (sample)." % len(USER_PROFILE), "columns": ("Employee", "Department", "Title", "Status"), "rows": rows}
    if resource == "admin-panel":
        weak = sum(1 for d in DEVICES if posture(d) < 70)
        rows = [("Registered users", len(USERS)), ("Registered devices", len(DEVICES)), ("Devices below score 70", weak),
                ("Active sessions", sum(1 for x in list(SESSIONS.values()) if x["exp"] > time.time())), ("Admin signed in", who)]
        return {"title": "IT admin console - live system overview", "summary": "Counts come from the running lab.", "columns": ("Item", "Value"), "rows": rows}
    if resource == "source-code":
        rows = [(r, rnd.choice(["main", "develop", "release"]), rnd.choice(_P_COMMITS), rnd.randint(0, 9)) for r in pick(_P_REPOS, 4)]
        return {"title": f"Repositories visible to {who}", "summary": "Your recent repositories.", "columns": ("Repository", "Branch", "Latest commit", "Open PRs"), "rows": rows}
    if resource == "ci-cd":
        rows = [(n, rnd.choice(["passed", "passed", "passed", "failed", "running"]), f"{rnd.randint(1, 14)}m {rnd.randint(0, 59):02d}s", f"#{rnd.randint(1000, 9999)}") for n in pick(_P_PIPES, 5)]
        return {"title": f"Pipelines owned by {who}", "summary": "Latest runs.", "columns": ("Pipeline", "Status", "Duration", "Run"), "rows": rows}
    if resource == "crm":
        rows = [(c, rnd.choice(["Prospecting", "Demo", "Proposal", "Negotiation", "Closed won"]), f"${rnd.randint(8, 240)}k", who) for c in pick(_P_CUST, 5)]
        return {"title": f"Accounts in {who}'s view", "summary": "Accounts assigned to you.", "columns": ("Account", "Stage", "Deal value", "Owner"), "rows": rows}
    if resource == "finance-ledger":
        rows = [(f"JE-{rnd.randint(10000, 99999)}", a, f"${rnd.randint(1, 480) * 100:,}", rnd.choice(["Posted", "Posted", "Pending approval"])) for a in pick(_P_ACCT, 5)]
        return {"title": f"Ledger entries for {who}", "summary": "Recent journal entries.", "columns": ("Entry", "Account", "Amount", "Status"), "rows": rows}
    if resource == "support-desk":
        rows = [(f"T-{rnd.randint(1000, 9999)}", t, rnd.choice(["Low", "Normal", "High", "Urgent"]), rnd.choice(["Open", "Waiting on customer", "In progress"])) for t in pick(_P_TICKET, 5)]
        return {"title": f"Ticket queue for {who}", "summary": "Tickets assigned to you.", "columns": ("Ticket", "Subject", "Priority", "Status"), "rows": rows}
    if resource == "legal-vault":
        rows = [(d, rnd.choice(_P_CUST), rnd.choice(["Signed", "In review", "Awaiting signature"]), f"20{rnd.randint(27, 29)}-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}") for d in pick(_P_DOCS, 5)]
        return {"title": f"Documents shared with {who}", "summary": "Contracts needing attention.", "columns": ("Document", "Counterparty", "Status", "Expires"), "rows": rows}
    if resource == "siem-console":
        rows = [(rnd.choice(["Critical", "High", "Medium", "Low"]), r, f"host-{rnd.randint(10, 99)}", rnd.randint(1, 40)) for r in pick(_P_RULES, 5)]
        return {"title": f"Alert queue for {who}", "summary": "Open alerts.", "columns": ("Severity", "Rule", "Host", "Events"), "rows": rows}
    if resource == "exec-reports":
        rows = [(m, v, d) for m, v, d in pick(_P_KPIS, 5)]
        return {"title": f"Board dashboard for {who}", "summary": "Latest company KPIs.", "columns": ("Metric", "Value", "Change"), "rows": rows}
    return {"title": resource, "summary": "No preview available.", "columns": ("Info",), "rows": [("-",)]}

def _fmt_hours(r):
    lo, hi = r["hours"]
    return "any time" if (lo, hi) == (0, 24) else f"{lo:02d}:00-{hi:02d}:00"

_TICK, _CROSS = "\u2714", "\u2716"

def resource_requirements(resource):
    """One readable line: what this resource demands."""
    r = RESOURCES[resource]
    bits = [f"device health score {r['min_posture']}+", "company-managed device" if r["managed"] else "any device",
            f"hours: {_fmt_hours(r)}", "from: " + " or ".join(r["locations"]), f"MFA within {r['mfa_age'] // 60} min"]
    return " | ".join(bits)

def explain_decision(resource, result):
    """Turn a raw access result into (verdict, headline, lines, tips) in plain English.
    verdict is ALLOW, STEPUP or DENY; every reason becomes a sentence a non-expert can act on."""
    decision = result.get("decision", "DENY"); r = RESOURCES.get(resource, {})
    if decision == "ALLOW":
        return "ALLOW", f"ACCESS GRANTED - you are in {resource}", [f"All checks passed (risk score {result.get('risk', 0)}/100)."], []
    err = result.get("error", "")
    simple = {"authentication required": ("You are not signed in.", "Open the Overview tab, choose a user, click 'Generate demo OTP', then 'Login'."),
              "session revoked": ("Your session was ended by an administrator.", "Sign in again from the Overview tab."),
              "session expired": ("Your session expired.", "Sign in again from the Overview tab."),
              "unknown resource": ("That system does not exist.", "Pick one of the resource cards."),
              "audit unavailable; action refused": ("The audit log is damaged or unavailable, so every action is refused until it is fixed (fail-closed).", "Open Audit & Integrity: press Verify, then follow the recovery steps shown there.")}
    if err in simple and decision == "DENY" and not result.get("reasons"):
        line, tip = simple[err]
        return "DENY", f"ACCESS DENIED - {line}", [], [tip]
    lines, tips = [], []; role = result.get("role", "?")
    for reason in result.get("reasons", []):
        t = str(reason)
        if t.startswith("RBAC"):
            lines.append(f"Your role ({role}) is not allowed to use {resource}. Allowed roles: {', '.join(r.get('roles', []))}.")
            tips.append("Sign in as a user whose role is on that list (see the 'Roles & Access' tab).")
        elif t.startswith("micro-segmentation"):
            lines.append(f"The network segment for {resource} is closed to your role, so the connection is blocked even before other checks.")
        elif t == "unknown device":
            lines.append("This device is not enrolled, so it cannot be trusted.")
            tips.append("Enroll it in the Identity & Devices tab.")
        elif t == "device not owned by user":
            lines.append("This device belongs to someone else.")
            tips.append("Log in from your own device.")
        elif t.startswith("posture"):
            nums = re.findall(r"\d+", t)
            lines.append(f"Your device health score is {nums[0]}/100 but {resource} needs at least {nums[1]}.")
            d = DEVICES.get(result.get("device"))
            if d and POSTURE_TTL > 0 and time.time() - d.get("last_report", 0) > POSTURE_TTL:
                lines.append(f"Reason: the device has not sent a health report for over {POSTURE_TTL // 60} minutes, so it is treated as unknown (score 0).")
                tips.append("Open Device Posture and turn on the simulated agent, or press 'Send report now'.")
            else:
                tips.append("Open the Device Posture tab and fix the failing checks (OS update, disk encryption, firewall, antivirus).")
        elif t.startswith("corporate-managed"):
            lines.append(f"{resource} only accepts company-managed devices; this one is a personal (BYOD) device.")
            tips.append("Log in from a company laptop instead.")
        elif t.startswith("outside allowed hours"):
            lines.append(f"{resource} is only open {_fmt_hours(r)}; the policy clock reads {result.get('hour', now_hour()):02d}:00.")
            tips.append("Try within those hours, or change the simulated hour on the Policy tab.")
        elif t.startswith("location"):
            lines.append(f"{resource} cannot be opened from your current location. Allowed: {', '.join(r.get('locations', []))}.")
            tips.append("Log in again with an allowed location.")
        elif t.startswith("risk score"):
            lines.append(f"Your overall risk score is too high ({result.get('risk', '?')}/100; 80 or more is blocked).")
            tips.append("Improve device health, use the office, and avoid repeated failed logins.")
        elif t.startswith("MFA older"):
            lines.append(f"{resource} needs a recent MFA check and yours is too old ({t}).")
            tips.append("Use 'Generate OTP' then 'Verify step-up' below, then request access again.")
        else:
            lines.append(t)
    for sig in result.get("signals", []):
        lines.append(f"Risk signal: {sig}.")
    if decision == "STEPUP":
        return "STEPUP", f"EXTRA VERIFICATION NEEDED - {resource}", lines or ["Please confirm your identity again."], tips
    return "DENY", f"ACCESS DENIED - {resource}", lines or ["Policy denied this request."], tips

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

def decide_signin_request(rid, approve, manager, note=""):
    """Manager decision. Returns the request row, or None if it was no longer pending. Audited; reverts if audit fails."""
    status="approved" if approve else "denied"; now=time.time()
    if _signin_write("UPDATE signin_requests SET status=?,decided_by=?,decided_at=?,note=?,closed_at=?,closed_reason=? WHERE id=? AND status='pending'",
                     (status,manager,now,(note or "")[:200],None if approve else now,None if approve else "denied by manager",rid))!=1:
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


class DesktopZTNA:
    """Small desktop-facing adapter around the hardened ZTNA """

    def __init__(self):
        self.session = None
        self.user = None
        self.device = None
        self.location = "office"

    def demo_otp(self, user):
        if not DEMO_OTP: raise RuntimeError("demo OTP generation disabled")
        return demo_totp_code(user)

    @staticmethod
    def _audit(**kw):
        """Audit without leaking AuditFull/AuditTamper into Tk callbacks; False means refuse the action."""
        try:
            audit(**kw); return True
        except (AuditFull, AuditTamper):
            return False

    def _fail_login(self, user, device, ip="desktop"):
        note_fail(user,ip)
        self._audit(user=user, device=device, resource="login", decision="DENY", reasons=["authentication failed"])
        n=recent_fails(user,ip)
        if n>=3 and user in USERS: db_alert_once("HIGH","BRUTE_FORCE_SUSPECTED",user,device,f"{n} recent failed authentication attempts",window=30.0)
        return False, "Authentication failed"

    def _authenticate(self, user, password, otp, device):
        """Password, then device ownership, then the one-time code LAST (so a code is only ever spent when everything else
        already checked out). Returns (ok, message); creates no session."""
        if device in BLOCKED_DEVICES:
            # A blocked device is refused outright, but its repeated attempts must not be able to flood the audit log.
            if audit_allowed(f"{user}|{device}","blocked-login",limit=3,window=60):
                self._audit(user=user, device=device, resource="login", decision="DENY", reasons=["device blocked by ZTNA manager"])
            return False, "This device has been blocked by the ZTNA manager"
        ip="desktop"
        if not reserve_auth_attempt(user,ip):
            n=recent_fails(user,"desktop")
            if n>=3 and user in USERS: db_alert_once("HIGH","BRUTE_FORCE_SUSPECTED",user,device,f"{n} failed attempts; further attempts are being throttled",window=30.0)
            return False, "Authentication temporarily unavailable"
        try:
            return self._authenticate_reserved(user,password,otp,device,ip)
        except StateStoreError:
            refund_auth_attempt(user,ip)                   # our storage failed, not the user's credentials
            return False, "Authentication state is unavailable; nothing was spent, try again shortly"
        except BaseException:
            refund_auth_attempt(user,ip); raise            # never leave an unexplained failure counted against the user

    def _authenticate_reserved(self, user, password, otp, device, ip):
        usr = USERS.get(user); dummy=next(iter(USERS.values())) if USERS else None
        pw_before = dict(usr["pw"]) if usr else None
        try: password_ok=pw_verify(password, usr["pw"] if usr else dummy["pw"] if dummy else {})
        except KdfBusy:
            refund_auth_attempt(user,ip)
            return False, "Authentication capacity temporarily unavailable"
        if usr and password_ok and usr["pw"] != pw_before:
            try: _persist_users()
            except Exception:
                logger.exception("could not persist upgraded password hash")
                refund_auth_attempt(user,ip)
                return False, "Account store unavailable; login refused"
        if not usr or not password_ok: return self._fail_login(user,device,ip)
        if device not in DEVICES or DEVICES[device]["owner"] != user: return self._fail_login(user,device,ip)
        if not totp_ok(user, usr["totp"], otp): return self._fail_login(user,device,ip)
        release_auth_attempt(user,ip)
        return True, "Credentials verified"

    def login(self, user, password, otp, device, location):
        ok, msg = self._authenticate(user, password, otp, device)
        if not ok: return False, msg
        return self._open_session(user, device, location)

    def request_signin(self, user, password, otp, device, location):
        """Verify credentials, then send the sign-in to the manager queue. Returns (True, request_id) or (False, message)."""
        ok, msg = self._authenticate(user, password, otp, device)
        if not ok: return False, msg
        try:
            rid = create_signin_request(user, device, location if location in ("office","home") else "office")
        except (StateStoreError, AuditFull, AuditTamper):
            return False, "Sign-in request could not be recorded; nothing was sent"
        self.pending_request = rid
        return True, rid

    def complete_signin(self, rid):
        """Open the session once a manager approved the request. One approval = one session."""
        try: row = get_signin_request(rid)
        except StateStoreError: return False, "The sign-in service is temporarily unavailable; try again in a moment"
        if not row or row["status"] != "approved":
            return False, "This sign-in has not been approved"
        user, device = row["user"], row["device"]
        if user not in USERS or device not in DEVICES or DEVICES[device].get("owner") != user:
            return False, "This sign-in can no longer be completed"
        if device in BLOCKED_DEVICES:                         # blocked after the approval was given: refuse, keep nothing open
            if audit_allowed(f"{user}|{device}","blocked-login",limit=3,window=60):
                self._audit(user=user, device=device, resource="login", decision="DENY", reasons=["approved sign-in refused: device was blocked after approval"])
            return False, "This device has been blocked by the ZTNA manager"
        try: claimed = claim_signin_request(rid)
        except StateStoreError: return False, "The sign-in service is temporarily unavailable; try again in a moment"
        if not claimed:
            return False, "This approval was already used or has expired"
        self.pending_request = None
        return self._open_session(row["user"], row["device"], row["location"],
                                  extra_reasons=[f"sign-in approved by manager {row['decided_by']}"])

    def _open_session(self, user, device, location, extra_reasons=()):
        ip="desktop"
        now = time.time()
        previous = LASTLOC.get(user)
        travel = bool(previous and previous[0] != location and now - previous[1] < 300)
        if travel: db_alert_once("MEDIUM","IMPOSSIBLE_TRAVEL",user,device,f"{previous[0]} -> {location} in {int(now-previous[1])}s",window=60.0)
        sid = secrets.token_hex(12)
        pop_salt = _new_session_salt()
        key = _derive_session_key(sid, pop_salt)
        sess = {
            "user": user,
            "device": device,
            "location": location,
            "exp": now + TOKEN_TTL,
            "abs_exp": now + _env_int("ZTNA_SESSION_MAX",3600,1,30*86400),
            "mfa_at": now,
            "travel": travel,
            "auth_ip": "desktop",
            "location_at": now,
            "created": now,
            "key": key,
        }
        with LOCK:
            _prune_sessions_for_login_locked(user,now)
            SESSIONS[sid] = sess
            LASTLOC[user] = (location, now)
        db_exec("INSERT OR REPLACE INTO sessions(sid,user,device,location,created,expires,revoked,pop_key,mfa_at) VALUES(?,?,?,?,?,?,0,?,?)",(sid,user,device,location,now,sess["abs_exp"],pop_salt,now))
        if not self._audit(user=user, device=device, resource="login", decision="ALLOW",
                   reasons=["password + TOTP verified"] + list(extra_reasons) +
                           (["location change within 5 min"] if travel else [])):
            with LOCK: SESSIONS.pop(sid,None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            return False, "Audit unavailable; login refused"
        if device in DEVICES: DEVICES[device]["last_report"] = now   # the device checks in when its user signs in
        self.session = (sid, sess)
        self.user, self.device, self.location = user, device, location
        return True, "Login successful"


    def stepup(self, otp):
        if not self.session:
            return False, "Not logged in"
        sid, sess = self.session
        with LOCK:
            if sid not in SESSIONS:
                self.session=None
                return False, "session revoked"
        if sess["exp"] <= time.time() or sess["abs_exp"] <= time.time():
            with LOCK: SESSIONS.pop(sid,None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            self.session=None
            return False, "Session expired"
        if not reserve_auth_attempt(sess["user"], "desktop"):
            return False, "Authentication temporarily unavailable"
        try: code_ok = totp_ok(sess["user"], USERS[sess["user"]]["totp"], otp)
        except StateStoreError:
            refund_auth_attempt(sess["user"], "desktop")
            return False, "Authentication state is unavailable; nothing was spent, try again shortly"
        if not code_ok:
            note_fail(sess["user"], "desktop")
            self._audit(user=sess["user"], device=sess["device"], resource="stepup",
                       decision="DENY", reasons=["bad step-up code"])
            return False, "Authentication failed"
        release_auth_attempt(sess["user"], "desktop")
        # Record the event first so an unavailable audit log cannot grant fresh MFA.
        if not self._audit(user=sess["user"], device=sess["device"], resource="stepup",
                   decision="ALLOW", reasons=["MFA re-verified"]):
            return False, "Audit unavailable; step-up refused"
        with LOCK:
            sess["mfa_at"] = time.time(); sess["travel"] = False
            sess["exp"] = min(sess["mfa_at"] + TOKEN_TTL, sess["abs_exp"])
            STEPUP_REQUIRED_USERS.discard(sess["user"])
        db_exec("UPDATE sessions SET mfa_at=? WHERE sid=?",(sess["mfa_at"],sid))
        return True, "MFA re-verified"

    def access(self, resource):
        if not self.session:
            return {"decision": "DENY", "error": "authentication required"}
        sid, sess = self.session
        with LOCK:
            if sid not in SESSIONS:
                self.session=None
                return {"decision":"DENY","error":"session revoked"}
        if sess["exp"] <= time.time() or sess["abs_exp"] <= time.time():
            with LOCK: SESSIONS.pop(sid, None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            self.session = None
            return {"decision": "DENY", "error": "session expired"}
        if resource not in RESOURCES:
            return {"decision": "DENY", "error": "unknown resource"}
        if sess["device"] in BLOCKED_DEVICES:
            return {"decision": "DENY", "error": "device blocked by manager", "reasons": ["This device has been blocked by the ZTNA manager."]}
        if sess["user"] in STEPUP_REQUIRED_USERS:
            if not self._audit(user=sess["user"], device=sess["device"], resource=resource, decision="STEPUP", reasons=["manager requires fresh MFA before next application request"]):
                return {"decision": "DENY", "error": "audit unavailable; action refused"}
            return {"decision": "STEPUP", "error": "manager requires fresh MFA", "device": sess["device"], "risk": 0, "reasons": ["A manager requires you to verify your authenticator again."], "signals": [], "role": USERS[sess["user"]]["role"], "segment": SEGMENTS[resource], "segment_allowed": segment_allows(sess["user"], resource)}
        if sess["device"] in BLOCKED_DEVICES:
            return {"decision": "DENY", "error": "device blocked by manager", "reasons": ["This device has been blocked by the ZTNA manager."]}
        # Idle timeout, not a hard stop: activity keeps the session alive (up to its absolute lifetime), so MFA
        # windows longer than the token lifetime (e.g. 15 min) can actually apply instead of being cut off at 5 min.
        with LOCK: sess["exp"] = min(time.time() + TOKEN_TTL, sess["abs_exp"])
        decision, reasons, risk, signals = evaluate(sess, sess["device"], resource)
        if not self._audit(user=sess["user"], device=sess["device"], resource=resource,
                   decision=decision, reasons=reasons, risk=risk, signals=signals):
            return {"decision": "DENY", "error": "audit unavailable; action refused"}
        result = {"decision": decision, "device": sess["device"], "risk": risk, "reasons": reasons, "signals": signals, "role": USERS[sess["user"]]["role"], "segment": SEGMENTS[resource], "segment_allowed": segment_allows(sess["user"], resource)}
        if decision == "ALLOW":
            result["data"] = f"[simulated {resource} content]"
            result["preview"] = resource_preview(sess["user"], resource)
            upstream = RESOURCES[resource].get("upstream")
            if upstream:
                try:
                    result["upstream"] = fetch_upstream(upstream)
                except Exception:
                    result["upstream_error"] = "upstream unavailable"
        elif decision == "STEPUP":
            result["error"] = "step-up authentication required"
        else:
            result["error"] = "access denied"
        return result

    def logout(self):
        if self.session:
            sid, sess = self.session
            with LOCK: SESSIONS.pop(sid, None)
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?",(sid,))
            self._audit(user=sess["user"], device=sess["device"], resource="session",
                       decision="REVOKE", reasons=["user logout"])
        self.session = None
        self.user = self.device = None


class Card(tk.Frame):
    """White, thin-bordered panel with an optional title row; put content in ``.body``."""

    def __init__(self, parent, title=None, subtitle=None, padding=14):
        super().__init__(parent, background="#d6e1ee", highlightthickness=0, bd=0)
        self._inner = ttk.Frame(self, style="Card.TFrame", padding=padding)
        self._inner.pack(fill="both", expand=True, padx=1, pady=1)
        self.head = None
        if title:
            self.head = ttk.Frame(self._inner, style="Card.TFrame")
            self.head.pack(fill="x", pady=(0, 10))
            ttk.Label(self.head, text=title, style="CardTitle.TLabel").pack(side="left")
            if subtitle:
                ttk.Label(self.head, text=subtitle, style="CardHint.TLabel").pack(side="left", padx=(10, 0))
        self.body = ttk.Frame(self._inner, style="Card.TFrame")
        self.body.pack(fill="both", expand=True)


class ScrollTab(tk.Frame):
    """Notebook page whose content always fills the page, and scrolls only when the window is too small."""

    def __init__(self, parent, background):
        super().__init__(parent, background=background, highlightthickness=0, bd=0)
        self.canvas = tk.Canvas(self, background=background, highlightthickness=0, bd=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body = ttk.Frame(self.canvas, padding=(20, 16))
        self._win = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self._vbar_shown = False
        self.body.bind("<Configure>", self._fit)
        self.canvas.bind("<Configure>", self._fit)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(seq, self._on_wheel, add="+")
        self._last_need = -1
        self.after(200, self._watch)

    def _watch(self):
        try:
            if self.body.winfo_reqheight() != self._last_need:
                self._fit()
            self.after(200, self._watch)
        except tk.TclError:
            pass

    def _fit(self, _event=None):
        cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
        if cw < 2 or ch < 2:
            return
        need = self._last_need = self.body.winfo_reqheight()
        height = max(ch, need)
        self.canvas.itemconfigure(self._win, width=cw, height=height)
        self.canvas.configure(scrollregion=(0, 0, cw, height))
        scrollable = need > ch + 1
        if scrollable and not self._vbar_shown:
            self.vbar.pack(side="right", fill="y", before=self.canvas); self._vbar_shown = True
        elif not scrollable and self._vbar_shown:
            self.vbar.pack_forget(); self._vbar_shown = False; self.canvas.yview_moveto(0)

    def _on_wheel(self, event):
        if not self._vbar_shown or not self.winfo_ismapped():
            return
        widget = event.widget
        try:
            if widget.winfo_class() in ("Treeview", "Text", "Listbox", "TCombobox", "TSpinbox", "Toplevel"):
                return
        except Exception:
            return
        node = widget
        while node is not None and node is not self:
            node = getattr(node, "master", None)
        if node is None:
            return
        if getattr(event, "num", None) == 4: step = -2
        elif getattr(event, "num", None) == 5: step = 2
        else: step = -2 if event.delta > 0 else 2
        self.canvas.yview_scroll(step, "units")


class LegacyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ZTNA Enterprise Lab — Zero Trust Security Control Center")
        # Size to the screen (leaving room for the taskbar/title bar) so the window can always be grabbed and moved.
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(1280, int(sw * 0.86)), min(780, int(sh * 0.80))
        self.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, int((sh - h) * 0.25))}")
        self.minsize(min(860, w), min(520, h))
        self.resizable(True, True)
        self.bind("<F11>", lambda _e: self.attributes("-fullscreen", not self.attributes("-fullscreen")))
        self.bind("<Escape>", lambda _e: self.attributes("-fullscreen", False))
        self.engine = DesktopZTNA()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build_style()
        if DEMO:
            # The runtime user store is authoritative; enrollments survive restarts.
            load_persisted_devices()
            if not POSTURE_KEYS:
                POSTURE_KEYS.update(_demo_posture_keys())
        self._build_ui()
        self.refresh_all()

    # ------------------------------------------------------------------ layout helpers
    GAP = 12

    def _build_style(self):
        """Light, enterprise-style dashboard theme; presentation only."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        C = self.C = dict(bg="#edf3f9", panel="#ffffff", panel2="#f3f7fc", border="#d6e1ee", fg="#12294b", muted="#607a9b",
                          blue="#0878e8", blue_hover="#0866c7", green="#07966b", red="#d83b4b", amber="#b26a00")
        bg, panel, panel2, border, fg, muted = C["bg"], C["panel"], C["panel2"], C["border"], C["fg"], C["muted"]
        blue, blue_hover, red = C["blue"], C["blue_hover"], C["red"]
        F = "Segoe UI"

        self.configure(background=bg)
        style.configure(".", font=(F, 10), background=bg, foreground=fg)
        style.configure("TFrame", background=bg)
        style.configure("Card.TFrame", background=panel)
        style.configure("Header.TFrame", background=panel)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Sub.TLabel", font=(F, 10), background=bg, foreground=muted)
        style.configure("PageStrong.TLabel", font=(F, 11, "bold"), background=bg, foreground=fg)
        style.configure("Card.TLabel", background=panel, foreground=fg)
        style.configure("CardStrong.TLabel", font=(F, 10, "bold"), background=panel, foreground=fg)
        style.configure("CardTitle.TLabel", font=(F, 11, "bold"), background=panel, foreground="#102d55")
        style.configure("CardHint.TLabel", font=(F, 9), background=panel, foreground=muted)
        style.configure("CardBanner.TLabel", font=(F, 13, "bold"), background=panel, foreground=fg)
        style.configure("KpiTitle.TLabel", font=(F, 9, "bold"), background=panel, foreground=muted)
        style.configure("KpiValue.TLabel", font=(F, 22, "bold"), background=panel, foreground=blue)
        style.configure("Score.TLabel", font=(F, 20, "bold"), background=panel, foreground=blue)
        style.configure("HeaderTitle.TLabel", font=(F, 19, "bold"), background=panel, foreground="#10284b")
        style.configure("HeaderSub.TLabel", font=(F, 10), background=panel, foreground=muted)
        # kept for compatibility with any caller that still uses the old names
        style.configure("Title.TLabel", font=(F, 23, "bold"), background=bg, foreground="#10284b")
        style.configure("Card.TLabelframe", background=panel, bordercolor=border, relief="solid", padding=15)
        style.configure("Card.TLabelframe.Label", font=(F, 11, "bold"), background=panel, foreground="#102d55")
        style.configure("TLabelframe", background=panel, bordercolor=border, relief="solid", padding=12)
        style.configure("TLabelframe.Label", background=panel, foreground="#102d55", font=(F, 10, "bold"))

        style.configure("TNotebook", background=bg, bordercolor=border, borderwidth=0, tabmargins=(0, 6, 0, 0))
        style.configure("TNotebook.Tab", background="#e3ecf7", foreground="#45617f", padding=(11, 8), bordercolor=border, font=(F, 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", blue), ("active", "#d3e8ff")], foreground=[("selected", "#ffffff"), ("active", fg)])

        style.configure("TButton", background="#f0f5fb", foreground=fg, bordercolor=border, padding=(12, 7), relief="flat", font=(F, 10))
        style.map("TButton", background=[("active", "#dcecff"), ("pressed", "#c9e0fb"), ("disabled", "#edf1f6")], foreground=[("disabled", "#9aa9ba")])
        style.configure("Action.TButton", font=(F, 10, "bold"), padding=(14, 8), background=blue, foreground="#ffffff", bordercolor=blue)
        style.map("Action.TButton", background=[("active", blue_hover), ("pressed", "#0758ac")], foreground=[("disabled", "#dce8f6")])
        style.configure("Danger.TButton", font=(F, 10, "bold"), padding=(12, 8), background=red, foreground="#ffffff", bordercolor=red)
        style.map("Danger.TButton", background=[("active", "#b92e3e")])
        style.configure("Link.TButton", font=(F, 9, "bold"), padding=(10, 4), background=panel, foreground=blue, bordercolor=border)
        style.map("Link.TButton", background=[("active", "#eaf3ff")])

        style.configure("TEntry", fieldbackground="#ffffff", foreground=fg, insertcolor=fg, bordercolor=border, lightcolor=border, darkcolor=border, padding=6)
        style.map("TEntry", bordercolor=[("focus", blue)])
        style.configure("TSpinbox", fieldbackground="#ffffff", foreground=fg, bordercolor=border, lightcolor=border, darkcolor=border, arrowcolor=blue, padding=5)
        style.map("TSpinbox", bordercolor=[("focus", blue)])
        style.configure("TCombobox", fieldbackground="#ffffff", background="#eaf2fb", foreground=fg, arrowcolor=blue, bordercolor=border, lightcolor=border, darkcolor=border, padding=5)
        style.map("TCombobox", fieldbackground=[("readonly", "#ffffff")], foreground=[("readonly", fg)], selectbackground=[("readonly", "#ffffff")],
                  selectforeground=[("readonly", fg)], bordercolor=[("focus", blue)])
        style.configure("TCheckbutton", background=panel, foreground=fg, indicatorbackground="#ffffff", indicatorforeground="#ffffff", bordercolor=border, lightcolor=border, darkcolor=border, upperbordercolor=border, lowerbordercolor=border)
        style.map("TCheckbutton", background=[("active", panel)], indicatorbackground=[("selected", blue), ("active", "#eaf3ff"), ("!selected", "#ffffff")],
                  indicatorforeground=[("selected", "#ffffff")])
        style.configure("Page.TCheckbutton", background=bg, foreground=fg, indicatorbackground="#ffffff", indicatorforeground="#ffffff", bordercolor=border, lightcolor=border, darkcolor=border)
        style.map("Page.TCheckbutton", background=[("active", bg)], indicatorbackground=[("selected", blue), ("!selected", "#ffffff")], indicatorforeground=[("selected", "#ffffff")])
        style.configure("TRadiobutton", background=panel, foreground=fg)
        style.configure("TSeparator", background=border)
        style.configure("TPanedwindow", background=bg)
        style.configure("TProgressbar", troughcolor=panel2, background=blue, bordercolor=border, lightcolor=blue, darkcolor=blue, thickness=10)
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", background="#c9d8ea", troughcolor=panel2, bordercolor=border, arrowcolor=muted, relief="flat")
            style.map(f"{orient}.TScrollbar", background=[("active", "#a9c3e0")])

        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground=fg, bordercolor=border, lightcolor=border, darkcolor=border, rowheight=28, font=(F, 9))
        style.configure("Treeview.Heading", background="#eaf1f9", foreground="#19385f", relief="flat", padding=(10, 7), font=(F, 9, "bold"))
        style.configure("Compact.Treeview", rowheight=24)
        style.configure("Compact.Treeview.Heading", background="#eaf1f9", foreground="#19385f", relief="flat", padding=(8, 5), font=(F, 9, "bold"))
        style.map("Treeview", background=[("selected", "#d6eaff")], foreground=[("selected", "#10284b")])
        style.map("Compact.Treeview", background=[("selected", "#d6eaff")], foreground=[("selected", "#10284b")])
        style.map("Treeview.Heading", background=[("active", "#dcecff")])

        self.option_add("*Text.background", "#ffffff")
        self.option_add("*Text.foreground", fg)
        self.option_add("*Text.insertBackground", fg)
        self.option_add("*Text.selectBackground", "#d6eaff")
        self.option_add("*Listbox.background", "#ffffff")
        self.option_add("*Listbox.foreground", fg)
        self.option_add("*Listbox.selectBackground", "#d6eaff")
        self.option_add("*TCombobox*Listbox.background", "#ffffff")
        self.option_add("*TCombobox*Listbox.foreground", fg)
        self.option_add("*TCombobox*Listbox.selectBackground", "#d6eaff")
        self.option_add("*TCombobox*Listbox.selectForeground", fg)
        self.option_add("*TCombobox*Listbox.font", (F, 10))

    def _new_tab(self, title):
        tab = ScrollTab(self.nb, self.C["bg"])
        self.nb.add(tab, text=title)
        return tab, tab.body

    def _lbl(self, parent, text="", kind="card", wrap=False, **kw):
        style = {"card": "Card.TLabel", "strong": "CardStrong.TLabel", "hint": "CardHint.TLabel", "page": "TLabel",
                 "pagehint": "Sub.TLabel", "pagestrong": "PageStrong.TLabel", "title": "CardTitle.TLabel"}[kind]
        lab = ttk.Label(parent, text=text, style=style, **kw)
        if wrap:
            self._wrap_label(lab)
        return lab

    @staticmethod
    def _wrap_label(lab):
        """Make a label re-wrap to whatever width its container gives it.
        width=1 stops the label's own text width from feeding back into the layout (no resize loops)."""
        lab.configure(wraplength=360, justify="left", width=1)
        def rewrap(event, w=lab):
            target = max(120, event.width - 4)
            if abs(int(float(str(w.cget("wraplength")))) - target) > 1:
                w.configure(wraplength=target)
        lab.bind("<Configure>", rewrap, add="+")
        return lab

    def _tree(self, parent, columns, *, height=6, hscroll=False, selectmode="browse", compact=False):
        """columns = (id, title, width, anchor, stretch). Returns (frame, tree) with scrollbars wired up."""
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height, selectmode=selectmode,
                            style="Compact.Treeview" if compact else "Treeview")
        for cid, title, width, anchor, stretch in columns:
            tree.heading(cid, text=title, anchor="w" if anchor == "w" else "center")
            tree.column(cid, width=width, minwidth=min(width, 60), anchor=anchor, stretch=stretch)
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew"); ys.grid(row=0, column=1, sticky="ns")
        if hscroll:
            xs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
            tree.configure(xscrollcommand=xs.set); xs.grid(row=1, column=0, sticky="ew")
        return frame, tree

    def _text(self, parent, height=5, *, mono=False, wrap="word", hscroll=False):
        """Read-only inset text panel with padding, a soft border and scrollbars. Returns (frame, text)."""
        C = self.C
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        t = tk.Text(frame, height=height, wrap=wrap, state="disabled", background=C["panel2"], foreground=C["fg"], relief="flat", bd=0,
                    highlightthickness=1, highlightbackground=C["border"], highlightcolor=C["blue"], padx=12, pady=10,
                    font=("Consolas", 10) if mono else ("Segoe UI", 10), spacing1=1, spacing3=3, insertbackground=C["fg"],
                    selectbackground="#d6eaff", selectforeground=C["fg"])
        ys = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=ys.set)
        t.grid(row=0, column=0, sticky="nsew"); ys.grid(row=0, column=1, sticky="ns")
        if hscroll:
            xs = ttk.Scrollbar(frame, orient="horizontal", command=t.xview)
            t.configure(xscrollcommand=xs.set); xs.grid(row=1, column=0, sticky="ew")
        return frame, t

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal"); widget.delete("1.0", "end"); widget.insert("1.0", text); widget.configure(state="disabled")

    def _guide(self, parent, headline, details):
        # Explanatory/help text is intentionally omitted from the operational UI.
        frame = ttk.Frame(parent, height=0)
        frame.grid_propagate(False)
        return frame

    # ------------------------------------------------------------------ shell
    def _build_ui(self):
        C = self.C
        header = ttk.Frame(self, style="Header.TFrame", padding=(24, 12))
        header.pack(fill="x")
        logo = tk.Label(header, text="ZT", background=C["blue"], foreground="#ffffff", font=("Segoe UI", 13, "bold"), padx=10, pady=4)
        logo.pack(side="left", padx=(0, 14))
        titles = ttk.Frame(header, style="Header.TFrame"); titles.pack(side="left")
        ttk.Label(titles, text="ZTNA Enterprise Lab", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(titles, text="Desktop Security Control Center  \u00b7  verify every request, trust nothing by default", style="HeaderSub.TLabel").pack(anchor="w")
        self.status = tk.Label(header, text="\u25cf Logged out", background="#e3ecf7", foreground=C["muted"], font=("Segoe UI", 10, "bold"), padx=14, pady=6)
        self.status.pack(side="right")
        tk.Frame(self, height=1, background=C["border"]).pack(fill="x")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14, pady=(8, 14))
        self._build_dashboard_tab()
        self._build_identity_devices_tab()
        self._build_roles_tab()
        self._build_access_tab()
        self._build_posture_tab()
        self._build_policy_tab()
        self._build_security_tab()
        self._build_audit_tab()

    # ------------------------------------------------------------------ Overview
    def _build_dashboard_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Overview"); self.overview_tab = tab
        body.columnconfigure(0, weight=3, uniform="ov"); body.columnconfigure(1, weight=2, uniform="ov")
        body.rowconfigure(2, weight=1)

        kpis = ttk.Frame(body); kpis.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.kpi_vars = {k: tk.StringVar(value="\u2014") for k in ("identities", "devices", "compliant", "totp")}
        items = (("identities", "IDENTITIES", "accounts in the directory"), ("devices", "REGISTERED DEVICES", "enrolled endpoints"),
                 ("compliant", "COMPLIANT DEVICES", "posture score 80 or higher"), ("totp", "TOTP ENABLED", "accounts with MFA configured"))
        for col, (key, title, caption) in enumerate(items):
            kpis.columnconfigure(col, weight=1, uniform="kpi")
            card = Card(kpis, padding=(16, 9))
            card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else G // 2, 0 if col == 3 else G // 2))
            ttk.Label(card.body, text=title, style="KpiTitle.TLabel").pack(anchor="w")
            ttk.Label(card.body, textvariable=self.kpi_vars[key], style="KpiValue.TLabel").pack(anchor="w", pady=(2, 0))
            ttk.Label(card.body, text=caption, style="CardHint.TLabel").pack(anchor="w")

        login = Card(body, "Identity & MFA")
        login.grid(row=1, column=0, sticky="nsew", padx=(0, G // 2), pady=(0, G))
        form = login.body; form.columnconfigure(1, weight=1)
        self.user_var = tk.StringVar(value="alice")
        self.pass_var = tk.StringVar(value="")
        self.otp_var = tk.StringVar()
        self.device_var = tk.StringVar(value="laptop-alice")
        self.location_var = tk.StringVar(value="office")
        self.user_combo = self._field(form, "User", self.user_var, 0, sorted(USERS))
        self.user_combo.bind("<<ComboboxSelected>>", self._on_user_pick)
        self._field(form, "Password", self.pass_var, 1, None, show="*")
        self._field(form, "TOTP", self.otp_var, 2)
        self.device_combo = self._field(form, "Device", self.device_var, 3, sorted(DEVICES))
        self._field(form, "Location", self.location_var, 4, ["office", "home"])
        btns = ttk.Frame(form, style="Card.TFrame"); btns.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        for c in range(3): btns.columnconfigure(c, weight=1, uniform="lb")
        self.demo_otp_btn = ttk.Button(btns, text="Generate demo OTP", command=self.generate_otp)
        self.demo_otp_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.demo_otp_btn.configure(state=("normal" if DEMO_OTP else "disabled"))
        ttk.Button(btns, text="Login", style="Action.TButton", command=self.do_login).grid(row=0, column=1, sticky="ew", padx=3)
        ttk.Button(btns, text="Logout", command=self.do_logout).grid(row=0, column=2, sticky="ew", padx=(6, 0))
        tip = ttk.Label(form, style="CardHint.TLabel", text="Demo tip: use the one-time generated password printed at provisioning, your authenticator TOTP, and your own device.")
        self._wrap_label(tip).grid(row=6, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        info = Card(body, "Current session")
        info.grid(row=1, column=1, sticky="nsew", padx=(G // 2, 0), pady=(0, G))
        self.session_text = tk.StringVar(value="Not authenticated")
        ttk.Label(info.body, textvariable=self.session_text, style="CardStrong.TLabel").pack(anchor="w")
        ttk.Separator(info.body).pack(fill="x", pady=10)
        grid = ttk.Frame(info.body, style="Card.TFrame"); grid.pack(fill="x"); grid.columnconfigure(1, weight=1)
        self.session_vars = {}
        for r, (key, label) in enumerate((("user", "User"), ("device", "Device"), ("location", "Location"), ("mfa", "MFA age"), ("ttl", "Session TTL"), ("travel", "Travel flag"))):
            self.session_vars[key] = tk.StringVar(value="\u2014")
            ttk.Label(grid, text=label, style="CardHint.TLabel").grid(row=r, column=0, sticky="w", pady=4, padx=(0, 16))
            ttk.Label(grid, textvariable=self.session_vars[key], style="CardStrong.TLabel").grid(row=r, column=1, sticky="w", pady=4)

        activity = Card(body, "Security activity", "latest decisions and events")
        activity.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2))
        ttk.Button(activity.head, text="Refresh", style="Link.TButton", command=self.refresh_dashboard_activity).pack(side="right")
        frame, self.activity_tree = self._tree(activity.body, (
            ("time", "Time", 70, "w", False), ("decision", "Decision", 90, "w", False), ("user", "User", 80, "w", False),
            ("device", "Device", 120, "w", False), ("resource", "Resource", 110, "w", False), ("risk", "Risk", 60, "w", False),
            ("details", "Details", 260, "w", True)), height=4)
        for tag, color in (("ALLOW", "#0a7d33"), ("DENY", "#c62828"), ("STEPUP", "#b26a00"), ("POLICY", "#0b5cad")):
            self.activity_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)

        summary = Card(body, "Security summary", "what just happened")
        summary.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0))
        frame, self.summary = self._text(summary.body, height=6)
        frame.pack(fill="both", expand=True)

    def _field(self, parent, label, var, row, values=None, show=None):
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, padx=(0, 16), pady=3, sticky="w")
        if values:
            w = ttk.Combobox(parent, textvariable=var, values=values, state="readonly", width=18)
        else:
            w = ttk.Entry(parent, textvariable=var, width=20, show=show or "")
        w.grid(row=row, column=1, pady=3, sticky="ew")
        return w

    @staticmethod
    def _devices_of(user):
        mine = sorted(d for d, v in DEVICES.items() if v.get("owner") == user)
        return mine or sorted(DEVICES)

    def _on_user_pick(self, _event=None):
        user = self.user_var.get()
        devs = self._devices_of(user)
        self.device_combo.configure(values=devs)
        self.device_var.set(devs[0] if devs else "")
        if DEMO and user in USER_PROFILE: self.pass_var.set(user + "123")
        self.otp_var.set("")

    # ------------------------------------------------------------------ Identity & Devices
    def _build_identity_devices_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Identity & Devices"); self.identity_tab = tab
        body.columnconfigure(0, weight=1, uniform="idv", minsize=320); body.columnconfigure(1, weight=3, uniform="idv")
        body.rowconfigure(1, weight=1)
        intro = ttk.Label(body, style="Sub.TLabel", text="Review existing identities and enroll endpoints into the shared policy, posture, MFA and audit engine.")
        self._wrap_label(intro).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))

        left = ttk.Frame(body); left.grid(row=1, column=0, sticky="nsew", padx=(0, G // 2))
        right = ttk.Frame(body); right.grid(row=1, column=1, sticky="nsew", padx=(G // 2, 0))
        right.columnconfigure(0, weight=1); right.rowconfigure(0, weight=1); right.rowconfigure(1, weight=1)

        admin = Card(left, "User administration"); admin.pack(fill="x", pady=(0, G))
        ttk.Button(admin.body, text="Add user\u2026", style="Action.TButton", command=self.add_user_ui).pack(fill="x", pady=(0, 6))
        ttk.Button(admin.body, text="Bulk-enroll missing devices", command=self.bulk_enroll_devices_ui).pack(fill="x")
        self._lbl(admin.body, "Bulk-enroll creates one demo device for every user that has none. Local demo administration only.", "hint", wrap=True).pack(fill="x", pady=(8, 0))

        dev = Card(left, "Enroll device"); dev.pack(fill="x")
        form = dev.body; form.columnconfigure(1, weight=1)
        self.new_device_id = tk.StringVar(); self.new_device_owner = tk.StringVar(); self.new_device_managed = tk.BooleanVar(value=True)
        ttk.Label(form, text="Device ID", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=5, padx=(0, 12))
        ttk.Entry(form, textvariable=self.new_device_id, width=20).grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Label(form, text="a-z, 0-9 and hyphen only", style="CardHint.TLabel").grid(row=1, column=1, sticky="w")
        ttk.Label(form, text="Owner", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=5, padx=(0, 12))
        self.new_device_owner.set(sorted(USERS)[0] if USERS else "")
        self.device_owner_combo = ttk.Combobox(form, textvariable=self.new_device_owner, values=sorted(USERS), state="readonly", width=18)
        self.device_owner_combo.grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Checkbutton(form, text="Corporate-managed device", variable=self.new_device_managed).grid(row=3, column=0, columnspan=2, sticky="w", pady=6)
        ttk.Button(form, text="Enroll device + key", style="Action.TButton", command=self.enroll_device_ui).grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 2))
        self._lbl(form, "New devices start with current posture signals set to compliant. Toggle them in Device Posture to test policy decisions.", "hint", wrap=True).grid(row=5, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        users = Card(right, "Identity overview", "select a user to inspect"); users.grid(row=0, column=0, sticky="nsew", pady=(0, G))
        frame, self.identity_tree = self._tree(users.body, (
            ("username", "Username", 100, "w", False), ("name", "Name / title", 240, "w", True), ("role", "Role", 100, "w", False),
            ("hash", "Password hash fingerprint", 220, "w", False), ("totp", "TOTP status", 120, "w", False)), height=5)
        frame.pack(fill="both", expand=True)
        self.identity_tree.bind("<<TreeviewSelect>>", self.show_identity_details)

        devs = Card(right, "Enrolled devices", "select a device to inspect"); devs.grid(row=1, column=0, sticky="nsew", pady=(0, G))
        frame, self.device_tree = self._tree(devs.body, (
            ("device", "Device ID", 160, "w", True), ("owner", "Owner", 110, "w", False), ("score", "Posture", 80, "w", False),
            ("managed", "Managed", 90, "w", False), ("key", "Key fingerprint", 170, "w", False)), height=5)
        frame.pack(fill="both", expand=True)
        self.device_tree.bind("<<TreeviewSelect>>", self.show_device_details)

        detail = Card(right, "Details", "stored hash and TOTP secret are sensitive lab material \u2013 keep this window private")
        detail.grid(row=2, column=0, sticky="ew")
        frame, self.identity_detail = self._text(detail.body, height=4)
        frame.pack(fill="x")
        self._set_text(self.identity_detail, "Select an identity or a device above to see its details.")
        self.refresh_identity_devices()
        self.refresh_dashboard_overview()

    def refresh_dashboard_overview(self):
        configured = sum(bool(u.get("totp")) for u in USERS.values())
        compliant = sum(1 for device_id in DEVICES if posture(device_id) >= 80)
        if hasattr(self, "kpi_vars"):
            self.kpi_vars["identities"].set(str(len(USERS)))
            self.kpi_vars["devices"].set(str(len(DEVICES)))
            self.kpi_vars["compliant"].set(f"{compliant} / {len(DEVICES)}")
            self.kpi_vars["totp"].set(f"{configured} / {len(USERS)}")

    def refresh_dashboard_activity(self):
        if not hasattr(self, "activity_tree"): return
        rows = []
        for idx, event in enumerate(list(LOG)[:25]):
            ts = event.get("ts", "")
            try:
                time_text = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
            except (TypeError, ValueError, OSError):
                time_text = str(ts)
            details = "; ".join(map(str, event.get("reasons", [])))
            rows.append((f"activity:{idx}", str(event.get("decision", "")), (
                time_text, event.get("decision", ""), event.get("user", ""),
                event.get("device", "") or "—", event.get("resource", "") or "—",
                event.get("risk", ""), details,
            )))
        if rows == getattr(self, "_activity_rows", None): return
        self._activity_rows = rows
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
        for iid, decision, values in rows:
            self.activity_tree.insert("", "end", iid=iid, values=values, tags=(decision,))

    def _confirm_admin_password(self):
        if not DEMO:
            messagebox.showerror("Administrator verification",
                                 "GUI user administration is available only in local demo mode.",
                                 parent=self)
            return False
        admin_password = simpledialog.askstring(
            "Administrator verification",
            "Enter the password for an existing admin account:",
            show="*",
            parent=self,
        )
        if admin_password is None:
            return False
        for _name, record in USERS.items():
            if record.get("role") != "admin":
                continue
            try:
                if pw_verify(admin_password, record.get("pw", {})):
                    return True
            except Exception:
                continue
        messagebox.showerror("Access denied", "The administrator password was incorrect.",
                             parent=self)
        return False

    def add_user_ui(self):
        if not self._confirm_admin_password():
            return
        dialog = tk.Toplevel(self)
        dialog.title("Add ZTNA user")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(background=self.C["bg"])
        body = ttk.Frame(dialog, padding=22)
        body.pack(fill="both", expand=True)
        username_var, role_var = tk.StringVar(), tk.StringVar(value="engineer")
        password_var, confirm_var = tk.StringVar(), tk.StringVar()
        ttk.Label(body, text="Username").grid(row=0, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Entry(body, textvariable=username_var, width=28).grid(row=0, column=1, pady=5)
        ttk.Label(body, text="Role").grid(row=1, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Combobox(body, textvariable=role_var, values=tuple(ROLES),
                     state="readonly", width=25).grid(row=1, column=1, pady=5)
        ttk.Label(body, text="New password").grid(row=2, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Entry(body, textvariable=password_var, show="*", width=28).grid(row=2, column=1, pady=5)
        ttk.Label(body, text="Confirm password").grid(row=3, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Entry(body, textvariable=confirm_var, show="*", width=28).grid(row=3, column=1, pady=5)
        ttk.Label(body, text="Minimum 8 characters. A unique TOTP secret is generated.", style="Sub.TLabel",
                  wraplength=340).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 14))

        def create():
            username, role = username_var.get().strip(), role_var.get().strip()
            password, confirm = password_var.get(), confirm_var.get()
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
                messagebox.showerror("Add user", "Use 1–64 letters, numbers, dots, underscores, @ or hyphens.", parent=dialog); return
            if username in USERS:
                messagebox.showerror("Add user", "That username already exists.", parent=dialog); return
            if role not in ROLES:
                messagebox.showerror("Add user", "Choose a supported role.", parent=dialog); return
            if len(password) < 8:
                messagebox.showerror("Add user", "Password must be at least 8 characters.", parent=dialog); return
            if not _ct_eq(password, confirm):
                messagebox.showerror("Add user", "Passwords do not match.", parent=dialog); return
            try:
                pwrec = _pw_record(password)
                totp_secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
                USERS[username] = {"pw": pwrec, "role": role, "totp": totp_secret}
                _persist_users()
                audit(user="admin", device="", resource="identity-create", decision="POLICY",
                      reasons=[f"created local demo identity {username} with role {role}"])
            except Exception as exc:
                USERS.pop(username, None)
                messagebox.showerror("Add user", f"Could not save user: {exc}", parent=dialog); return
            self.refresh_identity_devices()
            self.refresh_dashboard_overview()
            self._write_summary(f"Created user {username} ({role}); TOTP secret generated.")
            dialog.destroy()
            messagebox.showinfo("User created",
                f"User: {username}\nRole: {role}\nTOTP secret: {totp_secret}\n\n"
                "Store this secret securely and enroll it in an authenticator app. "
                "You can now enroll a device for this user.", parent=self)

        buttons = ttk.Frame(body)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="Create user", style="Action.TButton", command=create).pack(side="right")
        dialog.bind("<Return>", lambda _event: create())
        dialog.update_idletasks()
        dialog.geometry(f"+{self.winfo_rootx() + (self.winfo_width() - dialog.winfo_reqwidth()) // 2}+{self.winfo_rooty() + (self.winfo_height() - dialog.winfo_reqheight()) // 3}")
        dialog.wait_window()

    def bulk_enroll_devices_ui(self):
        if not self._confirm_admin_password():
            return
        owners_with_devices = {item.get("owner") for item in DEVICES.values()}
        pending = [username for username in sorted(USERS) if username not in owners_with_devices]
        if not pending:
            messagebox.showinfo("Bulk enrollment", "Every user already has at least one device.", parent=self); return
        if not messagebox.askyesno(
            "Confirm bulk enrollment",
            f"Enroll one demo device for each of {len(pending)} users without a device?\n\n"
            "These local demo records are not proof that real endpoints completed enrollment.",
            parent=self):
            return
        created = []
        try:
            if not DEMO:
                raise RuntimeError("Bulk enrollment is available only in local demo mode.")
            if not POSTURE_KEYS:
                POSTURE_KEYS.update(_demo_posture_keys())
            for username in pending:
                base = re.sub(r"[^a-z0-9-]+", "-", username.lower()).strip("-") or "user"
                device_id = f"laptop-{base}"[:64]
                suffix = 2
                while device_id in DEVICES:
                    tail = f"-{suffix}"
                    device_id = f"laptop-{base}"[:64-len(tail)] + tail
                    suffix += 1
                DEVICES[device_id] = {
                    "owner": username, "os_updated": True, "disk_encrypted": True,
                    "firewall": True, "antivirus": True, "corporate_managed": True,
                    "last_report": time.time(),
                }
                POSTURE_KEYS[device_id] = secrets.token_bytes(32)
                created.append(device_id)
            _persist_demo_device_keys()
            save_persisted_devices()
            for device_id in created:
                audit(user="admin", device=device_id, resource="device-enrollment", decision="POLICY",
                      reasons=[f"demo device bulk-enrolled for {DEVICES[device_id]['owner']}"])
        except Exception as exc:
            for device_id in created:
                DEVICES.pop(device_id, None); POSTURE_KEYS.pop(device_id, None)
            messagebox.showerror("Bulk enrollment", f"Could not save devices: {exc}", parent=self); return
        self.refresh_all()
        self.refresh_identity_devices()
        self.refresh_dashboard_overview()
        self._write_summary(f"Bulk-enrolled {len(created)} demo devices.")
        messagebox.showinfo("Bulk enrollment complete",
            f"Created {len(created)} demo devices.\n\n" + "\n".join(created[:12]) +
            (f"\n…and {len(created)-12} more" if len(created) > 12 else ""), parent=self)

    def enroll_device_ui(self):
        device_id = self.new_device_id.get().strip().lower()
        owner = self.new_device_owner.get().strip()
        if not DEMO:
            messagebox.showerror("Enroll device", "GUI enrollment is currently available only in local demo mode.", parent=self); return
        if not re.fullmatch(r"[a-z0-9-]{1,64}", device_id):
            messagebox.showerror("Enroll device", "Device ID must use lowercase letters, digits and hyphens (1–64 chars).", parent=self); return
        if device_id in DEVICES:
            messagebox.showerror("Enroll device", "That device ID already exists.", parent=self); return
        if owner not in USERS:
            messagebox.showerror("Enroll device", "Select an existing owner. Create the user first if needed.", parent=self); return
        record = {"owner": owner, **{k: True for k in POSTURE_W}, "corporate_managed": bool(self.new_device_managed.get()), "last_report": time.time()}
        try:
            DEVICES[device_id] = record
            if not POSTURE_KEYS:
                POSTURE_KEYS.update(_demo_posture_keys())
            POSTURE_KEYS[device_id] = secrets.token_bytes(32)
            _persist_demo_device_keys()
            save_persisted_devices()
            audit(user="admin", device=device_id, resource="device-enrollment", decision="POLICY", reasons=[f"device enrolled for {owner}"])
        except Exception as exc:
            DEVICES.pop(device_id, None); POSTURE_KEYS.pop(device_id, None)
            messagebox.showerror("Enroll device", f"Could not enroll device: {exc}", parent=self); return
        self.new_device_id.set(""); self.device_var.set(device_id)
        fingerprint = hashlib.sha256(POSTURE_KEYS[device_id]).hexdigest()[:16]
        self.refresh_all(); self.refresh_identity_devices(); self.refresh_dashboard_overview()
        self._write_summary(f"Device {device_id} enrolled for {owner}; posture key fingerprint {fingerprint}.")
        messagebox.showinfo("Device enrolled", f"Device: {device_id}\nOwner: {owner}\nPosture key fingerprint: {fingerprint}\nDevice is now available in login, posture, resource access and audit views.", parent=self)

    def refresh_identity_devices(self):
        if not hasattr(self, "identity_tree"): return
        selected = self.identity_tree.selection(); dev_selected = self.device_tree.selection()
        user_rows = []
        for username, user in sorted(USERS.items()):
            digest = user.get("pw", {}).get("hash", "")
            user_rows.append((username, (username, (USER_PROFILE.get(username, {}).get("name", "-") + (" - " + USER_PROFILE[username]["title"] if username in USER_PROFILE else "")), user.get("role", "?"), (digest[:16] + "…") if digest else "not set", "Configured" if user.get("totp") else "Missing")))
        dev_rows = []
        for device_id, dev in sorted(DEVICES.items()):
            key = POSTURE_KEYS.get(device_id)
            fingerprint = hashlib.sha256(key).hexdigest()[:16] if key else "not provisioned"
            dev_rows.append((device_id, (device_id, dev.get("owner", "?"), posture(device_id), "Yes" if dev.get("corporate_managed") else "No", fingerprint)))
        if user_rows != getattr(self, "_identity_rows", None):
            self._identity_rows = user_rows
            for item in self.identity_tree.get_children(): self.identity_tree.delete(item)
            for iid, values in user_rows: self.identity_tree.insert("", "end", iid=iid, values=values)
            for key in selected:
                if self.identity_tree.exists(key): self.identity_tree.selection_set(key)
        if dev_rows != getattr(self, "_device_rows", None):
            self._device_rows = dev_rows
            for item in self.device_tree.get_children(): self.device_tree.delete(item)
            for iid, values in dev_rows: self.device_tree.insert("", "end", iid=iid, values=values)
            for key in dev_selected:
                if self.device_tree.exists(key): self.device_tree.selection_set(key)
        owners = sorted(USERS)
        self.device_owner_combo.configure(values=owners)
        if self.new_device_owner.get() not in owners:
            self.new_device_owner.set(owners[0] if owners else "")
        if not self.new_device_owner.get() and USERS: self.new_device_owner.set(sorted(USERS)[0])
        if hasattr(self, "user_combo"):
            self.user_combo.configure(values=sorted(USERS))
        if hasattr(self, "device_combo"):
            self.device_combo.configure(values=self._devices_of(self.user_var.get()))

    def show_identity_details(self, _event=None):
        sel = self.identity_tree.selection()
        if not sel: return
        username = sel[0]; user = USERS.get(username, {}); pw = user.get("pw", {})
        detail = (f"USER: {username}\nROLE: {user.get('role', '?')}\nPASSWORD HASH: {pw.get('hash', 'not set')}\nSALT: {pw.get('salt', 'not set')}\nTOTP SECRET: {user.get('totp', 'not set')}\n\nThe password itself is not stored. Hash and TOTP are sensitive lab material.")
        self._set_text(self.identity_detail, detail)

    def show_device_details(self, _event=None):
        sel = self.device_tree.selection()
        if not sel: return
        device_id = sel[0]; dev = DEVICES.get(device_id, {}); key = POSTURE_KEYS.get(device_id)
        detail = f"DEVICE: {device_id}\nOWNER: {dev.get('owner', '?')}\nPOSTURE SCORE: {posture(device_id)}\nKEY FINGERPRINT: {hashlib.sha256(key).hexdigest() if key else 'not provisioned'}\nPOSTURE: " + ", ".join(f"{k}={bool(dev.get(k))}" for k in POSTURE_W)
        self._set_text(self.identity_detail, detail)

    # ------------------------------------------------------------------ Roles & Access
    def _build_roles_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Roles & Access"); self.roles_tab = tab
        body.columnconfigure(0, weight=1); body.rowconfigure(2, weight=1)
        names = list(RESOURCES)
        matrix = Card(body, "Role-to-resource matrix", "a tick = the ROLE is allowed; device, location, time and MFA rules must still pass \u00b7 click a role for details")
        matrix.grid(row=0, column=0, sticky="ew", pady=(0, G))
        cols = [("role", "Role", 110, "w", False), ("people", "People", 70, "center", False)] + [(n, self._SEG_ABBR.get(n, n[:7]), 76, "center", True) for n in names]
        frame, self.matrix_tree = self._tree(matrix.body, cols, height=len(ROLES), compact=True)
        frame.pack(fill="x")
        info = Card(body, "Selected role"); info.grid(row=1, column=0, sticky="ew", pady=(0, G))
        frame, self.role_info = self._text(info.body, height=3)
        frame.pack(fill="x")
        self._set_text(self.role_info, "Select a role in the matrix to see who holds it and what it can request.")
        reqs = Card(body, "What each system demands", "besides the role \u00b7 full system names")
        reqs.grid(row=2, column=0, sticky="nsew")
        frame, self.req_tree = self._tree(reqs.body, (
            ("res", "System", 120, "w", False), ("desc", "What it is", 280, "w", True), ("score", "Min score", 90, "center", False),
            ("managed", "Managed only", 110, "center", False), ("hours", "Open hours", 110, "center", False),
            ("where", "Allowed from", 130, "center", False), ("mfa", "MFA max age", 110, "center", False)), height=4, compact=True)
        frame.pack(fill="both", expand=True)
        self.matrix_tree.bind("<<TreeviewSelect>>", self._show_role_info)
        self.refresh_roles()

    def refresh_roles(self):
        if not hasattr(self, "matrix_tree"): return
        count = Counter(u.get("role") for u in USERS.values())
        snap = (tuple(sorted(count.items())), tuple((r, v["min_posture"], v["managed"], tuple(v["hours"]), v["mfa_age"]) for r, v in RESOURCES.items()))
        if snap == getattr(self, "_roles_snap", None): return
        self._roles_snap = snap
        sel = self.matrix_tree.selection()
        for i in self.matrix_tree.get_children(): self.matrix_tree.delete(i)
        for role in ROLES:
            self.matrix_tree.insert("", "end", iid=role, values=(role, count.get(role, 0), *("\u2714" if role in RESOURCES[r]["roles"] else "\u2013" for r in RESOURCES)))
        for i in self.req_tree.get_children(): self.req_tree.delete(i)
        for r, v in RESOURCES.items():
            self.req_tree.insert("", "end", values=(r, v["desc"], v["min_posture"], "Yes" if v["managed"] else "No", _fmt_hours(v), " / ".join(v["locations"]), f"{v['mfa_age'] // 60} min"))
        for k in sel:
            if self.matrix_tree.exists(k): self.matrix_tree.selection_set(k)

    def _show_role_info(self, _event=None):
        sel = self.matrix_tree.selection()
        if not sel: return
        role = sel[0]
        people = ", ".join(f"{u} ({USER_PROFILE[u]['name']})" if u in USER_PROFILE else u for u, v in sorted(USERS.items()) if v.get("role") == role)
        opens = ", ".join(r for r, v in RESOURCES.items() if role in v["roles"])
        text = f"ROLE: {role}\n{ROLES[role]}\nCAN REQUEST: {opens}\nPEOPLE: {people or 'nobody yet'}"
        self.role_info.configure(state="normal"); self.role_info.delete("1.0", "end"); self.role_info.insert("1.0", text); self.role_info.configure(state="disabled")

    # ------------------------------------------------------------------ Resource Access
    @staticmethod
    def _req_short(resource):
        r = RESOURCES[resource]
        return (f"Score {r['min_posture']}+ \u00b7 " + ("Managed device" if r["managed"] else "Any device") + f" \u00b7 {_fmt_hours(r)} \u00b7 "
                + " / ".join(r["locations"]) + f" \u00b7 MFA \u2264 {r['mfa_age'] // 60} min")

    def _place_res_cards(self, cols):
        """Lay the system cards out in 2-4 columns depending on the width available."""
        if cols == self._res_cols: return
        self._res_cols = cols
        grid, G, n = self._res_grid, self.GAP, len(self._res_cards)
        rows = (n + cols - 1) // cols
        for c in range(6): grid.columnconfigure(c, weight=0, uniform="")
        for r in range(n): grid.rowconfigure(r, weight=0)
        for c in range(cols): grid.columnconfigure(c, weight=1, uniform="rescard")
        for r in range(rows): grid.rowconfigure(r, weight=1)
        for i, card in enumerate(self._res_cards):
            r, c = divmod(i, cols)
            card.grid(row=r, column=c, sticky="nsew", padx=(0 if c == 0 else G // 2, 0 if c == cols - 1 else G // 2),
                      pady=(0 if r == 0 else G // 2, 0 if r == rows - 1 else G // 2))

    def _build_access_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Resource Access"); self.access_tab = tab
        body.columnconfigure(0, weight=7, uniform="acc"); body.columnconfigure(1, weight=3, uniform="acc")
        body.rowconfigure(1, weight=1)
        head = ttk.Frame(body); head.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.access_who = tk.StringVar(value="Not signed in. Go to Overview, pick a user and log in.")
        self._wrap_label(ttk.Label(head, textvariable=self.access_who, style="PageStrong.TLabel")).pack(fill="x")
        self._wrap_label(ttk.Label(head, style="Sub.TLabel", text="Pick a system. Each click is a fresh policy check of identity, device health, location, time and MFA. What you can open is different for each employee.")).pack(fill="x", pady=(2, 0))

        grid = ttk.Frame(body); grid.grid(row=1, column=0, sticky="nsew", padx=(0, G // 2))
        self.res_status = {}; self._res_cards = []; self._res_cols = 0; self._res_grid = grid
        for i, r in enumerate(RESOURCES):
            card = Card(grid, padding=11)
            ttk.Button(card.body, text="Open", style="Action.TButton", command=lambda x=r: self.request_access(x)).pack(side="bottom", fill="x", pady=(8, 0))
            top = ttk.Frame(card.body, style="Card.TFrame"); top.pack(fill="x")
            ttk.Label(top, text=r, style="CardTitle.TLabel").pack(side="left")
            lab = ttk.Label(top, text="", style="CardStrong.TLabel", font=("Segoe UI", 9, "bold")); lab.pack(side="right"); self.res_status[r] = lab
            self._lbl(card.body, RESOURCES[r]["desc"], "card", wrap=True).pack(fill="x", pady=(2, 0))
            self._lbl(card.body, self._req_short(r), "hint", wrap=True).pack(fill="x", pady=(4, 0))
            self._res_cards.append(card)
        self._place_res_cards(4)
        grid.bind("<Configure>", lambda e: self._place_res_cards(max(2, min(4, e.width // 205))), add="+")

        side = ttk.Frame(body); side.grid(row=1, column=1, sticky="nsew", padx=(G // 2, 0))
        side.columnconfigure(0, weight=1); side.rowconfigure(1, weight=1); side.rowconfigure(2, weight=1)
        step = Card(side, "Step-up MFA")
        step.grid(row=0, column=0, sticky="ew", pady=(0, G))
        self.step_otp = tk.StringVar()
        row = ttk.Frame(step.body, style="Card.TFrame"); row.pack(fill="x")
        row.columnconfigure(0, weight=1, uniform="su"); row.columnconfigure(1, weight=1, uniform="su")
        ttk.Entry(row, textvariable=self.step_otp, width=10).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Button(row, text="Generate OTP", command=self.generate_step_otp).grid(row=1, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(row, text="Verify", style="Action.TButton", command=self.do_stepup).grid(row=1, column=1, sticky="ew", padx=(4, 0))

        res = Card(side, "Result in plain English"); res.grid(row=1, column=0, sticky="nsew", pady=(0, G))
        frame, self.access_log = self._text(res.body, height=4)
        frame.pack(fill="both", expand=True)
        for tag, color, bold in (("ok", "#0a7d33", True), ("warn", "#b26a00", True), ("bad", "#c62828", True), ("fix", "#0b5cad", False), ("dim", "#667085", False)):
            self.access_log.tag_configure(tag, foreground=color, font=("Segoe UI", 10, "bold") if bold else ("Segoe UI", 10))

        prev = Card(side, "Preview of what you opened"); prev.grid(row=2, column=0, sticky="nsew")
        self.preview_title = tk.StringVar(value="Nothing opened yet.")
        self.preview_note = tk.StringVar(value="Open a system you are allowed to use and its content appears here.")
        ttk.Label(prev.body, textvariable=self.preview_title, style="CardStrong.TLabel").pack(anchor="w")
        self._wrap_label(ttk.Label(prev.body, textvariable=self.preview_note, style="CardHint.TLabel")).pack(fill="x", pady=(0, 8))
        frame, self.preview_tree = self._tree(prev.body, (("a", "", 300, "w", True),), height=3)
        frame.pack(fill="both", expand=True)

    def refresh_access_cards(self):
        if not hasattr(self, "res_status"): return
        if self.engine.session:
            _, s = self.engine.session
            u = USERS.get(s["user"], {}); role = u.get("role", "?"); prof = USER_PROFILE.get(s["user"], {})
            self.access_who.set(f"Signed in as {prof.get('name', s['user'])} ({s['user']})  |  role: {role}  |  device: {s['device']} (health {posture(s['device']) if s['device'] in DEVICES else 0}/100)  |  from: {s['location']}")
            for r, lab in self.res_status.items():
                if rbac_allows(s["user"], r): lab.configure(text="\u2714 allowed", foreground="#0a7d33")
                else: lab.configure(text="\u2716 blocked", foreground="#c62828")
        else:
            self.access_who.set("Not signed in. Go to Overview, pick a user and log in.")
            for lab in self.res_status.values(): lab.configure(text="sign in", foreground="#667085")

    def _show_preview(self, preview=None, why=""):
        for i in self.preview_tree.get_children(): self.preview_tree.delete(i)
        if not preview:
            self.preview_title.set("Nothing to show"); self.preview_note.set(why or "Access was not granted, so no content is shown.")
            self.preview_tree.configure(columns=("a",)); self.preview_tree.heading("a", text=""); return
        cols = tuple(f"c{i}" for i in range(len(preview["columns"])))
        self.preview_tree.configure(columns=cols)
        for c, name in zip(cols, preview["columns"]):
            self.preview_tree.heading(c, text=name); self.preview_tree.column(c, width=max(80, 520 // len(cols)), anchor="w")
        for row in preview["rows"]: self.preview_tree.insert("", "end", values=row)
        self.preview_title.set(preview["title"]); self.preview_note.set(preview["summary"] + "  (demo data)")

    def _show_access_result(self, resource, result):
        verdict, headline, lines, tips = explain_decision(resource, result)
        tag = {"ALLOW": "ok", "STEPUP": "warn", "DENY": "bad"}[verdict]
        pieces = [(f"{time.strftime('%H:%M:%S')}  {headline}\n", tag)]
        pieces += [(f"   \u2022 {x}\n", None) for x in lines]
        pieces += [(f"   How to fix: {x}\n", "fix") for x in tips]
        pieces.append(("\n", None))
        off = 0
        self.access_log.configure(state="normal")
        for text, t in pieces:
            self.access_log.insert(f"1.0+{off}c", text, t or ()); off += len(text)
        self.access_log.configure(state="disabled")
        if verdict == "ALLOW": self._show_preview(result.get("preview"))
        else: self._show_preview(None, "Access was not granted, so no content is shown.")

    # ------------------------------------------------------------------ Device Posture
    def _build_posture_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Device Posture"); self.posture_tab = tab
        body.columnconfigure(0, weight=3, uniform="pos"); body.columnconfigure(1, weight=2, uniform="pos")
        body.rowconfigure(2, weight=1)
        guide = self._guide(body, "Device posture is a 0-100 health score for the laptop or phone someone logs in from. Weak devices are refused even with the right password.", (
            "WHAT: a health check of the laptop or phone someone logs in from. Five checks add up to a score out of 100: "
            + ", ".join(f"{POSTURE_LABELS[k]} +{w}" for k, w in POSTURE_W.items())
            + ". Every system needs a minimum score (for example hr-db 70, admin-panel 90), so a weak device is refused even with the right password.\n\n"
            "IS IT AUTOMATIC? In a real company a small agent on each device measures these settings and reports them every few minutes. "
            "This lab has no real devices, so the agent is SIMULATED: the switch below re-sends every device's status once a minute. "
            "You can still tick or untick a check to pretend a device got a weakness or a fix, and watch access change immediately. "
            + ("A report older than %d minutes counts as 'stale' and scores 0.\n\n" % (POSTURE_TTL // 60) if POSTURE_TTL > 0 else
               "In this demo reports never expire; in production a report older than ZTNA_POSTURE_TTL (default 5 minutes) counts as 'stale' and scores 0.\n\n")
            + "TRY IT: pick a device on the left, untick 'Antivirus running' and 'Disk is encrypted', then open hr-db on the Resource Access tab."))
        guide.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))

        bar = ttk.Frame(body); bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.agent_on = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Simulated posture agent: auto-report every 60 s", variable=self.agent_on, style="Page.TCheckbutton").pack(side="left")
        self.agent_status = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.agent_status, style="Sub.TLabel").pack(side="left", padx=14)
        ttk.Button(bar, text="Select my device", command=self.posture_select_mine).pack(side="right")

        left = Card(body, "Devices", "select one to inspect and change"); left.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2))
        frame, self.posture_tree = self._tree(left.body, (
            ("device", "Device", 150, "w", True), ("owner", "Owner", 90, "w", False), ("score", "Score", 70, "w", False),
            ("status", "Health", 110, "w", False), ("report", "Last report", 100, "w", False)), height=7)
        for tag, color in (("good", "#0a7d33"), ("fair", "#b26a00"), ("bad", "#c62828"), ("stale", "#667085")):
            self.posture_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)
        self.posture_tree.bind("<<TreeviewSelect>>", lambda _e: self.refresh_posture(force=True))

        right = Card(body, "Selected device"); right.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0))
        rb = right.body
        self.pd_title = tk.StringVar(value="Select a device on the left")
        self.pd_score = tk.StringVar(value="")
        ttk.Label(rb, textvariable=self.pd_title, style="CardStrong.TLabel").pack(anchor="w")
        ttk.Label(rb, textvariable=self.pd_score, style="Score.TLabel").pack(anchor="w", pady=(2, 4))
        self.pd_bar = ttk.Progressbar(rb, maximum=100); self.pd_bar.pack(fill="x", pady=(0, 10))
        self.posture_vars = {}
        for field, w in POSTURE_W.items():
            var = tk.BooleanVar(value=False); self.posture_vars[field] = var
            ttk.Checkbutton(rb, text=f"{POSTURE_LABELS[field]}   (+{w} points)", variable=var,
                            command=lambda f=field, v=var: self.set_posture(self.posture_sel(), f, v.get())).pack(anchor="w", pady=2)
        btns = ttk.Frame(rb, style="Card.TFrame"); btns.pack(fill="x", pady=(10, 0))
        btns.columnconfigure(0, weight=1, uniform="pb"); btns.columnconfigure(1, weight=1, uniform="pb")
        ttk.Button(btns, text="Make healthy", command=lambda: self.posture_preset("healthy")).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(btns, text="Scan for vulnerabilities", command=self.posture_scan).grid(row=0, column=1, sticky="ew", padx=(4, 0))
        ttk.Button(btns, text="Send report now", style="Action.TButton", command=self.posture_report_now).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Separator(rb).pack(fill="x", pady=12)
        ttk.Label(rb, text="What can this device open?", style="CardStrong.TLabel").pack(anchor="w")
        self._lbl(rb, "Device rules only; role, hours and location also apply.", "hint", wrap=True).pack(fill="x", pady=(0, 6))
        frame, self.pd_caps = self._text(rb, height=5)
        self.pd_caps.tag_configure("ok", foreground="#0a7d33"); self.pd_caps.tag_configure("bad", foreground="#c62828")
        frame.pack(fill="both", expand=True)
        self._pd_loaded = None
        self.refresh_posture(force=True)
        kids = self.posture_tree.get_children()
        if kids:
            self.posture_tree.selection_set("laptop-alice" if "laptop-alice" in kids else kids[0])
            self.refresh_posture(force=True)

    # ------------------------------------------------------------------ Policy
    def _build_policy_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Policy"); self.policy_tab = tab
        body.columnconfigure(0, weight=1, uniform="pol"); body.columnconfigure(1, weight=1, uniform="pol")
        guide = self._guide(body, "A policy is the rulebook for ONE system: even with an allowed role, every rule must pass at that moment.", (
            "A POLICY is the rulebook for ONE system. Even when a person's role is allowed, they only get in if every rule below passes at that moment.\n\n"
            "HOW TO USE: 1) pick a system   2) change the rules (or press a quick preset)   3) press Save. It applies to the very next request; nobody has to log in again. "
            "Blocked requests are written to the audit log."))
        guide.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))

        pick = Card(body, padding=(14, 10)); pick.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, G))
        ttk.Label(pick.body, text="System", style="CardStrong.TLabel").pack(side="left")
        self.policy_resource = tk.StringVar(value="wiki")
        self.policy_combo = ttk.Combobox(pick.body, textvariable=self.policy_resource, values=list(RESOURCES), state="readonly", width=18)
        self.policy_combo.pack(side="left", padx=10)
        self.policy_combo.bind("<<ComboboxSelected>>", lambda _e: self.load_policy_fields())
        self.policy_desc = tk.StringVar(); ttk.Label(pick.body, textvariable=self.policy_desc, style="CardHint.TLabel").pack(side="left", padx=8)

        rules = Card(body, "Rules you can change"); rules.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2), pady=(0, G))
        rb = rules.body; rb.columnconfigure(2, weight=1)
        self.pv = {k: tk.StringVar() for k in ("mp", "lo", "hi", "mfa")}; self.pv_managed = tk.BooleanVar()
        rows = (("Minimum device health score", "mp", 0, 100, 1, "0-100. Weaker devices are refused. 40 = basic, 70 = good, 90 = excellent."),
                ("Open from hour", "lo", 0, 24, 1, "24-hour clock. 0 to 24 means all day; 9 to 18 means 09:00-18:00."),
                ("Open until hour", "hi", 0, 24, 1, ""),
                ("Re-verify identity (MFA) every (minutes)", "mfa", 0, 1440, 1, "After this long, the person must enter a fresh code. Shorter = safer."))
        for i, (label, key, lo, hi, inc, hint) in enumerate(rows):
            ttk.Label(rb, text=label, style="Card.TLabel").grid(row=i * 2, column=0, sticky="w", pady=(6, 0), padx=(0, 12))
            ttk.Spinbox(rb, from_=lo, to=hi, increment=inc, textvariable=self.pv[key], width=8).grid(row=i * 2, column=1, pady=(6, 0), sticky="w")
            if hint:
                self._lbl(rb, hint, "hint", wrap=True).grid(row=i * 2 + 1, column=0, columnspan=3, sticky="ew")
        ttk.Checkbutton(rb, text="Only company-managed devices (no personal laptops or phones)", variable=self.pv_managed).grid(row=8, column=0, columnspan=3, sticky="w", pady=(12, 0))
        self.policy_fixed = tk.StringVar()
        self._wrap_label(ttk.Label(rb, textvariable=self.policy_fixed, style="CardHint.TLabel")).grid(row=9, column=0, columnspan=3, sticky="ew", pady=(8, 0))

        summary = Card(body, "What this means in plain English"); summary.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0), pady=(0, G))
        self.policy_summary = tk.StringVar(); self.policy_state = tk.StringVar()
        self._wrap_label(ttk.Label(summary.body, textvariable=self.policy_summary, style="Card.TLabel")).pack(fill="x")
        ttk.Separator(summary.body).pack(fill="x", pady=12)
        ttk.Label(summary.body, textvariable=self.policy_state, style="CardStrong.TLabel").pack(anchor="w")
        for v in (*self.pv.values(), self.pv_managed): v.trace_add("write", lambda *_: self._policy_update_summary())

        actions = Card(body, padding=(14, 10)); actions.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, G))
        ttk.Label(actions.body, text="Quick presets (fill the form, then Save):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        for text, kind in (("Relaxed", "relaxed"), ("Standard", "standard"), ("Strict", "strict"), ("Restore default", "default")):
            ttk.Button(actions.body, text=text, command=lambda k=kind: self.policy_preset(k)).pack(side="left", padx=3)
        ttk.Button(actions.body, text="Save policy", style="Action.TButton", command=self.save_policy_fields).pack(side="right")
        ttk.Button(actions.body, text="Undo unsaved changes", command=self.load_policy_fields).pack(side="right", padx=8)

        sim = Card(body, "Test the hours rule", "pretend it is a different time"); sim.grid(row=4, column=0, columnspan=2, sticky="ew")
        row = ttk.Frame(sim.body, style="Card.TFrame"); row.pack(fill="x")
        self.hour_var = tk.StringVar(value="")
        ttk.Label(row, text="Hour (0-23)", style="Card.TLabel").pack(side="left", padx=(0, 8))
        ttk.Spinbox(row, from_=0, to=23, textvariable=self.hour_var, width=6).pack(side="left")
        ttk.Button(row, text="Set pretend hour", command=self.apply_hour).pack(side="left", padx=8)
        ttk.Button(row, text="Use the real clock", command=self.use_real_clock).pack(side="left")
        self.clock_text = tk.StringVar(); ttk.Label(row, textvariable=self.clock_text, style="CardStrong.TLabel").pack(side="left", padx=16)
        self._lbl(sim.body, "Example: set 22, then try hr-db on Resource Access (it is open 09-18) and read the explanation.", "hint", wrap=True).pack(fill="x", pady=(8, 0))
        self._policy_loading = False
        self.load_policy_fields()

    # ------------------------------------------------------------------ Security & Segmentation
    def _build_security_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Security & Segmentation"); self.security_tab = tab
        body.columnconfigure(0, weight=1, uniform="sec"); body.columnconfigure(1, weight=1, uniform="sec")
        body.rowconfigure(2, weight=1)
        self._wrap_label(ttk.Label(body, style="Sub.TLabel", text="Which network segments each person can reach, and what the system flagged as suspicious.")).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))
        kp = Card(body, padding=(14, 10)); kp.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.sec_kpis = tk.StringVar()
        self._wrap_label(ttk.Label(kp.body, textvariable=self.sec_kpis, style="CardStrong.TLabel")).pack(fill="x")

        left = Card(body, "RBAC + micro-segmentation", "\u2714 = role and network segment both allow it")
        left.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2))
        frame, self.seg_text = self._text(left.body, mono=True, wrap="none", hscroll=True, height=12)
        frame.pack(fill="both", expand=True)

        right = Card(body, "Security alerts", "suspicious things that need a human decision")
        right.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0))
        rb = right.body
        self._lbl(rb, ("Normal blocked requests (wrong role, outside hours...) are NOT alerts: they are simply recorded in the audit log. "
                       "An alert means something looked like an attack. Choose what it was: 'Reviewed' (looked, nothing to do), 'False alarm' (harmless), "
                       "or 'Confirm incident' (real problem: the user is signed out everywhere). Low/medium alerts can be cleared in bulk; high-severity ones need your individual decision."),
                  "hint", wrap=True).pack(fill="x", pady=(0, 8))
        top = ttk.Frame(rb, style="Card.TFrame"); top.pack(fill="x", pady=(0, 6))
        self.show_handled = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Also show alerts already handled", variable=self.show_handled, command=lambda: self.refresh_security(force=True)).pack(side="left")
        ttk.Button(top, text="Clear all low/medium", command=self.ack_alerts).pack(side="right")
        frame, self.alert_tree = self._tree(rb, (
            ("time", "Time", 70, "w", False), ("sev", "Severity", 80, "w", False), ("what", "What happened", 200, "w", True),
            ("who", "Who", 90, "w", False), ("status", "Status", 120, "w", False)), height=5)
        for tag, color in (("HIGH", "#c62828"), ("MEDIUM", "#b26a00"), ("LOW", "#667085"), ("done", "#667085")):
            self.alert_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)
        self.alert_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_alert_detail())
        frame, self.alert_text = self._text(rb, height=5); frame.pack(fill="x", pady=(8, 0))
        b = ttk.Frame(rb, style="Card.TFrame"); b.pack(fill="x", pady=(8, 0))
        ttk.Button(b, text="Reviewed", command=lambda: self.handle_selected_alerts(1)).pack(side="left", padx=(0, 6))
        ttk.Button(b, text="False alarm", command=lambda: self.handle_selected_alerts(2)).pack(side="left", padx=(0, 6))
        ttk.Button(b, text="Confirm incident + sign user out", style="Action.TButton", command=lambda: self.handle_selected_alerts(3)).pack(side="left")
        self.refresh_security(force=True)

    _SEG_ABBR = {"wiki": "wiki", "hr-db": "hr-db", "admin-panel": "admin", "source-code": "code", "ci-cd": "cicd", "crm": "crm",
                 "finance-ledger": "fin", "support-desk": "supp", "legal-vault": "legal", "siem-console": "siem", "exec-reports": "exec"}

    def refresh_security(self, force=False):
        t = telemetry_summary()
        self.sec_kpis.set(f"Last 60 min: {t['events']} decisions   ALLOW {t['allow']}   STEP-UP {t['stepup']}   DENY {t['deny']}   Avg risk {t['avg_risk']}   Alerts needing a decision: {t['alerts']}")
        snap = (tuple((u, v.get("role")) for u, v in sorted(USERS.items())), tuple(RESOURCES))
        if force or snap != getattr(self, "_seg_snap", None):
            self._seg_snap = snap
            ab = [self._SEG_ABBR.get(r, r[:5]) for r in RESOURCES]
            lines = ["USER     ROLE       " + " ".join(f"{a:<5}" for a in ab), "-" * (19 + 6 * len(ab))]
            for u, v in sorted(USERS.items()):
                lines.append(f"{u:<8} {v.get('role', '?'):<10} " + " ".join(f"{_TICK if (rbac_allows(u, r) and segment_allows(u, r)) else _CROSS:<5}" for r in RESOURCES))
            lines += ["", "Segments each role can reach:"]
            for role in ROLES:
                lines.append(f"  {role:<10} " + ", ".join(sorted(SEGMENT_ALLOW.get(role, set()))))
            lines += ["", "Lateral movement: a role can never reach a segment outside its own allow-list.", "A permitted request must still pass device, hours, location, MFA and risk checks."]
            self.seg_text.configure(state="normal"); self.seg_text.delete("1.0", "end"); self.seg_text.insert("1.0", "\n".join(lines)); self.seg_text.configure(state="disabled")
        alerts = [a for a in recent_alerts() if self.show_handled.get() or a.get("status", 0) == 0]
        asnap = tuple((a["id"], a["status"]) for a in alerts)
        if force or asnap != getattr(self, "_alert_snap", None):
            self._alert_snap = asnap; self._alerts_by_id = {str(a["id"]): a for a in alerts}
            sel = self.alert_tree.selection()
            for i in self.alert_tree.get_children(): self.alert_tree.delete(i)
            for a in alerts:
                title = describe_alert(a)[0]
                self.alert_tree.insert("", "end", iid=str(a["id"]), tags=(a["severity"] if a["status"] == 0 else "done",),
                                       values=(datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S"), a["severity"], title, a.get("user") or "-", ALERT_STATUS.get(a["status"], "?")))
            for k in sel:
                if self.alert_tree.exists(k): self.alert_tree.selection_set(k)
            self._show_alert_detail()

    def _show_alert_detail(self):
        sel = self.alert_tree.selection() if hasattr(self, "alert_tree") else ()
        a = getattr(self, "_alerts_by_id", {}).get(sel[0]) if sel else None
        if a:
            title, why, advice = describe_alert(a)
            text = f"{title}\nWhat it means: {why}\nDetails: {a.get('details') or '-'}  (user: {a.get('user') or '-'}, device: {a.get('device') or '-'})\nWhat to do: {advice}"
        else:
            text = "Select an alert to see what it means and what to do. No alerts needing a decision." if not getattr(self, "_alerts_by_id", None) else "Select an alert to see what it means and what to do."
        self.alert_text.configure(state="normal"); self.alert_text.delete("1.0", "end"); self.alert_text.insert("1.0", text); self.alert_text.configure(state="disabled")

    def handle_selected_alerts(self, status):
        sel = [i for i in self.alert_tree.selection() if self._alerts_by_id.get(i, {}).get("status", 1) == 0]
        if not sel:
            messagebox.showinfo("Security alerts", "Select one or more open alerts in the list first."); return
        label = ALERT_STATUS[status]; users = sorted({self._alerts_by_id[i].get("user") for i in sel if self._alerts_by_id[i].get("user")})
        if status == 3 and users and not messagebox.askyesno("Confirm incident", f"Sign out everywhere: {', '.join(users)}?\nThey must log in again."): return
        ended = 0
        if status == 3:
            for u in users:
                n_u, err_u = revoke_user_sessions_report(u); ended += n_u
                if err_u: messagebox.showwarning("Confirm incident", f"Sessions for {u} were ended, but the revocation could not be saved to the database ({err_u}).")
        acknowledge_alerts(sel, status)
        for i in sel:
            a = self._alerts_by_id[i]
            try: audit(user="admin", device=a.get("device"), resource="alert-review", decision="POLICY", reasons=[f"alert {a['kind']} for {a.get('user') or '-'} marked '{label}'" + (f"; {ended} session(s) ended" if status == 3 else "")])
            except (AuditFull, AuditTamper): pass
        self._write_summary(f"{len(sel)} alert(s) marked '{label}'" + (f"; {ended} session(s) ended" if status == 3 else ""))
        self.refresh_all()

    def ack_alerts(self):
        acknowledge_alerts(None, 1, include_high=False); self.refresh_security(force=True)
        self._write_summary("Low/medium alerts cleared. High-severity alerts still need an individual decision.")

    # ------------------------------------------------------------------ Audit & Integrity
    def _build_audit_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Audit & Integrity"); self.audit_tab = tab
        body.columnconfigure(0, weight=1); body.rowconfigure(2, weight=1)
        guide = self._guide(body, "Every decision is written to a tamper-evident log: each line is sealed to the one before it, so any edit, deletion or insertion breaks the chain.", (
            "THE LOG: every decision (who, what, allowed or blocked, and why) is written to a log nobody can quietly change. Each line carries a cryptographic 'seal' that depends on the line before it, "
            "and separate anchor files remember how many lines exist and the latest seal. Edit, delete or insert a line and the seals stop matching.\n\n"
            "VERIFY re-checks every seal and both anchors (this tab also does it automatically every minute). If it reports a problem, treat it as a security event and use the numbered steps below. "
            "The app also stops all new actions by itself if it notices the log file shrank or vanished while running."))
        guide.grid(row=0, column=0, sticky="ew", pady=(0, G))

        status = Card(body, "Integrity status"); status.grid(row=1, column=0, sticky="ew", pady=(0, G))
        sb = status.body
        top = ttk.Frame(sb, style="Card.TFrame"); top.pack(fill="x")
        self.audit_banner = tk.StringVar(value="\u25cf Not checked yet - press 'Verify now'")
        self.audit_banner_lbl = ttk.Label(top, textvariable=self.audit_banner, style="CardBanner.TLabel"); self.audit_banner_lbl.pack(side="left")
        self.audit_auto = tk.BooleanVar(value=True); self._audit_ok_last = None; self._audit_auto_at = time.time()
        ttk.Checkbutton(top, text="Auto-verify every minute", variable=self.audit_auto).pack(side="right")
        self.audit_detail = tk.StringVar(value="")
        self._wrap_label(ttk.Label(sb, textvariable=self.audit_detail, style="Card.TLabel")).pack(fill="x", pady=(6, 0))
        row = ttk.Frame(sb, style="Card.TFrame"); row.pack(fill="x", pady=(12, 0))
        ttk.Button(row, text="1  Verify now", style="Action.TButton", command=self.verify_audit).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="2  Save evidence copy", command=self.export_evidence_ui).pack(side="left", padx=6)
        ttk.Button(row, text="3  Safe repair", command=self.repair_audit_ui).pack(side="left", padx=6)
        ttk.Button(row, text="4  Archive damaged log + start fresh", command=self.reset_audit_ui).pack(side="left", padx=6)
        self._lbl(sb, ("1 Verify: checks the whole chain (safe, changes nothing).   2 Evidence copy: copies every audit file plus a report into a new folder - do this first if anything is wrong.   "
                       "3 Safe repair: fixes only the harmless case where an anchor lags exactly one entry behind a valid log (e.g. a crash); it refuses anything that looks like tampering.   "
                       "4 Archive and start fresh: demo mode only; moves the damaged files to an archive folder (nothing is deleted) and begins a new chain. In production, restore from backup and investigate instead."),
                  "hint", wrap=True).pack(fill="x", pady=(10, 0))

        log = Card(body, "Audit log"); log.grid(row=2, column=0, sticky="nsew")
        lb = log.body
        bar = ttk.Frame(lb, style="Card.TFrame"); bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Show", style="Card.TLabel").pack(side="left")
        self.audit_filter = tk.StringVar(value="Everything")
        cb = ttk.Combobox(bar, textvariable=self.audit_filter, state="readonly", width=30, values=("Everything", "Blocked or needs MFA", "Sign-ins and sign-outs", "Admin and policy changes", "Resource access only"))
        cb.pack(side="left", padx=8); cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh_audit(force=True))
        self.audit_count = tk.StringVar(); ttk.Label(bar, textvariable=self.audit_count, style="CardHint.TLabel").pack(side="left", padx=8)
        ttk.Button(bar, text="Refresh", style="Link.TButton", command=lambda: self.refresh_audit(force=True)).pack(side="right")
        frame, self.audit_tree = self._tree(lb, (("time", "Time", 80, "w", False), ("result", "Result", 120, "w", False), ("what", "What happened", 600, "w", True)), height=5)
        for tag, color in (("ok", "#0a7d33"), ("bad", "#c62828"), ("warn", "#b26a00"), ("info", "#0b5cad"), ("dim", "#667085")):
            self.audit_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)
        self.audit_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_audit_detail())
        frame, self.audit_text = self._text(lb, height=4); frame.pack(fill="x", pady=(8, 0))
        self._audit_by_iid = {}
        try: self.verify_audit()
        except Exception: pass

    def generate_otp(self):
        if not DEMO_OTP: return
        user = self.user_var.get().strip()
        if user in USERS:
            code = self.engine.demo_otp(user)
            self.otp_var.set(code)
            self._write_summary(f"Demo TOTP generated for {user}: {code}")

    def generate_step_otp(self):
        if DEMO_OTP and self.engine.user:
            self.step_otp.set(self.engine.demo_otp(self.engine.user))

    def do_login(self):
        ok, msg = self.engine.login(self.user_var.get(), self.pass_var.get(), self.otp_var.get(), self.device_var.get(), self.location_var.get())
        self._write_summary(msg)
        if not ok:
            messagebox.showerror("Login", msg)
        self.refresh_all()

    def do_stepup(self):
        ok, msg = self.engine.stepup(self.step_otp.get())
        self._write_access(msg)
        if not ok: messagebox.showerror("Step-up", msg)
        self.refresh_all()

    def do_logout(self):
        self.engine.logout(); self._write_summary("Logged out")
        self.refresh_all()

    def request_access(self, resource):
        result = self.engine.access(resource)
        self._show_access_result(resource, result)
        self.refresh_all()
        if result["decision"] == "STEPUP":
            self.nb.select(self.access_tab)

    def refresh_clock(self):
        if not hasattr(self, "clock_text"): return
        self.clock_text.set(f"Policy clock now: {now_hour():02d}:00 " + ("(PRETEND hour)" if SIM["hour"] is not None else "(real clock)"))

    def apply_hour(self):
        raw = self.hour_var.get().strip()
        try:
            hour = None if raw == "" else int(raw)
            if hour is not None and not 0 <= hour <= 23: raise ValueError
        except ValueError:
            messagebox.showerror("Time simulation", "Enter a whole number from 0 to 23.")
            return
        SIM["hour"] = hour
        audit(user="admin", device=None, resource="sim", decision="POLICY", reasons=[f"hour={hour}"])
        self.refresh_all()

    def use_real_clock(self):
        self.hour_var.set(""); self.apply_hour()

    def _policy_read_form(self):
        """Form -> policy dict, with friendly errors."""
        try:
            mp, lo, hi = int(self.pv["mp"].get()), int(self.pv["lo"].get()), int(self.pv["hi"].get())
            mfa = float(self.pv["mfa"].get())
        except (ValueError, tk.TclError):
            raise ValueError("Please enter whole numbers in the number boxes.")
        if lo == hi: raise ValueError("'Open from' and 'Open until' cannot be the same hour (use 0 and 24 for all day).")
        data = {"min_posture": mp, "mfa_age": int(round(mfa * 60)), "hours": [lo, hi], "managed": bool(self.pv_managed.get())}
        try: validate_policy_data({self.policy_resource.get(): data})
        except ValueError as exc: raise ValueError(f"Value out of range ({exc}). Score is 0-100, hours are 0-24, minutes cannot be negative.")
        return data

    def _policy_update_summary(self):
        if getattr(self, "_policy_loading", False) or not hasattr(self, "policy_summary"): return
        rname = self.policy_resource.get(); r = RESOURCES[rname]
        try: d = self._policy_read_form()
        except ValueError as exc:
            self.policy_summary.set(str(exc)); self.policy_state.set("Cannot save yet"); return
        people = [u for u, v in sorted(USERS.items()) if v.get("role") in r["roles"]]
        self.policy_summary.set(
            f"People with the role {', '.join(r['roles'])} ({len(people)} people) can open {rname} only:\n"
            f"  - from: {' or '.join(r['locations'])}\n  - during: {_fmt_hours({'hours': d['hours']})}\n"
            f"  - on: {'a company-managed device' if d['managed'] else 'any enrolled device'}\n"
            f"  - with a device health score of at least {d['min_posture']}/100\n"
            f"  - if they confirmed their identity (MFA) in the last {d['mfa_age'] / 60:g} minutes\n"
            "Anything else is blocked and written to the audit log.")
        saved = {k: r[k] for k in POLICY_KEYS}
        same = saved["min_posture"] == d["min_posture"] and saved["mfa_age"] == d["mfa_age"] and list(saved["hours"]) == d["hours"] and saved["managed"] == d["managed"]
        self.policy_state.set("Saved - this is exactly what is enforced now." if same else "Unsaved changes - press 'Save policy' to enforce them.")

    def load_policy_fields(self):
        rname = self.policy_resource.get(); r = RESOURCES[rname]
        self._policy_fill(r)
        self.policy_desc.set(r["desc"])
        self.policy_fixed.set(f"Fixed by design (not editable here): roles allowed = {', '.join(r['roles'])}; allowed from = {' or '.join(r['locations'])}.")
        self._policy_update_summary()

    def _policy_fill(self, d):
        self._policy_loading = True
        try:
            self.pv["mp"].set(str(d["min_posture"])); self.pv["lo"].set(str(d["hours"][0])); self.pv["hi"].set(str(d["hours"][1]))
            self.pv["mfa"].set(f"{d['mfa_age'] / 60:g}"); self.pv_managed.set(bool(d["managed"]))
        finally:
            self._policy_loading = False
        self._policy_update_summary()

    def policy_preset(self, kind):
        base = {"relaxed": {"min_posture": 40, "mfa_age": 3600, "hours": [0, 24], "managed": False},
                "standard": {"min_posture": 70, "mfa_age": 900, "hours": [9, 18], "managed": True},
                "strict": {"min_posture": 90, "mfa_age": 120, "hours": [9, 18], "managed": True},
                "default": POLICY_DEFAULTS[self.policy_resource.get()]}[kind]
        self._policy_fill(base)

    def save_policy_fields(self):
        rname = self.policy_resource.get(); r = RESOURCES[rname]
        try: data = self._policy_read_form()
        except ValueError as e:
            messagebox.showerror("Policy", str(e)); return
        r.update(data); save_policy()
        db_exec("INSERT INTO policy_changes(ts,actor,resource,policy_json) VALUES(?,?,?,?)",(time.time(),"admin",rname,json.dumps(data,sort_keys=True)))
        audit(user="admin", device=None, resource=rname, decision="POLICY", reasons=["policy updated: " + json.dumps(data, sort_keys=True, separators=(",", ":"))])
        self._write_summary(f"Policy saved for {rname}")
        self.refresh_all()
        self._policy_update_summary()

    def _audit_auto_verify(self):
        if not hasattr(self, "audit_auto") or not self.audit_auto.get() or time.time() - self._audit_auto_at < 60: return
        self._audit_auto_at = time.time()
        was = self._audit_ok_last
        ok = self.verify_audit()
        if was is True and not ok:
            self._write_summary("WARNING: the audit log failed its integrity check. Open Audit & Integrity.")
            try: self.nb.select(self.audit_tab)
            except Exception: pass

    def verify_audit(self):
        v = verify_chain(); ok, head, lines = verify_report(v); self._audit_ok_last = ok; self._audit_auto_at = time.time()
        self.audit_banner.set(("\u2714 " if ok else "\u2716 ") + head + f"   (checked {time.strftime('%H:%M:%S')})")
        self.audit_banner_lbl.configure(foreground="#0a7d33" if ok else "#c62828")
        self.audit_detail.set("\n".join(lines) + ("" if ok else "\nWhat to do: 2 save an evidence copy, then 3 try Safe repair; if it is still broken, 4 archive the damaged log (demo) or restore from backup (production)."))
        self.refresh_audit(force=True)
        return ok

    def export_evidence_ui(self):
        try: path = export_audit_evidence()
        except Exception as exc: messagebox.showerror("Evidence copy", f"Could not save evidence: {exc}"); return
        self._write_summary(f"Audit evidence saved to {os.path.basename(path)}")
        messagebox.showinfo("Evidence saved", f"A copy of every audit file and a report were saved to:\n{path}\n\nThe originals were not touched.")

    def repair_audit_ui(self):
        ok, msg = repair_chain_safe()
        (messagebox.showinfo if ok else messagebox.showwarning)("Safe repair", msg)
        self.verify_audit()

    def reset_audit_ui(self):
        if not DEMO:
            messagebox.showinfo("Archive and start fresh", "Only available in local demo mode. In production, restore the log from backup and investigate who changed it."); return
        if not self._confirm_admin_password(): return
        if not messagebox.askyesno("Archive damaged log?", "This moves the current audit log and anchors into an archive folder (nothing is deleted) and starts a NEW chain.\n\nOnly do this after saving evidence and confirming the damage cannot be repaired.\n\nContinue?"): return
        try: path = archive_and_reset_audit()
        except Exception as exc: messagebox.showerror("Archive and start fresh", f"Failed: {exc}"); return
        self._write_summary(f"Audit log archived to {os.path.basename(path)}; new chain started")
        self.verify_audit()
        messagebox.showinfo("New audit chain started", f"Old files are in:\n{path}\n\nThe new log starts with an entry recording this reset.")

    def posture_sel(self):
        sel = self.posture_tree.selection()
        return sel[0] if sel and sel[0] in DEVICES else None

    def posture_select_mine(self):
        dev = self.engine.device if self.engine.session else None
        if dev and self.posture_tree.exists(dev):
            self.posture_tree.selection_set(dev); self.posture_tree.see(dev)
        else:
            messagebox.showinfo("Device posture", "Log in first (Overview tab) and your device will be selected for you.")

    @staticmethod
    def _posture_state(dev):
        d = DEVICES[dev]; age = time.time() - d.get("last_report", 0)
        if not d.get("last_report"): return "stale", "Not signed in", age
        if POSTURE_TTL > 0 and age > POSTURE_TTL: return "stale", "Stale report", age
        sc = posture(dev)
        return ("good", "Healthy", age) if sc >= 80 else (("fair", "Fair", age) if sc >= 60 else ("bad", "At risk", age))

    def _posture_agent_beat(self):
        """Simulated endpoint agent: re-sends every device's CURRENT status (it never changes the checks themselves)."""
        if not self.agent_on.get(): return
        now = time.time()
        if now - getattr(self, "_agent_last", 0) < 60: return
        self._agent_last = now
        with LOCK: live = {s.get("device") for s in SESSIONS.values()}
        for name, d in DEVICES.items():
            if name in live: d["last_report"] = now

    def posture_report_now(self):
        dev = self.posture_sel()
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); return
        DEVICES[dev]["last_report"] = time.time()
        audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=["posture report sent"])
        self.refresh_all()

    @staticmethod
    def scan_findings(dev):
        """Simulated vulnerability / malware scan: derived from the device's current checks (no real endpoint here).
        -> list of (severity, title, detail, fix_field or None)."""
        d = DEVICES[dev]; out = []
        if not d.get("os_updated"): out.append(("HIGH", "Operating system is out of date", "Missing security patches leave known vulnerabilities open to attack.", "os_updated"))
        if not d.get("antivirus"): out.append(("HIGH", "No antivirus running - malware scan could not run", "Without an active scanner the device cannot be proven free of viruses, so it is treated as possibly infected.", "antivirus"))
        if not d.get("disk_encrypted"): out.append(("HIGH", "Disk is not encrypted", "Anyone who steals the device can read its data.", "disk_encrypted"))
        if not d.get("firewall"): out.append(("MEDIUM", "Firewall is switched off", "Incoming connections are not filtered, which exposes services on the device.", "firewall"))
        if not d.get("corporate_managed"): out.append(("LOW", "Device is not company-managed", "The company cannot enforce settings or remove it remotely. Not fixable by the scan; enrol the device.", None))
        return out

    def posture_scan(self):
        dev = self.posture_sel()
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); return
        win = tk.Toplevel(self); win.title(f"Vulnerability scan - {dev}"); win.transient(self); win.geometry("560x420")
        win.configure(background=self.C["bg"] if "bg" in self.C else "#f4f6f9")
        head = tk.StringVar(value=f"Scanning {dev} ..."); ttk.Label(win, textvariable=head, style="PageStrong.TLabel").pack(anchor="w", padx=14, pady=(14, 4))
        bar = ttk.Progressbar(win, maximum=5); bar.pack(fill="x", padx=14)
        step_txt = tk.StringVar(); ttk.Label(win, textvariable=step_txt, style="Sub.TLabel").pack(anchor="w", padx=14, pady=(4, 6))
        frame, out = self._text(win, height=10); frame.pack(fill="both", expand=True, padx=14)
        for tag, color in (("HIGH", "#c62828"), ("MEDIUM", "#b26a00"), ("LOW", "#667085"), ("OK", "#0a7d33")):
            out.tag_configure(tag, foreground=color, font=("Segoe UI", 10, "bold"))
        btns = ttk.Frame(win); btns.pack(fill="x", padx=14, pady=12)
        fix_btn = ttk.Button(btns, text="Fix all fixable issues", style="Action.TButton", state="disabled")
        fix_btn.pack(side="right"); ttk.Button(btns, text="Close", command=win.destroy).pack(side="right", padx=8)
        steps = ("Checking operating system patches", "Checking disk encryption", "Checking firewall", "Scanning for malware (antivirus)", "Checking device management")
        findings = self.scan_findings(dev)

        def finish():
            if not win.winfo_exists(): return
            bar["value"] = 5; step_txt.set("Scan complete"); fixable = [f for f in findings if f[3]]
            head.set(f"{dev}: {len(findings)} finding(s)" if findings else f"{dev}: no vulnerabilities or infections found")
            out.configure(state="normal"); out.delete("1.0", "end")
            if not findings: out.insert("end", "OK  ", "OK"); out.insert("end", "All checks passed and the antivirus scan is clean.\n")
            for sev, title, detail, _f in findings:
                out.insert("end", f"{sev}  ", sev); out.insert("end", f"{title}\n    {detail}\n\n")
            out.insert("end", "(Simulated scan: results come from the device's reported checks, not a real endpoint.)\n"); out.configure(state="disabled")
            audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=[f"vulnerability scan: {len(findings)} finding(s)"])
            if fixable:
                def fix_all():
                    for _s, _t, _d, f in fixable: DEVICES[dev][f] = True
                    DEVICES[dev]["last_report"] = time.time()
                    if dev not in FIXTURE_DEVICES:
                        try: save_persisted_devices()
                        except Exception: pass
                    audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=["scan: issues fixed"])
                    win.destroy(); self.refresh_all()
                fix_btn.configure(state="normal", command=fix_all)
            self.refresh_all()

        def tick(i=0):
            if not win.winfo_exists(): return
            if i >= len(steps): finish(); return
            bar["value"] = i; step_txt.set(steps[i] + " ..."); win.after(350, lambda: tick(i + 1))
        tick()

    def posture_preset(self, kind):
        dev = self.posture_sel()
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); return
        vals = {"healthy": dict(os_updated=True, disk_encrypted=True, firewall=True, antivirus=True)}[kind]
        DEVICES[dev].update(vals); DEVICES[dev]["last_report"] = time.time()
        audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=[f"preset {kind}"])
        self.refresh_all()

    def refresh_posture(self, force=False):
        if not hasattr(self, "posture_tree"): return
        tree = self.posture_tree
        for iid in tree.get_children():
            if iid not in DEVICES: tree.delete(iid)
        for dev, d in sorted(DEVICES.items()):
            tag, label, age = self._posture_state(dev)
            vals = (dev, d["owner"], posture(dev), label, f"{int(age)}s ago" if d.get("last_report") else "never")
            if tree.exists(dev): tree.item(dev, values=vals, tags=(tag,))
            else: tree.insert("", "end", iid=dev, values=vals, tags=(tag,))
        if self.agent_on.get():
            nxt = max(0, 60 - int(time.time() - getattr(self, "_agent_last", 0)))
            self.agent_status.set(f"Agent ON - next automatic report in {nxt}s")
        else:
            self.agent_status.set("Agent OFF - devices go stale after %d minutes and then score 0 (try it!)" % (POSTURE_TTL // 60) if POSTURE_TTL > 0
                                  else "Agent OFF - 'Last report' stops updating (demo mode never expires reports)")
        dev = self.posture_sel()
        if not dev:
            self.pd_title.set("Select a device on the left"); self.pd_score.set(""); self.pd_bar["value"] = 0; return
        d = DEVICES[dev]; tag, label, age = self._posture_state(dev); sc = posture(dev)
        self.pd_title.set(f"{dev}  -  owner: {d['owner']}")
        self.pd_score.set(f"{sc}/100  ({label})")
        self.pd_bar["value"] = sc
        for f, v in self.posture_vars.items():
            if v.get() != bool(d.get(f)): v.set(bool(d.get(f)))
        lines = []
        for r, v in RESOURCES.items():
            ok = sc >= v["min_posture"] and (not v["managed"] or d.get("corporate_managed"))
            need = f"needs {v['min_posture']}" + (" + company-managed" if v["managed"] else "")
            lines.append((("\u2714 " if ok else "\u2716 ") + f"{r}  ({need})\n", "ok" if ok else "bad"))
        key = repr(lines)
        if key != getattr(self, "_pd_caps_key", None):
            self._pd_caps_key = key
            self.pd_caps.configure(state="normal"); self.pd_caps.delete("1.0", "end")
            for text, t in lines: self.pd_caps.insert("end", text, t)
            self.pd_caps.configure(state="disabled")

    def set_posture(self, dev, field, value):
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); self.refresh_posture(); return
        DEVICES[dev][field] = bool(value)
        DEVICES[dev]["last_report"] = time.time()
        audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=[f"{field}={bool(value)}"])
        if dev not in FIXTURE_DEVICES:
            try: save_persisted_devices()
            except Exception: pass
        self.refresh_all()

    def _audit_matches(self, e, label, tag):
        f = self.audit_filter.get(); res = str(e.get("resource", ""))
        if f == "Blocked or needs MFA": return e.get("decision") in ("DENY", "STEPUP")
        if f == "Sign-ins and sign-outs": return res in ("login", "stepup", "session")
        if f == "Admin and policy changes": return e.get("decision") == "POLICY"
        if f == "Resource access only": return res in RESOURCES and e.get("decision") != "POLICY"
        return True

    def refresh_audit(self, force=False):
        if not hasattr(self, "audit_tree"): return
        snap = (AUDIT.get("entries"), self.audit_filter.get())
        if not force and snap == getattr(self, "_audit_snap", None): return
        self._audit_snap = snap
        sel = self.audit_tree.selection()
        for i in self.audit_tree.get_children(): self.audit_tree.delete(i)
        self._audit_by_iid = {}; shown = 0
        for e in list(LOG)[:400]:
            label, tag, text = describe_audit_event(e)
            if not self._audit_matches(e, label, tag): continue
            try: when = datetime.fromisoformat(str(e.get("ts", "")).replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
            except ValueError: when = str(e.get("ts", ""))[-9:-1]
            iid = str(e.get("hash", ""))[:24] or f"row{shown}"
            if self.audit_tree.exists(iid): continue
            self.audit_tree.insert("", "end", iid=iid, values=(when, label, text), tags=(tag,)); self._audit_by_iid[iid] = e; shown += 1
        self.audit_count.set(f"showing {shown} of the latest {min(len(LOG), 400)} entries  |  {AUDIT.get('entries', 0)} entries in the chain")
        for k in sel:
            if self.audit_tree.exists(k): self.audit_tree.selection_set(k)
        self._show_audit_detail()

    def _show_audit_detail(self):
        sel = self.audit_tree.selection()
        e = self._audit_by_iid.get(sel[0]) if sel else None
        text = "Select a line to see the technical details behind it." if not e else (
            f"Time (UTC): {e.get('ts')}   User: {e.get('user') or '-'}   Device: {e.get('device') or '-'}   System/action: {e.get('resource')}   Decision: {e.get('decision')}   Risk: {e.get('risk', '-')}\n"
            f"Reasons recorded: {'; '.join(map(str, e.get('reasons', []))) or '-'}\nRisk signals: {'; '.join(map(str, e.get('signals', []))) or '-'}\n"
            f"Seal (HMAC-SHA256): {e.get('hash')}\nPrevious line's seal: {e.get('prev')}")
        self.audit_text.configure(state="normal"); self.audit_text.delete("1.0", "end"); self.audit_text.insert("1.0", text); self.audit_text.configure(state="disabled")

    def _write_summary(self, text):
        self.summary.configure(state="normal"); self.summary.insert("1.0", f"{time.strftime('%H:%M:%S')}  {text}\n"); self.summary.configure(state="disabled")

    def _write_access(self, text):
        self.access_log.configure(state="normal"); self.access_log.insert("1.0", f"{time.strftime('%H:%M:%S')}  {text}\n"); self.access_log.configure(state="disabled")

    def refresh_all(self):
        if self.engine.session:
            _, s = self.engine.session
            self.status.config(text=f"● {s['user']}  ·  {s['device']}  ·  {s['location']}", background="#dcf3ea", foreground="#056b4c")
            age = int(time.time() - s["mfa_at"])
            self.session_text.set("Authenticated")
            for key, val in (("user", s["user"]), ("device", s["device"]), ("location", s["location"]), ("mfa", f"{age}s"),
                             ("ttl", f"{max(0, int(s['exp'] - time.time()))}s"), ("travel", str(s.get("travel", False)))):
                self.session_vars[key].set(val)
        else:
            self.status.config(text="● Logged out", background="#e3ecf7", foreground=self.C["muted"])
            self.session_text.set("Not authenticated")
            for var in self.session_vars.values(): var.set("—")
        self.refresh_posture()
        self.refresh_access_cards()
        self.refresh_clock()
        self.refresh_audit()
        self.refresh_security()
        self.refresh_identity_devices()
        self.refresh_roles()
        self.refresh_dashboard_overview()
        self.refresh_dashboard_activity()
        if not getattr(self,"_refresh_scheduled",False): self._refresh_scheduled=True; self.after(1500,self._tick)

    def _tick(self):
        self._refresh_scheduled=False
        if self.winfo_exists():
            self._posture_agent_beat()
            self._audit_auto_verify()
            self.refresh_all()

    def on_close(self):
        try: self.engine.logout()
        finally: self.destroy()




# ============================================================
# ENTERPRISE API / OIDC / PERSISTENT POLICY BRIDGE
# ============================================================
# This section is intentionally embedded in the same file.  The original
# desktop/lab engine remains the authoritative demo engine; the Enterprise
# API exposes the same policy, posture, segmentation and audit decisions and
# adds OIDC/Keycloak, durable SQL storage, reverse proxying, SIEM and IDS.
try:
    from fastapi import FastAPI, Request, HTTPException, Depends, Header
    from fastapi.responses import JSONResponse, StreamingResponse
    from pydantic import BaseModel, Field
    from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, Text, DateTime, UniqueConstraint, text as sql_text
    from sqlalchemy.orm import declarative_base, sessionmaker, Session
    from sqlalchemy.exc import IntegrityError
    import httpx
    import jwt as pyjwt
    from jwt import PyJWKClient
    from jwt.exceptions import PyJWKClientConnectionError
    from starlette.concurrency import run_in_threadpool
    FASTAPI_AVAILABLE = True
except Exception as _import_exc:
    FASTAPI_AVAILABLE = False
    _enterprise_import_error = str(_import_exc)  # `except ... as` names are deleted on exit, so keep a separate name

if FASTAPI_AVAILABLE:
    ENTERPRISE_APP_NAME = os.environ.get("APP_NAME", "enterprise-ztna")
    ENTERPRISE_DB_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'enterprise.db')}")
    KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080").rstrip("/")
    KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "ztna")
    KEYCLOAK_ISSUER = os.environ.get("KEYCLOAK_ISSUER", f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}").rstrip("/")
    KEYCLOAK_JWKS_URL = os.environ.get("KEYCLOAK_JWKS_URL", f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs")
    OIDC_AUDIENCE = os.environ.get("OIDC_AUDIENCE", "")
    OIDC_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "ztna")
    OIDC_REQUIRED = os.environ.get("OIDC_REQUIRED", "false" if DEMO else "true").lower() == "true"
    OIDC_ALLOW_LOCAL = os.environ.get("OIDC_ALLOW_LOCAL", "true" if DEMO else "false").lower() == "true"
    JWT_LEEWAY = 30
    UP_WIKI = os.environ.get("UP_WIKI", "").rstrip("/")
    UP_HR = os.environ.get("UP_HR", "").rstrip("/")
    UP_ADMIN = os.environ.get("UP_ADMIN", "").rstrip("/")
    SIEM_URL = os.environ.get("SIEM_URL", "").rstrip("/")
    SIEM_TOKEN = os.environ.get("SIEM_TOKEN", "")
    SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "")
    SYSLOG_PORT = 514
    SURICATA_EVE_FILE = os.environ.get("SURICATA_EVE_FILE", os.path.join(DATA_DIR, "eve.json"))
    ZTNA_ENFORCE_FIREWALL = os.environ.get("ZTNA_ENFORCE_FIREWALL", "false").lower() == "true"
    FIREWALL_INTERFACE = os.environ.get("FIREWALL_INTERFACE", "eth0")
    FIREWALL_CHAIN = os.environ.get("FIREWALL_CHAIN", "ZTNA")
    REQUEST_TIMEOUT = 15.0
    MAX_BODY_SIZE = 10 * 1024 * 1024
    ENTERPRISE_AUDIT_SECRET = os.environ.get("AUDIT_SECRET", "")
    def _ensure_enterprise_audit_secret():
        global ENTERPRISE_AUDIT_SECRET
        if ENTERPRISE_AUDIT_SECRET: return
        if not DEMO: raise RuntimeError("enterprise audit secret is required")
        path=os.path.join(DATA_DIR,"enterprise_audit.secret")
        try: ENTERPRISE_AUDIT_SECRET=Path(path).read_text(encoding="ascii").strip()
        except FileNotFoundError:
            ENTERPRISE_AUDIT_SECRET=secrets.token_hex(32)
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"w",encoding="ascii") as f: f.write(ENTERPRISE_AUDIT_SECRET); f.flush(); os.fsync(f.fileno())
            _fsync_dir(path)
        if len(ENTERPRISE_AUDIT_SECRET)<32: raise RuntimeError("enterprise audit secret must be at least 32 characters")
    ENTERPRISE_REQUIRE_POSTURE_ATTESTATION = os.environ.get("REQUIRE_POSTURE_ATTESTATION", "false" if DEMO else "true").lower() == "true"
    ENTERPRISE_AUDIT_LOCK = threading.RLock()
    ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE=os.environ.get("ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE",os.path.join(DATA_DIR,"enterprise_audit.monotonic"))
    ENTERPRISE_POSTURE_NONCES = {}
    ENTERPRISE_HTTP_CLIENT = None
    ENTERPRISE_POSTURE_TTL = 300
    ENTERPRISE_MFA_MAX_AGE = 300
    ENTERPRISE_RATE_LIMIT = 120
    TRUSTED_PROXY_NETS=[]

    if ENTERPRISE_DB_URL.startswith("sqlite"):
        enterprise_engine = create_engine(ENTERPRISE_DB_URL, connect_args={"check_same_thread": False, "timeout": 30}, pool_pre_ping=True)
    else:
        enterprise_engine = create_engine(ENTERPRISE_DB_URL, pool_pre_ping=True, pool_recycle=1800)
    EnterpriseBase = declarative_base()
    EnterpriseSession = sessionmaker(autocommit=False, autoflush=False, bind=enterprise_engine)

    class EUser(EnterpriseBase):
        __tablename__ = "enterprise_users"
        id = Column(Integer, primary_key=True)
        subject = Column(String(255), unique=True, nullable=False)
        username = Column(String(255))
        email = Column(String(255))
        enabled = Column(Boolean, default=True)
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    class EDevice(EnterpriseBase):
        __tablename__ = "enterprise_devices"
        id = Column(Integer, primary_key=True)
        device_id = Column(String(255), unique=True, nullable=False)
        subject = Column(String(255), nullable=False)
        hostname = Column(String(255))
        platform = Column(String(255))
        os_version = Column(String(255))
        agent_version = Column(String(255))
        compliant = Column(Boolean, default=False)
        encrypted_disk = Column(Boolean, default=False)
        firewall_enabled = Column(Boolean, default=False)
        antivirus_enabled = Column(Boolean, default=False)
        risk_score = Column(Float, default=100)
        last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    class EPolicy(EnterpriseBase):
        __tablename__ = "enterprise_policies"
        id = Column(Integer, primary_key=True)
        name = Column(String(255), unique=True, nullable=False)
        priority = Column(Integer, default=1000, nullable=False)
        subject_pattern = Column(String(255))
        role = Column(String(255))
        resource = Column(String(255), nullable=False)
        action = Column(String(32), default="allow")
        min_device_score = Column(Float, default=0)
        max_risk_score = Column(Float, default=100)
        require_mfa = Column(Boolean, default=True)
        enabled = Column(Boolean, default=True)

    class EAuditLock(EnterpriseBase):
        __tablename__ = "enterprise_audit_lock"
        id = Column(Integer, primary_key=True)

    class EAuditAnchor(EnterpriseBase):
        __tablename__ = "enterprise_audit_anchor"
        id = Column(Integer, primary_key=True)
        entries = Column(Integer, nullable=False, default=0)
        last_hash = Column(String(128), nullable=False, default="GENESIS")
        mac = Column(String(128), nullable=False, default="")

    class EAudit(EnterpriseBase):
        __tablename__ = "enterprise_audit_events"
        id = Column(Integer, primary_key=True)
        event_id = Column(String(64), unique=True, nullable=False)
        timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        timestamp_iso = Column(String(40))
        subject = Column(String(255))
        source_ip = Column(String(64))
        device_id = Column(String(255))
        resource = Column(String(255))
        action = Column(String(64), nullable=False)
        decision = Column(String(32))
        risk_score = Column(Float)
        event_type = Column(String(64), default="access")
        details = Column(Text)
        previous_hash = Column(String(128))
        event_hash = Column(String(128), nullable=False)

    class EAnchorOutbox(EnterpriseBase):
        """Durable intent to publish an audit checkpoint outside the primary DB."""
        __tablename__ = "enterprise_anchor_outbox"
        id = Column(Integer, primary_key=True)
        event_id = Column(String(64), unique=True, nullable=False)
        previous_count = Column(Integer, nullable=False)
        previous_hash = Column(String(128), nullable=False)
        entries = Column(Integer, unique=True, nullable=False)
        last_hash = Column(String(128), nullable=False)
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
        delivered_at = Column(DateTime)
        attempts = Column(Integer, nullable=False, default=0)
        last_error = Column(Text)

    class EDeliveryOutbox(EnterpriseBase):
        """Durable at-least-once delivery queue for configured SIEM/syslog sinks."""
        __tablename__ = "enterprise_delivery_outbox"
        id = Column(Integer, primary_key=True)
        event_id = Column(String(64), nullable=False)
        destination = Column(String(16), nullable=False)
        payload = Column(Text, nullable=False)
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
        next_attempt_at = Column(Float, nullable=False, default=0.0)
        attempts = Column(Integer, nullable=False, default=0)
        delivered_at = Column(DateTime)
        last_error = Column(Text)
        __table_args__ = (UniqueConstraint("event_id", "destination", name="uq_enterprise_delivery_event_destination"),)

    class EIDSAlert(EnterpriseBase):
        __tablename__ = "enterprise_ids_alerts"
        id = Column(Integer, primary_key=True)
        timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        signature = Column(String(1024))
        category = Column(String(255))
        severity = Column(Integer)
        src_ip = Column(String(64))
        src_port = Column(Integer)
        dest_ip = Column(String(64))
        dest_port = Column(Integer)
        raw_event = Column(Text, nullable=False)

    class EIngestOffset(EnterpriseBase):
        __tablename__ = "enterprise_ingest_offsets"
        name = Column(String(255), primary_key=True)
        offset = Column(Integer, nullable=False, default=0)

    class EReplayNonce(EnterpriseBase):
        """Durable replay cache shared by workers using the same enterprise DB."""
        __tablename__ = "enterprise_replay_nonces"
        id = Column(Integer, primary_key=True)
        kind = Column(String(32), nullable=False)
        scope = Column(String(128), nullable=False)
        nonce_hash = Column(String(64), nullable=False)
        expires_at = Column(Float, nullable=False)
        __table_args__ = (UniqueConstraint("kind", "scope", "nonce_hash", name="uq_enterprise_replay_nonce"),)

    class ERequestRateBucket(EnterpriseBase):
        """Shared per-peer fixed-window rate counter for multi-worker deployments."""
        __tablename__ = "enterprise_request_rate_buckets"
        scope = Column(String(128), primary_key=True)
        window_id = Column(Integer, nullable=False)
        hits = Column(Integer, nullable=False, default=0)
        last_seen = Column(Float, nullable=False, default=0.0)

    ENTERPRISE_NONCE_PRUNE_LAST = 0.0
    ENTERPRISE_NONCE_PRUNE_LOCK = threading.Lock()

    def _enterprise_accept_replay_nonce(kind: str, scope: str, nonce: str, now: float, ttl: int, limit: int) -> bool:
        """Consume a nonce atomically in the enterprise database across processes.

        Returns True for a new nonce, False for a replay, and None when the
        scope reaches capacity. Database errors raise so callers can return 503.
        """
        global ENTERPRISE_NONCE_PRUNE_LAST
        if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
            return False
        scope = str(scope or "")
        if not scope or len(scope) > 128:
            return False
        kind = str(kind)[:32]
        digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        db = EnterpriseSession()
        try:
            if ENTERPRISE_DB_URL.startswith("sqlite"):
                # Reserve the write lock before counting so a per-scope limit is
                # enforced consistently within a shared SQLite database.
                db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            with ENTERPRISE_NONCE_PRUNE_LOCK:
                prune = now - ENTERPRISE_NONCE_PRUNE_LAST >= 10.0
                if prune:
                    ENTERPRISE_NONCE_PRUNE_LAST = now
            if prune:
                db.query(EReplayNonce).filter(EReplayNonce.expires_at <= now).delete(synchronize_session=False)
            used = db.query(EReplayNonce.id).filter(
                EReplayNonce.kind == kind,
                EReplayNonce.scope == scope,
                EReplayNonce.expires_at > now,
            ).count()
            if used >= max(1, int(limit)):
                db.rollback()
                return None  # scope capacity reached; caller returns 429
            db.add(EReplayNonce(kind=kind, scope=scope, nonce_hash=digest, expires_at=now + int(ttl)))
            db.commit()
            return True
        except IntegrityError:
            db.rollback()
            return False  # replay (unique constraint)
        except Exception as exc:
            db.rollback()
            logger.warning("durable replay nonce check failed closed: %s", exc)
            raise RuntimeError("durable replay nonce store unavailable") from exc
        finally:
            db.close()

    ENTERPRISE_RATE_PRUNE_LAST = 0.0
    ENTERPRISE_RATE_PRUNE_LOCK = threading.Lock()

    def _enterprise_rate_allow(peer: str, now: float, limit: int, window_seconds: int = 60) -> bool:
        """Atomically consume one per-peer request slot using the shared enterprise DB.

        SQLite serializes writers with BEGIN IMMEDIATE; PostgreSQL locks an existing
        peer row and retries a concurrent first insert. Storage errors fail closed.
        """
        global ENTERPRISE_RATE_PRUNE_LAST
        scope = str(peer or "unknown")[:128]
        window_seconds = max(1, int(window_seconds))
        limit = max(1, int(limit))
        window_id = int(now // window_seconds)
        for attempt in range(3):
            db = EnterpriseSession()
            try:
                if ENTERPRISE_DB_URL.startswith("sqlite"):
                    db.connection().exec_driver_sql("BEGIN IMMEDIATE")
                row = (db.query(ERequestRateBucket)
                         .filter(ERequestRateBucket.scope == scope)
                         .with_for_update().one_or_none())
                if row is None:
                    row = ERequestRateBucket(scope=scope, window_id=window_id, hits=0, last_seen=now)
                    db.add(row)
                    db.flush()
                if row.window_id != window_id:
                    row.window_id = window_id
                    row.hits = 0
                if row.hits >= limit:
                    db.rollback()
                    return False
                row.hits += 1
                row.last_seen = now
                with ENTERPRISE_RATE_PRUNE_LOCK:
                    prune = now - ENTERPRISE_RATE_PRUNE_LAST >= 10.0
                    if prune:
                        ENTERPRISE_RATE_PRUNE_LAST = now
                if prune:
                    db.query(ERequestRateBucket).filter(
                        ERequestRateBucket.last_seen < now - (window_seconds * 2)
                    ).delete(synchronize_session=False)
                db.commit()
                return True
            except IntegrityError as exc:
                db.rollback()
                if attempt < 2:
                    continue
                logger.warning("rate-limit bucket creation conflict: %s", exc)
                raise RuntimeError("shared rate-limit store unavailable") from exc
            except Exception as exc:
                db.rollback()
                logger.warning("shared rate-limit store failed closed: %s", exc)
                raise RuntimeError("shared rate-limit store unavailable") from exc
            finally:
                db.close()
        raise RuntimeError("shared rate-limit store unavailable")

    def _enterprise_reconcile_external_anchor(*, acknowledge=True):
        """Verify the full chain and reconcile only a checkpoint change backed by durable outbox intent.

        A one-entry lag is considered crash recovery ONLY if a committed EAnchorOutbox row proves the exact
        expected previous and next checkpoints. This distinguishes an interrupted append from replaying an old,
        validly MACed anchor file. The DB chain and local anchor are always verified before file writes.
        """
        with EnterpriseSession() as db:
            verified = _enterprise_stream_verify_chain(
                db, external_mode="reconcile", check_process_checkpoint=False
            )
            if not verified["ok"]:
                raise RuntimeError(
                    "enterprise audit verification failed; no anchor was changed: "
                    + str(verified.get("reason", "unknown audit integrity error"))
                )
            count, last_hash = verified["entries"], verified["last_hash"]
            external = verified.get("_external")
            if external is None or external[0] != count:
                if external is None:
                    previous = (0, "GENESIS")
                else:
                    previous = (external[0], external[1])
                # The streaming verifier has checked that a matching undelivered outbox entry exists.
                _enterprise_external_anchor_update(count, last_hash, previous=previous)

        # Ack only after the anchor is on disk and exactly matches the verified DB tail.
        # When called from a handler that already holds a SQLite write transaction,
        # defer this acknowledgement to that transaction to avoid lock inversion.
        if acknowledge:
            with EnterpriseSession() as ack_db:
                ack_db.query(EAnchorOutbox).filter(
                    EAnchorOutbox.entries <= count,
                    EAnchorOutbox.delivered_at.is_(None),
                ).update({EAnchorOutbox.delivered_at: datetime.now(timezone.utc), EAnchorOutbox.last_error: None}, synchronize_session=False)
                ack_db.commit()
        return (count, last_hash)

    def enterprise_init_db():
        _ENT_ANCHOR_STATE.update(degraded=None,last=None,pending=None)
        _ensure_enterprise_audit_secret()
        EnterpriseBase.metadata.create_all(bind=enterprise_engine)
        with EnterpriseSession() as _lock_db:
            if _lock_db.query(EAuditLock).first() is None:
                _lock_db.add(EAuditLock(id=1))
            if _lock_db.query(EAuditAnchor).first() is None:
                _lock_db.add(EAuditAnchor(id=1,entries=0,last_hash="GENESIS",mac=hmac.new(ENTERPRISE_AUDIT_SECRET.encode(),b"0:GENESIS",hashlib.sha256).hexdigest()))
            _lock_db.commit()
        if not ENTERPRISE_DB_URL.startswith("sqlite"):
            from sqlalchemy import inspect
            cols={c["name"] for c in inspect(enterprise_engine).get_columns("enterprise_policies")}
            if "priority" not in cols: raise RuntimeError("enterprise_policies.priority is missing; run Alembic migration before startup")
        if ENTERPRISE_DB_URL.startswith("sqlite"):
            try:
                with enterprise_engine.begin() as conn:
                    cols={row[1] for row in conn.exec_driver_sql("PRAGMA table_info(enterprise_policies)").fetchall()}
                    if "priority" not in cols: conn.exec_driver_sql("ALTER TABLE enterprise_policies ADD COLUMN priority INTEGER NOT NULL DEFAULT 1000")
                    acols={row[1] for row in conn.exec_driver_sql("PRAGMA table_info(enterprise_audit_events)").fetchall()}
                    if "timestamp_iso" not in acols: conn.exec_driver_sql("ALTER TABLE enterprise_audit_events ADD COLUMN timestamp_iso VARCHAR(40)")
            except Exception as exc: logger.warning("enterprise SQLite migration failed: %s",exc)
        else:
            from sqlalchemy import inspect
            insp=inspect(enterprise_engine)
            acols={c["name"] for c in insp.get_columns("enterprise_audit_events")}
            if "timestamp_iso" not in acols: raise RuntimeError("enterprise_audit_events.timestamp_iso is missing; run Alembic migration before startup")
        # Only reconcile once schema upgrades/compatibility checks are complete.
        _enterprise_reconcile_external_anchor()
    _enterprise_jwks = PyJWKClient(KEYCLOAK_JWKS_URL)

    class EnterpriseDevicePosture(BaseModel):
        device_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
        hostname: str | None = None
        platform: str | None = None
        os_version: str | None = None
        agent_version: str | None = None
        compliant: bool
        encrypted_disk: bool
        firewall_enabled: bool
        antivirus_enabled: bool
        integrity_token: str | None = None
        posture_timestamp: float | None = None
        posture_nonce: str | None = None

    class EnterprisePolicyCreate(BaseModel):
        name: str
        priority: int = Field(default=1000, ge=0, le=1000000)
        subject_pattern: str | None = None
        role: str | None = None
        resource: str
        action: str = "allow"
        min_device_score: float = Field(default=0, ge=0, le=100)
        max_risk_score: float = Field(default=100, ge=0, le=100)
        require_mfa: bool = True
        enabled: bool = True

    class EnterpriseFirewallRequest(BaseModel):
        source_ip: str
        destination_ip: str
        destination_port: int = Field(ge=0, le=65535)
        protocol: str = "tcp"
        action: str = "allow"
        remove: bool = False
        ttl_seconds: int = Field(default=0, ge=0, le=86400)

    ENTERPRISE_SIEM_QUEUE=queue.Queue(maxsize=1000)
    ENTERPRISE_STOP=threading.Event()
    ENTERPRISE_SIEM_THREAD=None
    ENTERPRISE_SURICATA_TASK=None

    def _enterprise_deliver_outbox(destination: str, payload: str):
        """Deliver one committed outbox row. Returns only after success; failures remain retryable."""
        if destination == "siem":
            if not SIEM_URL: raise RuntimeError("SIEM_URL is not configured")
            headers = {"Content-Type": "application/json"}
            if SIEM_TOKEN: headers["Authorization"] = f"Bearer {SIEM_TOKEN}"
            response = httpx.post(SIEM_URL, content=payload, headers=headers, timeout=5)
            response.raise_for_status()
            return
        if destination == "syslog":
            if not SYSLOG_HOST: raise RuntimeError("SYSLOG_HOST is not configured")
            packet = (f"<134>1 {datetime.now(timezone.utc).isoformat()} "
                      f"{socket.gethostname()} {ENTERPRISE_APP_NAME} - - - {payload}").encode("utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(packet, (SYSLOG_HOST, SYSLOG_PORT))
            return
        raise ValueError(f"unknown outbox destination {destination!r}")

    def _enterprise_drain_delivery_outbox(batch_size=50):
        """At-least-once dispatcher: committed rows survive process restarts and queue overflow."""
        now = time.time()
        with EnterpriseSession() as db:
            rows = db.query(EDeliveryOutbox).filter(
                EDeliveryOutbox.delivered_at.is_(None),
                EDeliveryOutbox.next_attempt_at <= now,
            ).order_by(EDeliveryOutbox.id.asc()).limit(max(1, min(int(batch_size), 500))).all()
            work = [(r.id, r.destination, r.payload, r.attempts) for r in rows]
        delivered = 0
        for row_id, destination, payload, attempts in work:
            failure = None
            try:
                _enterprise_deliver_outbox(destination, payload)
            except Exception as exc:
                failure = f"{type(exc).__name__}: {exc}"[:2000]
            with EnterpriseSession() as db:
                row = db.query(EDeliveryOutbox).filter(EDeliveryOutbox.id == row_id).one_or_none()
                if row is None or row.delivered_at is not None:
                    continue
                row.attempts = int(row.attempts or 0) + 1
                if failure is None:
                    row.delivered_at = datetime.now(timezone.utc)
                    row.last_error = None
                    delivered += 1
                else:
                    row.last_error = failure
                    row.next_attempt_at = time.time() + min(300.0, float(2 ** min(row.attempts, 8)))
                db.commit()
            if failure is not None:
                logger.warning("durable %s outbox delivery failed (attempt %s); retry scheduled: %s", destination, attempts + 1, failure)
        return delivered

    def _enterprise_siem_worker():
        while not ENTERPRISE_STOP.is_set():
            try:
                try: ENTERPRISE_SIEM_QUEUE.get(timeout=0.5)
                except queue.Empty: pass  # periodic poll recovers missed/overflowed wake-ups
                else: ENTERPRISE_SIEM_QUEUE.task_done()
                _enterprise_drain_delivery_outbox()
            except Exception as exc:
                logger.warning("durable SIEM outbox worker failed; pending rows remain in database: %s", exc)
                ENTERPRISE_STOP.wait(0.5)

    @asynccontextmanager
    async def enterprise_lifespan(_app):
        global ENTERPRISE_HTTP_CLIENT,ENTERPRISE_SIEM_THREAD,ENTERPRISE_SURICATA_TASK,TRUSTED_PROXY_NETS
        global JWT_LEEWAY,SYSLOG_PORT,REQUEST_TIMEOUT,MAX_BODY_SIZE,ENTERPRISE_POSTURE_TTL,ENTERPRISE_MFA_MAX_AGE,ENTERPRISE_RATE_LIMIT,ENTERPRISE_SIEM_QUEUE
        _configure_logging()
        _workers=_env_int("WEB_CONCURRENCY",os.environ.get("UVICORN_WORKERS","1"),1,128,error_type=RuntimeError)
        if _workers>1 or __import__("multiprocessing").parent_process() is not None:
            # Covers `uvicorn module:enterprise_app --workers N` / env-configured workers, which bypass run_enterprise_api().
            raise RuntimeError("enterprise mode supports a single worker process only; multi-worker deployment is unsupported until cross-process audit-anchor updates are validated")
        init_runtime("enterprise", asgi=True)
        logger.info("Enterprise request-rate limits, replay nonces, and local-demo session revocation use the shared database. Multi-worker deployments must point all workers at the same transactional DATABASE_URL.")
        TRUSTED_PROXY_NETS=_parse_cidrs("ZTNA_TRUSTED_PROXY_CIDRS","",error_type=RuntimeError)
        JWT_LEEWAY=_env_int("JWT_LEEWAY",30,0,600,error_type=RuntimeError)
        SYSLOG_PORT=_env_int("SYSLOG_PORT",514,1,65535,error_type=RuntimeError)
        REQUEST_TIMEOUT=float(os.environ.get("REQUEST_TIMEOUT","15"))
        if not math.isfinite(REQUEST_TIMEOUT) or REQUEST_TIMEOUT<=0: raise RuntimeError("REQUEST_TIMEOUT must be positive and finite")
        MAX_BODY_SIZE=_env_int("MAX_BODY_SIZE",10*1024*1024,1024,100*1024*1024,error_type=RuntimeError)
        ENTERPRISE_POSTURE_TTL=_env_int("ENTERPRISE_POSTURE_TTL",300,0,86400,error_type=RuntimeError)
        ENTERPRISE_MFA_MAX_AGE=_env_int("ZTNA_ENTERPRISE_MFA_MAX_AGE",300,1,86400,error_type=RuntimeError)
        ENTERPRISE_RATE_LIMIT=_env_int("ENTERPRISE_RATE_LIMIT",120,1,100000,error_type=RuntimeError)
        ENTERPRISE_SIEM_QUEUE=queue.Queue(maxsize=_env_int("SIEM_QUEUE_SIZE",1000,1,100000,error_type=RuntimeError))
        if DEMO:
            _ensure_demo_jwt_key()
            global USERS
            if not USERS: USERS=load_users()
        _ensure_enterprise_audit_secret()
        if not DEMO:
            if not ENTERPRISE_AUDIT_SECRET or len(ENTERPRISE_AUDIT_SECRET)<32: raise RuntimeError("production requires separate AUDIT_SECRET of at least 32 characters")
            if not OIDC_AUDIENCE: raise RuntimeError("production requires OIDC_AUDIENCE")
            if "ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE" not in os.environ: raise RuntimeError("production requires ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE outside the mutable database directory")
            _db_dir=os.path.dirname(os.path.abspath(ENTERPRISE_DB_URL[len("sqlite:///"):])) if ENTERPRISE_DB_URL.startswith("sqlite:///") and not ENTERPRISE_DB_URL.endswith(":memory:") else None
            _validate_external_anchor_location(ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE,[DATA_DIR,_db_dir])
            try:
                __import__("cryptography")
            except ImportError as exc: raise RuntimeError("RS256 enterprise verification requires PyJWT[crypto] / cryptography") from exc
        enterprise_init_db()
        ENTERPRISE_HTTP_CLIENT=httpx.AsyncClient(timeout=REQUEST_TIMEOUT,follow_redirects=False,limits=httpx.Limits(max_connections=200,max_keepalive_connections=50))
        ENTERPRISE_STOP.clear(); ENTERPRISE_SIEM_THREAD=threading.Thread(target=_enterprise_siem_worker,daemon=True); ENTERPRISE_SIEM_THREAD.start()
        async def suricata_loop():
            while not ENTERPRISE_STOP.is_set():
                try: await asyncio.to_thread(enterprise_ingest_suricata_once)
                except Exception as exc: logger.warning("Suricata ingest failed: %s",exc)
                await asyncio.sleep(5)
        ENTERPRISE_SURICATA_TASK=asyncio.create_task(suricata_loop())
        try:
            yield
        finally:
            ENTERPRISE_STOP.set()
            if ENTERPRISE_SURICATA_TASK: ENTERPRISE_SURICATA_TASK.cancel()
            if ENTERPRISE_SIEM_THREAD: ENTERPRISE_SIEM_THREAD.join(timeout=2)
            if ENTERPRISE_HTTP_CLIENT:
                await ENTERPRISE_HTTP_CLIENT.aclose()
                ENTERPRISE_HTTP_CLIENT=None

    enterprise_app = FastAPI(title="Enterprise ZTNA + ZTNA Lab", version="3.0.0", lifespan=enterprise_lifespan)
    @enterprise_app.middleware("http")
    async def enterprise_security_middleware(request: Request, call_next):
        # request.client.host is the transport peer because Uvicorn proxy-header
        # rewriting is disabled; trusted-proxy resolution is used separately for audit.
        peer=request.client.host if request.client else "unknown"
        default_hosts=f"{HOST_ENV}:{os.environ.get('ZTNA_API_PORT',str(PORT))},localhost:{os.environ.get('ZTNA_API_PORT',str(PORT))},127.0.0.1:{os.environ.get('ZTNA_API_PORT',str(PORT))}"
        allowed_hosts={x.strip().lower() for x in os.environ.get("ZTNA_ENTERPRISE_ALLOWED_HOSTS",os.environ.get("ZTNA_ALLOWED_HOSTS",default_hosts)).split(",") if x.strip()}
        host=request.headers.get("host","").lower()
        if allowed_hosts and host not in allowed_hosts: return JSONResponse({"detail":"invalid host"},status_code=421)
        now=time.time()
        try:
            rate_allowed=await run_in_threadpool(_enterprise_rate_allow,peer,now,ENTERPRISE_RATE_LIMIT,60)
        except RuntimeError:
            return JSONResponse({"detail":"rate-limit store unavailable"},status_code=503,headers={"Retry-After":"2"})
        if not rate_allowed:
            return JSONResponse({"detail":"rate limit exceeded"},status_code=429,headers={"Retry-After":"60"})
        response=await call_next(request)
        response.headers.setdefault("Cache-Control","no-store")
        response.headers.setdefault("X-Content-Type-Options","nosniff")
        response.headers.setdefault("X-Frame-Options","DENY")
        response.headers.setdefault("Referrer-Policy","no-referrer")
        if request.url.scheme=="https": response.headers.setdefault("Strict-Transport-Security","max-age=31536000; includeSubDomains")
        return response

    def enterprise_db():
        db = EnterpriseSession()
        try:
            yield db
        finally:
            db.close()

    def _enterprise_bearer(authorization: str | None) -> str | None:
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return None

    def _enterprise_oidc(token: str) -> dict:
        try: header=pyjwt.get_unverified_header(token)
        except Exception: raise HTTPException(401,"Invalid identity token")
        if header.get("alg") not in {"RS256","RS384","RS512"} or header.get("typ") not in {"Bearer","JWT"}: raise HTTPException(401,"Invalid access token type")
        key = _enterprise_jwks.get_signing_key_from_jwt(token)
        kwargs = {"algorithms": ["RS256", "RS384", "RS512"], "issuer": KEYCLOAK_ISSUER, "leeway": JWT_LEEWAY, "options": {"require": ["exp", "iat", "sub"], "verify_nbf": True}}
        if OIDC_AUDIENCE:
            claims=pyjwt.decode(token, key.key, audience=OIDC_AUDIENCE, **kwargs)
            azp=claims.get("azp")
            if azp and azp!=OIDC_CLIENT_ID: raise HTTPException(401,"Invalid token client")
            if not azp and not DEMO: raise HTTPException(401,"Token azp is missing")
            return claims
        raise HTTPException(503,"OIDC audience is not configured")

    def _validate_lab_request(request: Request, token: str) -> dict:
        claims=jwt_decode(token)
        if not claims: raise HTTPException(401,"Invalid identity token")
        if not DEMO: raise HTTPException(401,"Local lab tokens are demo-only")
        sid=claims.get("sid")
        # The shared legacy session database is authoritative. Never trust a
        # process-local cache alone: logout/revocation in another worker must
        # invalidate this token immediately.
        try:
            with closing(sqlite3.connect(DB_FILE,timeout=2)) as c:
                try:
                    row=c.execute("SELECT user,device,location,expires,revoked,pop_key,mfa_at FROM sessions WHERE sid=?",(sid,)).fetchone()
                except sqlite3.OperationalError:
                    row=None
        except sqlite3.Error:
            row=None
        now=time.time()
        if not row or row[4] or row[3] is None or float(row[3])<=now:
            raise HTTPException(401,"Session expired or revoked")
        try:
            key=_derive_session_key(sid,row[5] or "")
            absolute_exp=float(row[3])
            token_exp=float(claims.get("exp",0))
            mfa_at=float(row[6]) if row[6] is not None else 0.0
        except (ValueError,TypeError,OverflowError):
            raise HTTPException(401,"Invalid or legacy session key")
        sess={"user":row[0],"device":row[1],"location":row[2],
              "exp":min(token_exp,absolute_exp),"abs_exp":absolute_exp,
              "mfa_at":mfa_at,"key":key,"created":0.0}
        if sess["exp"]<=now or claims.get("sub")!=row[0] or claims.get("dev")!=row[1]:
            raise HTTPException(401,"Session expired or subject binding failed")
        dev=request.headers.get("x-device-id")
        if dev is not None and not re.fullmatch(r"[a-z0-9-]{1,64}",dev): raise HTTPException(400,"invalid device id")
        if dev!=sess.get("device"): raise HTTPException(401,"Device binding failed")
        if not hmac.compare_digest(str(claims.get("cnf","")),sha_bytes(sess.get("key",b""))): raise HTTPException(401,"Proof-of-possession binding failed")
        try:
            ts=float(request.headers.get("x-device-timestamp","")); nonce=request.headers.get("x-device-nonce",""); proof=request.headers.get("x-device-proof","")
            declared=request.headers.get("x-content-sha256","")
            if not PROOF_NONCE_RE.fullmatch(nonce) or not PROOF_DIGEST_RE.fullmatch(declared) or not math.isfinite(ts) or abs(time.time()-ts)>30: raise ValueError
            # Full request target exactly as received (raw path + raw query string), not the decoded route path.
            raw_path=request.scope.get("raw_path") or request.url.path.encode()
            qs=request.scope.get("query_string") or b""
            target=raw_path.decode("latin-1")+("?"+qs.decode("latin-1") if qs else "")
            expected=hmac.new(sess["key"],proof_message(request.method,target,declared,ts,nonce),hashlib.sha256).hexdigest()
            if not hmac.compare_digest(proof,expected): raise ValueError
            if request.headers.get("content-length","0").strip() in ("","0") and request.headers.get("transfer-encoding") is None:
                if declared!=EMPTY_SHA256: raise ValueError      # no body sent, so the signed digest must be the empty digest
            request.state.declared_body_sha=declared
            nonce_result=_enterprise_accept_replay_nonce("proof",sid,nonce,time.time(),35,PROOF_NONCE_LIMIT)
            if nonce_result is None: raise HTTPException(429,"Device proof nonce capacity reached")
            if not nonce_result: raise ValueError
        except RuntimeError as exc: raise HTTPException(503,"Replay protection unavailable") from exc
        except (ValueError,TypeError): raise HTTPException(401,"Device proof required")
        # Refresh the process-local cache only after checking durable revocation.
        with LOCK:
            cached=SESSIONS.get(sid)
            if cached is not None:
                cached.update(sess)
                sess=cached
        user=USERS.get(claims.get("sub"))
        if not user: raise HTTPException(401,"Unknown local identity")
        return {"sub":claims["sub"],"preferred_username":claims["sub"],"realm_access":{"roles":[user.get("role","user")]},"amr":["pwd","otp"],"auth_time":int(sess.get("mfa_at",0) or 0)}

    def _enterprise_check_body(request, raw: bytes):
        """Bind the signed X-Content-SHA256 to the bytes actually received (local device-proof sessions only)."""
        declared=getattr(request.state,"declared_body_sha",None)
        if declared is not None and not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),declared):
            raise HTTPException(401,"Request body does not match signed digest")

    async def enterprise_signed_body(request: Request):
        """Verify a local session's signed body digest before a mutating handler runs.

        OIDC bearer tokens do not set ``declared_body_sha`` because production OIDC
        device binding is not implemented; that limitation is documented separately.
        ``Request.body()`` is cached by Starlette, so typed-body handlers can safely
        use this dependency even after FastAPI has parsed their Pydantic model.
        """
        raw = await request.body()
        _enterprise_check_body(request, raw)

    def enterprise_identity(request: Request, authorization: str | None = Header(default=None)) -> dict:
        token=_enterprise_bearer(authorization)
        if token:
            try:
                if OIDC_ALLOW_LOCAL and DEMO:
                    try:
                        alg=pyjwt.get_unverified_header(token).get("alg")
                    except Exception: alg=None
                    if alg=="HS256": return _validate_lab_request(request,token)
                identity=_enterprise_oidc(token)
                db=EnterpriseSession()
                try:
                    u=enterprise_sync_user(db,identity)
                    if not u.enabled: raise HTTPException(403,"Identity disabled")
                finally: db.close()
                return identity
            except HTTPException: raise
            except PyJWKClientConnectionError as exc:
                logger.warning("OIDC/JWKS unavailable: %s",exc)
                raise HTTPException(503,"Identity provider unavailable")
            except Exception as exc:
                logger.warning("OIDC validation failed: %s",exc)
                if OIDC_REQUIRED or not OIDC_ALLOW_LOCAL: raise HTTPException(401,"Invalid identity token")
        if OIDC_REQUIRED and not OIDC_ALLOW_LOCAL: raise HTTPException(401,"Bearer token required")
        if not OIDC_ALLOW_LOCAL or not DEMO: raise HTTPException(401,"Bearer token required")
        if not token: raise HTTPException(401,"Bearer token required")
        return _validate_lab_request(request,token)

    def enterprise_roles(identity: dict) -> list[str]:
        out = set((identity.get("realm_access") or {}).get("roles", []) or [])
        own_client = os.environ.get("KEYCLOAK_CLIENT_ID", "ztna")
        client_roles = (identity.get("resource_access") or {}).get(own_client, {})
        out.update(client_roles.get("roles", []) or [])
        return sorted(str(x) for x in out)

    def enterprise_mfa(identity: dict) -> bool:
        acr = str(identity.get("acr", "")).lower()
        amr = identity.get("amr", [])
        if isinstance(amr, str): amr = [amr]
        amr = {str(x).lower() for x in amr}
        return acr in {"2","mfa","otp"} or bool({"mfa","otp"} & amr)

    def enterprise_device_score(p: EnterpriseDevicePosture) -> float:
        score = 100.0
        if not p.compliant: score -= 30
        if not p.encrypted_disk: score -= 20
        if not p.firewall_enabled: score -= 20
        if not p.antivirus_enabled: score -= 20
        if not p.agent_version: score -= 5
        return max(0, min(100, score))

    _ENTERPRISE_USER_CACHE={}
    _ENTERPRISE_USER_CACHE_LOCK=threading.RLock()
    def enterprise_sync_user(db: Session, identity: dict) -> EUser:
        subject = identity.get("sub")
        if not subject: raise HTTPException(401, "OIDC subject missing")
        with _ENTERPRISE_USER_CACHE_LOCK:
            cached=_ENTERPRISE_USER_CACHE.get(subject)
        if cached:
            u=db.get(EUser,cached)
            if u: return u
        u = db.query(EUser).filter(EUser.subject == subject).first()
        if not u:
            u = EUser(subject=subject, username=identity.get("preferred_username"), email=identity.get("email"), enabled=True)
            db.add(u)
            try: db.commit(); db.refresh(u)
            except IntegrityError:
                db.rollback(); u=db.query(EUser).filter(EUser.subject==subject).first()
                if not u: raise HTTPException(503,"Identity synchronization race")
        with _ENTERPRISE_USER_CACHE_LOCK: _ENTERPRISE_USER_CACHE[subject]=u.id
        return u

    def enterprise_client_ip(request: Request) -> str:
        peer=request.client.host if request.client else "unknown"
        try: peer_ip=ipaddress.ip_address(peer)
        except ValueError: peer_ip=None
        if peer_ip and any(peer_ip in n for n in TRUSTED_PROXY_NETS):
            forwarded=request.headers.get("x-forwarded-for")
            if forwarded:
                vals=[x.strip() for x in forwarded.split(",") if x.strip()]
                for value in reversed(vals):
                    try:
                        candidate=ipaddress.ip_address(value)
                        if not any(candidate in n for n in TRUSTED_PROXY_NETS): return str(candidate)[:64]
                    except ValueError: continue
        return peer

    class EnterpriseAnchorTamper(RuntimeError): pass
    # Process-wide fail-closed flag: set on proven anchor tamper/rollback, cleared only by a restart whose
    # reconcile step validates the DB chain and anchor prefix. _ENT_ANCHOR_LAST is the last checkpoint this process
    # wrote; after a transient anchor I/O outage it is the exact checkpoint the next update must find on disk.
    # "pending" is set (to the (count, hash) that failed to publish) when the external write fails AFTER the DB commit.
    # While it is set, no further sensitive write is allowed until _enterprise_resolve_pending_anchor() succeeds.
    _ENT_ANCHOR_STATE={"degraded":None,"last":None,"pending":None}
    _ENT_PENDING_LOCK=threading.Lock()
    # Serializes checkpoint file I/O and in-process checkpoint state. DB transaction
    # locks are always acquired before this lock; no DB writes occur while publishing it.
    _ENT_EXTERNAL_ANCHOR_IO_LOCK=threading.RLock()

    def _enterprise_validate_local_anchor(anchor, row_count, tail_hash, *, check_process_checkpoint=True):
        """Validate the local checkpoint without repairing it; a mismatch is evidence and fails closed."""
        entries=anchor.entries; last_hash=anchor.last_hash
        if type(entries) is not int or entries<0:
            raise EnterpriseAnchorTamper("enterprise local audit anchor entry count is invalid")
        if (not isinstance(last_hash,str) or not isinstance(anchor.mac,str)
                or not hmac.compare_digest(anchor.mac,_enterprise_anchor_mac(entries,last_hash))):
            raise EnterpriseAnchorTamper("enterprise local audit anchor MAC is invalid")
        if entries!=row_count:
            raise EnterpriseAnchorTamper(f"enterprise local audit anchor count {entries} != {row_count} audit rows")
        if not hmac.compare_digest(last_hash,tail_hash):
            raise EnterpriseAnchorTamper("enterprise local audit anchor hash does not match the audit chain tail")
        last=_ENT_ANCHOR_STATE["last"]
        if check_process_checkpoint and last is not None and (last[0]!=entries or not hmac.compare_digest(last[1],last_hash)):
            raise EnterpriseAnchorTamper("enterprise local audit anchor does not match the last verified checkpoint")

    def _enterprise_resolve_pending_anchor(*, acknowledge=True):
        """Recover from a transient external-anchor outage. Streams and verifies the committed DB audit chain and the
        local anchor, then repairs the external checkpoint only if it is exactly one entry behind (the reconcile rules).
        Raises (caller answers 503) if any step fails; ``pending`` stays set so the next write retries recovery."""
        with _ENT_PENDING_LOCK:
            if not _ENT_ANCHOR_STATE["pending"]: return
            checkpoint=_enterprise_reconcile_external_anchor(acknowledge=acknowledge)
            with _ENT_EXTERNAL_ANCHOR_IO_LOCK:
                current=_ENT_ANCHOR_STATE.get("last")
                if current is None or checkpoint[0]>=current[0]:
                    _ENT_ANCHOR_STATE["last"]=checkpoint
                _ENT_ANCHOR_STATE["pending"]=None
            logger.warning("enterprise audit external anchor reconciled after outage at entry %s",checkpoint[0])

    def _enterprise_anchor_mac(c,h):
        return hmac.new(ENTERPRISE_AUDIT_SECRET.encode(),f"{c}:{h}".encode(),hashlib.sha256).hexdigest()

    def _enterprise_external_anchor_read():
        """Return (count, hash) of the external anchor, None if the file is absent; raise EnterpriseAnchorTamper if invalid."""
        path=ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE
        if not os.path.exists(path): return None
        try:
            parts=Path(path).read_text(encoding="ascii").strip().split(":")
            if len(parts)!=3: raise ValueError("malformed anchor")
            count,h,m=int(parts[0]),parts[1],parts[2]
            if count<0 or not hmac.compare_digest(m,_enterprise_anchor_mac(count,h)): raise ValueError("invalid anchor MAC")
            return count,h
        except Exception as exc:
            raise EnterpriseAnchorTamper(f"enterprise audit external anchor invalid; preserved for investigation, reconciliation required: {exc}") from exc

    def _enterprise_external_anchor_verify(previous):
        """Ordinary-append rule: the anchor must be EXACTLY the expected previous checkpoint (count and hash).
        Read-only; used both before committing a mutation and before advancing the anchor."""
        cur=_enterprise_external_anchor_read()
        if cur is None:
            if previous[0]>0: raise EnterpriseAnchorTamper("enterprise audit external anchor missing while audit rows exist; reconciliation required")
            return
        if cur[0]!=previous[0]:
            raise EnterpriseAnchorTamper(f"enterprise audit external anchor count {cur[0]} != expected previous {previous[0]} (rollback or gap)")
        if not hmac.compare_digest(cur[1],previous[1]):
            raise EnterpriseAnchorTamper("enterprise audit external anchor does not match the expected previous hash")

    def _enterprise_external_anchor_update(entries,last_hash,previous=None):
        """Advance the external checkpoint only from a verified predecessor.

        Callers must establish the DB-chain checkpoint before invoking this function.
        A valid but older checkpoint is not overwritten unless a durable, matching
        outbox intent has already been validated by the streaming verifier.
        """
        with _ENT_EXTERNAL_ANCHOR_IO_LOCK:
            path=ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE
            Path(path).parent.mkdir(parents=True,exist_ok=True)
            cur=_enterprise_external_anchor_read()      # raises on malformed / bad MAC; leave evidence intact
            if cur is not None:
                if entries<cur[0]: raise EnterpriseAnchorTamper("enterprise audit external anchor is ahead of requested checkpoint")
                if entries==cur[0]:
                    if hmac.compare_digest(cur[1],last_hash): return
                    raise EnterpriseAnchorTamper("enterprise audit external anchor same-count hash mismatch")
            if previous is not None: _enterprise_external_anchor_verify(previous)
            mac=_enterprise_anchor_mac(entries,last_hash); tmp=path+f".tmp.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}"
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                with os.fdopen(fd,"w",encoding="ascii") as f: f.write(f"{entries}:{last_hash}:{mac}"); f.flush(); os.fsync(f.fileno())
                os.replace(tmp,path); _fsync_dir(path)
            except BaseException:
                try: os.unlink(tmp)
                except OSError: pass
                raise

    def enterprise_audit(db: Session, *, identity: dict | None, request: Request, resource: str | None, action: str, decision: str | None, risk: float | None, event_type: str, details: dict):
        """Commit a business mutation and its audit row in one DB transaction.

        Mutating handlers must flush, not commit, before calling this function.
        SQLite write transactions and the PostgreSQL audit-lock row serialize chain
        writers. Anchor and SIEM delivery intents are committed transactionally in
        durable outbox tables. The external anchor is published after commit and
        reconciled only when the outbox proves the exact checkpoint transition.
        """
        if _ENT_ANCHOR_STATE["degraded"]:
            db.rollback()   # discard any flushed, not-yet-audited mutation
            raise HTTPException(503, "audit anchor integrity failure; writes refused until verified reconciliation")
        if _ENT_ANCHOR_STATE["pending"]:
            # A committed audit row is not yet externally anchored. Verify + reconcile BEFORE accepting another write.
            try: _enterprise_resolve_pending_anchor(acknowledge=False)
            except Exception as exc:
                db.rollback()
                logger.error("enterprise audit anchor recovery failed; write refused (503) until it succeeds: %s", exc)
                raise HTTPException(503, "audit anchor update pending; writes refused until verified reconciliation")
        try:
            connection = db.connection()
            proxy = connection.connection
            driver = getattr(proxy, "driver_connection", proxy)
            sqlite_in_write_transaction = ENTERPRISE_DB_URL.startswith("sqlite") and bool(getattr(driver, "in_transaction", False))

            def append_and_commit():
                # The I/O lock spans chain verification, DB commit, and the decision about
                # the prior external checkpoint. SQLite/PostgreSQL transaction locks are
                # acquired before this lock, and no DB I/O is done by publishers while holding it.
                with _ENT_EXTERNAL_ANCHOR_IO_LOCK:
                    return _append_and_commit_locked()

            def _append_and_commit_locked():
                subject = identity.get("sub") if identity else None
                # Critical invariant: stream-verify EVERY committed audit record before any new audited mutation
                # is committed. A valid tail/anchor alone is insufficient if an older record was altered.
                chain = _enterprise_stream_verify_chain(
                    db, external_mode="reconcile", check_process_checkpoint=False
                )
                if not chain["ok"]:
                    raise EnterpriseAnchorTamper(
                        "enterprise audit chain verification failed: "
                        + str(chain.get("reason", "unknown integrity error"))
                    )
                previous_hash = chain["last_hash"]
                # A process checkpoint may lag by one entry only when the corresponding
                # durable anchor outbox row proves an append committed but publication was
                # interrupted. Any other in-memory disagreement is treated as tampering.
                process_checkpoint = _ENT_ANCHOR_STATE.get("last")
                external_checkpoint = chain.get("_external")
                if process_checkpoint is not None and process_checkpoint != (chain["entries"], previous_hash):
                    matching_pending = db.query(EAnchorOutbox).filter(
                        EAnchorOutbox.entries == chain["entries"],
                        EAnchorOutbox.previous_count == chain["entries"] - 1,
                        EAnchorOutbox.previous_hash == process_checkpoint[1],
                        EAnchorOutbox.last_hash == previous_hash,
                        EAnchorOutbox.delivered_at.is_(None),
                    ).first()
                    in_flight = (
                        external_checkpoint is not None
                        and process_checkpoint == external_checkpoint
                        and external_checkpoint[0] == chain["entries"] - 1
                        and matching_pending is not None
                    )
                    if not in_flight:
                        raise EnterpriseAnchorTamper("enterprise in-memory audit checkpoint disagrees with the verified chain")
                # If a committed event's anchor publication was interrupted, catch up the
                # external file while holding the I/O lock, and acknowledge pending rows in
                # this same transaction. Recovery is allowed only by the verifier above.
                if external_checkpoint is None or external_checkpoint[0] != chain["entries"]:
                    previous_checkpoint = external_checkpoint or (0, "GENESIS")
                    _enterprise_external_anchor_update(
                        chain["entries"], previous_hash, previous=previous_checkpoint
                    )
                    db.query(EAnchorOutbox).filter(
                        EAnchorOutbox.entries <= chain["entries"],
                        EAnchorOutbox.delivered_at.is_(None),
                    ).update({EAnchorOutbox.delivered_at: datetime.now(timezone.utc), EAnchorOutbox.last_error: None}, synchronize_session=False)
                    with _ENT_EXTERNAL_ANCHOR_IO_LOCK:
                        current = _ENT_ANCHOR_STATE.get("last")
                        if current is None or chain["entries"] >= current[0]:
                            _ENT_ANCHOR_STATE["last"] = (chain["entries"], previous_hash)
                # If a prior delivery succeeded but its acknowledgement write failed, an exact external
                # checkpoint proves the earlier entries are delivered; acknowledge them transactionally.
                db.query(EAnchorOutbox).filter(
                    EAnchorOutbox.entries <= chain["entries"],
                    EAnchorOutbox.delivered_at.is_(None),
                ).update({EAnchorOutbox.delivered_at: datetime.now(timezone.utc), EAnchorOutbox.last_error: None}, synchronize_session=False)
                anchor = db.query(EAuditAnchor).filter(EAuditAnchor.id == 1).one()
                event_id = uuid.uuid4().hex
                timestamp_iso = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
                timestamp = datetime.fromisoformat(timestamp_iso.replace("Z", "+00:00"))
                raw_device_id = request.headers.get("x-device-id")
                try:
                    device_id = enterprise_device_id(raw_device_id)
                except HTTPException:
                    device_id = None
                event = {
                    "event_id": event_id, "timestamp": timestamp_iso, "subject": subject,
                    "source_ip": enterprise_client_ip(request), "device_id": device_id,
                    "resource": resource, "action": action, "decision": decision,
                    "risk_score": float(risk) if risk is not None else None,
                    "event_type": event_type, "details": details,
                    "previous_hash": previous_hash,
                }
                payload = _canonical_enterprise_event(event)
                event_hash = hmac.new(
                    ENTERPRISE_AUDIT_SECRET.encode(), previous_hash.encode() + b"|" + payload,
                    hashlib.sha256,
                ).hexdigest()
                db.add(EAudit(
                    event_id=event_id, timestamp=timestamp, timestamp_iso=timestamp_iso,
                    subject=subject, source_ip=event["source_ip"], device_id=device_id,
                    resource=resource, action=action, decision=decision,
                    risk_score=event["risk_score"], event_type=event_type,
                    details=json.dumps(details, default=str), previous_hash=previous_hash,
                    event_hash=event_hash,
                ))
                durable_event = {**event, "event_hash": event_hash}
                # Record the expected external checkpoint in the SAME transaction as the event and local anchor.
                # A valid one-entry-lag can only be repaired after restart if this committed intent exists.
                db.add(EAnchorOutbox(
                    event_id=event_id, previous_count=chain["entries"],
                    previous_hash=previous_hash, entries=chain["entries"] + 1,
                    last_hash=event_hash,
                ))
                # SIEM/syslog delivery is also durable and at-least-once; the worker is only a dispatcher.
                payload = json.dumps(durable_event, default=str, separators=(",", ":"))
                if SIEM_URL:
                    db.add(EDeliveryOutbox(event_id=event_id, destination="siem", payload=payload,
                                           next_attempt_at=time.time()))
                if SYSLOG_HOST:
                    db.add(EDeliveryOutbox(event_id=event_id, destination="syslog", payload=payload,
                                           next_attempt_at=time.time()))
                # Fail closed BEFORE committing: the external checkpoint must be exactly the expected previous one
                # (the last checkpoint this process wrote, else the DB's current count/hash). On mismatch the pending
                # mutation and audit row are rolled back by the caller below.
                _enterprise_external_anchor_verify((chain["entries"], previous_hash))
                anchor.entries = int(anchor.entries or 0) + 1
                anchor.last_hash = event_hash
                anchor.mac = hmac.new(
                    ENTERPRISE_AUDIT_SECRET.encode(),
                    f"{anchor.entries}:{anchor.last_hash}".encode(), hashlib.sha256,
                ).hexdigest()
                entries, last_hash = anchor.entries, anchor.last_hash
                db.commit()
                return {**event, "event_hash": event_hash}, entries, last_hash

            if ENTERPRISE_DB_URL.startswith("sqlite"):
                if sqlite_in_write_transaction:
                    # A flushed mutation already owns the SQLite writer lock. Don't
                    # acquire the process lock here: an audit-only request may hold
                    # it while waiting for this writer, causing a lock-order deadlock.
                    result, entries, last_hash = append_and_commit()
                else:
                    with ENTERPRISE_AUDIT_LOCK:
                        if not bool(getattr(driver, "in_transaction", False)):
                            connection.exec_driver_sql("BEGIN IMMEDIATE")
                        result, entries, last_hash = append_and_commit()
            else:
                with ENTERPRISE_AUDIT_LOCK:
                    db.query(EAuditLock).filter(EAuditLock.id == 1).with_for_update().one()
                    result, entries, last_hash = append_and_commit()
        except EnterpriseAnchorTamper as exc:
            db.rollback()
            _ENT_ANCHOR_STATE["degraded"]=str(exc)
            logger.critical("enterprise audit chain/anchor integrity TAMPER detected before commit; mutation refused, fail-closed: %s", exc)
            raise HTTPException(503, "audit anchor integrity failure; writes refused until verified reconciliation")
        except Exception:
            db.rollback()
            raise

        try:
            with _ENT_EXTERNAL_ANCHOR_IO_LOCK:
                expected_prev=_ENT_ANCHOR_STATE["last"] or (entries-1, result["previous_hash"])
                _enterprise_external_anchor_update(entries, last_hash, expected_prev)
                current=_ENT_ANCHOR_STATE.get("last")
                if current is None or entries>=current[0]:
                    _ENT_ANCHOR_STATE["last"]=(entries, last_hash)
            try:
                with EnterpriseSession() as ack_db:
                    ack_db.query(EAnchorOutbox).filter(
                        EAnchorOutbox.entries <= entries,
                        EAnchorOutbox.delivered_at.is_(None),
                    ).update({EAnchorOutbox.delivered_at: datetime.now(timezone.utc), EAnchorOutbox.last_error: None}, synchronize_session=False)
                    ack_db.commit()
            except Exception:
                # External checkpoint succeeded; an unacknowledged outbox row is safe to reconcile idempotently.
                logger.exception("external anchor updated, but durable outbox acknowledgement failed; reconciliation will retry")
        except EnterpriseAnchorTamper as exc:
            # Another request may have committed and published a later, valid checkpoint first.
            # Treat that as an idempotently superseded write only if a full chain verification proves
            # the external anchor matches the current DB tail. Never infer success from counter alone.
            latest = None
            try:
                with EnterpriseSession() as check_db:
                    latest = _enterprise_stream_verify_chain(
                        check_db, external_mode="exact", check_process_checkpoint=False
                    )
            except Exception:
                latest = None
            if latest and latest.get("ok") and latest["entries"] > entries:
                with _ENT_EXTERNAL_ANCHOR_IO_LOCK:
                    current=_ENT_ANCHOR_STATE.get("last")
                    if current is None or latest["entries"]>=current[0]:
                        _ENT_ANCHOR_STATE["last"]=(latest["entries"],latest["last_hash"])
                try:
                    with EnterpriseSession() as ack_db:
                        ack_db.query(EAnchorOutbox).filter(
                            EAnchorOutbox.entries <= latest["entries"],
                            EAnchorOutbox.delivered_at.is_(None),
                        ).update({EAnchorOutbox.delivered_at: datetime.now(timezone.utc), EAnchorOutbox.last_error: None}, synchronize_session=False)
                        ack_db.commit()
                except Exception:
                    logger.exception("superseded external anchor outbox acknowledgement failed")
                logger.info("audit checkpoint %s was superseded by already-verified checkpoint %s", entries, latest["entries"])
            else:
                _ENT_ANCHOR_STATE["degraded"]=str(exc)
                logger.critical("enterprise audit external anchor tampered between pre-commit check and update; fail-closed, anchor preserved: %s", exc, exc_info=True)
        except Exception:
            # Transient I/O outage: the row and its anchor intent are durable but the file checkpoint is not yet
            # published. Mark it pending for fast same-process refusal; after restart, the durable outbox drives the
            # same verified, one-step reconciliation. No sensitive write proceeds until reconciliation succeeds.
            _ENT_ANCHOR_STATE["pending"]=(entries, last_hash)
            logger.exception("enterprise audit committed but external anchor update failed; writes blocked until reconciliation")
        return result

    def _utc_dt(value):
        if value is None: return None
        if value.tzinfo is None: return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _canonical_enterprise_event(event: dict) -> bytes:
        e=dict(event)
        ts=e.get("timestamp")
        if isinstance(ts, datetime): ts=ts.astimezone(timezone.utc).isoformat(timespec="microseconds")
        elif isinstance(ts,str):
            try: ts=datetime.fromisoformat(ts.replace("Z","+00:00")).astimezone(timezone.utc).isoformat(timespec="microseconds")
            except ValueError: pass
        e["timestamp"]=ts
        risk=e.get("risk_score")
        e["risk_score"]=float(risk) if risk is not None else None
        return json.dumps(e,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str).encode()

    def _enterprise_stream_verify_chain(db: Session, *, external_mode="exact", check_process_checkpoint=False):
        """Stream-verify every enterprise audit row, local anchor and external checkpoint.

        ``external_mode='exact'`` is used before sensitive writes and by the audit
        verification endpoint: the external anchor must match the DB tail exactly.
        ``external_mode='reconcile'`` permits only a valid external checkpoint at the
        committed tail or exactly one row behind with a matching prefix hash. A
        missing external checkpoint is tolerated only for an empty genesis chain.

        Rows are fetched in bounded batches; the full log is never loaded into memory.
        The function is read-only and returns a structured failure report rather than
        silently repairing either anchor.
        """
        if external_mode not in {"exact", "reconcile"}:
            raise ValueError("invalid enterprise audit external verification mode")
        started = time.perf_counter()
        external = None
        try:
            external = _enterprise_external_anchor_read()
        except EnterpriseAnchorTamper as exc:
            return {"ok": False, "broken_at": 0, "entries": 0,
                    "external_anchor": True, "reason": str(exc),
                    "verify_seconds": time.perf_counter() - started}

        previous_hash = "GENESIS"
        count = 0
        external_prefix = "GENESIS" if external and external[0] == 0 else None
        try:
            query = db.query(EAudit).order_by(EAudit.id.asc()).yield_per(500)
            for row in query:
                try:
                    details = json.loads(row.details) if row.details else {}
                except (ValueError, TypeError):
                    details = row.details
                try:
                    risk_score = float(row.risk_score) if row.risk_score is not None else None
                    if risk_score is not None and not math.isfinite(risk_score):
                        raise ValueError("non-finite audit risk score")
                    event = {
                        "event_id": row.event_id,
                        "timestamp": row.timestamp_iso or (
                            _utc_dt(row.timestamp).isoformat(timespec="microseconds").replace("+00:00", "Z")
                            if row.timestamp else None
                        ),
                        "subject": row.subject, "source_ip": row.source_ip,
                        "device_id": row.device_id, "resource": row.resource,
                        "action": row.action, "decision": row.decision,
                        "risk_score": risk_score, "event_type": row.event_type,
                        "details": details, "previous_hash": row.previous_hash,
                    }
                    expected = hmac.new(
                        ENTERPRISE_AUDIT_SECRET.encode(),
                        previous_hash.encode() + b"|" + _canonical_enterprise_event(event),
                        hashlib.sha256,
                    ).hexdigest()
                except Exception as exc:
                    return {"ok": False, "broken_at": count, "entries": count + 1,
                            "reason": f"malformed audit record at entry {count}: {exc}",
                            "verify_seconds": time.perf_counter() - started}
                if row.previous_hash != previous_hash or not hmac.compare_digest(row.event_hash, expected):
                    return {"ok": False, "broken_at": count, "entries": count + 1,
                            "reason": f"audit chain hash or predecessor mismatch at entry {count}",
                            "verify_seconds": time.perf_counter() - started}
                previous_hash = row.event_hash
                count += 1
                if external is not None and count == external[0]:
                    external_prefix = previous_hash
        except Exception as exc:
            return {"ok": False, "broken_at": count, "entries": count,
                    "reason": f"audit chain could not be read: {type(exc).__name__}: {exc}",
                    "verify_seconds": time.perf_counter() - started}

        try:
            anchor = db.query(EAuditAnchor).filter(EAuditAnchor.id == 1).one_or_none()
            if anchor is None:
                return {"ok": False, "broken_at": count, "entries": count,
                        "anchor": True, "reason": "enterprise local audit anchor is missing",
                        "verify_seconds": time.perf_counter() - started}
            _enterprise_validate_local_anchor(
                anchor, count, previous_hash,
                check_process_checkpoint=check_process_checkpoint,
            )
        except Exception as exc:
            return {"ok": False, "broken_at": count, "entries": count,
                    "anchor": True, "reason": str(exc),
                    "verify_seconds": time.perf_counter() - started}

        if external_mode == "exact":
            if external is None:
                return {"ok": False, "broken_at": count, "entries": count,
                        "external_anchor": True, "reason": "enterprise external audit anchor is missing",
                        "verify_seconds": time.perf_counter() - started}
            if external[0] != count or not hmac.compare_digest(external[1], previous_hash):
                return {"ok": False, "broken_at": count, "entries": count,
                        "external_anchor": True,
                        "reason": "enterprise external audit anchor does not match the verified DB tail",
                        "verify_seconds": time.perf_counter() - started}
        else:
            if external is None:
                if count == 0:
                    pass  # Empty genesis may create its initial external checkpoint.
                else:
                    pending = db.query(EAnchorOutbox).filter(
                        EAnchorOutbox.entries == count,
                        EAnchorOutbox.previous_count == count - 1,
                        EAnchorOutbox.previous_hash == "GENESIS",
                        EAnchorOutbox.last_hash == previous_hash,
                        EAnchorOutbox.delivered_at.is_(None),
                    ).first() if count == 1 else None
                    if not pending:
                        return {"ok": False, "broken_at": count, "entries": count,
                                "external_anchor": True,
                                "reason": "external anchor missing without a matching durable genesis-to-first-entry outbox; refusing recovery",
                                "verify_seconds": time.perf_counter() - started}
            else:
                ext_count, ext_hash = external
                if ext_count == count and hmac.compare_digest(ext_hash, previous_hash):
                    pass
                elif ext_count == count - 1 and count > 0 and external_prefix is not None and hmac.compare_digest(ext_hash, external_prefix):
                    pending = db.query(EAnchorOutbox).filter(
                        EAnchorOutbox.entries == count,
                        EAnchorOutbox.previous_count == ext_count,
                        EAnchorOutbox.previous_hash == ext_hash,
                        EAnchorOutbox.last_hash == previous_hash,
                        EAnchorOutbox.delivered_at.is_(None),
                    ).first()
                    if not pending:
                        return {"ok": False, "broken_at": count, "entries": count,
                                "external_anchor": True,
                                "reason": "one-entry external anchor lag has no matching durable outbox intent; possible rollback",
                                "verify_seconds": time.perf_counter() - started}
                else:
                    return {"ok": False, "broken_at": count, "entries": count,
                            "external_anchor": True,
                            "reason": "enterprise external audit anchor is outside the verified recovery checkpoint",
                            "verify_seconds": time.perf_counter() - started}

        elapsed = time.perf_counter() - started
        _ENT_ANCHOR_STATE["last_verify_seconds"] = elapsed
        return {"ok": True, "entries": count, "last_hash": previous_hash,
                "_external": external, "verify_seconds": elapsed}

    def enterprise_device_id(value):
        if value is None or value == "": return None
        value=str(value)
        if not re.fullmatch(r"[a-z0-9-]{1,64}",value): raise HTTPException(400,"invalid device id")
        return value

    def enterprise_lookup_device(subject: str, device_id: str | None):
        if not device_id: return None
        db=EnterpriseSession()
        try: return db.query(EDevice).filter(EDevice.device_id==device_id,EDevice.subject==subject).first()
        finally: db.close()

    def enterprise_policy(db: Session, identity: dict, resource: str, device: EDevice | None):
        """Decision model (also in README): enabled rules for the resource, ordered by priority asc then id asc.
        For each rule in order:
          1. action not allow/deny -> DENY (fail closed).
          2. subject_pattern or role selector does not match -> skip.
          3. no device and ZTNA_REQUIRE_DEVICE=true -> skip (if nothing else terminates: DENY "no matching policy").
          4. DENY rule: no device -> DENY; stale posture -> DENY; score<min or risk>max, or unconditional (min=0,max=100) -> DENY;
             otherwise the conditional deny does NOT trigger and evaluation continues with later rules (intentional).
          5. ALLOW rule: stale posture, score<min or risk>max -> skip; require_mfa without fresh MFA -> STEP_UP (terminal);
             otherwise ALLOW (terminal).
          6. no terminal rule -> DENY "no matching policy".
        """
        resource=enterprise_resource_name(resource)
        if resource is None: return "deny",None,"unknown resource"
        policies=db.query(EPolicy).filter(EPolicy.resource==resource,EPolicy.enabled==True).order_by(EPolicy.priority.asc(),EPolicy.id.asc()).all()
        roles=enterprise_roles(identity); subject=identity.get("sub","")
        require_device=os.environ.get("ZTNA_REQUIRE_DEVICE","true").lower()=="true"
        stale=False; device_score=0.0; risk_score=100.0
        if device is not None:
            last_seen=_utc_dt(device.last_seen)
            stale=ENTERPRISE_POSTURE_TTL>0 and (not last_seen or (datetime.now(timezone.utc)-last_seen).total_seconds()>ENTERPRISE_POSTURE_TTL)
            risk_score=float(device.risk_score if device.risk_score is not None else 100.0)
            device_score=100.0-risk_score
        for p in policies:
            action=(p.action or "").strip().lower()
            if action not in {"allow","deny"}: return "deny",p,"invalid policy action"
            if p.subject_pattern and not fnmatch.fnmatchcase(subject,p.subject_pattern): continue
            if p.role and p.role not in roles: continue
            if device is None and require_device: continue
            if action=="deny":
                if device is None: return "deny",p,"policy denied: device required"
                bad_score=device_score < float(p.min_device_score)
                bad_risk=risk_score > float(p.max_risk_score)
                if stale: return "deny",p,"policy denied: stale device posture"
                if (bad_score or bad_risk or (p.min_device_score==0 and p.max_risk_score==100)): return "deny",p,"policy denied"
                continue
            if device is None and require_device: continue
            if stale: continue
            if device_score < float(p.min_device_score) or risk_score > float(p.max_risk_score): continue
            if p.require_mfa:
                auth_time=identity.get("auth_time")
                try: mfa_age=time.time()-float(auth_time) if auth_time is not None and math.isfinite(float(auth_time)) else float("inf")
                except (TypeError,ValueError,OverflowError): mfa_age=float("inf")
                if not enterprise_mfa(identity) or mfa_age<0 or mfa_age>ENTERPRISE_MFA_MAX_AGE:
                    return "step_up",p,"MFA required or too old"
            return "allow",p,"policy allowed"
        return "deny",None,"no matching policy"

    RESOURCE_ALIASES={"wiki":"wiki","hr":"hr","hr-db":"hr","admin":"admin","admin-panel":"admin"}
    def enterprise_resource_name(resource):
        return RESOURCE_ALIASES.get(str(resource))

    def enterprise_upstream(resource: str) -> str:
        resource=enterprise_resource_name(resource)
        if resource is None: raise HTTPException(404, "Unknown resource")
        return {"wiki": UP_WIKI, "hr": UP_HR, "admin": UP_ADMIN}.get(resource, "")

    def enterprise_policy_json(p: EPolicy) -> dict:
        return {
            "id": p.id, "name": p.name, "priority": p.priority, "subject_pattern": p.subject_pattern,
            "role": p.role, "resource": p.resource, "action": p.action,
            "min_device_score": p.min_device_score, "max_risk_score": p.max_risk_score,
            "require_mfa": p.require_mfa, "enabled": p.enabled,
        }

    def enterprise_audit_json(e: EAudit) -> dict:
        try: details = json.loads(e.details) if e.details else {}
        except (TypeError, ValueError): details = e.details
        return {
            "id": e.id, "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "subject": e.subject, "source_ip": e.source_ip, "device_id": e.device_id,
            "resource": e.resource, "action": e.action, "decision": e.decision,
            "risk_score": e.risk_score, "event_type": e.event_type, "details": details,
            "previous_hash": e.previous_hash, "event_hash": e.event_hash,
        }

    def enterprise_ids_json(e: EIDSAlert) -> dict:
        try: raw = json.loads(e.raw_event)
        except (TypeError, ValueError): raw = e.raw_event
        return {
            "id": e.id, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "signature": e.signature, "category": e.category, "severity": e.severity,
            "src_ip": e.src_ip, "src_port": e.src_port, "dest_ip": e.dest_ip,
            "dest_port": e.dest_port, "raw_event": raw,
        }

    def enterprise_firewall_command(rule: EnterpriseFirewallRequest):
        try:
            ipaddress.ip_address(rule.source_ip)
            ipaddress.ip_address(rule.destination_ip)
        except ValueError:
            raise HTTPException(400, "Invalid source or destination IP")
        proto = rule.protocol.lower()
        if proto not in {"tcp", "udp", "icmp"}: raise HTTPException(400, "Unsupported protocol")
        if rule.action.lower() not in {"deny", "drop"}: raise HTTPException(400, "The managed firewall chain is deny-only; use deny/drop")
        src=ipaddress.ip_address(rule.source_ip); dst=ipaddress.ip_address(rule.destination_ip)
        if src.version!=dst.version: raise HTTPException(400,"source and destination address families must match")
        family="ip6tables" if src.version==6 else "iptables"
        cmd = [family, "-C", FIREWALL_CHAIN, "-i", FIREWALL_INTERFACE, "-s", rule.source_ip, "-d", rule.destination_ip]
        if proto != "icmp": cmd += ["-p", proto, "--dport", str(rule.destination_port)]
        else: cmd += ["-p", "icmp"]
        # The managed chain is deny-only; matching entries DROP, terminal RETURN
        # is installed by the enforcer after these rules.
        cmd += ["-j", "DROP"]
        if rule.remove: cmd[1]="-D"
        return cmd

    def enterprise_publish(event: dict):
        # Delivery is durable in EDeliveryOutbox as part of enterprise_audit's transaction.
        # This bounded queue is only a wake-up optimization; overflow never drops the event.
        try: ENTERPRISE_SIEM_QUEUE.put_nowait(str(event.get("event_id", "wake")))
        except queue.Full: pass

    @enterprise_app.get("/enterprise/health")
    def enterprise_health():
        return {"status":"ok"}

    @enterprise_app.get("/enterprise/ready")
    def enterprise_ready(db: Session = Depends(enterprise_db)):
        db.execute(sql_text("SELECT 1"))
        return {"status": "ready"}

    @enterprise_app.post("/enterprise/api/device/posture")
    def enterprise_posture(p: EnterpriseDevicePosture, request: Request, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db), _body_verified: None = Depends(enterprise_signed_body)):
        subject=identity["sub"]; d=db.query(EDevice).filter(EDevice.device_id==p.device_id).first()
        if d and d.subject!=subject: raise HTTPException(403,"Device belongs to another identity")
        if ENTERPRISE_REQUIRE_POSTURE_ATTESTATION:
            key=posture_key(p.device_id)
            if key is None: raise HTTPException(503,"No posture verification key configured")
            if not p.integrity_token: raise HTTPException(401,"Signed posture attestation required")
            ts=request.headers.get("x-posture-timestamp") or (str(p.posture_timestamp) if p.posture_timestamp is not None else None); nonce=request.headers.get("x-posture-nonce") or p.posture_nonce
            if not ts or not nonce: raise HTTPException(401,"Posture timestamp and nonce required")
            try: tsf=float(ts)
            except ValueError: raise HTTPException(401,"Invalid posture timestamp")
            now=time.time()
            if not math.isfinite(tsf) or abs(now-tsf)>60: raise HTTPException(401,"Posture attestation expired")
            checks={"os_updated":p.compliant,"disk_encrypted":p.encrypted_disk,"firewall":p.firewall_enabled,"antivirus":p.antivirus_enabled}
            expected=hmac.new(key,f"{p.device_id}|{ts}|{nonce}|{json.dumps(checks,sort_keys=True)}".encode(),hashlib.sha256).hexdigest()
            try: valid_integrity=hmac.compare_digest(expected.encode("ascii"),p.integrity_token.encode("utf-8"))
            except (TypeError,UnicodeError): valid_integrity=False
            if not valid_integrity: raise HTTPException(401,"Invalid posture attestation")
            try: nonce_result=_enterprise_accept_replay_nonce("posture",p.device_id,nonce,now,75,32)
            except RuntimeError as exc: raise HTTPException(503,"Posture replay protection unavailable") from exc
            if nonce_result is None: raise HTTPException(429,"Posture attestation rate limit reached")
            if not nonce_result: raise HTTPException(409,"Posture attestation replayed")
        score=enterprise_device_score(p)
        if d is None:
            d=EDevice(device_id=p.device_id,subject=subject,compliant=False,encrypted_disk=False,firewall_enabled=False,antivirus_enabled=False,risk_score=100)
            db.add(d)
        d.hostname,d.platform,d.os_version,d.agent_version=p.hostname,p.platform,p.os_version,p.agent_version
        d.compliant,d.encrypted_disk,d.firewall_enabled,d.antivirus_enabled=p.compliant,p.encrypted_disk,p.firewall_enabled,p.antivirus_enabled
        d.risk_score,d.last_seen=100-score,datetime.now(timezone.utc)
        try:
            db.flush()
            event=enterprise_audit(db,identity=identity,request=request,resource=None,action="device_posture",decision="accepted",risk=d.risk_score,event_type="posture_attestation",details={"device_id":p.device_id,"score":score})
        except Exception:
            db.rollback()
            logger.exception("posture update and audit failed; transaction rolled back")
            raise HTTPException(503,"Posture update and audit failed; change rolled back") from None
        enterprise_publish(event)
        return {"device_id":p.device_id,"posture_score":score,"risk_score":d.risk_score}

    @enterprise_app.get("/enterprise/api/access/evaluate")
    def enterprise_access(resource: str, request: Request, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db)):
        resource=enterprise_resource_name(resource)
        if resource is None: raise HTTPException(404,"Unknown resource")
        device_id = enterprise_device_id(request.headers.get("x-device-id"))
        device = db.query(EDevice).filter(EDevice.device_id == device_id, EDevice.subject == identity.get("sub")).first() if device_id else None
        decision, policy, reason = enterprise_policy(db, identity, resource, device)
        risk = device.risk_score if device else 100
        event = enterprise_audit(db, identity=identity, request=request, resource=resource, action="access_evaluate", decision=decision, risk=risk, event_type="access", details={"reason": reason, "policy_id": policy.id if policy else None, "device_id": device_id})
        enterprise_publish(event)
        return {"decision": decision, "reason": reason, "resource": resource, "subject": identity.get("sub"), "roles": enterprise_roles(identity), "device_id": device_id, "risk_score": risk, "policy_id": policy.id if policy else None}

    @enterprise_app.post("/enterprise/admin/policies")
    def enterprise_create_policy(policy: EnterprisePolicyCreate, request: Request, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db), _body_verified: None = Depends(enterprise_signed_body)):
        if not ({"admin", "ztna-admin"} & set(enterprise_roles(identity))): raise HTTPException(403, "Administrator role required")
        action=policy.action.strip().lower()
        if action not in {"allow","deny"}: raise HTTPException(400,"action must be allow or deny")
        if not all(math.isfinite(float(x)) and 0<=float(x)<=100 for x in (policy.min_device_score,policy.max_risk_score)): raise HTTPException(400,"policy scores must be finite and 0..100")
        if enterprise_resource_name(policy.resource) is None: raise HTTPException(400,"unknown resource")
        if db.query(EPolicy).filter(EPolicy.name == policy.name).first(): raise HTTPException(409, "Policy already exists")
        data=policy.model_dump() if hasattr(policy,"model_dump") else policy.dict(); data["action"]=action; data["resource"]=enterprise_resource_name(policy.resource)
        record = EPolicy(**data); db.add(record)
        try:
            db.flush()
            event = enterprise_audit(db, identity=identity, request=request, resource=policy.resource, action="policy_create", decision="allow", risk=None, event_type="administrative", details=(policy.model_dump() if hasattr(policy,"model_dump") else policy.dict()))
            db.refresh(record)
        except IntegrityError:
            db.rollback(); raise HTTPException(409,"Policy already exists")
        except Exception:
            db.rollback()
            logger.exception("policy create and audit failed; transaction rolled back")
            raise HTTPException(503,"Policy change and audit failed; change rolled back") from None
        enterprise_publish(event)
        return enterprise_policy_json(record)

    @enterprise_app.put("/enterprise/admin/policies/{policy_id}")
    def enterprise_update_policy(policy_id: int, policy: EnterprisePolicyCreate, request: Request, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db), _body_verified: None = Depends(enterprise_signed_body)):
        if not ({"admin","ztna-admin"} & set(enterprise_roles(identity))): raise HTTPException(403,"Administrator role required")
        action=policy.action.strip().lower()
        if action not in {"allow","deny"}: raise HTTPException(400,"action must be allow or deny")
        if not all(math.isfinite(float(x)) and 0<=float(x)<=100 for x in (policy.min_device_score,policy.max_risk_score)): raise HTTPException(400,"policy scores must be finite and 0..100")
        if enterprise_resource_name(policy.resource) is None: raise HTTPException(400,"unknown resource")
        record=db.get(EPolicy,policy_id)
        if not record: raise HTTPException(404,"Policy not found")
        conflict=db.query(EPolicy).filter(EPolicy.name==policy.name,EPolicy.id!=policy_id).first()
        if conflict: raise HTTPException(409,"Policy name already exists")
        data=(policy.model_dump() if hasattr(policy,"model_dump") else policy.dict()); data["action"]=action; data["resource"]=enterprise_resource_name(policy.resource)
        for k,v in data.items(): setattr(record,k,v)
        try:
            db.flush()
            event=enterprise_audit(db,identity=identity,request=request,resource=record.resource,action="policy_update",decision="allow",risk=None,event_type="administrative",details=enterprise_policy_json(record))
            db.refresh(record)
        except IntegrityError:
            db.rollback(); raise HTTPException(409,"Policy update conflict")
        except Exception:
            db.rollback()
            logger.exception("policy update and audit failed; transaction rolled back")
            raise HTTPException(503,"Policy change and audit failed; change rolled back") from None
        enterprise_publish(event)
        return enterprise_policy_json(record)

    @enterprise_app.delete("/enterprise/admin/policies/{policy_id}")
    def enterprise_delete_policy(policy_id: int, request: Request, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db), _body_verified: None = Depends(enterprise_signed_body)):
        if not ({"admin","ztna-admin"} & set(enterprise_roles(identity))): raise HTTPException(403,"Administrator role required")
        record=db.get(EPolicy,policy_id)
        if not record: raise HTTPException(404,"Policy not found")
        name=record.name; resource=record.resource
        db.delete(record)
        try:
            db.flush()
            event=enterprise_audit(db,identity=identity,request=request,resource=resource,action="policy_delete",decision="allow",risk=None,event_type="administrative",details={"policy_id":policy_id,"name":name})
        except Exception:
            db.rollback()
            logger.exception("policy delete and audit failed; transaction rolled back")
            raise HTTPException(503,"Policy change and audit failed; change rolled back") from None
        enterprise_publish(event)
        return {"deleted":True,"id":policy_id}

    @enterprise_app.get("/enterprise/admin/policies")
    def enterprise_list_policies(identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db)):
        if not ({"admin", "ztna-admin"} & set(enterprise_roles(identity))): raise HTTPException(403, "Administrator role required")
        return [enterprise_policy_json(p) for p in db.query(EPolicy).order_by(EPolicy.priority.asc(),EPolicy.id.asc()).all()]

    @enterprise_app.get("/enterprise/admin/audit")
    def enterprise_audit_api(limit: int = 100, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db)):
        if not ({"admin", "ztna-admin", "security-auditor"} & set(enterprise_roles(identity))): raise HTTPException(403, "Audit role required")
        return [enterprise_audit_json(e) for e in db.query(EAudit).order_by(EAudit.id.desc()).limit(max(1, min(limit, 1000))).all()]

    @enterprise_app.post("/enterprise/admin/firewall/apply")
    def enterprise_firewall(rule: EnterpriseFirewallRequest, request: Request, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db), _body_verified: None = Depends(enterprise_signed_body)):
        if not ({"admin", "ztna-admin"} & set(enterprise_roles(identity))):
            raise HTTPException(403, "Administrator role required")
        peer = enterprise_client_ip(request)
        if rule.action.lower() in {"deny", "drop"} and rule.source_ip == peer and not rule.remove:
            raise HTTPException(400, "refusing a rule that would lock out the current client")
        command = enterprise_firewall_command(rule)
        rule_data = rule.model_dump() if hasattr(rule, "model_dump") else rule.dict()

        # Firewall changes affect the host kernel and cannot be rolled back with the DB
        # transaction. Persist a verified intent event BEFORE invoking iptables/nft tools.
        intent = enterprise_audit(
            db, identity=identity, request=request, resource=None,
            action="firewall_apply_requested", decision="requested", risk=None,
            event_type="security", details={"rule": rule_data},
        )
        enterprise_publish(intent)
        if ZTNA_ENFORCE_FIREWALL and (
            _ENT_ANCHOR_STATE["degraded"] or _ENT_ANCHOR_STATE["pending"]
        ):
            # The intent row is durable, but don't perform an external side effect
            # unless the external checkpoint is healthy and current.
            raise HTTPException(503, "firewall action not applied: audit anchor requires reconciliation")

        result = {"enforced": False, "command": command, "reason": "ZTNA_ENFORCE_FIREWALL=false"}
        if ZTNA_ENFORCE_FIREWALL:
            try:
                if rule.ttl_seconds and not rule.remove:
                    raise RuntimeError("TTL firewall rules are disabled: expiry must be managed by a persistent external controller")
                family = command[0]
                # Create chain if absent; never auto-hook it into INPUT/FORWARD.
                subprocess.run([family, "-N", FIREWALL_CHAIN], capture_output=True, text=True, timeout=5, check=False)
                return_rule = [family, "-D", FIREWALL_CHAIN, "-j", "RETURN"]
                for _ in range(16):
                    if subprocess.run(return_rule, capture_output=True, text=True, timeout=5, check=False).returncode != 0:
                        break
                if subprocess.run([family, "-A", FIREWALL_CHAIN, "-j", "RETURN"], capture_output=True, text=True, timeout=5, check=False).returncode != 0:
                    raise RuntimeError("could not ensure terminal RETURN rule")
                check_cmd = list(command)
                cp_check = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5, check=False)
                if cp_check.returncode != 0 and not rule.remove:
                    apply_cmd = list(command)
                    apply_cmd[1] = "-I"
                    cp = subprocess.run(apply_cmd, capture_output=True, text=True, timeout=10, check=False)
                    if cp.returncode:
                        raise RuntimeError("firewall enforcement failed")
                elif cp_check.returncode != 0 and rule.remove:
                    raise RuntimeError("firewall rule not present")
                hooked = False
                for parent in ("INPUT", "FORWARD"):
                    hook = [family, "-C", parent, "-j", FIREWALL_CHAIN]
                    if subprocess.run(hook, capture_output=True, text=True, timeout=5, check=False).returncode == 0:
                        hooked = True
                result = {
                    "enforced": bool(hooked), "command": command, "chain_hooked": hooked,
                    "reason": None if hooked else "rule stored in deny-only chain; no parent-chain jump was installed automatically",
                }
            except Exception as exc:
                try:
                    error_event = enterprise_audit(
                        db, identity=identity, request=request, resource=None,
                        action="firewall_apply_result", decision="error", risk=None,
                        event_type="security", details={"error": str(exc), "rule": rule_data},
                    )
                    enterprise_publish(error_event)
                except Exception:
                    logger.critical("firewall action failed and its result could not be audited; intent event remains durable", exc_info=True)
                raise HTTPException(500, "firewall enforcement failed; request intent is audited") from None

        # Record the outcome separately: an intent event alone must never be mistaken
        # for proof that an external firewall rule was successfully applied.
        result_event = enterprise_audit(
            db, identity=identity, request=request, resource=None,
            action="firewall_apply_result", decision="allow" if result.get("enforced") else "simulated",
            risk=None, event_type="security", details={"rule": rule_data, "result": result},
        )
        enterprise_publish(result_event)
        return result

    @enterprise_app.get("/enterprise/admin/audit/verify")
    def enterprise_audit_verify(identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db)):
        if not ({"admin", "ztna-admin", "security-auditor"} & set(enterprise_roles(identity))):
            raise HTTPException(403, "Audit role required")
        # Same streaming verifier as the pre-mutation guard and startup reconciler.
        # Never repair from this read-only endpoint.
        result = _enterprise_stream_verify_chain(db, external_mode="exact", check_process_checkpoint=False)
        return {k: v for k, v in result.items() if not k.startswith("_")}

    @enterprise_app.post("/enterprise/admin/ids/ingest")
    async def enterprise_ids_ingest(request: Request, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db)):
        if not ({"admin", "ztna-admin"} & set(enterprise_roles(identity))):
            raise HTTPException(403, "Administrator role required")
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > 2 * 1024 * 1024:
                    raise HTTPException(413, "IDS payload too large")
            except ValueError:
                raise HTTPException(400, "Invalid Content-Length") from None
        raw = await request.body()
        if len(raw) > 2 * 1024 * 1024:
            raise HTTPException(413, "IDS payload too large")
        _enterprise_check_body(request, raw)
        try:
            payload = json.loads(raw)
        except Exception:
            raise HTTPException(400, "Invalid JSON") from None
        events = payload if isinstance(payload, list) else [payload]
        if len(events) > 5000 or any(not isinstance(e, dict) for e in events):
            raise HTTPException(400, "IDS events must be objects")

        def _ingest_and_audit(items):
            count = 0
            try:
                for event in items:
                    typ = event.get("event_type")
                    if typ not in {"alert", "anomaly", "drop"}:
                        continue
                    alert = event.get("alert") or {}
                    if not isinstance(alert, dict):
                        raise ValueError("Invalid IDS alert object")
                    try:
                        severity = int(alert.get("severity", 0) or 0)
                        src_port = alert.get("src_port", event.get("src_port"))
                        dest_port = alert.get("dest_port", event.get("dest_port"))
                        if not 0 <= severity <= 5:
                            raise ValueError
                        if src_port is not None:
                            src_port = int(src_port)
                            if not 0 <= src_port <= 65535:
                                raise ValueError
                        if dest_port is not None:
                            dest_port = int(dest_port)
                            if not 0 <= dest_port <= 65535:
                                raise ValueError
                        for ipkey in ("src_ip", "dest_ip"):
                            val = event.get(ipkey)
                            if val:
                                ipaddress.ip_address(str(val))
                    except (ValueError, TypeError):
                        raise ValueError("Invalid IDS severity, port or IP") from None
                    db.add(EIDSAlert(
                        signature=str(alert.get("signature", ""))[:1024],
                        category=str(alert.get("category", ""))[:255], severity=severity,
                        src_ip=str(event.get("src_ip", ""))[:64], src_port=src_port,
                        dest_ip=str(event.get("dest_ip", ""))[:64], dest_port=dest_port,
                        raw_event=json.dumps(event, default=str)[:MAX_BODY_SIZE],
                    ))
                    count += 1
                if not count:
                    db.rollback()
                    return 0, None
                # Flush alert records, but DO NOT commit. enterprise_audit runs the
                # complete streaming verifier and commits alerts + audit as one transaction.
                db.flush()
                audit_event = enterprise_audit(
                    db, identity=identity, request=request, resource=None,
                    action="ids_alert", decision="alert", risk=None,
                    event_type="ids", details={"count": count},
                )
                return count, audit_event
            except Exception:
                db.rollback()
                raise

        try:
            count, audit_event = await run_in_threadpool(_ingest_and_audit, events)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        except HTTPException:
            raise
        except Exception:
            logger.exception("IDS ingest and audit failed; transaction rolled back")
            raise HTTPException(503, "IDS ingest and audit failed; changes rolled back") from None
        if audit_event:
            enterprise_publish(audit_event)
        return {"ingested": count}

    @enterprise_app.get("/enterprise/admin/ids")
    def enterprise_ids(limit: int = 100, identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db)):
        if not ({"admin", "ztna-admin", "security-auditor"} & set(enterprise_roles(identity))): raise HTTPException(403, "Security role required")
        return [enterprise_ids_json(e) for e in db.query(EIDSAlert).order_by(EIDSAlert.id.desc()).limit(max(1, min(limit, 1000))).all()]

    def _enterprise_policy_threadsafe(identity, resource, device_id):
        dbx=EnterpriseSession()
        try:
            device=dbx.query(EDevice).filter(EDevice.device_id==device_id,EDevice.subject==identity.get("sub")).first() if device_id else None
            return enterprise_policy(dbx,identity,resource,device)
        finally: dbx.close()

    def _enterprise_audit_threadsafe(**kwargs):
        dbx=EnterpriseSession()
        try: return enterprise_audit(dbx,**kwargs)
        finally: dbx.close()

    @enterprise_app.api_route("/enterprise/resource/{resource}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    @enterprise_app.api_route("/enterprise/resource/{resource}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def enterprise_proxy(resource: str, request: Request, path: str = "", identity: dict = Depends(enterprise_identity), db: Session = Depends(enterprise_db)):
        resource=enterprise_resource_name(resource)
        if resource is None: raise HTTPException(404, "Unknown resource")
        # Starlette already decodes the route path. Reject traversal and URL
        # delimiters in each segment before safely re-encoding it upstream.
        raw_segments=path.split("/") if path else []
        if any(seg in {".",".."} or "\\" in seg or "?" in seg or "#" in seg or "\x00" in seg for seg in raw_segments):
            raise HTTPException(400,"Invalid upstream path")
        device_id = enterprise_device_id(request.headers.get("x-device-id"))
        device = await run_in_threadpool(enterprise_lookup_device, identity.get("sub",""), device_id)
        decision, policy, reason = await run_in_threadpool(_enterprise_policy_threadsafe, identity, resource, device_id)
        risk = device.risk_score if device else 100
        if decision != "allow":
            event = await run_in_threadpool(_enterprise_audit_threadsafe, identity=identity, request=request, resource=resource, action="resource_access", decision=decision, risk=risk, event_type="access", details={"reason": reason, "policy_id": policy.id if policy else None})
            enterprise_publish(event)
            if decision == "step_up": return JSONResponse({"error": "step_up_required", "message": "MFA is required"}, status_code=401, headers={"WWW-Authenticate": 'Bearer error="mfa_required"'})
            return JSONResponse({"error": "access_denied"}, status_code=403)
        # Audit the authorization decision BEFORE contacting the upstream. If the
        # audit store is unavailable, the request is refused rather than fail-open.
        event = await run_in_threadpool(_enterprise_audit_threadsafe, identity=identity, request=request, resource=resource, action="resource_access", decision="allow", risk=risk, event_type="access", details={"policy_id":policy.id if policy else None})
        enterprise_publish(event)
        upstream = enterprise_upstream(resource)
        if not upstream:
            return {"resource": resource, "subject": identity.get("sub"), "decision": "allow", "risk_score": risk, "simulated": True}
        content_length=request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length)>MAX_BODY_SIZE: raise HTTPException(413,"Request body too large")
            except ValueError: raise HTTPException(400,"Invalid Content-Length")
        async def limited_request_body():
            total=0
            async for chunk in request.stream():
                total+=len(chunk)
                if total>MAX_BODY_SIZE: raise HTTPException(413,"Request body too large")
                yield chunk
        # Starlette has already parsed the route path. Validate its segments and
        # re-encode them exactly once; do not decode already-decoded paths again.
        decoded_path=path
        if "\\" in decoded_path or any(part in {".",".."} for part in decoded_path.split("/")) or any(ord(ch)<32 for ch in decoded_path): raise HTTPException(400,"Invalid resource path")
        safe_path="/".join(quote(part,safe="-._~:@!$&'()*+,;=") for part in decoded_path.split("/"))
        target=upstream.rstrip("/")+"/"+safe_path.lstrip("/")
        if request.url.query: target += "?" + request.url.query
        allowed={"accept","accept-encoding","accept-language","content-type","user-agent","range","if-none-match","if-modified-since","content-length"}
        headers={k:v for k,v in request.headers.items() if k.lower() in allowed}
        headers.update({"x-ztna-subject": identity.get("sub", ""), "x-ztna-resource": resource, "x-ztna-policy": str(policy.id if policy else ""), "x-forwarded-for": enterprise_client_ip(request)})
        client=ENTERPRISE_HTTP_CLIENT
        if client is None: raise HTTPException(503,"Upstream client unavailable")
        stream_cm=None; upstream_response=None
        has_request_body=(request.method not in {"GET","HEAD","OPTIONS"} or content_length is not None or request.headers.get("transfer-encoding") is not None)
        request_body=None
        if has_request_body:
            # Buffer (bounded by MAX_BODY_SIZE) so the signed digest is verified BEFORE anything reaches the upstream.
            request_body=b"".join([chunk async for chunk in limited_request_body()])
            _enterprise_check_body(request,request_body)
        try:
            stream_cm=client.stream(request.method,target,headers=headers,content=request_body)
            upstream_response=await stream_cm.__aenter__()
            content_length=upstream_response.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length)>MAX_BODY_SIZE: raise HTTPException(502,"Upstream response too large")
                except ValueError: raise HTTPException(502,"Invalid upstream Content-Length")
            response_headers={k:v for k,v in upstream_response.headers.items() if k.lower() not in {"content-length","transfer-encoding","connection","content-encoding","upgrade","te","keep-alive","set-cookie","location","www-authenticate"}}
            async def limited_body():
                total=0
                try:
                    async for chunk in upstream_response.aiter_bytes():
                        total+=len(chunk)
                        if total>MAX_BODY_SIZE:
                            raise RuntimeError("upstream response exceeded configured body limit")
                        yield chunk
                finally:
                    if stream_cm is not None:
                        await stream_cm.__aexit__(None,None,None)
            return StreamingResponse(limited_body(),status_code=upstream_response.status_code,headers=response_headers,media_type=upstream_response.headers.get("content-type"))
        except httpx.RequestError:
            if stream_cm is not None:
                try: await stream_cm.__aexit__(None,None,None)
                except Exception: pass
            raise HTTPException(502, "Upstream resource unavailable")
        except Exception:
            if stream_cm is not None:
                try: await stream_cm.__aexit__(None,None,None)
                except Exception: pass
            raise

    SURICATA_OFFSET_FILE=SURICATA_EVE_FILE+".offset"
    def enterprise_ingest_suricata_once():
        if not os.path.exists(SURICATA_EVE_FILE): return 0
        db=EnterpriseSession(); count=0
        try:
            offset_row=db.query(EIngestOffset).filter(EIngestOffset.name==SURICATA_EVE_FILE).first()
            if offset_row is not None: offset=int(offset_row.offset)
            else:
                try:
                    raw_offset=Path(SURICATA_OFFSET_FILE).read_text(encoding="ascii").strip()
                    try: offset=int(raw_offset)
                    except ValueError: offset=int(json.loads(raw_offset).get("offset",0))
                except Exception: offset=0
            size=os.path.getsize(SURICATA_EVE_FILE)
            if offset>size: offset=0
            new_offset=offset
            with open(SURICATA_EVE_FILE,"rb") as fh:
                fh.seek(offset)
                while True:
                    line_start=fh.tell()
                    raw=fh.readline()
                    if not raw: break
                    if not raw.endswith(b"\n"):
                        # Leave a partial final record at the current offset for retry.
                        new_offset=line_start
                        break
                    new_offset=fh.tell()
                    try:
                        event=json.loads(raw.decode("utf-8")); typ=event.get("event_type")
                        if typ not in {"alert","anomaly","drop"}: continue
                        a=event.get("alert") or {}
                        sev=int(a.get("severity",0) or 0); srcp=event.get("src_port"); dstp=event.get("dest_port")
                        if not 0<=sev<=5: continue
                        if srcp is not None and not 0<=int(srcp)<=65535: continue
                        if dstp is not None and not 0<=int(dstp)<=65535: continue
                        if srcp is not None: srcp=int(srcp)
                        if dstp is not None: dstp=int(dstp)
                        db.add(EIDSAlert(signature=str(a.get("signature",""))[:1024],category=str(a.get("category",""))[:255],severity=sev,src_ip=str(event.get("src_ip",""))[:64],src_port=srcp,dest_ip=str(event.get("dest_ip",""))[:64],dest_port=dstp,raw_event=json.dumps(event,default=str)[:MAX_BODY_SIZE])); count+=1
                    except (ValueError,TypeError,UnicodeDecodeError):
                        # Invalid complete rows are deliberately skipped, and their offset advances.
                        continue
            # Persist offset and all alert rows in one DB transaction. A crash
            # after commit but before updating the human-readable mirror cannot re-ingest.
            if offset_row is None:
                offset_row=EIngestOffset(name=SURICATA_EVE_FILE,offset=new_offset); db.add(offset_row)
            else: offset_row.offset=new_offset
            db.commit()
            try: _atomic_json_replace(SURICATA_OFFSET_FILE,{"offset":new_offset})
            except Exception: logger.warning("Suricata offset mirror update failed; database offset remains authoritative")
        finally: db.close()
        return count


else:
    enterprise_app = None
    def enterprise_ingest_suricata_once(): return 0


def run_enterprise_api():
    workers=_env_int("WEB_CONCURRENCY",os.environ.get("UVICORN_WORKERS","1"),1,128)
    if workers>1:
        # Rate-limit caches are process-local and uvicorn.run() is given an app object (it cannot fork workers),
        # so a multi-worker setting could never have worked as configured. Fail clearly instead of ignoring it.
        raise SystemExit("WEB_CONCURRENCY/UVICORN_WORKERS > 1 is not supported: enterprise mode runs as a single process "
                         "(rate limits are process-local). Scale by running separate instances behind a load balancer with sticky routing, "
                         "or add a shared rate-limit backend first.")
    if not FASTAPI_AVAILABLE:
        raise SystemExit(f"Enterprise API dependencies are missing: {_enterprise_import_error}. Install: fastapi uvicorn httpx sqlalchemy PyJWT[crypto]")
    try:
        import uvicorn
    except ImportError:
        raise SystemExit("uvicorn is required for enterprise mode: pip install uvicorn")
    _configure_logging()
    host=os.environ.get("ZTNA_API_HOST",HOST_ENV); port=_env_int("ZTNA_API_PORT",PORT,1,65535)
    cert=os.environ.get("ZTNA_CERT"); key=os.environ.get("ZTNA_KEY"); ca=os.environ.get("ZTNA_CLIENT_CA")
    if not DEMO and (not cert or not key): raise SystemExit("production enterprise mode requires ZTNA_CERT and ZTNA_KEY")
    if not DEMO:
        try: __import__("cryptography")
        except ImportError: raise SystemExit("enterprise RS256 verification requires cryptography (install PyJWT[crypto])")
    if not DEMO and not OIDC_AUDIENCE: raise SystemExit("production enterprise mode requires OIDC_AUDIENCE")
    if not DEMO and (not ENTERPRISE_AUDIT_SECRET or len(ENTERPRISE_AUDIT_SECRET) < 32): raise SystemExit("enterprise mode requires AUDIT_SECRET of at least 32 characters")
    if DEMO: _ensure_enterprise_audit_secret()
    kwargs={"host":host,"port":port,"log_level":os.environ.get("LOG_LEVEL","info"),"proxy_headers":False}
    if cert and key:
        kwargs.update(ssl_certfile=cert,ssl_keyfile=key)
        if ca: kwargs.update(ssl_ca_certs=ca,ssl_cert_reqs=ssl.CERT_REQUIRED)
    uvicorn.run(enterprise_app,**kwargs)


def run_legacy_server():
    _configure_logging()
    global LAB_MAX_TRANSFER
    LAB_MAX_TRANSFER=_env_int("ZTNA_LAB_MAX_TRANSFER",16*1024*1024,1024,256*1024*1024)
    H.LAB_TRANSFERS=threading.BoundedSemaphore(_env_int("ZTNA_LAB_MAX_TRANSFERS",2,1,64))
    H.CONNECTIONS=threading.BoundedSemaphore(_env_int("ZTNA_MAX_CONNECTIONS",32,1,10000))
    H.timeout=float(os.environ.get("ZTNA_REQUEST_DEADLINE","15"))
    if not math.isfinite(H.timeout) or H.timeout<=0: raise SystemExit("ZTNA_REQUEST_DEADLINE must be positive and finite")
    # Validate production TLS before binding any listening socket.
    bind_host = HOST_ENV
    cert_file = os.environ.get("ZTNA_CERT")
    key_file = os.environ.get("ZTNA_KEY")
    if not DEMO and (not cert_file or not key_file):
        raise SystemExit("production server requires ZTNA_CERT and ZTNA_KEY")
    server_class = PooledHTTPServer6 if ":" in bind_host else PooledHTTPServer
    server = server_class((bind_host, PORT), H, max_workers=_env_int("ZTNA_MAX_CONNECTIONS",32,1,10000))
    if cert_file and key_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        ca = os.environ.get("ZTNA_CLIENT_CA")
        if ca:
            context.load_verify_locations(cafile=ca)
            context.verify_mode = ssl.CERT_REQUIRED
        server.ssl_context=context
    logger.info("Legacy ZTNA server listening on %s:%s", bind_host, PORT)
    previous_handlers = {}
    def _stop_server(*_):
        # shutdown() must run on a different thread than serve_forever().
        threading.Thread(target=server.shutdown, daemon=True, name="ztna-shutdown").start()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                previous_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, _stop_server)
            except (ValueError, OSError):
                pass  # non-main-thread embedding; caller owns signal handling
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        for sig, handler in previous_handlers.items():
            try: signal.signal(sig, handler)
            except (ValueError, OSError): pass



class PooledHTTPServer6(PooledHTTPServer):
    address_family = socket.AF_INET6

def add_user_cli(args):
    if len(args)!=2: raise SystemExit("usage: adduser USER ROLE (password is prompted securely)")
    username,role=args[0],args[1]
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}",username): raise SystemExit("invalid username")
    if role not in ROLES: raise SystemExit("role must be one of: "+", ".join(ROLES))
    import getpass
    password=getpass.getpass("Password: ")
    confirm=getpass.getpass("Confirm password: ")
    if not _ct_eq(password, confirm): raise SystemExit("passwords do not match")
    if len(password)<8: raise SystemExit("password must be at least 8 characters")
    path=os.path.join(DATA_DIR,"demo_users.json") if DEMO else USERS_FILE
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    if DEMO:
        _load_or_create_demo_users()  # preserve Alice/Bob/Carol before first adduser invocation
    with _file_lock(path):
        try:
            with open(path,encoding="utf-8") as f: users=json.load(f)
        except FileNotFoundError: users={}
        if not isinstance(users,dict): raise SystemExit("users file is corrupt")
        if username in users: raise SystemExit("user already exists")
        pwrec=_pw_record(password); secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        users[username]={"pw":pwrec,"role":role,"totp":secret}
        _atomic_json_replace(path,_encode_user_records(users))
    print(json.dumps({"user":username,"role":role,"totp_secret":secret,"users_file":path},indent=2))

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

# ============================================================
# Lab toolkit: DNS server, remote admin console, systemd unit
# (standalone: none of these touch the audit log, users or session state)
# ============================================================
_DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "ANY": 255}
_DNS_TYPE_NAMES = {v: k for k, v in _DNS_TYPES.items()}
_DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_DNS_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
DNS_MAX_RECORDS = 1000


def dns_norm_name(name):
    """Lower-case, strip the trailing dot and validate a DNS name (LDH + underscore, 63/253 length limits)."""
    n = str(name).strip().lower().rstrip(".")
    if not n or len(n) > 253 or not all(_DNS_LABEL_RE.match(label) for label in n.split(".")):
        raise ValueError(f"invalid DNS name: {str(name)[:80]!r}")
    return n


def dns_encode_name(name):
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_parse_name(buf, off, *, allow_pointers=True):
    """Parse a (possibly compressed) name at buf[off]; returns (name, offset just after it)."""
    labels, end, hops = [], None, 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if not allow_pointers or off + 1 >= len(buf):
                raise ValueError("bad compression pointer")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if end is None:
                end = off + 2
            hops += 1
            if hops > 16 or ptr >= len(buf):
                raise ValueError("bad compression pointer")
            off = ptr
            continue
        if ln & 0xC0:
            raise ValueError("bad label type")
        off += 1
        if off + ln > len(buf):
            raise ValueError("truncated label")
        labels.append(buf[off:off + ln].decode("ascii"))
        off += ln
        if sum(len(x) + 1 for x in labels) > 254:
            raise ValueError("name too long")
    return ".".join(labels).lower(), (end if end is not None else off)


class DnsRecords:
    """A/CNAME store persisted as JSON; one record per name. Edits from other processes (the `dns` CLI) are picked up live."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._sig = None
        self._table = {}
        self._checked = 0.0

    @staticmethod
    def validate(kind, name, value):
        kind = str(kind).upper()
        name = dns_norm_name(name)
        if kind == "A":
            ip = ipaddress.ip_address(str(value).strip())
            if ip.version != 4:
                raise ValueError("A record value must be an IPv4 address")
            value = str(ip)
        elif kind == "CNAME":
            value = dns_norm_name(value)
            if value == name:
                raise ValueError("a CNAME cannot point to itself")
        else:
            raise ValueError("record type must be A or CNAME")
        return kind, name, value

    def _read_file(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise ValueError(f"cannot read {self.path}: {exc}") from None
        items = raw.get("records") if isinstance(raw, dict) else None
        if not isinstance(items, list) or len(items) > DNS_MAX_RECORDS:
            raise ValueError(f"{self.path}: expected {{\"records\": [...]}} with at most {DNS_MAX_RECORDS} entries")
        table = {}
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{self.path}: record entries must be objects")
            kind, name, value = self.validate(item.get("type"), item.get("name"), item.get("value"))
            table[name] = (kind, value)
        return table

    def table(self, max_age=1.0):
        """Current {name: (type, value)} snapshot; the file is re-stat'ed at most once per max_age seconds."""
        now = time.monotonic()
        with self._lock:
            if now - self._checked >= max_age:
                self._checked = now
                try:
                    st = os.stat(self.path)
                    sig = (st.st_mtime_ns, st.st_size)
                except FileNotFoundError:
                    sig = None
                if sig != self._sig:
                    try:
                        self._table = self._read_file() if sig else {}
                        self._sig = sig
                    except ValueError as exc:
                        logger.error("DNS records not reloaded (keeping previous table): %s", exc)
                        self._sig = sig
            return self._table

    def _write(self, table):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        data = {"records": [{"type": k, "name": n, "value": v} for n, (k, v) in sorted(table.items())]}
        _atomic_json_replace(self.path, data)

    def add(self, kind, name, value):
        kind, name, value = self.validate(kind, name, value)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.path, timeout=10):
            table = self._read_file()
            if name not in table and len(table) >= DNS_MAX_RECORDS:
                raise ValueError(f"record limit reached ({DNS_MAX_RECORDS})")
            table[name] = (kind, value)
            self._write(table)
        self._checked = 0.0
        return kind, name, value

    def remove(self, name):
        name = dns_norm_name(name)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.path, timeout=10):
            table = self._read_file()
            existed = table.pop(name, None) is not None
            if existed:
                self._write(table)
        self._checked = 0.0
        return existed


class DnsQuery:
    __slots__ = ("raw", "txid", "flags", "opcode", "rd", "qname", "qtype", "qclass", "question")


def dns_parse_query(raw):
    """Return (DnsQuery or None, error rcode or None). (None, None) means drop silently (runt packet or a response)."""
    if len(raw) < 12:
        return None, None
    flags = struct.unpack("!H", raw[2:4])[0]
    if flags & 0x8000:
        return None, None
    q = DnsQuery()
    q.raw, q.txid, q.flags = raw, raw[:2], flags
    q.opcode, q.rd = (flags >> 11) & 0xF, bool(flags & 0x0100)
    q.qname = q.qtype = q.qclass = None
    q.question = b""
    if q.opcode != 0:
        return q, 4
    if struct.unpack("!H", raw[4:6])[0] != 1:
        return q, 1
    try:
        name, off = dns_parse_name(raw, 12, allow_pointers=False)
        if off + 4 > len(raw):
            raise ValueError("truncated question")
        qtype, qclass = struct.unpack("!HH", raw[off:off + 4])
    except (ValueError, struct.error):
        return q, 1
    q.qname, q.qtype, q.qclass, q.question = name, qtype, qclass, raw[12:off + 4]
    return q, None


def dns_response(q, rcode, *, ra=False, aa=False, tc=False, answers=b"", ancount=0):
    flags = 0x8000 | (q.opcode << 11) | (0x0400 if aa else 0) | (0x0200 if tc else 0) | (0x0100 if q.rd else 0) | (0x0080 if ra else 0) | rcode
    return q.txid + struct.pack("!HHHHH", flags, 1 if q.question else 0, ancount, 0, 0) + q.question + answers


def dns_local_answer(q, table, ttl, ra=False):
    """Authoritative answer for names in the lab table (CNAME chains followed), or None if the name is not ours."""
    if q.qname not in table:
        return None
    want_cname = q.qtype == _DNS_TYPES["CNAME"]
    chain, seen, name = [], set(), q.qname
    while len(chain) < 9:
        rec = table.get(name)
        if rec is None:
            break
        if name in seen:
            return dns_response(q, 2, ra=ra)  # CNAME loop -> SERVFAIL
        seen.add(name)
        chain.append((name, rec[0], rec[1]))
        if rec[0] != "CNAME" or want_cname:
            break
        name = rec[1]
    else:
        return dns_response(q, 2, ra=ra)      # chain too long -> SERVFAIL
    rrs = []
    for n, kind, value in chain:
        if kind == "CNAME":
            rtype, rdata = 5, dns_encode_name(value)
        elif q.qtype in (1, 255):
            rtype, rdata = 1, socket.inet_aton(value)
        else:
            continue                           # name exists, but not for this type: NOERROR/NODATA
        rrs.append(dns_encode_name(n) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata)
    resp = dns_response(q, 0, ra=ra, aa=True, answers=b"".join(rrs), ancount=len(rrs))
    return resp if len(resp) <= 512 else dns_response(q, 0, ra=ra, aa=True, tc=True)


def dns_parse_response(buf):
    """Decode a DNS response (A / AAAA / CNAME rdata understood; others are shown as hex)."""
    if len(buf) < 12:
        raise ValueError("short response")
    txid, flags, qd, an = struct.unpack("!HHHH", buf[:8])
    off = 12
    for _ in range(qd):
        _, off = dns_parse_name(buf, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = dns_parse_name(buf, off)
        if off + 10 > len(buf):
            raise ValueError("truncated record")
        rtype, _cls, ttl, rlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        if off + rlen > len(buf):
            raise ValueError("truncated rdata")
        rdata = buf[off:off + rlen]
        if rtype == 1 and rlen == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 28 and rlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            value, _ = dns_parse_name(buf, off)
        else:
            value = rdata.hex()
        answers.append({"name": name, "type": _DNS_TYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl, "value": value})
        off += rlen
    return {"txid": txid, "rcode": _DNS_RCODES.get(flags & 0xF, str(flags & 0xF)), "aa": bool(flags & 0x400),
            "tc": bool(flags & 0x200), "ra": bool(flags & 0x80), "answers": answers}


def _split_hostport(text, default_port):
    """Parse 'ip', 'ip:port', '[v6]:port' (IP literals only, so no surprise name resolution)."""
    t = str(text).strip()
    host, port = t, default_port
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        if rest.startswith(":"):
            port = rest[1:]
        elif rest:
            raise ValueError(f"bad address {text!r}")
    elif t.count(":") == 1:
        host, _, port = t.partition(":")
    try:
        ip = ipaddress.ip_address(host)
        port = int(port)
    except ValueError:
        raise ValueError(f"expected an IP address with optional port, got {text!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range in {text!r}")
    return str(ip), port


def dns_query_once(name, qtype, server, *, timeout=2.0):
    """Send one query (RD set) and return the decoded response plus round-trip time in ms."""
    host, port = server
    qname = dns_norm_name(name)
    txid = secrets.randbits(16)
    packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_encode_name(qname) + struct.pack("!HH", qtype, 1)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.sendto(packet, (host, port))
        deadline = time.monotonic() + timeout
        while True:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            data, addr = sock.recvfrom(4096)
            if addr[0] == host and addr[1] == port and data[:2] == packet[:2]:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out")
        rtt = (time.perf_counter() - t0) * 1000
    result = dns_parse_response(data)
    result["rtt_ms"] = round(rtt, 3)
    return result


class LabDnsServer:
    """UDP DNS for the lab: authoritative for the A/CNAME table, REFUSED for everything else (deny by default).
    Optional forwarding to one upstream resolver, limited to allow-listed client networks; per-client rate limit."""

    def __init__(self, host, port, records, *, ttl=30, forward=None, forward_clients=(), rate=50, workers=8):
        self.records, self.ttl, self.forward = records, ttl, forward
        self.forward_clients = list(forward_clients)
        self.rate = float(rate)
        self.family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self.address = self.sock.getsockname()[:2]
        self.queries = deque(maxlen=500)
        self._buckets = OrderedDict()          # least-recently-seen first; hard-capped at BUCKET_LIMIT
        self._bucket_lock = threading.Lock()
        self._pending = threading.BoundedSemaphore(256)
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ztna-dns")
        self._stop = threading.Event()

    BUCKET_LIMIT = 4096

    def _allow(self, ip):
        now = time.monotonic()
        with self._bucket_lock:
            tokens, last = self._buckets.get(ip, (self.rate, now))
            tokens = min(self.rate, tokens + (now - last) * self.rate)
            allowed = tokens >= 1
            self._buckets[ip] = (tokens - 1 if allowed else tokens, now)
            self._buckets.move_to_end(ip)
            while len(self._buckets) > self.BUCKET_LIMIT:
                self._buckets.popitem(last=False)   # evict the idlest source; memory stays bounded under spoofed-source floods
            return allowed

    def _may_forward(self, ip):
        if not self.forward:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in net for net in self.forward_clients)

    def _forward_query(self, q):
        host, port = self.forward
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.sendto(q.raw, (host, port))
            deadline = time.monotonic() + 2.0
            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    return None
                sock.settimeout(remain)
                try:
                    data, addr = sock.recvfrom(65535)
                except (socket.timeout, OSError):
                    return None
                # accept only the upstream's reply to *this* query (id + echoed question), never a stray datagram
                if addr[0] == host and addr[1] == port and len(data) >= 12 + len(q.question) and data[:2] == q.txid and data[2] & 0x80 and data[12:12 + len(q.question)] == q.question:
                    return data

    def _log(self, ip, q, rcode, how):
        qtype = _DNS_TYPE_NAMES.get(q.qtype, str(q.qtype)) if q and q.qtype is not None else "-"
        qname = q.qname if q and q.qname is not None else "-"
        self.queries.append({"ts": time.time(), "client": ip, "qname": qname, "qtype": qtype, "rcode": rcode, "via": how})
        logger.info("dns %s %a %s -> %s (%s)", ip, qname, qtype, rcode, how)

    def handle(self, data, addr):
        ip = addr[0]
        try:
            if not self._allow(ip):
                return
            q, err = dns_parse_query(data)
            if q is None:
                return
            ra = bool(self.forward)
            if err is not None:
                resp, how = dns_response(q, err, ra=ra), "error"
            elif q.qclass not in (1, 255):
                resp, how = dns_response(q, 5, ra=ra), "refused"
            else:
                resp = dns_local_answer(q, self.records.table(), self.ttl, ra)
                how = "local"
                if resp is None and self._may_forward(ip):
                    resp, how = self._forward_query(q), "forward"
                    if resp is None:
                        resp, how = dns_response(q, 2, ra=ra), "forward-failed"
                elif resp is None:
                    resp, how = dns_response(q, 5, ra=ra), "refused"
            self._log(ip, q, _DNS_RCODES.get(resp[3] & 0xF, str(resp[3] & 0xF)), how)
            self.sock.sendto(resp, addr)
        except OSError:
            pass
        except Exception:
            logger.exception("dns handler failed")
        finally:
            self._pending.release()

    def serve_forever(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            if not self._pending.acquire(blocking=False):
                continue  # overloaded: drop rather than queue without bound
            try:
                self._pool.submit(self.handle, data, addr)
            except RuntimeError:
                self._pending.release()
                break

    def shutdown(self):
        self._stop.set()

    def close(self):
        self._stop.set()
        self._pool.shutdown(wait=False, cancel_futures=True)
        try:
            self.sock.close()
        except OSError:
            pass


def _dns_records_path():
    return os.environ.get("ZTNA_DNS_RECORDS") or os.path.join(DATA_DIR, "dns_records.json")


def run_dns_server():
    host = os.environ.get("ZTNA_DNS_HOST", "127.0.0.1").strip() or "127.0.0.1"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit(f"ZTNA_DNS_HOST must be an IP address (got {host!r})") from None
    port = _env_int("ZTNA_DNS_PORT", 5353, 1, 65535)
    if not _is_loopback_bind(host) and os.environ.get("ZTNA_DNS_ALLOW_REMOTE") != "1":
        raise SystemExit("refusing to bind the lab DNS server to a non-loopback address; set ZTNA_DNS_ALLOW_REMOTE=1 to override")
    ttl = _env_int("ZTNA_DNS_TTL", 30, 0, 86400)
    rate = _env_int("ZTNA_DNS_RATE", 50, 1, 100000)
    forward = None
    raw_forward = os.environ.get("ZTNA_DNS_FORWARD", "").strip()
    if raw_forward:
        try:
            forward = _split_hostport(raw_forward, 53)
        except ValueError as exc:
            raise SystemExit(f"ZTNA_DNS_FORWARD: {exc}") from None
    clients = _parse_cidrs("ZTNA_DNS_FORWARD_CLIENTS", "127.0.0.0/8,::1/128")
    records = DnsRecords(_dns_records_path())
    try:
        records._read_file()
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    try:
        server = LabDnsServer(host, port, records, ttl=ttl, forward=forward, forward_clients=clients, rate=rate)
    except PermissionError:
        raise SystemExit(f"permission denied binding {host}:{port}: ports below 1024 need elevated rights (or CAP_NET_BIND_SERVICE)") from None
    except OSError as exc:
        raise SystemExit(f"cannot bind {host}:{port}: {exc}") from None
    logger.info("Lab DNS listening on %s:%s udp; records=%s; forwarding=%s", server.address[0], server.address[1], records.path,
                f"{forward[0]}:{forward[1]} for {[str(c) for c in clients]}" if forward else "off (unknown names -> REFUSED)")
    previous = {}

    def _stop(*_):
        server.shutdown()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass
    try:
        server.serve_forever()
    finally:
        server.close()
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
    return 0


def run_dns_cli(args):
    usage = ("usage: dns serve | dns list | dns add NAME IPV4 | dns cname NAME TARGET | dns remove NAME\n"
             "       dns query NAME [A|AAAA|CNAME|ANY] [IP[:PORT]]\n"
             "       dns probe NAME [IP[:PORT]] [count 1-1000] [interval_ms 0-60000]")
    if not args:
        raise SystemExit(usage)
    cmd, rest = args[0].lower(), args[1:]
    try:
        if cmd == "serve" and not rest:
            return run_dns_server()
        store = DnsRecords(_dns_records_path())
        if cmd == "list" and not rest:
            table = store._read_file()
            print(json.dumps({"records": [{"type": k, "name": n, "value": v} for n, (k, v) in sorted(table.items())]}, indent=2))
            return 0
        if cmd == "add" and len(rest) == 2:
            print(json.dumps(dict(zip(("type", "name", "value"), store.add("A", rest[0], rest[1])))))
            return 0
        if cmd == "cname" and len(rest) == 2:
            print(json.dumps(dict(zip(("type", "name", "value"), store.add("CNAME", rest[0], rest[1])))))
            return 0
        if cmd == "remove" and len(rest) == 1:
            existed = store.remove(rest[0])
            print(json.dumps({"removed": existed, "name": dns_norm_name(rest[0])}))
            return 0 if existed else 1
        default_server = ("127.0.0.1", _env_int("ZTNA_DNS_PORT", 5353, 1, 65535))
        if cmd == "query" and 1 <= len(rest) <= 3:
            qtype_name = (rest[1] if len(rest) > 1 else "A").upper()
            if qtype_name not in _DNS_TYPES:
                raise ValueError(f"query type must be one of {sorted(_DNS_TYPES)}")
            server = _split_hostport(rest[2], default_server[1]) if len(rest) > 2 else default_server
            result = dns_query_once(rest[0], _DNS_TYPES[qtype_name], server)
            result["server"] = f"{server[0]}:{server[1]}"
            print(json.dumps(result, indent=2))
            return 0 if result["rcode"] == "NOERROR" else 1
        if cmd == "probe" and 1 <= len(rest) <= 4:
            server = _split_hostport(rest[1], default_server[1]) if len(rest) > 1 else default_server
            count = int(rest[2]) if len(rest) > 2 else 20
            gap = int(rest[3]) if len(rest) > 3 else 200
            if not 1 <= count <= 1000 or not 0 <= gap <= 60000:
                raise ValueError("count must be 1-1000 and interval_ms 0-60000")
            samples, failures, rcodes = [], 0, Counter()
            for i in range(count):
                try:
                    r = dns_query_once(rest[0], 1, server)
                    samples.append(r["rtt_ms"])
                    rcodes[r["rcode"]] += 1
                except (OSError, ValueError):
                    failures += 1
                if gap and i < count - 1:
                    time.sleep(gap / 1000.0)
            out = probe_stats(samples, failures)
            out.update({"server": f"{server[0]}:{server[1]}", "name": dns_norm_name(rest[0]), "rcodes": dict(rcodes)})
            print(json.dumps(out, indent=2))
            return 0 if samples else 1
    except (ValueError, TimeoutError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    raise SystemExit(usage)


# ---------- remote admin console (talks to a running `server`) ----------
_CLI_HELP = """commands:
  health                 liveness probe (no admin key needed)
  status                 users, devices, sessions, simulated hour
  sessions               active sessions
  revoke SID             revoke one session
  logs [N]               last N audit entries (default 20, max 100)
  metrics                allow/deny counters and latency percentiles
  verify                 verify the audit hash chain
  firewall               print the generated iptables rules (dry run)
  help | exit"""


def _cli_clean(value):
    """Flatten server-provided text for the terminal: control characters (incl. ESC) can never reach it."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(value))


def _cli_base():
    demo = os.environ.get("ZTNA_DEMO") == "1"
    base = (os.environ.get("ZTNA_ADMIN_URL") or f"{'http' if demo else 'https'}://127.0.0.1:{os.environ.get('ZTNA_PORT', '8443')}").rstrip("/")
    u = urlsplit(base)
    if u.scheme not in ("http", "https") or not u.netloc:
        raise SystemExit("ZTNA_ADMIN_URL must start with http:// or https://")
    # The admin key travels in a header: refuse to send it in clear text beyond this machine.
    if u.scheme == "http" and not _is_loopback_bind(u.hostname or "") and os.environ.get("ZTNA_CLI_ALLOW_PLAINTEXT") != "1":
        raise SystemExit("refusing to send the admin key over plain http to a non-loopback host; use https (or set ZTNA_CLI_ALLOW_PLAINTEXT=1 for an isolated lab)")
    return base


def _cli_request(base, method, path, *, key=True):
    headers = {}
    if key:
        admin = os.environ.get("ZTNA_ADMIN_KEY", "")
        if not admin:
            raise SystemExit("ZTNA_ADMIN_KEY is not set (the key is read from the environment, never from the command line)")
        headers["X-Admin-Key"] = admin
    ctx = ssl.create_default_context(cafile=os.environ.get("ZTNA_CA_FILE") or None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    data = b"{}" if method == "POST" else None
    req = urllib.request.Request(base + path, data, {"Content-Type": "application/json", **headers}, method=method)
    try:
        with opener.open(req, timeout=10) as r:
            status, raw = r.status, r.read(4 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(65536)
    except (urllib.error.URLError, OSError) as exc:
        raise SystemExit(f"cannot reach {base}: {_cli_clean(getattr(exc, 'reason', exc))}") from None
    if len(raw) > 4 * 1024 * 1024:
        raise SystemExit("response too large")
    try:
        return status, json.loads(raw or b"{}")
    except ValueError:
        return status, raw.decode("utf-8", "replace")


def cli_exec(base, argv):
    """Run one console command; returns a process-style exit code."""
    if not argv:
        return 0
    cmd, rest = argv[0].lower(), argv[1:]
    if cmd == "help":
        print(_CLI_HELP)
        return 0
    if cmd == "health" and not rest:
        status, body = _cli_request(base, "GET", "/health", key=False)
        print(json.dumps(body))
        return 0 if status == 200 else 1
    paths = {"status": "/api/state", "sessions": "/api/state", "metrics": "/api/metrics", "verify": "/api/verify", "firewall": "/api/firewall", "logs": "/api/logs"}
    if cmd == "revoke":
        if len(rest) != 1 or not re.fullmatch(r"[0-9a-f]{1,64}", rest[0]):
            print("usage: revoke SID (hex session id from `sessions`)", file=sys.stderr)
            return 2
        status, body = _cli_request(base, "POST", f"/api/session/{rest[0]}/revoke")
    elif cmd in paths and (cmd == "logs" or not rest):
        status, body = _cli_request(base, "GET", paths[cmd])
    else:
        print(f"unknown command or arguments: {_cli_clean(cmd)} (try `help`)", file=sys.stderr)
        return 2
    if status == 401:
        print("unauthorized: check ZTNA_ADMIN_KEY", file=sys.stderr)
        return 1
    if status != 200 or not isinstance(body, (dict, list)):
        print(f"server answered {status}", file=sys.stderr)
        return 1
    if cmd == "status":
        print(json.dumps({"users": len(body.get("users", {})), "devices": len(body.get("devices", {})), "sessions": len(body.get("sessions", [])),
                          "hour": body.get("hour"), "simulated_hour": bool(body.get("sim"))}, indent=2))
    elif cmd == "sessions":
        rows = body.get("sessions", [])
        print(f"{'SID':26} {'USER':12} {'DEVICE':16} {'LOC':8} {'TTL':>5} {'MFA-AGE':>8}")
        for x in rows:
            print(f"{_cli_clean(x.get('sid'))[:26]:26} {_cli_clean(x.get('user'))[:12]:12} {_cli_clean(x.get('device'))[:16]:16} {_cli_clean(x.get('location'))[:8]:8} {int(x.get('ttl', 0)):>5} {int(x.get('mfa', 0)):>8}")
        if not rows:
            print("(no active sessions)")
    elif cmd == "logs":
        try:
            n = int(rest[0]) if rest else 20
        except ValueError:
            n = 0
        if not 1 <= n <= 100 or len(rest) > 1:
            print("usage: logs [N 1-100]", file=sys.stderr)
            return 2
        for e in reversed(body[:n]):
            print(_cli_clean(f"{e.get('ts', '')} {e.get('decision', ''):7} {e.get('user') or '-':10} {e.get('device') or '-':16} {e.get('resource', '')} {'; '.join(map(str, e.get('reasons', [])))}"))
    elif cmd == "firewall":
        for line in body.get("rules", []):
            print(_cli_clean(line))
    else:
        print(json.dumps(body, indent=2))
        if cmd == "verify":
            return 0 if body.get("ok") else 1
    return 0


def run_admin_cli(args):
    base = _cli_base()
    if args:
        return cli_exec(base, args)
    import shlex
    print(f"ztna-lab console -> {base}   (type `help`, `exit` to leave)")
    while True:
        try:
            line = input("ztna> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        try:
            words = shlex.split(line)
        except ValueError as exc:
            print(f"parse error: {exc}", file=sys.stderr)
            continue
        if words and words[0].lower() in ("exit", "quit"):
            return 0
        try:
            cli_exec(base, words)
        except SystemExit as exc:
            if exc.code not in (None, 0):
                print(exc.code if isinstance(exc.code, str) else f"error ({exc.code})", file=sys.stderr)


# ---------- deployment helper ----------
def print_systemd_unit(args):
    kind = args[0] if args else "server"
    if kind not in ("server", "dns") or len(args) > 1:
        raise SystemExit("usage: systemd [server|dns]")
    exe, script = os.path.abspath(sys.executable), os.path.abspath(__file__)
    for p in (exe, script):
        if not re.fullmatch(r"[A-Za-z0-9_./:+@-]+", p):
            raise SystemExit(f"path needs manual quoting for systemd, move it somewhere simpler: {p!r}")
    dns = kind == "dns"
    unit = f"""[Unit]
Description=ZTNA Enterprise Lab ({kind})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ztna-lab
Group=ztna-lab
# Defaults first, then your settings (keys, TLS paths, ZTNA_ALLOWED_HOSTS...) override them:
Environment=ZTNA_DATA_DIR=/var/lib/ztna-lab
{"Environment=ZTNA_DNS_RECORDS=/var/lib/ztna-lab/dns_records.json" + chr(10) if dns else ""}EnvironmentFile=/etc/ztna-lab/config.env
ExecStart={exe} {script} {kind}
Restart=on-failure
RestartSec=2
StateDirectory=ztna-lab
UMask=0077

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
{"# Only needed when ZTNA_DNS_PORT is below 1024 (e.g. 53):" + chr(10) + "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" + chr(10) + "AmbientCapabilities=CAP_NET_BIND_SERVICE" if dns else "CapabilityBoundingSet=" + chr(10) + "# If ZTNA_AUDIT_EXTERNAL_ANCHOR_FILE lives outside /var/lib/ztna-lab, add: ReadWritePaths=<its directory>"}

[Install]
WantedBy=multi-user.target
"""
    print(unit, end="")
    return 0


# =====================================================================================================
#  Blue & white desktop GUI.  One hub window opens an Employee window and a Manager window that run side
#  by side in the same process, so an employee's sign-in request lands live in the manager's queue.
# =====================================================================================================
BLUE_DARK, BLUE, BLUE_MID = "#0b3d91", "#1d4ed8", "#3b82f6"
BLUE_SOFT, BLUE_LINE, BLUE_PALE = "#eaf2ff", "#bcd3f7", "#f5f9ff"
BLUE_TEXT, BLUE_MUTED, WHITE = "#0b2a63", "#4b6aa3", "#ffffff"
UI_FONT = "Segoe UI"


def apply_blue_white_theme(root):
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except tk.TclError: pass
    root.configure(background=WHITE)
    root.option_add("*TCombobox*Listbox.background", WHITE)
    root.option_add("*TCombobox*Listbox.foreground", BLUE_TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", BLUE)
    root.option_add("*TCombobox*Listbox.selectForeground", WHITE)
    style.configure(".", background=WHITE, foreground=BLUE_TEXT, font=(UI_FONT, 10), bordercolor=BLUE_LINE,
                    lightcolor=WHITE, darkcolor=WHITE, troughcolor=BLUE_SOFT, focuscolor=BLUE, insertcolor=BLUE_TEXT)
    style.configure("TFrame", background=WHITE)
    style.configure("Soft.TFrame", background=BLUE_SOFT)
    style.configure("Band.TFrame", background=BLUE)
    for name, bg, fg, font in (
        ("TLabel", WHITE, BLUE_TEXT, (UI_FONT, 10)),
        ("Muted.TLabel", WHITE, BLUE_MUTED, (UI_FONT, 9)),
        ("Title.TLabel", WHITE, BLUE_DARK, (UI_FONT, 18, "bold")),
        ("Section.TLabel", WHITE, BLUE_DARK, (UI_FONT, 13, "bold")),
        ("Strong.TLabel", WHITE, BLUE_TEXT, (UI_FONT, 10, "bold")),
        ("Accent.TLabel", WHITE, BLUE, (UI_FONT, 10, "bold")),
        ("Big.TLabel", WHITE, BLUE_DARK, (UI_FONT, 16, "bold")),
        ("Soft.TLabel", BLUE_SOFT, BLUE_TEXT, (UI_FONT, 10)),
        ("PanelTitle.TLabel", BLUE_SOFT, BLUE_DARK, (UI_FONT, 11, "bold")),
        ("SoftMuted.TLabel", BLUE_SOFT, BLUE_MUTED, (UI_FONT, 9)),
        ("BandKicker.TLabel", BLUE, "#cfe0ff", (UI_FONT, 9, "bold")),
        ("BandTitle.TLabel", BLUE, WHITE, (UI_FONT, 20, "bold")),
        ("BandSub.TLabel", BLUE, "#dce9ff", (UI_FONT, 10)),
        ("Badge.TLabel", WHITE, BLUE, (UI_FONT, 10, "bold")),
    ):
        style.configure(name, background=bg, foreground=fg, font=font)
    style.configure("TButton", padding=(10, 5), font=(UI_FONT, 10), background=WHITE, foreground=BLUE,
                    bordercolor=BLUE, relief="flat")
    style.map("TButton", background=[("active", BLUE_SOFT), ("disabled", BLUE_PALE)],
              foreground=[("disabled", "#9db6e0")], bordercolor=[("disabled", BLUE_LINE)])
    style.configure("Primary.TButton", padding=(14, 8), font=(UI_FONT, 10, "bold"), background=BLUE,
                    foreground=WHITE, bordercolor=BLUE)
    style.map("Primary.TButton", background=[("active", BLUE_DARK), ("disabled", "#a9c1ee")],
              foreground=[("disabled", WHITE)], bordercolor=[("disabled", "#a9c1ee")])
    style.configure("Ghost.TButton", padding=(12, 6), background=BLUE, foreground=WHITE, bordercolor="#cfe0ff")
    style.map("Ghost.TButton", background=[("active", BLUE_DARK)])
    style.configure("TEntry", padding=6, fieldbackground=WHITE, bordercolor=BLUE_LINE)
    style.map("TEntry", bordercolor=[("focus", BLUE)])
    style.configure("TCombobox", padding=5, fieldbackground=WHITE, background=BLUE_SOFT, arrowcolor=BLUE,
                    bordercolor=BLUE_LINE)
    style.map("TCombobox", fieldbackground=[("readonly", WHITE)], selectbackground=[("readonly", WHITE)],
              selectforeground=[("readonly", BLUE_TEXT)], bordercolor=[("focus", BLUE)])
    style.configure("TCheckbutton", background=WHITE, foreground=BLUE_TEXT, indicatorcolor=WHITE)
    style.map("TCheckbutton", indicatorcolor=[("selected", BLUE)], background=[("active", WHITE)])
    style.configure("TSeparator", background=BLUE_LINE)
    style.configure("TNotebook", background=WHITE, borderwidth=0, tabmargins=(0, 0, 0, 0))
    style.configure("TNotebook.Tab", padding=(13, 8), font=(UI_FONT, 10, "bold"), background=BLUE_SOFT, foreground=BLUE)
    style.map("TNotebook.Tab", background=[("selected", BLUE), ("active", BLUE_LINE)], foreground=[("selected", WHITE)])
    style.configure("Treeview", rowheight=28, font=(UI_FONT, 9), background=WHITE, fieldbackground=WHITE,
                    foreground=BLUE_TEXT, bordercolor=BLUE_LINE)
    style.map("Treeview", background=[("selected", BLUE)], foreground=[("selected", WHITE)])
    style.configure("Treeview.Heading", font=(UI_FONT, 9, "bold"), background=BLUE_SOFT, foreground=BLUE_DARK,
                    bordercolor=BLUE_LINE, padding=(6, 6))
    style.map("Treeview.Heading", background=[("active", BLUE_LINE)])
    style.configure("Vertical.TScrollbar", background=BLUE_LINE, troughcolor=BLUE_SOFT, arrowcolor=BLUE, bordercolor=BLUE_SOFT)
    style.configure("Horizontal.TScrollbar", background=BLUE_LINE, troughcolor=BLUE_SOFT, arrowcolor=BLUE, bordercolor=BLUE_SOFT)
    style.configure("Blue.Horizontal.TProgressbar", troughcolor=BLUE_SOFT, background=BLUE, bordercolor=BLUE_LINE,
                    lightcolor=BLUE, darkcolor=BLUE)


class Panel(tk.Frame):
    """White panel with a thin blue border and an optional soft-blue title bar. Put content in ``.body``."""

    def __init__(self, parent, title=None, subtitle=None, padding=16):
        super().__init__(parent, background=BLUE_LINE, bd=0, highlightthickness=0)
        inner = ttk.Frame(self)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        if title:
            bar = ttk.Frame(inner, style="Soft.TFrame", padding=(14, 9))
            bar.pack(fill="x")
            ttk.Label(bar, text=title, style="PanelTitle.TLabel").pack(side="left")
            if subtitle:
                ttk.Label(bar, text=subtitle, style="SoftMuted.TLabel").pack(side="left", padx=(10, 0))
        self.body = ttk.Frame(inner, padding=padding)
        self.body.pack(fill="both", expand=True)


class ScrollFrame(tk.Frame):
    """Page whose content fills the width and scrolls vertically only when the window is too short."""

    def __init__(self, parent):
        super().__init__(parent, background=WHITE, bd=0, highlightthickness=0)
        self.canvas = tk.Canvas(self, background=WHITE, bd=0, highlightthickness=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self._bar_shown = False
        self.body.bind("<Configure>", self._fit)
        self.canvas.bind("<Configure>", self._fit)
        _install_wheel_router(self)

    def scrollable(self):
        return self.body.winfo_reqheight() > self.canvas.winfo_height() + 1

    def _fit(self, _e=None):
        cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
        if cw < 2 or ch < 2: return
        need = self.body.winfo_reqheight()
        self.canvas.itemconfigure(self._win, width=cw)
        self.canvas.configure(scrollregion=(0, 0, cw, max(need, ch)))
        if need > ch + 1 and not self._bar_shown:
            self.vbar.pack(side="right", fill="y", before=self.canvas); self._bar_shown = True
        elif need <= ch + 1 and self._bar_shown:
            self.vbar.pack_forget(); self._bar_shown = False; self.canvas.yview_moveto(0)


def _install_wheel_router(widget):
    root = widget._root()
    if getattr(root, "_ztna_wheel", False): return
    root._ztna_wheel = True

    def route(event):
        w = event.widget
        if not isinstance(w, tk.Misc): return
        try:
            if w.winfo_class() in ("Treeview", "Text", "Listbox", "TCombobox", "TSpinbox"): return
        except tk.TclError: return
        node = w
        while node is not None and not isinstance(node, ScrollFrame): node = getattr(node, "master", None)
        if node is None or not node.scrollable(): return
        num = getattr(event, "num", None)
        step = -2 if num == 4 else 2 if num == 5 else (-2 if event.delta > 0 else 2)
        node.canvas.yview_scroll(step, "units")

    for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"): root.bind_all(seq, route, add="+")


def _fmt_ts(ts, fmt="%Y-%m-%d %H:%M:%S"):
    if isinstance(ts, (int, float)):
        try: return datetime.fromtimestamp(ts).strftime(fmt)
        except (ValueError, OSError, OverflowError): return str(ts)
    return str(ts or "")


def _person(user):
    p = USER_PROFILE.get(user, {})
    return p.get("name", user), p.get("title", ""), p.get("dept", "")


_RES_TITLES = {"hr-db": "HR Database", "ci-cd": "CI/CD Pipelines", "crm": "CRM", "siem-console": "SIEM Console",
               "exec-reports": "Executive Reports", "wiki": "Wiki", "admin-panel": "Admin Panel", "source-code": "Source Code",
               "finance-ledger": "Finance Ledger", "support-desk": "Support Desk", "legal-vault": "Legal Vault"}


def _res_title(res):
    return _RES_TITLES.get(res, res.replace("-", " ").title())


def _req_lines(res):
    r = RESOURCES[res]
    hrs = "any time" if tuple(r["hours"]) == (0, 24) else f"{r['hours'][0]:02d}:00–{r['hours'][1]:02d}:00"
    return [f"Device health {r['min_posture']}+ · " + ("company-managed device" if r["managed"] else "any enrolled device"),
            f"Open {hrs} · from " + " or ".join(r["locations"]), f"Fresh MFA within {max(1, r['mfa_age'] // 60)} min"]


def _device_summary(device):
    d = DEVICES.get(device)
    if not d: return ""
    kind = "company-managed" if d.get("corporate_managed") else "personal (BYOD)"
    return f"Device health {posture(device)}/100 · {kind}"


class _PortalUI:
    """Shared helpers for the hub and the portal windows."""

    def _init_ui(self):
        self._jobs = {}

    def _schedule(self, key, ms, fn):
        old = self._jobs.pop(key, None)
        if old:
            try: self.after_cancel(old)
            except Exception: pass
        self._jobs[key] = self.after(ms, fn)

    def _cancel_jobs(self):
        for job in self._jobs.values():
            try: self.after_cancel(job)
            except Exception: pass
        self._jobs.clear()

    def _clear(self):
        self._cancel_jobs()
        for child in self.winfo_children(): child.destroy()

    def _band(self, title, subtitle, kicker="ZERO TRUST ACCESS"):
        band = ttk.Frame(self, style="Band.TFrame", padding=(26, 16))
        band.pack(fill="x")
        right = ttk.Frame(band, style="Band.TFrame"); right.pack(side="right", padx=(12, 0))
        left = ttk.Frame(band, style="Band.TFrame"); left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text=kicker, style="BandKicker.TLabel").pack(anchor="w")
        ttk.Label(left, text=title, style="BandTitle.TLabel").pack(anchor="w", pady=(3, 2))
        if str(subtitle or "").strip():
            ttk.Label(left, text=subtitle, style="BandSub.TLabel", wraplength=600, justify="left").pack(anchor="w")
        return right

    def _tree(self, parent, columns, headings, widths, stretch=None):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew"); y.grid(row=0, column=1, sticky="ns"); x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        for c, h, w in zip(columns, headings, widths):
            tree.heading(c, text=h, anchor="w")
            tree.column(c, width=w, minwidth=50, anchor="w", stretch=(c == (stretch or columns[-1])))
        tree.tag_configure("strong", font=(UI_FONT, 9, "bold"), foreground=BLUE_DARK)
        tree.tag_configure("pending", font=(UI_FONT, 9, "bold"), background=BLUE_SOFT, foreground=BLUE_DARK)
        tree.tag_configure("blocked", font=(UI_FONT, 9, "bold"), foreground=BLUE_DARK, background=BLUE_PALE)
        return tree

    def _fill_tree(self, tree, rows, iids=None, tags=None):
        """Rebuild only when the data changed; keep selection and scroll position."""
        if not tree or not tree.winfo_exists(): return
        sig = (tuple(map(tuple, rows)), tuple(iids or ()))
        if getattr(tree, "_sig", None) == sig: return
        tree._sig = sig
        keep = set(tree.selection()); top = tree.yview()[0]
        tree.delete(*tree.get_children())
        for i, row in enumerate(rows):
            iid = iids[i] if iids else None
            kw = {"iid": iid} if iid else {}
            tag = tags[i] if tags else ()
            tree.insert("", "end", values=tuple(str(v)[:800] for v in row), tags=tag, **kw)
        if iids:
            still = [i for i in iids if i in keep]
            if still: tree.selection_set(still)
        tree.yview_moveto(top)

    def _form_row(self, grid, row, label, widget_factory):
        ttk.Label(grid, text=label, style="Strong.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 14), pady=7)
        w = widget_factory(grid)
        w.grid(row=row, column=1, sticky="ew", pady=7)
        return w


class PortalWindow(_PortalUI, tk.Toplevel):
    def __init__(self, app, title, size, minsize):
        tk.Toplevel.__init__(self, app)
        self._init_ui()
        self.app = app
        self.base_title = title
        self.title(title)
        self.geometry(size)
        self.minsize(*minsize)
        self.configure(background=WHITE)
        self.protocol("WM_DELETE_WINDOW", self.close)

    def close(self):
        self._cancel_jobs()
        self.app.portal_closed(self)
        try: self.destroy()
        except tk.TclError: pass


# Persist only convenience preferences; never store passwords or OTPs.
def _gui_preferences_path():
    return os.path.join(DATA_DIR, "desktop_gui_preferences.json")

def _load_gui_preferences():
    try:
        with open(_gui_preferences_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError): return {}

def _save_gui_preferences(data):
    safe = {k: str(data.get(k, ""))[:100] for k in ("username", "device", "location")}
    path = _gui_preferences_path(); os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(safe, f)
    os.replace(tmp, path)

# ------------------------------------------------------------------------------ employee side
class EmployeePortal(PortalWindow):
    def __init__(self, app):
        super().__init__(app, "ZTNA Access Workspace — Employee", "1000x740", (860, 620))
        self.engine = DesktopZTNA()
        self.request_id = None
        self._session_warning_shown = False
        self._show_login()

    # ---- sign-in form
    def _show_login(self):
        self._clear(); self.title("ZTNA Access Workspace — Employee sign-in")
        self.request_id = None
        self._band("Employee sign-in", "")
        wrap = ttk.Frame(self, padding=(30, 22)); wrap.pack(fill="both", expand=True)
        panel = Panel(wrap, "Employee identity", padding=22); panel.pack(pady=4)
        grid = panel.body; grid.columnconfigure(1, weight=1)
        remembered = _load_gui_preferences()
        self.v_user = tk.StringVar(value=remembered.get("username") if remembered.get("username") in USERS else (sorted(USERS)[0] if USERS else ""))
        self.v_pass, self.v_otp = tk.StringVar(), tk.StringVar()
        self.v_dev, self.v_loc = tk.StringVar(), tk.StringVar(value=remembered.get("location", "office"))
        self.v_who = tk.StringVar(); self.v_devinfo = tk.StringVar()
        self.cb_user = self._form_row(grid, 0, "Username", lambda p: ttk.Combobox(p, textvariable=self.v_user, values=sorted(USERS), state="readonly", width=34))
        self.cb_user.bind("<<ComboboxSelected>>", self._user_changed)
        ttk.Label(grid, textvariable=self.v_who, style="Muted.TLabel").grid(row=1, column=1, sticky="w", pady=(0, 4))
        pw = self._form_row(grid, 2, "Password", lambda p: ttk.Entry(p, textvariable=self.v_pass, show="•", width=36))
        otp_row = ttk.Frame(grid)
        ttk.Label(grid, text="Authenticator code", style="Strong.TLabel").grid(row=3, column=0, sticky="w", padx=(0, 14), pady=7)
        otp_row.grid(row=3, column=1, sticky="ew", pady=7)
        ttk.Entry(otp_row, textvariable=self.v_otp, width=16).pack(side="left", fill="x", expand=True)
        b = ttk.Button(otp_row, text="Generate code", command=self._demo_otp)
        b.pack(side="left", padx=(8, 0))
        if not DEMO_OTP: b.state(["disabled"])
        self.cb_dev = self._form_row(grid, 4, "Registered device", lambda p: ttk.Combobox(p, textvariable=self.v_dev, state="readonly", width=34))
        self.cb_dev.bind("<<ComboboxSelected>>", lambda _e: self.v_devinfo.set(_device_summary(self.v_dev.get())))
        ttk.Label(grid, textvariable=self.v_devinfo, style="Muted.TLabel").grid(row=5, column=1, sticky="w", pady=(0, 4))
        self._form_row(grid, 6, "Connection", lambda p: ttk.Combobox(p, textvariable=self.v_loc, values=["office", "home"], state="readonly", width=14))
        ttk.Separator(grid).grid(row=7, column=0, columnspan=2, sticky="ew", pady=(14, 12))
        actions = ttk.Frame(grid); actions.grid(row=8, column=0, columnspan=2, sticky="ew")
        ttk.Button(actions, text="Close", command=self.close).pack(side="left")
        ttk.Button(actions, text="Request sign-in  →", style="Primary.TButton", command=self._submit).pack(side="right")
        self.bind("<Return>", lambda _e: self._submit())
        self._user_changed()
        pw.focus_set()

    def _user_changed(self, _e=None):
        user = self.v_user.get().strip()
        name, title, dept = _person(user)
        role = USERS.get(user, {}).get("role", "")
        self.v_who.set(f"{name} · {title} · {dept} · role: {role}" if role else "")
        devices = sorted(d for d, v in DEVICES.items() if v.get("owner") == user)
        self.cb_dev.configure(values=devices)
        remembered = _load_gui_preferences()
        preferred = remembered.get("device")
        self.v_dev.set(preferred if preferred in devices else (devices[0] if devices else ""))
        self.v_devinfo.set(_device_summary(self.v_dev.get()))

    def _demo_otp(self):
        user = self.v_user.get().strip()
        try: self.v_otp.set(self.engine.demo_otp(user))
        except Exception as exc: messagebox.showerror("Demo code", str(exc), parent=self)

    def _submit(self):
        user, dev = self.v_user.get().strip(), self.v_dev.get().strip()
        if not user or not dev:
            messagebox.showerror("Sign in", "Choose an employee account that has a registered device.", parent=self); return
        _save_gui_preferences({"username": user, "device": dev, "location": self.v_loc.get()})
        ok, res = self.engine.request_signin(user, self.v_pass.get(), self.v_otp.get().strip(), dev, self.v_loc.get())
        if not ok:
            messagebox.showerror("Sign-in request failed", res, parent=self); return
        self.unbind("<Return>")
        self.request_id = res
        self.app.refresh_hub()
        self._show_waiting()

    # ---- waiting for the manager
    def _show_waiting(self):
        self._clear(); self.title("ZTNA Access Workspace — Waiting for approval")
        try: row = get_signin_request(self.request_id) or {}
        except StateStoreError: row = {}
        self._band("Waiting for manager approval", "")
        wrap = ttk.Frame(self, padding=(30, 26)); wrap.pack(fill="both", expand=True)
        panel = Panel(wrap, "Sign-in request", padding=24); panel.pack(pady=4)
        body = panel.body
        self.v_wait = tk.StringVar(value="Waiting for a manager to review your request…")
        ttk.Label(body, textvariable=self.v_wait, style="Section.TLabel", wraplength=520).pack(anchor="w")
        bar = ttk.Progressbar(body, mode="indeterminate", length=520, style="Blue.Horizontal.TProgressbar")
        bar.pack(fill="x", pady=(14, 14)); bar.start(14)
        info = ttk.Frame(body); info.pack(fill="x")
        name, title, _dept = _person(row.get("user", ""))
        for i, (k, v) in enumerate((("Request ID", self.request_id), ("Employee", f"{name} ({row.get('user','')})"),
                                    ("Device", row.get("device", "")), ("Connection", row.get("location", "")),
                                    ("Submitted", _fmt_ts(row.get("ts"))))):
            ttk.Label(info, text=k, style="Strong.TLabel").grid(row=i, column=0, sticky="w", padx=(0, 18), pady=3)
            ttk.Label(info, text=v).grid(row=i, column=1, sticky="w", pady=3)
        self.v_elapsed = tk.StringVar()
        ttk.Label(body, textvariable=self.v_elapsed, style="Muted.TLabel").pack(anchor="w", pady=(12, 0))
        ttk.Separator(body).pack(fill="x", pady=14)
        ttk.Button(body, text="Cancel request", command=self._cancel_request).pack(anchor="w")
        self._poll()

    def _cancel_request(self):
        if self.request_id:
            try: cancel_signin_request(self.request_id)
            except StateStoreError: messagebox.showwarning("Cancel request", "The request could not be cancelled right now (database unavailable). It will expire on its own.", parent=self)
        self.app.refresh_hub(); self._show_login()

    def _poll(self):
        try: row = get_signin_request(self.request_id) if self.request_id else None
        except StateStoreError:                    # a transient database error must not end the loop: keep waiting and retry
            self.v_elapsed.set("Cannot reach the sign-in service right now; retrying…")
            self._schedule("poll", 2000, self._poll); return
        if not row: self._show_login(); return
        st = row["status"]
        if st == "pending":
            self.v_elapsed.set(f"Waiting {int(time.time() - row['ts'])} s · requests expire after {SIGNIN_REQUEST_TTL // 60} minutes")
            self._schedule("poll", 1000, self._poll); return
        if st == "approved":
            ok, msg = self.engine.complete_signin(self.request_id)
            self.app.refresh_hub()
            if ok: self._show_workspace()
            elif "temporarily unavailable" in msg:                 # the approval is still valid: retry rather than throw it away
                self.v_elapsed.set(msg); self._schedule("poll", 2000, self._poll)
            else:
                messagebox.showerror("Sign-in", msg, parent=self); self._show_login()
            return
        text = {"denied": "A manager denied your sign-in request.", "expired": "Your request expired before a manager answered.",
                "cancelled": "This sign-in request was cancelled."}.get(st, f"Request ended: {st}")
        if st == "denied" and row.get("note"): text += f"\n\nManager note: {row['note']}"
        messagebox.showwarning("Sign-in not approved", text, parent=self)
        self._show_login()

    # ---- workspace
    def _show_workspace(self):
        self._session_warning_shown = False                       # a new session: the "about to expire" prompt may show again
        self._clear()
        sid, sess = self.engine.session
        user = sess["user"]; name, title, dept = _person(user); role = USERS[user].get("role", "employee")
        self.title(f"ZTNA Access Workspace — {name}")
        right = self._band(f"Welcome, {name}", f"{title} · {dept} · Role: {role.upper()} · Device: {sess['device']} · Connection: {sess['location']}")
        ttk.Button(right, text="Sign out", style="Ghost.TButton", command=self._sign_out).pack()
        page = ScrollFrame(self); page.pack(fill="both", expand=True)
        body = page.body; body.configure(padding=(26, 20))
        # status tiles
        tiles = ttk.Frame(body); tiles.pack(fill="x", pady=(0, 18))
        self.v_tiles = {k: tk.StringVar() for k in ("score", "left", "mfa")}
        for i, (label, key) in enumerate((("Device trust", "score"), ("Session time left", "left"), ("Last MFA", "mfa"))):
            p = Panel(tiles, label, padding=(14, 10)); p.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            tiles.columnconfigure(i, weight=1, uniform="tile")
            ttk.Label(p.body, textvariable=self.v_tiles[key], style="Big.TLabel").pack(anchor="w")
        ttk.Label(body, text="Applications", style="Section.TLabel").pack(anchor="w", pady=(0, 10))
        grid = ttk.Frame(body); grid.pack(fill="x")
        self.resource_access_buttons = {}
        names = sorted(RESOURCES, key=lambda r: (not (rbac_allows(user, r) and segment_allows(user, r)), r))
        for c in range(3): grid.columnconfigure(c, weight=1, uniform="res")
        for idx, res in enumerate(names):
            assigned = rbac_allows(user, res) and segment_allows(user, res)
            p = Panel(grid, _res_title(res), padding=(14, 10))
            p.grid(row=idx // 3, column=idx % 3, sticky="nsew", padx=5, pady=5)
            ttk.Label(p.body, text=RESOURCES[res]["desc"], wraplength=215, justify="left").pack(anchor="w")
            ttk.Label(p.body, text="ASSIGNED TO YOUR ROLE" if assigned else "NOT ASSIGNED TO YOUR ROLE",
                      style="Accent.TLabel" if assigned else "Muted.TLabel").pack(anchor="w", pady=(0, 8))
            if assigned:
                btn = ttk.Button(p.body, text="Request access", style="Primary.TButton", command=lambda r=res: self._request(r))
            else:
                btn = ttk.Button(p.body, text="Request temporary exception", command=lambda r=res: self._request_exception(r))
            btn.pack(anchor="w")
            self.resource_access_buttons[res] = btn
        # decision output
        out = Panel(body, "Access decision", padding=12); out.pack(fill="x", pady=(18, 0))
        self.out = tk.Text(out.body, height=13, wrap="word", font=("Consolas", 10), background=WHITE, foreground=BLUE_TEXT,
                           relief="flat", bd=0, highlightthickness=0, padx=10, pady=8, selectbackground=BLUE_LINE)
        sb = ttk.Scrollbar(out.body, orient="vertical", command=self.out.yview); self.out.configure(yscrollcommand=sb.set)
        self.out.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        self.out.tag_configure("allow", background=BLUE, foreground=WHITE, font=("Consolas", 11, "bold"), spacing1=4, spacing3=4)
        self.out.tag_configure("stepup", background=BLUE_LINE, foreground=BLUE_DARK, font=("Consolas", 11, "bold"), spacing1=4, spacing3=4)
        self.out.tag_configure("deny", background=BLUE_DARK, foreground=WHITE, font=("Consolas", 11, "bold"), spacing1=4, spacing3=4)
        self.out.tag_configure("head", foreground=BLUE_DARK, font=("Consolas", 10, "bold"))
        self._write_out([("Choose an application above and press “Request access”. The decision and its reasons appear here.", "")])
        # Employee-only activity view: show only this identity's own recent events.
        activity = Panel(body, "My activity", padding=12); activity.pack(fill="x", pady=(14, 4))
        self.my_activity = tk.Text(activity.body, height=5, wrap="word", font=(UI_FONT, 9), background=WHITE, foreground=BLUE_TEXT, relief="flat", bd=0, highlightthickness=0)
        self.my_activity.pack(fill="x")
        own_events = [e for e in list(LOG) if e.get("user") == user][:12]
        if own_events:
            self.my_activity.insert("1.0", "\n".join(f"{_fmt_ts(e.get('ts'))} · {e.get('resource','')} · {e.get('decision','')} · {', '.join(map(str, e.get('reasons', [])))[:160]}" for e in own_events))
        else: self.my_activity.insert("1.0", "Your recent access and audit events will appear here.")
        self.my_activity.configure(state="disabled")
        # step-up
        step = Panel(body, "Step-up verification", padding=12); step.pack(fill="x", pady=(14, 4))
        self.v_step = tk.StringVar()
        ttk.Button(step.body, text="Verify MFA", style="Primary.TButton", command=self._stepup).pack(side="right")
        b2 = ttk.Button(step.body, text="Generate code", command=self._step_demo); b2.pack(side="right", padx=8)
        if not DEMO_OTP: b2.state(["disabled"])
        ttk.Entry(step.body, textvariable=self.v_step, width=11).pack(side="right")
        self._tick()

    def _write_out(self, segments):
        if not self.out.winfo_exists(): return
        self.out.configure(state="normal"); self.out.delete("1.0", "end")
        for text, tag in segments: self.out.insert("end", text, tag)
        self.out.configure(state="disabled")

    def _request_exception(self, res):
        reason = simpledialog.askstring("Request temporary access", f"Why do you need temporary access to {_res_title(res)}?\nInclude a short business justification:", parent=self)
        if not reason or not reason.strip(): return
        try:
            rid = create_access_exception_request(self.engine.user, self.engine.device, res, reason.strip())
            messagebox.showinfo("Request submitted", f"Your temporary access request ({rid}) was sent to the ZTNA manager. It does not grant access until approved.", parent=self)
        except (ValueError, StateStoreError, AuditFull, AuditTamper) as exc:
            messagebox.showerror("Request not submitted", str(exc), parent=self)

    def _request(self, res):
        result = self.engine.access(res)
        verdict, headline, lines, _tips = explain_decision(res, result)
        tag = {"ALLOW": "allow", "STEPUP": "stepup"}.get(verdict, "deny")
        seg = [(f" {headline} \n", tag),
               (f"\nApplication: {RESOURCES.get(res, {}).get('desc', res)}\nNetwork segment: {result.get('segment', SEGMENTS.get(res, '-'))}"
                f"   Risk: {result.get('risk', 'n/a')}/100   Device: {result.get('device', self.engine.device or '-')}\n", "")]
        if verdict == "ALLOW":
            pv = result.get("preview") or {}
            seg.append((f"\n{pv.get('title', '')}\n", "head"))
            cols, rows = list(pv.get("columns", ())), [list(map(str, r)) for r in pv.get("rows", ())]
            if cols:
                widths = [max(len(str(x)) for x in col) for col in zip(cols, *rows)]
                fmt = lambda r: "  " + "   ".join(str(v).ljust(w) for v, w in zip(r, widths)) + "\n"
                seg.append((fmt(cols), "head")); seg.extend((fmt(r), "") for r in rows)
            if result.get("upstream_error"): seg.append(("\nThe configured upstream is currently unavailable.\n", ""))
        self._write_out(seg)
        if verdict == "STEPUP":
            messagebox.showinfo("Extra verification needed", "Verify a fresh authenticator code in Step-up verification, then request access again.", parent=self)

    @staticmethod
    def _tips(result):
        err = str(result.get("error", ""))
        if err in ("session revoked", "session expired", "authentication required"): return ["Sign out and request sign-in again."]
        if result.get("decision") == "STEPUP": return ["Verify a fresh code under Step-up verification, then request access again."]
        tips = []
        for t in map(str, result.get("reasons", [])):
            if t.startswith(("RBAC", "micro-segmentation")): s = "This application is not part of your role. Ask your manager if you need it."
            elif t.startswith(("posture", "corporate-managed")): s = "Your device does not meet this application's health rules. Ask a ZTNA manager to review it."
            elif t.startswith("outside allowed hours"): s = "Try again during the allowed hours shown on the application card."
            elif t.startswith("location"): s = "Sign in again from an allowed connection (see the application card)."
            elif t.startswith("MFA older"): s = "Verify a fresh code under Step-up verification, then request access again."
            elif t.startswith("risk score"): s = "Risk is too high right now. Ask a ZTNA manager to review your session."
            else: continue
            if s not in tips: tips.append(s)
        return tips

    def _step_demo(self):
        try: self.v_step.set(self.engine.demo_otp(self.engine.user))
        except Exception as exc: messagebox.showerror("Demo code", str(exc), parent=self)

    def _stepup(self):
        ok, msg = self.engine.stepup(self.v_step.get().strip())
        if ok: messagebox.showinfo("MFA verified", "Fresh MFA recorded. Request the application again.", parent=self)
        else: messagebox.showerror("MFA verification failed", msg, parent=self)

    def _tick(self):
        """Live tiles; also notices when a manager revoked the session or it expired."""
        if not self.engine.session: return
        sid, sess = self.engine.session
        with LOCK: alive = sid in SESSIONS
        now = time.time()
        if not alive or sess["exp"] <= now or sess["abs_exp"] <= now:
            why = "A manager ended your session." if not alive else "Your session expired."
            self.engine.logout(); self.app.refresh_hub()
            messagebox.showwarning("Signed out", why + " Request sign-in again to continue.", parent=self)
            self._show_login(); return
        if sess.get("device") in BLOCKED_DEVICES:
            self.engine.logout(); self.app.refresh_hub()
            messagebox.showwarning("Device blocked", "The manager blocked this device. Your session has ended.", parent=self)
            self._show_login(); return
        remaining = max(0, int(sess["exp"] - now))
        if remaining <= 120 and remaining > 0 and not self._session_warning_shown:
            self._session_warning_shown = True
            if messagebox.askyesno("Session expiring", f"Your session expires in {remaining} seconds. Verify MFA now to extend it?", parent=self):
                code = simpledialog.askstring("Fresh MFA required", "Enter your current authenticator code:", parent=self)
                if code:
                    ok, msg = self.engine.stepup(code.strip())
                    if not ok: messagebox.showwarning("Session not extended", msg, parent=self)
                    else: self._session_warning_shown = False
        for resource, button in getattr(self, "resource_access_buttons", {}).items():
            assigned = rbac_allows(sess["user"], resource) and segment_allows(sess["user"], resource)
            if assigned:
                button.configure(text="Request access", command=lambda r=resource: self._request(r), style="Primary.TButton")
            else:
                button.configure(text="Request temporary exception", command=lambda r=resource: self._request_exception(r), style="TButton")
        self.v_tiles["score"].set(f"{posture(sess['device'])}/100")
        self.v_tiles["left"].set(f"{max(0, int(sess['exp'] - now))} s")
        self.v_tiles["mfa"].set(f"{int(now - sess['mfa_at'])} s ago")
        self._schedule("tick", 1000, self._tick)

    def _sign_out(self):
        try: self.engine.logout()
        finally:
            self.app.refresh_hub(); self._show_login()

    def close(self):
        try:
            if self.request_id and not self.engine.session: cancel_signin_request(self.request_id)
            if self.engine.session: self.engine.logout()
        except Exception: pass
        super().close(); self.app.refresh_hub()


# ------------------------------------------------------------------------------ SIEM dashboard (manager side)
# Everything below reads the live engine state (audit chain, alert table, sessions, device blocks). Nothing is invented:
# an empty window renders as an empty chart.
SEV_COLOR = {"INFO": "#64748b", "LOW": "#2563eb", "MEDIUM": "#d97706", "HIGH": "#dc2626", "CRITICAL": "#991b1b"}
OUTCOME_COLOR = {"allowed": "#16a34a", "challenged": "#f59e0b", "blocked": "#dc2626", "other": "#cbd5e1"}
OUTCOME_LABEL = {"allowed": "Allowed", "challenged": "Challenged", "blocked": "Blocked", "other": "Other"}
OK_GREEN, WARN_AMBER, BAD_RED = "#15803d", "#b45309", "#b91c1c"
SIEM_WINDOWS = (("15 minutes", 900), ("1 hour", 3600), ("6 hours", 21600), ("24 hours", 86400))
SIEM_AUTH_FAIL_RES = ("login", "stepup", "manager-login")
SIEM_ADMIN_RES = {"posture", "sim", "policy", "identity-create", "device-enrollment", "audit-repair", "audit-reset", "audit-export", "firewall"}
SIEM_RESPONSE_RES = {"alert", "alert-review", "alert-response", "device-control", "stepup-control", "sessions"}
SIEM_THREAT_LEVELS = ((20, "LOW", "#16a34a"), (45, "GUARDED", "#2563eb"), (70, "ELEVATED", "#d97706"), (101, "SEVERE", "#dc2626"))


def _evt_epoch(e):
    """Unix time of an audit entry (ISO-8601 string) or alert (float). 0.0 if unreadable."""
    ts = e.get("ts") if isinstance(e, dict) else e
    if isinstance(ts, (int, float)): return float(ts)
    try: return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        try: return float(ts)
        except (ValueError, TypeError): return 0.0


def _to_int(v, default=0):
    try: return int(float(v))
    except (ValueError, TypeError, OverflowError): return default


def _tint(color, amount=0.85):
    """Blend a #rrggbb colour towards white (amount 0..1)."""
    c = color.lstrip("#")
    r, g, b = (int(c[i:i + 2], 16) for i in (0, 2, 4))
    return "#%02x%02x%02x" % tuple(int(x + (255 - x) * amount) for x in (r, g, b))


def siem_category(e):
    res, dec = str(e.get("resource", "")), str(e.get("decision", ""))
    if dec == "POLICY" or res in SIEM_ADMIN_RES: return "Admin"
    if _is_exception_record(e): return "Response"
    if res in RESOURCES: return "Access"
    if res in SIEM_AUTH_FAIL_RES or res == "signin-request": return "Authentication"
    if res in ("session", "manager-logout"): return "Session"
    # Manager actions on names outside the audit allow-list are stored as "unknown:<hash>", so the decision identifies them.
    if res in SIEM_RESPONSE_RES or dec in ("REVOKE", "FALSE_ALARM", "REVIEWED"): return "Response"
    return "Other"


def siem_event_severity(e, cat):
    dec, res, risk = str(e.get("decision", "")), str(e.get("resource", "")), _to_int(e.get("risk"))
    if res in ("audit-reset", "audit-repair") or dec == "ERROR": return "HIGH"
    if dec == "DENY":
        if cat == "Access": return "HIGH" if risk >= 80 else "MEDIUM"
        return "MEDIUM" if cat == "Authentication" else "LOW"
    if dec in ("STEPUP", "PENDING", "POLICY"): return "LOW"
    if dec == "REVOKE" and cat == "Response": return "LOW"
    return "INFO"


def siem_outcome(dec):
    return {"ALLOW": "allowed", "DENY": "blocked", "STEPUP": "challenged", "PENDING": "challenged"}.get(str(dec), "other")


_SIEM_DESC = OrderedDict()


def _siem_describe(e):
    """(label, plain-English sentence) for an audit entry; cached by entry hash."""
    key = e.get("hash") or id(e)
    hit = _SIEM_DESC.get(key)
    if hit: return hit
    try:
        label, _tag, sentence = describe_audit_event(e)
    except Exception:
        label, sentence = str(e.get("decision", "")).title(), "; ".join(map(str, e.get("reasons") or [])) or str(e.get("resource", ""))
    _SIEM_DESC[key] = (label, sentence)
    while len(_SIEM_DESC) > 1500: _SIEM_DESC.popitem(last=False)
    return label, sentence


def _siem_aggregate(rows):
    access = [x for x in rows if x["cat"] == "Access"]
    risks = [x["risk"] for x in access]
    return {"events": len(rows), "access": len(access),
            "allow": sum(1 for x in access if x["decision"] == "ALLOW"),
            "stepup": sum(1 for x in access if x["decision"] == "STEPUP"),
            "deny": sum(1 for x in access if x["decision"] == "DENY"),
            "failed_auth": sum(1 for x in rows if x["resource"] in SIEM_AUTH_FAIL_RES and x["decision"] == "DENY"),
            "avg_risk": round(sum(risks) / len(risks), 1) if risks else 0.0}


def siem_threat(open_alerts, cur, integrity_ok=None):
    """Transparent 0-100 threat score. Every point comes from a listed factor."""
    sev = Counter(str(a.get("severity", "")).upper() for a in open_alerts)
    high, med, low = sev["HIGH"] + sev["CRITICAL"], sev["MEDIUM"], sev["LOW"]
    factors = []

    def add(label, pts, detail):
        if pts >= 0.5: factors.append((label, int(round(pts)), detail))
    add("Open high-severity alerts", min(45, 15 * high), f"{high} awaiting a decision")
    add("Open medium alerts", min(24, 6 * med), f"{med} awaiting a decision")
    add("Open low alerts", min(6, 2 * low), f"{low} awaiting a decision")
    if cur["access"] >= 5:
        add("Share of access requests denied", min(15, cur["deny"] / cur["access"] * 30), f"{round(cur['deny'] * 100 / cur['access'])}% of {cur['access']} requests")
    add("Average access risk", cur["avg_risk"] / 100 * 10, f"{cur['avg_risk']}/100")
    if integrity_ok is False: add("Audit chain failed verification", 40, "evidence may have been altered")
    score = min(100, sum(f[1] for f in factors))
    for limit, name, color in SIEM_THREAT_LEVELS:
        if score < limit: return {"score": score, "level": name, "color": color, "factors": factors}


def siem_snapshot(window_s=3600, buckets=30, now=None, integrity_ok=None):
    """Aggregate live engine state for one dashboard window. Pure read; safe to call from the Tk thread."""
    now = time.time() if now is None else now
    W = float(window_s); start, prev_start = now - W, now - 2 * W
    with LOCK: log = list(LOG)
    evs = []
    for e in log:
        cat = siem_category(e)
        evs.append({"raw": e, "ts": _evt_epoch(e), "user": str(e.get("user") or ""), "device": str(e.get("device") or ""),
                    "resource": str(e.get("resource", "")), "decision": str(e.get("decision", "")), "risk": _to_int(e.get("risk")),
                    "cat": cat, "sev": siem_event_severity(e, cat), "outcome": siem_outcome(e.get("decision"))})
    oldest = min((x["ts"] for x in evs), default=None)
    full = bool(LOG.maxlen) and len(log) >= LOG.maxlen
    truncated = bool(full and oldest is not None and oldest > start)
    prev_ok = not (full and oldest is not None and oldest > prev_start)
    cur = [x for x in evs if x["ts"] >= start]
    prev = [x for x in evs if prev_start <= x["ts"] < start]
    cur_agg, prev_agg = _siem_aggregate(cur), (_siem_aggregate(prev) if prev_ok else None)
    try: al = [dict(a) for a in recent_alerts(limit=500)]
    except Exception: al = []
    for a in al: a["_ts"] = _evt_epoch(a); a["_sev"] = str(a.get("severity", "")).upper()
    cur_alerts = [a for a in al if a["_ts"] >= start]
    open_alerts = [a for a in al if not a.get("acknowledged")]
    bw = W / buckets
    bk = [{"t0": start + i * bw, "ev": 0, "alerts": 0, "allowed": 0, "challenged": 0, "blocked": 0, "other": 0} for i in range(buckets)]
    for x in cur:
        b = bk[max(0, min(buckets - 1, int((x["ts"] - start) / bw)))]; b["ev"] += 1; b[x["outcome"]] += 1
    for a in cur_alerts: bk[max(0, min(buckets - 1, int((a["_ts"] - start) / bw)))]["alerts"] += 1
    # identities with risk signals
    ident = {}
    def slot(u): return ident.setdefault(u, {"user": u, "deny": 0, "stepup": 0, "high": 0, "med": 0, "low": 0, "max_risk": 0})
    for x in cur:
        if x["user"] and x["decision"] in ("DENY", "STEPUP") and x["cat"] in ("Access", "Authentication"):
            s = slot(x["user"]); s["deny" if x["decision"] == "DENY" else "stepup"] += 1; s["max_risk"] = max(s["max_risk"], x["risk"])
    for a in cur_alerts:
        if a.get("user"):
            s = slot(a["user"]); s["high" if a["_sev"] in ("HIGH", "CRITICAL") else "med" if a["_sev"] == "MEDIUM" else "low"] += 1
    people = []
    for s in ident.values():
        s["score"] = min(100, int(4 * s["deny"] + 2 * s["stepup"] + 20 * s["high"] + 6 * s["med"] + 3 * s["low"] + 0.2 * s["max_risk"]))
        s["alerts"] = s["high"] + s["med"] + s["low"]; s["name"] = _person(s["user"])[0]; people.append(s)
    people.sort(key=lambda s: (-s["score"], s["user"]))
    with LOCK:
        live = [s for s in SESSIONS.values() if s.get("exp", 0) > now and s.get("abs_exp", 0) > now and s.get("device") not in BLOCKED_DEVICES]
    try: pending = count_pending_signins()
    except Exception: pending = 0
    return {"now": now, "start": start, "window": W, "cur": cur, "cur_agg": cur_agg, "prev_agg": prev_agg, "truncated": truncated,
            "buckets": bk, "alerts": al, "open_alerts": open_alerts, "people": people[:5], "sessions": len(live), "pending": pending,
            "blocked": sorted(BLOCKED_DEVICES), "stepup_users": sorted(STEPUP_REQUIRED_USERS),
            "temp_grants": sorted((u, r, int((exp - now) // 60) + 1) for (u, r), exp in list(TEMP_RESOURCE_GRANTS.items()) if exp > now),
            "threat": siem_threat(open_alerts, cur_agg, integrity_ok)}


def siem_integrity_state():
    """Cheap, in-memory integrity facts. The full cryptographic scan is verify_chain(), run in the background."""
    with LOCK:
        entries = AUDIT.get("entries", 0); log = list(LOG)
    blocks = []
    for i, e in enumerate(log[:8]):
        ok = (i + 1 >= len(log)) or e.get("prev") == log[i + 1].get("hash")
        blocks.append({"seq": entries - i, "hash": str(e.get("hash", "")), "ok": bool(ok)})
    blocks.reverse()
    return {"entries": entries, "linked": all(b["ok"] for b in blocks), "blocks": blocks,
            "anchors": os.path.exists(AUDIT_ANCHOR_FILE) and os.path.exists(AUDIT_EXTERNAL_ANCHOR_FILE)}


class _Verifier:
    """Runs verify_chain() off the Tk thread; the dashboard polls .result from its timer."""

    def __init__(self):
        self.running, self.result = False, None

    def start(self):
        if self.running: return False
        self.running = True
        threading.Thread(target=self._run, name="siem-verify", daemon=True).start()
        return True

    def _run(self):
        t0 = time.time()
        try: r = verify_chain()
        except Exception as exc: r = {"ok": False, "error": str(exc), "entries": 0}
        self.result = (time.time(), r, time.time() - t0)
        self.running = False


# ---- canvas charts (stdlib Tk has no charting; these are small, resize-aware and theme-matched)
class _Chart(tk.Canvas):
    def __init__(self, parent, height):
        super().__init__(parent, height=height, background=WHITE, bd=0, highlightthickness=0)
        self._args = None
        self.bind("<Configure>", lambda _e: self.draw())

    def set(self, *args, **kw):
        self._args = (args, kw); self.draw()

    def draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if self._args is None or w < 30 or h < 10: return
        self._paint(w, h, *self._args[0], **self._args[1])

    def _empty(self, w, h, text):
        self.create_text(w / 2, h / 2, text=text, fill=BLUE_MUTED, font=(UI_FONT, 9))


def _nice_step(top, ticks=4):
    raw = max(top, 1) / ticks
    for s in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000):
        if s >= raw: return s
    return 1000


class TimelineChart(_Chart):
    ORDER = ("allowed", "challenged", "blocked", "other")

    def _paint(self, w, h, buckets=(), window=3600):
        L, R, T, B = 34, 8, 34, 20
        pw, ph = w - L - R, h - T - B
        totals = [sum(b[k] for k in self.ORDER) for b in buckets]
        if not buckets or not any(totals): return self._empty(w, h, "No events in this window")
        step = _nice_step(max(totals)); top = step * math.ceil(max(totals) / step)
        for v in range(0, top + 1, step):
            y = T + ph - ph * v / top
            self.create_line(L, y, w - R, y, fill=BLUE_SOFT if v else BLUE_LINE)
            self.create_text(L - 5, y, text=str(v), anchor="e", fill=BLUE_MUTED, font=(UI_FONT, 7))
        n = len(buckets); slot = pw / n; bw = max(2, slot - 2)
        for i, b in enumerate(buckets):
            x0, base = L + i * slot + (slot - bw) / 2, T + ph
            for k in self.ORDER:
                if not b[k]: continue
                y1 = base - ph * b[k] / top
                self.create_rectangle(x0, y1, x0 + bw, base, fill=OUTCOME_COLOR[k], outline="")
                base = y1
            if b["alerts"]:
                cx, cy = x0 + bw / 2, T - 9
                self.create_polygon(cx, cy - 5, cx + 5, cy, cx, cy + 5, cx - 5, cy, fill=SEV_COLOR["HIGH"], outline=WHITE)
        self.create_text(4, T - 9, text="alerts", anchor="w", fill=BLUE_MUTED, font=(UI_FONT, 7))
        x = L
        for k in self.ORDER:
            self.create_rectangle(x, 7, x + 9, 16, fill=OUTCOME_COLOR[k], outline="")
            self.create_text(x + 13, 11, text=OUTCOME_LABEL[k], anchor="w", fill=BLUE_TEXT, font=(UI_FONT, 8)); x += 22 + 7 * len(OUTCOME_LABEL[k])
        fmt = "%a %H:%M" if window > 21600 else "%H:%M"
        for i in range(5):
            f = i / 4; ts = buckets[0]["t0"] + f * (buckets[-1]["t0"] + window / n - buckets[0]["t0"])
            self.create_text(L + f * pw, h - 9, text=_fmt_ts(ts, fmt), anchor="e" if i == 4 else "w" if i == 0 else "center", fill=BLUE_MUTED, font=(UI_FONT, 7))


class HBars(_Chart):
    ROW = 26

    def set_rows(self, rows, empty="Nothing to show", vmax=None):
        self.configure(height=max(34, self.ROW * len(rows) + 6) if rows else 34)
        self.set(rows=rows, empty=empty, vmax=vmax)

    def _paint(self, w, h, rows=(), empty="", vmax=None):
        if not rows: return self._empty(w, h, empty)
        vmax = vmax or max(r[1] for r in rows) or 1
        lw = min(130, int(w * 0.34)); rw = min(int(w * 0.45), max(34, 6 * max(len(r[3]) for r in rows) + 12)); bx0, bx1 = lw + 6, w - rw - 4
        for i, (label, value, color, note) in enumerate(rows):
            y = 4 + i * self.ROW + self.ROW / 2
            self.create_text(2, y, text=(label if len(label) <= 17 else label[:16] + "…"), anchor="w", fill=BLUE_TEXT, font=(UI_FONT, 9))
            self.create_rectangle(bx0, y - 5, bx1, y + 5, fill=BLUE_SOFT, outline="")
            if value > 0: self.create_rectangle(bx0, y - 5, bx0 + max(3, (bx1 - bx0) * min(1, value / vmax)), y + 5, fill=color, outline="")
            self.create_text(w - 2, y, text=note, anchor="e", fill=BLUE_MUTED, font=(UI_FONT, 8))


class Gauge(_Chart):
    def _paint(self, w, h, score=0, level="", color=BLUE):
        cy = h - 50; r = max(30, min(w / 2 - 16, cy - 8)); cx = w / 2
        box = (cx - r + 7, cy - r + 7, cx + r - 7, cy + r - 7)
        prev = 0
        for limit, _n, c in SIEM_THREAT_LEVELS:
            top = min(limit, 100)
            self.create_arc(*box, start=180 - prev * 1.8, extent=-(top - prev) * 1.8, style="arc", outline=_tint(c, 0.35), width=14); prev = top
        a = math.radians(180 - max(0, min(100, score)) * 1.8)
        self.create_line(cx, cy, cx + (r - 20) * math.cos(a), cy - (r - 20) * math.sin(a), fill=BLUE_DARK, width=3)
        self.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, fill=BLUE_DARK, outline=WHITE)
        self.create_text(cx, cy + 20, text=str(score), fill=color, font=(UI_FONT, 20, "bold"))
        self.create_text(cx, cy + 40, text=level, fill=color, font=(UI_FONT, 9, "bold"))
        self.create_text(cx - r + 7, cy + 12, text="0", fill=BLUE_MUTED, font=(UI_FONT, 7)); self.create_text(cx + r - 7, cy + 12, text="100", fill=BLUE_MUTED, font=(UI_FONT, 7))


class ChainRibbon(_Chart):
    def _paint(self, w, h, blocks=()):
        if not blocks: return self._empty(w, h, "The audit chain is empty")
        n = len(blocks); gap = 18; bw = (w - 8 - gap * (n - 1)) / n
        for i, b in enumerate(blocks):
            x0 = 4 + i * (bw + gap); col = OK_GREEN if b["ok"] else BAD_RED
            if i: self.create_line(x0 - gap, h / 2, x0, h / 2, fill=col, width=2)
            self.create_rectangle(x0, 6, x0 + bw, h - 6, fill=_tint(col, 0.92), outline=col, width=2)
            self.create_text(x0 + bw / 2, h / 2 - 8, text=f"#{b['seq']}", fill=BLUE_DARK, font=(UI_FONT, 9, "bold"))
            self.create_text(x0 + bw / 2, h / 2 + 9, text=b["hash"][:8] or "–", fill=BLUE_MUTED, font=("Consolas", 8))


class _KpiTile(tk.Frame):
    def __init__(self, parent, caption):
        super().__init__(parent, background=BLUE_LINE, bd=0, highlightthickness=0)
        inner = tk.Frame(self, background=WHITE); inner.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Label(inner, text=caption.upper(), font=(UI_FONT, 8, "bold"), foreground=BLUE_MUTED, background=WHITE, anchor="w").pack(fill="x", padx=12, pady=(9, 0))
        self.v_val, self.v_sub = tk.StringVar(value="–"), tk.StringVar()
        self.val = tk.Label(inner, textvariable=self.v_val, font=(UI_FONT, 22, "bold"), foreground=BLUE_DARK, background=WHITE, anchor="w"); self.val.pack(fill="x", padx=12)
        self.sub = tk.Label(inner, textvariable=self.v_sub, font=(UI_FONT, 8), foreground=BLUE_MUTED, background=WHITE, anchor="w"); self.sub.pack(fill="x", padx=12, pady=(0, 9))

    def set(self, value, sub="", sub_color=BLUE_MUTED, value_color=BLUE_DARK):
        self.v_val.set(str(value)); self.v_sub.set(sub); self.sub.configure(foreground=sub_color); self.val.configure(foreground=value_color)


def _delta(cur, prev, polarity="bad_up"):
    """-> (text, colour). Increases are painted red because every tile that uses this is a 'bad if up' count."""
    if prev is None: return "no earlier data", BLUE_MUTED
    if cur == prev: return "same as previous window", BLUE_MUTED
    if not prev: return "▲ from 0 in previous window", BAD_RED
    pct = round(abs(cur - prev) * 100 / prev); up = cur > prev
    return f"{'▲' if up else '▼'} {pct}% vs previous window", BAD_RED if up else OK_GREEN


def daily_summary_text(now=None):
    """The manager's 24-hour summary. 'Access events' are access decisions only: logins, admin changes and manager
    responses are counted separately (they used to be lumped into the access numbers)."""
    now = time.time() if now is None else now; since = now - 86400
    rows = [e for e in list(LOG) if _evt_epoch(e) >= since]
    access = [e for e in rows if siem_category(e) == "Access"]
    counts = Counter(str(e.get("decision", "UNKNOWN")) for e in access)
    failed_logins = sum(1 for e in rows if e.get("resource") in SIEM_AUTH_FAIL_RES and e.get("decision") == "DENY")
    pending = count_pending_signins()
    alerts = [a for a in recent_alerts(limit=500) if _evt_epoch(a) >= since]
    high = sum(1 for a in alerts if str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL"))
    return (f"Last 24 hours\n\nAccess events: {len(access)}\nAllowed: {counts.get('ALLOW', 0)}\n"
            f"Step-up: {counts.get('STEPUP', 0)}\nDenied: {counts.get('DENY', 0)}\nFailed sign-ins: {failed_logins}\n"
            f"Alerts: {len(alerts)} (high/critical: {high})\nPending sign-in requests: {pending}\n"
            f"Audit integrity: {'verified' if verify_chain().get('ok') else 'CHECK REQUIRED'}")


class SiemDashboard(tk.Frame):
    """Manager-console security dashboard: metrics, event stream, threat monitoring, alerts, audit integrity."""
    STREAM_LIMIT = 100
    AUTO_VERIFY_S = 300

    def __init__(self, parent, portal):
        super().__init__(parent, background=WHITE, bd=0, highlightthickness=0)
        self.p = portal
        self.window_s = 3600
        self.paused = False; self._pause_ids = set(); self._prev_ids = None; self._sig = None
        self.verifier = _Verifier(); self.integrity_ok = None; self._verify_detail = ("", []); self._verified_at = None
        self._failure_shown = False; self._last_verify_start = time.time()
        self.snap = None; self._seen_alert_ids = None; self._had_fresh = False
        self._build()
        self.verifier.start()
        self.refresh()
        self.p._schedule("siem", 2000, self._tick)

    # ---- layout
    def _section(self, title, subtitle, badge=None):
        box = ttk.Frame(self.page.body); box.pack(fill="x", pady=(16, 0), padx=2)
        head = ttk.Frame(box); head.pack(fill="x", pady=(0, 6))
        ttk.Label(head, text=title, style="Section.TLabel").pack(side="left")
        if badge is not None: ttk.Label(head, textvariable=badge, style="Accent.TLabel").pack(side="left", padx=(8, 0), pady=(3, 0))
        ttk.Label(head, text=subtitle, style="Muted.TLabel").pack(side="left", padx=(10, 0), pady=(3, 0))
        inner = ttk.Frame(box); inner.pack(fill="x")
        return inner

    def _build(self):
        self.page = ScrollFrame(self); self.page.pack(fill="both", expand=True)
        body = self.page.body; body.configure(padding=(4, 4, 10, 16))
        self.banner = tk.Label(body, text="", background=BAD_RED, foreground=WHITE, font=(UI_FONT, 10, "bold"), anchor="w", justify="left", padx=14, pady=10, wraplength=1000)
        bar = ttk.Frame(body); bar.pack(fill="x"); self.toolbar = bar
        self.live = tk.Canvas(bar, width=12, height=12, background=WHITE, bd=0, highlightthickness=0); self.live.pack(side="left", padx=(0, 6), pady=(2, 0))
        self.live.create_oval(1, 1, 11, 11, fill="#16a34a", outline="", tags="dot")
        self.v_updated = tk.StringVar(value="Loading…"); ttk.Label(bar, textvariable=self.v_updated, style="Muted.TLabel").pack(side="left")
        self.cb_window = ttk.Combobox(bar, state="readonly", width=11, values=[n for n, _ in SIEM_WINDOWS]); self.cb_window.set("1 hour")
        self.cb_window.pack(side="right"); self.cb_window.bind("<<ComboboxSelected>>", self._window_changed)
        ttk.Label(bar, text="Time window", style="Muted.TLabel").pack(side="right", padx=(0, 6))
        self.v_trunc = tk.StringVar(); ttk.Label(body, textvariable=self.v_trunc, style="Muted.TLabel").pack(anchor="w")
        self._build_metrics(); self._build_stream(); self._build_threats(); self._build_alerts(); self._build_integrity()

    def _build_metrics(self):
        f = self._section("Security metrics", "for the selected time window")
        grid = ttk.Frame(f); grid.pack(fill="x")
        self.tiles = {}
        for i, (key, label) in enumerate((("deny", "Denied requests"), ("failed_auth", "Failed sign-ins"), ("alerts", "Open alerts"), ("sessions", "Active sessions"))):
            t = _KpiTile(grid, label); self.tiles[key] = t
            t.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0)); grid.columnconfigure(i, weight=1, uniform="kpi")
        panel = Panel(f, "Event volume by outcome", padding=(8, 6)); panel.pack(fill="x", pady=(10, 0))
        self.timeline = TimelineChart(panel.body, 170); self.timeline.pack(fill="both", expand=True)

    def _build_stream(self):
        f = self._section("Event stream", "newest first, from the tamper-evident audit chain")
        bar = ttk.Frame(f); bar.pack(fill="x", pady=(0, 6))
        self.btn_pause = ttk.Button(bar, text="⏸ Pause", command=self._toggle_pause); self.btn_pause.pack(side="left")
        self.v_rate = tk.StringVar(); ttk.Label(bar, textvariable=self.v_rate, style="Muted.TLabel").pack(side="right")
        self.stream = self.p._tree(f, ("time", "sev", "user", "resource", "decision", "what"), ("Time", "Severity", "User", "Resource", "Decision", "What happened"),
                                   (70, 75, 80, 110, 80, 600), stretch="what")
        self.stream.configure(height=9, selectmode="browse")
        for sev, col in SEV_COLOR.items(): self.stream.tag_configure(f"sev_{sev}", foreground=col if sev != "INFO" else BLUE_TEXT)
        for sev in ("HIGH", "CRITICAL"): self.stream.tag_configure(f"sev_{sev}", foreground=SEV_COLOR[sev], font=(UI_FONT, 9, "bold"))
        self.stream.tag_configure("new", background="#fff7d6")

    def _build_threats(self):
        f = self._section("Threat monitoring", "what looks like an attack right now")
        row = ttk.Frame(f); row.pack(fill="x")
        for c, wt in enumerate((4, 4, 3)): row.columnconfigure(c, weight=wt, uniform="thr")
        p1 = Panel(row, "Threat level", padding=(10, 8)); p1.grid(row=0, column=0, sticky="nsew")
        self.gauge = Gauge(p1.body, 178); self.gauge.pack(fill="x")
        self.factor_box = ttk.Frame(p1.body); self.factor_box.pack(fill="x", pady=(4, 0))
        p2 = Panel(row, "Highest-risk identities", padding=(10, 8)); p2.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self.people_bars = HBars(p2.body, 60); self.people_bars.pack(fill="x")
        p3 = Panel(row, "Active containment", padding=(12, 8)); p3.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        self.contain = {}
        for i, (key, label) in enumerate((("blocked", "Blocked devices"), ("stepup", "Forced step-up MFA"), ("grants", "Extra access in use"), ("signins", "Sign-ins waiting"))):
            ttk.Label(p3.body, text=label, style="Strong.TLabel").grid(row=i, column=0, sticky="nw", pady=3, padx=(0, 12))
            v = tk.StringVar(value="–"); ttk.Label(p3.body, textvariable=v, wraplength=170, justify="left").grid(row=i, column=1, sticky="nw", pady=3); self.contain[key] = v
        p3.body.columnconfigure(1, weight=1)

    def _build_alerts(self):
        self.v_alert_badge = tk.StringVar()
        f = self._section("Alerts", "open alerts first", badge=self.v_alert_badge)
        bar = ttk.Frame(f); bar.pack(fill="x", pady=(0, 6))
        self.v_alert_sum = tk.StringVar(); ttk.Label(bar, textvariable=self.v_alert_sum, style="Strong.TLabel").pack(side="left")
        ttk.Button(bar, text="Mark reviewed", command=lambda: self.p._ack_alert(self.al_tree)).pack(side="right")
        ttk.Button(bar, text="False alarm", command=lambda: self.p._alert_outcome("false_alarm", self.al_tree)).pack(side="right", padx=6)
        ttk.Button(bar, text="Confirm incident + sign out", style="Primary.TButton", command=lambda: self.p._alert_outcome("incident_confirmed", self.al_tree)).pack(side="right", padx=6)
        self.al_tree = self.p._tree(f, ("time", "sev", "kind", "user", "device", "state"), ("Time", "Severity", "Alert", "User", "Device", "State"), (70, 75, 330, 90, 120, 60), stretch="kind")
        self.al_tree.configure(height=6, selectmode="browse")
        for sev, col in SEV_COLOR.items(): self.al_tree.tag_configure(f"sev_{sev}", foreground=col)
        self.al_tree.tag_configure("seen", foreground=BLUE_MUTED); self.al_tree.tag_configure("fresh", background="#fff7d6")
        self.al_tree.bind("<<TreeviewSelect>>", self._alert_selected)
        self.v_al_detail = tk.StringVar(value="Select an alert to see why it was raised and what to do.")
        ttk.Label(f, textvariable=self.v_al_detail, style="Muted.TLabel", wraplength=1000, justify="left").pack(anchor="w", pady=(6, 0))

    def _build_integrity(self):
        f = self._section("Audit integrity", "hash chain plus two independent anchors")
        panel = Panel(f, padding=14); panel.pack(fill="x")
        top = ttk.Frame(panel.body); top.pack(fill="x"); top.columnconfigure(1, weight=1)
        self.pill = tk.Label(top, text="NOT VERIFIED", font=(UI_FONT, 11, "bold"), foreground=WHITE, background="#64748b", padx=14, pady=8); self.pill.grid(row=0, column=0, sticky="nw", padx=(0, 16))
        self.v_int_head, self.v_int_lines = tk.StringVar(), tk.StringVar()
        txt = ttk.Frame(top); txt.grid(row=0, column=1, sticky="nw")
        ttk.Label(txt, textvariable=self.v_int_head, style="Strong.TLabel").pack(anchor="w")
        ttk.Label(txt, textvariable=self.v_int_lines, style="Muted.TLabel", wraplength=620, justify="left").pack(anchor="w", pady=(2, 0))
        btns = ttk.Frame(top); btns.grid(row=0, column=2, sticky="ne")
        self.btn_verify = ttk.Button(btns, text="Verify now", style="Primary.TButton", command=self._verify_now); self.btn_verify.pack(side="left")
        ttk.Button(btns, text="Export JSONL", command=self.p._export).pack(side="left", padx=(6, 0))
        self.v_int_facts = tk.StringVar(); ttk.Label(panel.body, textvariable=self.v_int_facts, style="Muted.TLabel").pack(anchor="w", pady=(12, 4))
        self.ribbon = ChainRibbon(panel.body, 62); self.ribbon.pack(fill="x")

    # ---- actions
    def _window_changed(self, _e=None):
        self.window_s = dict(SIEM_WINDOWS).get(self.cb_window.get(), 3600); self._prev_ids = None; self.refresh()

    def _verify_now(self):
        if self.verifier.start(): self._last_verify_start = time.time(); self.btn_verify.state(["disabled"]); self._paint_integrity()

    def _toggle_pause(self):
        self.paused = not self.paused
        if self.paused: self._pause_ids = set(self._prev_ids or ())
        self._paint_stream(force=True)

    def _alert_selected(self, _e=None):
        a = self.p._selected_alert(self.al_tree)
        if not a: return
        title, why, advice = describe_alert(a)
        self.v_al_detail.set(f"{title}. {why}  Detail: {a.get('details') or '–'}  Next step: {advice}")

    # ---- refresh
    def _tick(self):
        try:
            if not self.winfo_exists(): return
            al = recent_alerts(limit=1)
            sig = (AUDIT.get("entries"), al[0]["id"] if al else 0)
            if sig != getattr(self, "_tick_sig", None) or self.verifier.result is not None or self.verifier.running:
                self._tick_sig = sig; self.refresh()
        except tk.TclError: return
        except Exception: logger.exception("SIEM dashboard tick failed")
        self.p._schedule("siem", 2000, self._tick)

    def refresh(self):
        self._poll_verifier()
        self.snap = s = siem_snapshot(self.window_s, integrity_ok=self.integrity_ok)
        self.v_updated.set(f"Live · updated {_fmt_ts(s['now'], '%H:%M:%S')}")
        self.live.itemconfigure("dot", fill="#f59e0b" if self.paused else "#16a34a")
        self.v_trunc.set("Showing the most recent 500 audit entries; the selected window reaches further back than the in-memory log." if s["truncated"] else "")
        self._paint_metrics(s); self._paint_stream(); self._paint_threats(s); self._paint_alerts(s); self._paint_integrity()

    def _poll_verifier(self):
        res = self.verifier.result
        if res is None: return
        self.verifier.result = None
        at, r, _took = res
        ok, headline, lines = verify_report(r) if not r.get("error") else (False, f"Verification error: {r['error']}", [])
        self.integrity_ok = bool(ok); self._verify_detail = (headline, lines); self._verified_at = at
        self.btn_verify.state(["!disabled"])
        if not ok and not self._failure_shown:
            self._failure_shown = True
            try: messagebox.showerror("Audit integrity failure", "The audit chain did not verify. Preserve the original log and anchor files and compare with a trusted backup; do not edit the chain.", parent=self.p)
            except tk.TclError: pass
        if ok: self._failure_shown = False

    def _paint_metrics(self, s):
        cur, prev = s["cur_agg"], s["prev_agg"]
        for key in ("deny", "failed_auth"):
            text, color = _delta(cur[key], prev[key] if prev else None)
            self.tiles[key].set(cur[key], text, color, BAD_RED if cur[key] else BLUE_DARK)
        high = sum(1 for a in s["open_alerts"] if a["_sev"] in ("HIGH", "CRITICAL"))
        self.tiles["alerts"].set(len(s["open_alerts"]), f"{high} high severity" if high else "none high severity", BAD_RED if high else BLUE_MUTED, BAD_RED if high else BLUE_DARK)
        self.tiles["sessions"].set(s["sessions"])
        self.timeline.set(buckets=s["buckets"], window=s["window"])

    def _stream_rows(self, s):
        rows, seen = [], set()
        for x in s["cur"][:self.STREAM_LIMIT]:
            label, sentence = _siem_describe(x["raw"])
            h = str(x["raw"].get("hash", "")); iid = h[:20] or f"e{len(rows)}"
            while iid in seen: iid += "_"
            seen.add(iid)
            rows.append({**x, "iid": iid, "label": label, "sentence": sentence})
        return rows

    def _paint_stream(self, force=False):
        s = self.snap
        if s is None: return
        recent = sum(1 for x in s["cur"] if x["ts"] >= s["now"] - 300)
        self.v_rate.set(f"{recent / 5:.1f} events/min · {len(s['cur'])} in window")
        rows = self._stream_rows(s); ids = {r["iid"] for r in rows}
        if self.paused:
            fresh = len(ids - self._pause_ids)
            self.btn_pause.configure(text=f"▶ Resume ({fresh} new)" if fresh else "▶ Resume"); return
        self.btn_pause.configure(text="⏸ Pause")
        fresh = set() if self._prev_ids is None else ids - self._prev_ids
        self._prev_ids = ids
        tags = [(f"sev_{r['sev']}",) + (("new",) if r["iid"] in fresh else ()) for r in rows]
        sig = (tuple(r["iid"] for r in rows), tuple(tags))
        if sig == self._sig and not force: return
        self._sig = sig
        top = self.stream.yview()[0]
        self.stream.delete(*self.stream.get_children())
        for r, tg in zip(rows, tags):
            self.stream.insert("", "end", iid=r["iid"], tags=tg, values=(_fmt_ts(r["ts"], "%H:%M:%S"), r["sev"], r["user"], r["resource"], r["label"], r["sentence"][:300]))
        self.stream.yview_moveto(top)

    def _paint_threats(self, s):
        th = s["threat"]
        self.gauge.set(score=th["score"], level=th["level"], color=th["color"])
        sig = tuple(th["factors"])
        if sig != getattr(self, "_factor_sig", None):
            self._factor_sig = sig
            for w in self.factor_box.winfo_children(): w.destroy()
            if not th["factors"]: ttk.Label(self.factor_box, text="No open alerts or risky traffic are raising the score.", style="Muted.TLabel", wraplength=260).pack(anchor="w")
            for label, pts, detail in th["factors"]:
                r = ttk.Frame(self.factor_box); r.pack(fill="x", pady=1)
                tk.Label(r, text=f"+{pts}", font=(UI_FONT, 9, "bold"), foreground=th["color"], background=WHITE, width=4, anchor="w").pack(side="left")
                ttk.Label(r, text=f"{label} — {detail}", style="Muted.TLabel", wraplength=250, justify="left").pack(side="left")
        self.people_bars.set_rows([(p["name"], p["score"], SEV_COLOR["HIGH"] if p["score"] >= 60 else SEV_COLOR["MEDIUM"] if p["score"] >= 25 else SEV_COLOR["LOW"],
                                    f"{p['deny']} denied · {p['alerts']} alert{'' if p['alerts'] == 1 else 's'}") for p in s["people"]], "No identities with risk signals", 100)
        c = self.contain
        c["blocked"].set(", ".join(s["blocked"]) or "none"); c["stepup"].set(", ".join(s["stepup_users"]) or "none"); c["signins"].set(str(s["pending"]))
        c["grants"].set(", ".join(f"{u} → {r} ({m} min)" for u, r, m in s["temp_grants"]) or "none")

    def _paint_alerts(self, s):
        al = s["alerts"][:120]
        order = sorted(range(len(al)), key=lambda i: (bool(al[i].get("acknowledged")), -al[i]["_ts"]))
        ids = {a.get("id") for a in al}
        fresh = set() if self._seen_alert_ids is None else ids - self._seen_alert_ids
        self._seen_alert_ids = ids
        rows, tags = [], []
        for i in order:
            a = al[i]; seen = bool(a.get("acknowledged"))
            rows.append((_fmt_ts(a["_ts"], "%H:%M:%S"), a["_sev"], describe_alert(a)[0], a.get("user") or "", a.get("device") or "", {0: "NEW", 1: "REVIEWED", 2: "FALSE ALARM", 3: "INCIDENT"}.get(a.get("status", 0), "SEEN")))
            base = ("seen",) if seen or a["_sev"] not in SEV_COLOR else (f"sev_{a['_sev']}",)
            tags.append(base + (("fresh",) if a.get("id") in fresh and not seen else ()))
        # tags are not part of _fill_tree's change signature, so make a highlight change count as a change
        if fresh or self._had_fresh: self.al_tree._sig = None
        self._had_fresh = bool(fresh)
        self.p._fill_tree(self.al_tree, rows, iids=[str(al[i].get("id", "")) for i in order], tags=tags)
        n_open = len(s["open_alerts"]); high = sum(1 for a in s["open_alerts"] if a["_sev"] in ("HIGH", "CRITICAL"))
        text = f"{n_open} open ({high} high)" if n_open else "No open alerts"
        self.v_alert_sum.set(text + (f"  ·  {len(fresh)} new just now" if fresh else ""))
        self.v_alert_badge.set(f"● {n_open}" if n_open else "")

    def _paint_integrity(self):
        st = siem_integrity_state(); running = self.verifier.running
        if running: pill, color, head, lines = "VERIFYING…", "#2563eb", "Scanning every entry and both anchors", []
        elif self.integrity_ok is None: pill, color, head, lines = "NOT VERIFIED", "#64748b", "No full verification has finished yet", []
        else:
            head, lines = self._verify_detail
            pill, color = ("CHAIN INTACT", OK_GREEN) if self.integrity_ok else ("CHAIN BROKEN", BAD_RED)
        self.pill.configure(text=pill, background=color); self.v_int_head.set(head); self.v_int_lines.set("\n".join(lines))
        if self.integrity_ok is False and not running:
            self.banner.configure(text=f"AUDIT INTEGRITY FAILURE — {head}. Preserve the audit log and both anchor files as they are; do not edit hashes to force a pass.")
            if not self.banner.winfo_ismapped(): self.banner.pack(fill="x", pady=(0, 8), before=self.toolbar)
        elif self.banner.winfo_ismapped(): self.banner.pack_forget()
        verified = _fmt_ts(self._verified_at, "%H:%M:%S") if self._verified_at else "never"
        self.v_int_facts.set(f"{st['entries']:,} entries · last full verification {verified} · anchors {'present' if st['anchors'] else 'MISSING'} · recent links {'consistent' if st['linked'] else 'BROKEN'} · latest 8 entries, newest at right:")
        self.ribbon.set(blocks=st["blocks"])
        if self.AUTO_VERIFY_S and not running and time.time() - self._last_verify_start >= self.AUTO_VERIFY_S:
            self._last_verify_start = time.time(); self.verifier.start()


# ------------------------------------------------------------------------------ manager side
class ManagerPortal(PortalWindow):
    MANAGER_DEMO_USER = "puja"
    MANAGER_DEMO_PASSWORD = "puja123"

    def __init__(self, app):
        super().__init__(app, "ZTNA Access Workspace — Manager Console", "1180x780", (940, 640))
        self.manager_user = None
        self._seen_pending = set()
        self._show_login()

    def _show_login(self):
        self._clear(); self.title("ZTNA Access Workspace — Manager sign-in")
        self._band("ZTNA manager console", "")
        wrap = ttk.Frame(self, padding=(30, 26)); wrap.pack(fill="both", expand=True)
        panel = Panel(wrap, "Operator authentication", padding=22); panel.pack(pady=4)
        g = panel.body; g.columnconfigure(1, weight=1)
        self.v_mu, self.v_mp = tk.StringVar(), tk.StringVar()
        eu = self._form_row(g, 0, "Manager username", lambda p: ttk.Entry(p, textvariable=self.v_mu, width=34))
        self._form_row(g, 1, "Password", lambda p: ttk.Entry(p, textvariable=self.v_mp, show="•", width=34))
        ttk.Separator(g).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 12))
        a = ttk.Frame(g); a.grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Button(a, text="Close", command=self.close).pack(side="left")
        ttk.Button(a, text="Sign in to manager console", style="Primary.TButton", command=self._signin).pack(side="right")
        self.bind("<Return>", lambda _e: self._signin())
        eu.focus_set()

    def _signin(self):
        u, p = self.v_mu.get().strip(), self.v_mp.get()
        if DEMO: eu, ep = self.MANAGER_DEMO_USER, self.MANAGER_DEMO_PASSWORD
        else: eu, ep = os.environ.get("ZTNA_MANAGER_USER", ""), os.environ.get("ZTNA_MANAGER_PASSWORD", "")
        ok = bool(eu and ep and (_ct_eq(u, eu) & _ct_eq(p, ep)))
        if not ok:
            try: audit(user=u or "unknown", device="manager-desktop", resource="manager-login", decision="DENY", reasons=["manager authentication failed"])
            except Exception: pass
            messagebox.showerror("Sign in failed", "Manager credentials were not accepted.", parent=self); return
        try: audit(user=u, device="manager-desktop", resource="manager-login", decision="ALLOW", reasons=["manager authentication verified"])
        except (AuditFull, AuditTamper):
            messagebox.showerror("Audit unavailable", "The audit system is unavailable, so manager access is refused. Preserve the log and investigate integrity before retrying.", parent=self); return
        self.unbind("<Return>")
        self.manager_user = u
        self._show_workspace()

    def _show_workspace(self):
        self._clear(); self.title("ZTNA Access Workspace — Manager Console")
        right = self._band("Security operations center", f"Signed in as {self.manager_user}")
        self.v_badge = tk.StringVar()
        ttk.Label(right, textvariable=self.v_badge, style="BandSub.TLabel", font=(UI_FONT, 10, "bold")).pack(side="left", padx=(0, 14))
        ttk.Button(right, text="Sign out", style="Ghost.TButton", command=self._sign_out).pack(side="left")
        wrap = ttk.Frame(self, padding=(18, 14, 18, 16)); wrap.pack(fill="both", expand=True)
        self.nb = ttk.Notebook(wrap); self.nb.pack(fill="both", expand=True)
        self._dev_sig = None
        for build in (self._tab_dashboard, self._tab_requests, self._tab_exceptions, self._tab_overview, self._tab_events, self._tab_sessions, self._tab_identity,
                      self._tab_posture, self._tab_policies, self._tab_alerts, self._tab_audit):
            build()
        self._refresh()

    def _tab(self, text):
        t = ttk.Frame(self.nb, padding=14); self.nb.add(t, text=text); return t

    def _tab_dashboard(self):
        t = ttk.Frame(self.nb, padding=(6, 8, 2, 4)); self.nb.add(t, text="Dashboard"); self.t_dashboard = t
        self.siem = SiemDashboard(t, self); self.siem.pack(fill="both", expand=True)

    # ---- sign-in requests
    def _tab_requests(self):
        t = self._tab("Sign-in requests"); self.t_requests = t
        top = ttk.Frame(t); top.pack(fill="x", pady=(0, 10))
        self.v_req_sum = tk.StringVar()
        ttk.Label(top, textvariable=self.v_req_sum, style="Section.TLabel").pack(side="left")
        self.v_req_view = tk.StringVar(value="Waiting"); self.rb_view = {}
        views = ttk.Frame(top); views.pack(side="right")
        ttk.Label(views, text="Show:", style="Muted.TLabel").pack(side="left", padx=(0, 4))
        for name in ("Waiting", "History", "All"):
            rb = ttk.Radiobutton(views, text=name, value=name, variable=self.v_req_view, command=self._refresh); rb.pack(side="left", padx=6); self.rb_view[name] = rb
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 10))
        self.btn_approve = ttk.Button(bar, text="Approve selected", style="Primary.TButton", command=lambda: self._decide(True))
        self.btn_approve.pack(side="left")
        self.btn_deny = ttk.Button(bar, text="Deny selected", command=lambda: self._decide(False)); self.btn_deny.pack(side="left", padx=8)
        ttk.Button(bar, text="Approve low-risk managed", command=self._approve_managed).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="Export CSV", command=self._export_signins).pack(side="left", padx=(0, 8))
        ttk.Label(bar, text="Filter:", style="Muted.TLabel").pack(side="left", padx=(4, 4))
        self.v_req_filter = tk.StringVar()
        ent_filter = ttk.Entry(bar, textvariable=self.v_req_filter, width=18); ent_filter.pack(side="left")
        ent_filter.bind("<KeyRelease>", lambda _e: self._refresh())
        ttk.Label(bar, text="Reason (optional):", style="Muted.TLabel").pack(side="left", padx=(16, 6))
        self.v_note = tk.StringVar(); ttk.Entry(bar, textvariable=self.v_note, width=34).pack(side="left")
        self.v_req_context = tk.StringVar(value="Select a request to see its context (waiting) or its full timeline (decided).")
        ttk.Label(t, textvariable=self.v_req_context, style="Muted.TLabel", wraplength=1100, justify="left").pack(side="bottom", fill="x", pady=(8, 0))
        self.req_tree = self._tree(t, ("time", "emp", "name", "role", "dev", "trust", "loc", "status", "outcome", "by", "at", "note"),
                                   ("Requested", "Employee", "Name", "Role", "Device", "Health", "Network", "Status", "Outcome", "Decided by", "Decided / closed", "Reason"),
                                   (140, 70, 115, 70, 105, 60, 65, 80, 270, 80, 140, 200), stretch="note")
        self.req_tree.bind("<<TreeviewSelect>>", lambda _e: (self._sync_buttons(), self._request_context()))
        self.req_tree.bind("<Double-1>", lambda _e: self._request_context())

    @staticmethod
    def _dur(seconds):
        seconds = max(0, int(seconds))
        return f"{seconds} s" if seconds < 60 else f"{seconds // 60} min {seconds % 60} s" if seconds < 3600 else f"{seconds // 3600} h {seconds % 3600 // 60} min"

    def _signin_timeline(self, r):
        steps = [f"Requested {_fmt_ts(r['ts'])} from {r['device']} ({r['location']})"]
        if r.get("decided_by") and r.get("decided_at"):
            word = "denied" if r["status"] == "denied" else "approved"
            steps.append(f"{word} by {r['decided_by']} at {_fmt_ts(r['decided_at'])}, {self._dur(r['decided_at'] - r['ts'])} after the request")
        if r.get("note"): steps.append(f"reason given: \"{r['note']}\"")
        end = f" ({_fmt_ts(r['closed_at'])})" if r.get("closed_at") else ""
        steps.append(f"outcome: {signin_outcome(r)}{end}")
        return "  →  ".join(steps)

    def _request_context(self):
        sel = self.req_tree.selection() if hasattr(self, "req_tree") else ()
        if not sel: return
        row = get_signin_request(sel[0])
        if not row: return
        if row["status"] != "pending":
            self.v_req_context.set("Timeline: " + self._signin_timeline(row)); return
        user, device = row.get("user", ""), row.get("device", "")
        fails = recent_fails(user, "desktop") if user else 0
        previous = LASTLOC.get(user)
        location_note = "no recent location change recorded"
        if previous and time.time() - previous[1] < 3600:
            location_note = f"last observed location {previous[0]} at {_fmt_ts(previous[1])}"
        approved = _db_connection().execute("SELECT MAX(decided_at) FROM signin_requests WHERE user=? AND status='approved'", (user,)).fetchone()[0]
        approved_note = _fmt_ts(approved) if approved else "never"
        health = posture(device) if device in DEVICES else 0
        managed = bool(DEVICES.get(device, {}).get("corporate_managed"))
        self.v_req_context.set(f"Context: {fails} recent failed authentication(s) · device {'managed' if managed else 'BYOD/unknown'} · health {health}/100 · {location_note} · last manager approval: {approved_note}. Review context before approving.")

    def _approve_managed(self):
        eligible = []
        for iid in self.req_tree.get_children():
            if self.req_tree.set(iid, "status") != "PENDING": continue
            row = get_signin_request(iid)
            d = DEVICES.get(row.get("device", ""), {}) if row else {}
            if row and row.get("location") == "office" and d.get("corporate_managed") and posture(row.get("device", "")) >= 90 and row.get("device") not in BLOCKED_DEVICES:
                eligible.append(iid)
        if not eligible:
            messagebox.showinfo("Low-risk approvals", "No pending request meets all criteria: office connection, managed device, health ≥90, and not blocked.", parent=self); return
        if not messagebox.askyesno("Approve low-risk requests", f"Approve {len(eligible)} request(s) from managed devices with health ≥90 on the office network?", parent=self): return
        done = 0
        for rid in eligible:
            try:
                if decide_signin_request(rid, True, self.manager_user, "Bulk approved: office + managed device + health >= 90"): done += 1
            except (AuditFull, AuditTamper, StateStoreError) as exc:
                messagebox.showerror("Audit failure", str(exc), parent=self); break
        self._refresh()
        messagebox.showinfo("Low-risk approvals", f"Approved {done} request(s).", parent=self)

    def _export_signins(self):
        from tkinter import filedialog
        target = filedialog.asksaveasfilename(parent=self, title="Export sign-in requests", defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="ztna_signin_requests.csv")
        if not target: return
        try:
            with open(target, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f); w.writerow(_SIGNIN_COLS + ("outcome",))
                for row in list_signin_requests(100000):
                    w.writerow([(_fmt_ts(row[k]) if k in ("ts", "decided_at", "closed_at") and row.get(k) else row.get(k, "")) for k in _SIGNIN_COLS] + [signin_outcome(row)])
            messagebox.showinfo("Export complete", f"Sign-in requests exported to:\n{target}", parent=self)
        except OSError as exc: messagebox.showerror("Export failed", str(exc), parent=self)

    def _sync_buttons(self):
        ok = any(self.req_tree.set(i, "status") == "PENDING" for i in self.req_tree.selection())
        for b in (self.btn_approve, self.btn_deny): b.state(["!disabled"] if ok else ["disabled"])

    def _decide(self, approve):
        ids = [i for i in self.req_tree.selection() if self.req_tree.set(i, "status") == "PENDING"]
        if not ids:
            messagebox.showinfo("Sign-in requests", "Select a pending request first.", parent=self); return
        done = 0
        for rid in ids:
            try:
                if decide_signin_request(rid, approve, self.manager_user, self.v_note.get().strip()): done += 1
            except (AuditFull, AuditTamper, StateStoreError):
                messagebox.showerror("Audit failure", "The decision could not be recorded in the audit log, so it was not applied.", parent=self); break
        self.v_note.set(""); self._refresh()
        if done < len(ids): messagebox.showinfo("Sign-in requests", "Some requests were already handled or expired.", parent=self)

    def _tab_exceptions(self):
        t = self._tab("App exceptions"); self.t_exceptions = t
        top = ttk.Frame(t); top.pack(fill="x", pady=(0, 8))
        self.v_exc_sum = tk.StringVar(); ttk.Label(top, textvariable=self.v_exc_sum, style="Section.TLabel").pack(side="left")
        ttk.Button(top, text="Approve 1 hour", style="Primary.TButton", command=lambda: self._decide_exception(True)).pack(side="right")
        ttk.Button(top, text="Deny", command=lambda: self._decide_exception(False)).pack(side="right", padx=6)
        self.v_exc_detail = tk.StringVar(value="Every request raises an alert. Your decision closes it, and the outcome is tracked here until the access ends.")
        ttk.Label(t, textvariable=self.v_exc_detail, style="Muted.TLabel", wraplength=1100, justify="left").pack(side="bottom", fill="x", pady=(8, 0))
        self.exc_tree = self._tree(t, ("time","user","role","resource","device","reason","status","alert","outcome","by","expires"),
                                   ("Requested","User","Role","Application","Device","Business reason","Status","Alert","Outcome","Decided by","Access ends"),
                                   (140,70,80,110,110,230,80,110,230,80,130), stretch="reason")
        self.exc_tree.bind("<<TreeviewSelect>>", lambda _e: self._exception_detail())
        self._exc_rows = {}

    def _exception_detail(self):
        sel = self.exc_tree.selection(); r = self._exc_rows.get(sel[0]) if sel else None
        if not r: return
        steps = [f"Requested {_fmt_ts(r['ts'])} by {_person(r['user'])[0]} for {r['resource']}: \"{r['reason']}\""]
        if r.get("decided_by") and r.get("decided_at"): steps.append(f"{'denied' if r['status'] == 'denied' else 'approved'} by {r['decided_by']} at {_fmt_ts(r['decided_at'])}")
        steps.append(f"outcome: {exception_outcome(r)}" + (f" ({_fmt_ts(r['closed_at'])})" if r.get("closed_at") else ""))
        self.v_exc_detail.set("Timeline: " + "  →  ".join(steps))

    def _decide_exception(self, approve):
        selected = self.exc_tree.selection()
        if not selected: messagebox.showinfo("App exceptions", "Select a request first.", parent=self); return
        done = 0
        for rid in selected:
            try:
                row = decide_access_exception_request(rid, approve, self.manager_user, 3600)
                if row: done += 1
            except (AuditFull, AuditTamper, StateStoreError) as exc:
                messagebox.showerror("Audit failure", str(exc), parent=self); break
        self._refresh()
        messagebox.showinfo("App exceptions", f"{'Approved for one hour' if approve else 'Denied'}: {done} request(s).", parent=self)

    # ---- other tabs
    def _tab_overview(self):
        t = self._tab("Overview")
        tiles = ttk.Frame(t); tiles.pack(fill="x", pady=(0, 14))
        self.v_kpi = {k: tk.StringVar(value="–") for k in ("events", "allow", "stepup", "deny", "risk", "alerts", "sessions", "pending")}
        for i, (key, label) in enumerate((("events", "Decisions (60 min)"), ("allow", "Allowed"), ("stepup", "Step-up"), ("deny", "Denied"),
                                          ("risk", "Average risk"), ("alerts", "Alerts"), ("sessions", "Active sessions"), ("pending", "Sign-ins waiting"))):
            p = Panel(tiles, label, padding=(12, 8)); p.grid(row=i // 4, column=i % 4, sticky="nsew", padx=(0 if i % 4 == 0 else 8, 0), pady=(0 if i < 4 else 8, 0))
            tiles.columnconfigure(i % 4, weight=1, uniform="kpi")
            ttk.Label(p.body, textvariable=self.v_kpi[key], style="Big.TLabel").pack(anchor="w")
        ttk.Label(t, text="Recent decisions", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.ov_tree = self._tree(t, ("time", "user", "resource", "decision", "risk"), ("Time", "Identity", "Resource", "Decision", "Risk"), (150, 110, 160, 100, 70))

    def _tab_events(self):
        t = self._tab("Events")
        self.v_ev_filter = tk.StringVar(); efilter = ttk.Entry(t, textvariable=self.v_ev_filter); efilter.pack(fill="x", pady=(0, 8)); efilter.bind("<KeyRelease>", lambda _e: self._refresh())
        self.ev_tree = self._tree(t, ("time", "user", "device", "resource", "decision", "what"), ("Time", "User", "Device", "Resource", "Decision", "What happened"), (150, 90, 120, 130, 90, 500), stretch="what")

    def _tab_sessions(self):
        t = self._tab("Sessions")
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="Revoke selected session", style="Primary.TButton", command=self._revoke).pack(side="left")
        ttk.Button(bar, text="Sign user out everywhere", command=self._signout_everywhere).pack(side="left", padx=6)
        ttk.Button(bar, text="Require step-up MFA", command=self._require_stepup).pack(side="left", padx=6)
        ttk.Button(bar, text="Block selected device", command=self._block_selected_device).pack(side="left", padx=6)
        self.ss_tree = self._tree(t, ("sid", "user", "device", "loc", "exp", "mfa"), ("Session", "User", "Device", "Connection", "Expires in", "MFA age"), (170, 110, 140, 100, 100, 100), stretch="mfa")

    def _revoke(self):
        sel = self.ss_tree.selection()
        if not sel: messagebox.showinfo("Revoke session", "Select an active session first.", parent=self); return
        for sid in sel:
            with LOCK: sess = SESSIONS.pop(sid, None)
            if not sess: continue
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?", (sid,))
            try: audit(user=self.manager_user, device="manager-desktop", resource="session", decision="REVOKE", reasons=[f"manager revoked session for {sess.get('user', 'unknown')}"], risk=0)
            except (AuditFull, AuditTamper): messagebox.showerror("Audit failure", "The session was removed, but the audit write failed. Preserve logs and investigate.", parent=self)
        self._refresh()

    def _selected_session_values(self):
        sel = self.ss_tree.selection()
        if not sel: return None, None, None
        sid = sel[0]
        with LOCK: sess = SESSIONS.get(sid)
        if not sess: return sid, None, None
        return sid, sess.get("user"), sess.get("device")

    def _signout_everywhere(self):
        _sid, user, _dev = self._selected_session_values()
        if not user: messagebox.showinfo("Sign out everywhere", "Select a live session first.", parent=self); return
        n, err = revoke_user_sessions_report(user)
        if err: messagebox.showwarning("Sign out everywhere", f"{n} live session(s) were ended, but the revocation could not be saved to the database ({err}). Retry once the database is healthy.", parent=self)
        try: audit(user=self.manager_user, device="manager-desktop", resource="sessions", decision="REVOKE", reasons=[f"manager signed out {user} everywhere ({n} session(s))"])
        except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit failure", str(exc), parent=self)
        publish_gui_event("sessions-revoked", user=user)
        self._refresh()

    def _require_stepup(self):
        _sid, user, _dev = self._selected_session_values()
        if not user: messagebox.showinfo("Require step-up", "Select a live session first.", parent=self); return
        STEPUP_REQUIRED_USERS.add(user)
        try: audit(user=self.manager_user, device="manager-desktop", resource="stepup-control", decision="POLICY", reasons=[f"manager required fresh MFA for {user} on next application request"])
        except (AuditFull, AuditTamper) as exc:
            STEPUP_REQUIRED_USERS.discard(user); messagebox.showerror("Audit failure", str(exc), parent=self); return
        publish_gui_event("stepup-required", user=user)
        messagebox.showinfo("Step-up required", f"{user} must verify fresh MFA before the next application request.", parent=self)

    def _block_selected_device(self):
        _sid, _user, device = self._selected_session_values()
        if not device: messagebox.showinfo("Block device", "Select a live session first.", parent=self); return
        if not messagebox.askyesno("Block device", f"Block {device} and terminate its active sessions?", parent=self): return
        try: set_device_blocked(device, True, actor=self.manager_user)
        except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit failure", str(exc), parent=self); return
        self._refresh()
        messagebox.showinfo("Device blocked", f"{device} is blocked for this running lab session.", parent=self)

    def _tab_identity(self):
        t = self._tab("Identity")
        self.id_tree = self._tree(t, ("user", "name", "role", "dept", "res", "seg"), ("User", "Name", "Role", "Department", "Eligible applications", "Segments"), (80, 140, 90, 120, 340, 260), stretch="res")

    DEVICE_CHECKS = (("os_updated", "OS current"), ("disk_encrypted", "Disk encrypted"), ("firewall", "Firewall"), ("antivirus", "Antivirus"), ("corporate_managed", "Managed"))

    def _tab_posture(self):
        t = self._tab("Devices")
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        self.v_dev_sum = tk.StringVar(); ttk.Label(bar, textvariable=self.v_dev_sum, style="Strong.TLabel").pack(side="left")
        self.v_dev_filter = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.v_dev_filter, width=26); e.pack(side="right"); e.bind("<KeyRelease>", lambda _e: self._refresh_posture())
        ttk.Label(bar, text="Find employee or device", style="Muted.TLabel").pack(side="right", padx=(0, 6))
        ttk.Label(t, text=("Every employee and the devices enrolled to them. Click a PASS/FAIL cell to flip that check (lab only)." if DEMO
                           else "Every employee and the devices enrolled to them. Posture is read-only: it comes from endpoint attestation."), style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        frame = ttk.Frame(t); frame.pack(fill="both", expand=True)
        cols = ("role", "dept", "health", "os_updated", "disk_encrypted", "firewall", "antivirus", "corporate_managed", "status")
        tree = ttk.Treeview(frame, columns=cols, show="tree headings", selectmode="browse")
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview); x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew"); y.grid(row=0, column=1, sticky="ns"); x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        heads = {"role": ("Role", 80), "dept": ("Department", 110), "health": ("Health", 80), "status": ("Status", 130)}
        tree.heading("#0", text="Employee / device", anchor="w"); tree.column("#0", width=230, minwidth=160, anchor="w", stretch=False)
        for c in cols:
            title, width = heads.get(c) or (dict(self.DEVICE_CHECKS)[c], 95)
            tree.heading(c, text=title, anchor="w"); tree.column(c, width=width, minwidth=60, anchor="w", stretch=(c == "status"))
        tree.tag_configure("emp", font=(UI_FONT, 9, "bold"), foreground=BLUE_DARK, background=BLUE_PALE)
        tree.tag_configure("nodev", foreground=BLUE_MUTED, background=BLUE_PALE, font=(UI_FONT, 9, "bold"))
        tree.tag_configure("weak", foreground=BAD_RED); tree.tag_configure("blocked", foreground=BAD_RED, font=(UI_FONT, 9, "bold"))
        tree.tag_configure("waiting", foreground=BLUE_MUTED)
        self.dev_tree = tree; self._dev_sig = None
        if DEMO: tree.bind("<Button-1>", self._device_click)

    def _tab_policies(self):
        t = self._tab("Policies")
        right = Panel(t, "Edit policy", padding=16); right.pack(side="right", fill="y", padx=(14, 0))
        left = ttk.Frame(t); left.pack(side="left", fill="both", expand=True)
        self.pol_tree = self._tree(left, ("res", "roles", "score", "managed", "hours", "mfa"), ("Application", "Roles", "Health", "Managed", "Hours", "MFA min"), (115, 200, 55, 70, 90, 60), stretch="roles")
        self.pol_tree.configure(selectmode="browse")
        self.pol_tree.bind("<<TreeviewSelect>>", lambda _e: self._load_policy())
        g = right.body
        self.v_pol = {k: tk.StringVar() for k in ("res", "score", "mfa", "start", "end")}; self.v_managed = tk.BooleanVar()
        ttk.Label(g, textvariable=self.v_pol["res"], style="Section.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        for i, (label, key) in enumerate((("Min health score", "score"), ("MFA age (sec)", "mfa"), ("From hour (0–23)", "start"), ("Until hour (1–24)", "end")), 1):
            ttk.Label(g, text=label).grid(row=i, column=0, sticky="w", pady=6, padx=(0, 10))
            ttk.Entry(g, textvariable=self.v_pol[key], width=10).grid(row=i, column=1, sticky="w", pady=6)
        ttk.Checkbutton(g, text="Managed device only", variable=self.v_managed).grid(row=5, column=0, columnspan=2, sticky="w", pady=8)
        ttk.Button(g, text="Save policy", style="Primary.TButton", command=self._save_policy).grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 4))
        self._policy_sel = None

    def _policy_rows(self):
        rows = []
        for n, r in RESOURCES.items():
            rows.append((n, ", ".join(r["roles"]), r["min_posture"], "yes" if r["managed"] else "no", _fmt_hours(r), r["mfa_age"] // 60))
        return rows

    def _load_policy(self):
        sel = self.pol_tree.selection()
        if not sel: return
        name = self.pol_tree.item(sel[0], "values")[0]
        r = RESOURCES[name]; self._policy_sel = name
        self.v_pol["res"].set(name)
        self.v_pol["score"].set(str(r.get("min_posture", 0))); self.v_pol["mfa"].set(str(r.get("mfa_age", 3600)))
        self.v_pol["start"].set(str(r.get("hours", [0, 24])[0])); self.v_pol["end"].set(str(r.get("hours", [0, 24])[1]))
        self.v_managed.set(bool(r.get("managed", False)))

    def _save_policy(self):
        name = self._policy_sel
        if not name: messagebox.showinfo("Policy", "Select an application in the table first.", parent=self); return
        try:
            data = {"min_posture": int(self.v_pol["score"].get()), "mfa_age": int(self.v_pol["mfa"].get()),
                    "hours": [int(self.v_pol["start"].get()), int(self.v_pol["end"].get())], "managed": bool(self.v_managed.get())}
            validate_policy_data({name: data})
            RESOURCES[name].update(data); save_policy()
            db_exec("INSERT INTO policy_changes(ts,actor,resource,policy_json) VALUES(?,?,?,?)", (time.time(), self.manager_user, name, json.dumps(data, sort_keys=True)))
            audit(user=self.manager_user, device="manager-desktop", resource=name, decision="POLICY", reasons=[f"policy updated: {data}"])
            messagebox.showinfo("Policy saved", f"Policy for {name} saved and audited.", parent=self)
            self._refresh()
        except (ValueError, tk.TclError, AuditFull, AuditTamper) as exc:
            messagebox.showerror("Policy not saved", f"Invalid policy or audit failure: {exc}", parent=self)

    def _tab_alerts(self):
        t = self._tab("Alerts"); self.t_alerts = t
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        self.v_alert_sum = tk.StringVar(); ttk.Label(bar, textvariable=self.v_alert_sum, style="Strong.TLabel").pack(side="left")
        ttk.Button(bar, text="Mark reviewed", command=self._ack_alert).pack(side="right")
        ttk.Button(bar, text="False alarm", command=lambda: self._alert_outcome("false_alarm")).pack(side="right", padx=6)
        ttk.Button(bar, text="Confirm incident + sign out", command=lambda: self._alert_outcome("incident_confirmed")).pack(side="right", padx=6)
        self.al_tree = self._tree(t, ("time", "sev", "kind", "user", "device", "state", "details"), ("Time", "Severity", "Type", "User", "Device", "State", "Details"), (80, 80, 190, 90, 120, 70, 420), stretch="details")

    def _selected_alert(self, tree=None):
        sel = (tree or self.al_tree).selection()
        if not sel: return None
        try: aid = int(sel[0])
        except (TypeError, ValueError): return None
        return next((a for a in recent_alerts(limit=120) if int(a.get("id", -1)) == aid), None)

    def _ack_alert(self, tree=None):
        try:
            alert = self._selected_alert(tree)
            if not alert:
                messagebox.showinfo("Alerts", "Select an alert first.", parent=self); return
            acknowledge_alerts(ids=[alert["id"]], status=1, include_high=True)
            try: audit(user=self.manager_user, device="manager-desktop", resource="alert", decision="REVIEWED", reasons=[f"alert {alert['id']} acknowledged; no approval implied"])
            except (AuditFull, AuditTamper): pass
            self._refresh()
        except Exception as exc: messagebox.showerror("Alert acknowledgement", str(exc), parent=self)

    def _alert_outcome(self, outcome, tree=None):
        alert = self._selected_alert(tree)
        if not alert: messagebox.showinfo("Alert outcome", "Select an alert first.", parent=self); return
        if outcome == "incident_confirmed" and not messagebox.askyesno("Confirm incident", f"Confirm the incident for {alert.get('user') or 'unknown user'} and sign them out everywhere?", parent=self): return
        try:
            acknowledge_alerts(ids=[alert["id"]], status={"false_alarm": 2, "incident_confirmed": 3}.get(outcome, 1), include_high=True)
            user = alert.get("user")
            if outcome == "incident_confirmed" and user:
                n, err = revoke_user_sessions_report(user)
                if err: messagebox.showwarning("Incident response", f"{n} live session(s) were ended, but the revocation could not be saved to the database ({err}).", parent=self)
                try: audit(user=self.manager_user, device=alert.get("device"), resource="alert-response", decision="REVOKE", reasons=[f"incident confirmed from alert {alert['id']}; signed out {user} ({n} sessions)"])
                except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit warning", f"Sessions were revoked, but audit write failed: {exc}", parent=self)
                publish_gui_event("incident-confirmed", user=user, alert_id=alert["id"])
            else:
                try: audit(user=self.manager_user, device=alert.get("device"), resource="alert-response", decision="FALSE_ALARM", reasons=[f"alert {alert['id']} marked false alarm"])
                except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit warning", str(exc), parent=self)
            self._refresh()
        except Exception as exc: messagebox.showerror("Alert outcome", str(exc), parent=self)

    def _tab_audit(self):
        t = self._tab("Audit"); self.t_audit = t
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        self.v_audit = tk.StringVar(value="Not yet verified")
        ttk.Button(bar, text="Verify audit chain", style="Primary.TButton", command=self._verify).pack(side="left")
        ttk.Button(bar, text="Export audit JSONL", command=self._export).pack(side="left", padx=8)
        ttk.Button(bar, text="Daily summary", command=self._daily_summary).pack(side="left", padx=8)
        ttk.Label(bar, textvariable=self.v_audit, style="Accent.TLabel").pack(side="left", padx=10)
        self.v_au_filter = tk.StringVar(); af = ttk.Entry(t, textvariable=self.v_au_filter); af.pack(fill="x", pady=(0, 8)); af.bind("<KeyRelease>", lambda _e: self._refresh())
        self.au_tree = self._tree(t, ("time", "user", "device", "resource", "decision", "risk", "what"), ("Time", "User", "Device", "Resource", "Decision", "Risk", "What happened"), (150, 90, 120, 130, 90, 50, 460), stretch="what")

    def _daily_summary(self):
        messagebox.showinfo("Daily security summary", daily_summary_text(), parent=self)

    def _verify(self):
        r = verify_chain()
        if r.get("ok"): self.v_audit.set(f"VERIFIED · {r.get('entries', 0)} entries")
        else:
            self.v_audit.set(f"FAILED · entry {r.get('broken_at', '?')}")
            messagebox.showerror("Audit integrity failure", "The audit chain did not verify. Preserve the original log and anchor files and compare with a trusted backup; do not edit the chain.", parent=self)
        self._refresh()

    def _export(self):
        from tkinter import filedialog
        target = filedialog.asksaveasfilename(parent=self, title="Export audit JSONL", defaultextension=".jsonl", filetypes=[("JSON Lines", "*.jsonl")], initialfile="ztna_audit_export.jsonl")
        if not target: return
        try:
            shutil.copy2(AUDIT_FILE, target)
            messagebox.showinfo("Audit exported", f"A copy was exported to:\n{target}", parent=self)
        except OSError as exc: messagebox.showerror("Export failed", str(exc), parent=self)

    # ---- device posture (scrollable, updated in place)
    def _device_rows(self):
        """-> list of (employee iid, label, summary values, [(device iid, device id, values, tags)], tags) for EVERY employee."""
        now = time.time(); stale_after = POSTURE_TTL
        by_owner = {}
        for dev, rec in DEVICES.items(): by_owner.setdefault(rec.get("owner", ""), []).append(dev)
        owners = sorted(USERS, key=lambda u: (_person(u)[0].lower(), u)) + sorted(o for o in by_owner if o not in USERS)
        out = []
        for u in owners:
            devs = sorted(by_owner.get(u, []))
            known = u in USERS
            label = f"{_person(u)[0]} ({u})" if known else f"{u or 'unassigned'} (not in directory)"
            role = USERS[u].get("role", "") if known else ""
            dept = USER_PROFILE.get(u, {}).get("dept", "") if known else ""
            kids = []
            for dev in devs:
                rec = DEVICES[dev]; score = posture(dev)
                if dev in BLOCKED_DEVICES: status, tag = "Blocked", "blocked"
                elif not rec.get("last_report"): status, tag = "No report yet", "waiting"
                elif stale_after > 0 and now - rec.get("last_report", 0) > stale_after: status, tag = "Report is stale", "weak"
                elif score < 70: status, tag = "Below score 70", "weak"
                else: status, tag = "Healthy", ""
                checks = tuple("PASS" if rec.get(f) else "FAIL" for f, _l in self.DEVICE_CHECKS)
                kids.append((f"d:{dev}", dev, ("", "", f"{score}/100") + checks + (status,), (tag,) if tag else ()))
            summary = (role, dept, f"{len(devs)} device{'s' if len(devs) != 1 else ''}" if devs else "", "", "", "", "", "", "" if devs else "No device enrolled")
            out.append((f"u:{u}", label, summary, kids, ("emp",) if devs else ("nodev",)))
        return out

    def _device_click(self, event):
        tree = self.dev_tree
        if tree.identify_region(event.x, event.y) != "cell": return
        row, col = tree.identify_row(event.y), tree.identify_column(event.x)
        fields = {f"#{i}": f for i, f in enumerate(("role", "dept", "health") + tuple(f for f, _l in self.DEVICE_CHECKS), 1)}
        field = fields.get(col)
        if row.startswith("d:") and field in dict(self.DEVICE_CHECKS) and row[2:] in DEVICES:
            self._set_posture(row[2:], field, not DEVICES[row[2:]].get(field, False))

    def _refresh_posture(self):
        tree = getattr(self, "dev_tree", None)
        if tree is None or not tree.winfo_exists(): return
        needle = self.v_dev_filter.get().strip().lower()
        rows = []
        for iid, label, summary, kids, tags in self._device_rows():
            if needle:
                kids = [k for k in kids if needle in k[1].lower()] if needle not in label.lower() else kids
                if needle not in label.lower() and not kids: continue
            rows.append((iid, label, summary, kids, tags))
        n_emp = len(USERS); n_dev = len(DEVICES); weak = sum(1 for d in DEVICES if posture(d) < 70)
        none = sum(1 for u in USERS if not any(r.get("owner") == u for r in DEVICES.values()))
        self.v_dev_sum.set(f"{n_emp} employees · {n_dev} devices · {weak} below score 70" + (f" · {none} with no device" if none else ""))
        sig = tuple((r[0], r[1], r[2], tuple((k[0], k[2], k[3]) for k in r[3]), r[4]) for r in rows)
        if sig == self._dev_sig: return
        first = self._dev_sig is None; self._dev_sig = sig
        closed = set() if first else {i for i in tree.get_children() if str(tree.item(i, "open")).lower() in ("0", "false")}
        keep = set(tree.selection()); top = tree.yview()[0]
        tree.delete(*tree.get_children())
        for iid, label, summary, kids, tags in rows:
            tree.insert("", "end", iid=iid, text=label, values=summary, tags=tags, open=iid not in closed)
            for kid, dev, values, ktags in kids: tree.insert(iid, "end", iid=kid, text="   " + dev, values=values, tags=ktags)
        still = [i for i in keep if tree.exists(i)]
        if still: tree.selection_set(still)
        tree.yview_moveto(top)

    def _set_posture(self, device, field, value):
        if not DEMO:
            messagebox.showwarning("Read-only", "Production posture must come from authenticated endpoint attestation.", parent=self); return
        DEVICES[device][field] = bool(value); DEVICES[device]["last_report"] = time.time()
        try: audit(user=self.manager_user, device=device, resource="posture", decision="POLICY", reasons=[f"{field}={bool(value)}"])
        except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit failure", str(exc), parent=self)
        self._refresh()

    # ---- refresh loop
    def _log_rows(self, limit=250):
        rows = []
        for e in list(LOG)[:limit]:
            try: what = describe_audit_event(e)[2]
            except Exception: what = "; ".join(map(str, e.get("reasons", [])))
            rows.append((_fmt_ts(e.get("ts", "")).replace("T", " ").replace("Z", ""), e.get("user", ""), e.get("device", ""), e.get("resource", ""), e.get("decision", ""), e.get("risk", ""), what))
        return rows

    def _update_counters(self, n_signin, n_exc, n_alerts, n_high):
        """Live counts beside the tab headings and in the header band. Called from every refresh, which every
        sign-in / exception / alert event also triggers, so the numbers follow the queues as they change."""
        def label(base, n, extra=""): return f"{base} ({n}{extra})" if n else base
        self.nb.tab(self.t_requests, text=label("Sign-in requests", n_signin))
        self.nb.tab(self.t_exceptions, text=label("App exceptions", n_exc))
        self.nb.tab(self.t_alerts, text=label("Alerts", n_alerts, f" · {n_high} high" if n_high else ""))
        parts = []
        if n_signin: parts.append(f"● {n_signin} sign-in{'s' if n_signin != 1 else ''} waiting")
        if n_exc: parts.append(f"{n_exc} exception{'s' if n_exc != 1 else ''} waiting")
        if n_alerts: parts.append(f"{n_alerts} alert{'s' if n_alerts != 1 else ''} unreviewed")
        self.v_badge.set("   ·   ".join(parts) if parts else "All clear")

    def _refresh(self):
        if not self.winfo_exists() or not self.manager_user: return
        db_error = None
        try: reqs = list_signin_requests(1000)
        except StateStoreError as exc: reqs, db_error = [], str(exc)
        pending = [r for r in reqs if r["status"] == "pending"]
        new = [r for r in pending if r["id"] not in self._seen_pending]
        self._seen_pending |= {r["id"] for r in pending}
        if new:
            try: self.bell()
            except tk.TclError: pass
        n = len(pending)
        self.v_req_sum.set(f"{n} waiting for your approval" if n else "No sign-in requests are waiting")
        past = len(reqs) - n
        self.rb_view["Waiting"].configure(text=f"Waiting ({n})" if n else "Waiting"); self.rb_view["History"].configure(text=f"History ({past})" if past else "History")
        view = self.v_req_view.get()
        rows, tags = [], []
        req_iids = []
        req_filter = self.v_req_filter.get().strip().lower() if hasattr(self, "v_req_filter") else ""
        for r in reqs:
            if (view == "Waiting" and r["status"] != "pending") or (view == "History" and r["status"] == "pending"): continue
            name, _t, _d = _person(r["user"])
            by = r["decided_by"] or ("employee" if r["status"] == "cancelled" and "employee" in (r.get("closed_reason") or "") else "system" if r["status"] in ("expired", "cancelled") else "")
            when = r["decided_at"] if r["decided_by"] and r["status"] in ("approved", "denied") else r.get("closed_at") or r["decided_at"]
            row_values = (_fmt_ts(r["ts"]), r["user"], name, USERS.get(r["user"], {}).get("role", ""), r["device"], f"{posture(r['device'])}/100" if r["device"] in DEVICES else "–", r["location"], r["status"].upper(), signin_outcome(r), by, _fmt_ts(when) if when else "", r["note"] or "")
            if req_filter and req_filter not in " ".join(map(str, row_values)).lower(): continue
            rows.append(row_values); req_iids.append(r["id"])
            tags.append(("pending",) if r["status"] == "pending" else ("blocked",) if r["status"] == "denied" else ())
        if db_error is None:                                  # never replace the visible queue with an empty one because of a database error
            self._fill_tree(self.req_tree, rows, iids=req_iids, tags=tags); self._sync_buttons()
            self._request_context()
        try: exceptions = list_access_exception_requests(200)
        except StateStoreError as exc: exceptions, db_error = [], db_error or str(exc)
        if not any(x.get("id") for x in exceptions) and db_error: pass
        else:
            self._exc_rows = {x["id"]: x for x in exceptions}
            alert_text = {None: "–", 0: "Needs a decision", 1: "Closed", 2: "False alarm", 3: "Incident"}
            ex_rows = [(_fmt_ts(x["ts"]), x["user"], USERS.get(x["user"], {}).get("role", ""), x["resource"], x["device"], x["reason"], x["status"].upper(), alert_text.get(x.get("alert_status"), "–"),
                        exception_outcome(x), x["decided_by"] or ("system" if x["status"] in ("expired", "cancelled") else ""), (_fmt_ts(x["expires_at"]) if x["expires_at"] else "–")) for x in exceptions]
            self._fill_tree(self.exc_tree, ex_rows, iids=[x["id"] for x in exceptions], tags=[("pending",) if x["status"] == "pending" else () for x in exceptions])
            n_wait = sum(1 for x in exceptions if x["status"] == "pending")
            with LOCK: active = sum(1 for v in TEMP_RESOURCE_GRANTS.values() if v > time.time())
            self.v_exc_sum.set(f"{n_wait} waiting for a decision" + (f" · {active} extra access grant{'s' if active != 1 else ''} in use" if active else "") if n_wait or active else "No extra-access requests are waiting")
        try:
            t = telemetry_summary()
            now = time.time()
            with LOCK: live = [s for s in SESSIONS.values() if s.get("exp", 0) > now and s.get("abs_exp", 0) > now]
            vals = {"events": t.get("events", 0), "allow": t.get("allow", 0), "stepup": t.get("stepup", 0), "deny": t.get("deny", 0), "risk": t.get("avg_risk", 0), "alerts": t.get("alerts", 0), "sessions": len(live), "pending": n}
            for k, v in vals.items(): self.v_kpi[k].set(str(v))
        except Exception: pass
        log = self._log_rows(250)
        self._fill_tree(self.ov_tree, [(r[0], r[1], r[3], r[4], r[5]) for r in log[:100]])
        ev_filter = self.v_ev_filter.get().strip().lower() if hasattr(self, "v_ev_filter") else ""
        ev_rows = [(r[0], r[1], r[2], r[3], r[4], r[6]) for r in log]
        if ev_filter: ev_rows = [r for r in ev_rows if ev_filter in " ".join(map(str, r)).lower()]
        self._fill_tree(self.ev_tree, ev_rows)
        au_filter = self.v_au_filter.get().strip().lower() if hasattr(self, "v_au_filter") else ""
        au_rows = [r for r in log if not au_filter or au_filter in " ".join(map(str, r)).lower()]
        self._fill_tree(self.au_tree, au_rows)
        now = time.time(); srows, sids = [], []
        with LOCK: snap = list(SESSIONS.items())
        for sid, s in snap:
            if s.get("exp", 0) <= now or s.get("abs_exp", 0) <= now or s.get("device") in BLOCKED_DEVICES: continue
            sids.append(sid); srows.append((sid, s.get("user", ""), s.get("device", ""), s.get("location", ""), f"{max(0, int(s.get('exp', now) - now))} s", f"{max(0, int(now - s.get('mfa_at', now)))} s"))
        self._fill_tree(self.ss_tree, srows, iids=sids)
        irows = []
        for u, rec in sorted(USERS.items()):
            role = rec.get("role", "unknown")
            irows.append((u, _person(u)[0], role, USER_PROFILE.get(u, {}).get("dept", "–"), ", ".join(r for r in RESOURCES if rbac_allows(u, r) and segment_allows(u, r)) or "None", ", ".join(sorted(SEGMENT_ALLOW.get(role, set())))))
        self._fill_tree(self.id_tree, irows)
        names = list(RESOURCES)
        self._fill_tree(self.pol_tree, self._policy_rows(), iids=names)
        if self._policy_sel is None and names:
            self.pol_tree.selection_set(names[0]); self._load_policy()
        alerts = []
        al = recent_alerts(limit=120)
        for a in al:
            alerts.append((_fmt_ts(a.get("ts", ""), "%H:%M:%S"), a.get("severity", ""), describe_alert(a)[0], a.get("user", ""), a.get("device", ""), {0: "NEW", 1: "REVIEWED", 2: "FALSE ALARM", 3: "INCIDENT"}.get(a.get("status", 0), "SEEN"), a.get("details", "")))
        self._fill_tree(self.al_tree, alerts, iids=[str(a.get("id", "")) for a in al])
        self.v_alert_sum.set(f"{sum(1 for a in al if not a.get('acknowledged'))} unreviewed · {len(al)} recent")
        open_al = [a for a in recent_alerts(limit=500) if not a.get("acknowledged")]
        if db_error:
            self.v_badge.set("⚠ Database unavailable: queues below may be out of date")
        else:
            self._update_counters(n, sum(1 for x in exceptions if x["status"] == "pending"), len(open_al), sum(1 for a in open_al if str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL")))
        self._refresh_posture()
        siem = getattr(self, "siem", None)
        if siem is not None:
            try: siem.refresh()
            except tk.TclError: pass
            except Exception: logger.exception("SIEM dashboard refresh failed")
        self.app.refresh_hub()
        self._schedule("refresh", 10000, self._refresh)
        self._schedule("event-watch", 100, self._watch_gui_events)

    def _watch_gui_events(self):
        if not self.winfo_exists() or not self.manager_user: return
        changed = False
        try:
            while True:
                event = GUI_EVENTS.get_nowait()
                if event.get("kind", "").startswith(("signin-", "exception-", "sessions-", "device-", "stepup-", "incident-", "alert-")):
                    changed = True
        except queue.Empty: pass
        if changed:
            try: self._refresh()
            except (tk.TclError, sqlite3.Error): pass
        else:
            self._schedule("event-watch", 100, self._watch_gui_events)

    def _sign_out(self):
        if self.manager_user:
            try: audit(user=self.manager_user, device="manager-desktop", resource="manager-logout", decision="REVOKE", reasons=["manager signed out"])
            except Exception: pass
        self.manager_user = None; self._show_login()

    def close(self):
        if self.manager_user: self._sign_out_quiet()
        super().close()

    def _sign_out_quiet(self):
        try: audit(user=self.manager_user, device="manager-desktop", resource="manager-logout", decision="REVOKE", reasons=["manager signed out"])
        except Exception: pass
        self.manager_user = None


# ------------------------------------------------------------------------------ hub window
class App(_PortalUI, tk.Tk):
    """Launcher. Employee and manager windows are opened from here and share one policy engine and audit chain."""

    def __init__(self):
        tk.Tk.__init__(self)
        self._init_ui()
        self.title("ZTNA Access Workspace")
        self.geometry("1000x740"); self.minsize(880, 680)
        if DEMO:
            load_persisted_devices()
            if not POSTURE_KEYS: POSTURE_KEYS.update(_demo_posture_keys())
        apply_blue_white_theme(self)
        self.portals = []
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build_hub()
        self._schedule("hub", 1500, self._hub_tick)
        if DEMO and DEMO_BOOTSTRAP_CREDENTIALS: self.after(450, self._show_bootstrap_credentials)

    def _build_hub(self):
        self._band("Secure access to your work", "")
        page = ttk.Frame(self, padding=(26, 22)); page.pack(fill="both", expand=True)
        cards = ttk.Frame(page); cards.pack(fill="x", expand=True)
        cards.columnconfigure(0, weight=1, uniform="c"); cards.columnconfigure(1, weight=1, uniform="c")
        emp = Panel(cards, "Employee", padding=22); emp.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        ttk.Label(emp.body, text="Employee access", style="Section.TLabel").pack(anchor="w", pady=(0, 14))
        ttk.Button(emp.body, text="Open employee sign-in  →", style="Primary.TButton", command=self.open_employee).pack(anchor="w")
        mgr = Panel(cards, "Manager", padding=22); mgr.grid(row=0, column=1, sticky="nsew", padx=(9, 0))
        ttk.Label(mgr.body, text="ZTNA manager console", style="Section.TLabel").pack(anchor="w", pady=(0, 14))
        ttk.Button(mgr.body, text="Open manager console  →", style="Primary.TButton", command=self.open_manager).pack(anchor="w")
        both = ttk.Frame(page); both.pack(fill="x", pady=(14, 0))
        ttk.Button(both, text="Open both side by side", command=self.open_both).pack(side="left")
        self.v_hub = tk.StringVar()
        ttk.Label(page, textvariable=self.v_hub, style="Accent.TLabel").pack(anchor="w", pady=(16, 0))
        self.refresh_hub()

    def refresh_hub(self):
        try:
            now = time.time()
            with LOCK: sessions = sum(1 for s in SESSIONS.values() if s.get("exp", 0) > now and s.get("abs_exp", 0) > now)
            self.v_hub.set(f"Sign-ins waiting for approval: {count_pending_signins()}   ·   Active sessions: {sessions}   ·   Open windows: {len(self.portals)}")
        except Exception: pass

    def _hub_tick(self):
        self.refresh_hub(); self._schedule("hub", 1500, self._hub_tick)

    def _track(self, win):
        self.portals.append(win); self.refresh_hub(); return win

    def portal_closed(self, win):
        if win in self.portals: self.portals.remove(win)

    def _live(self, cls):
        return next((w for w in self.portals if isinstance(w, cls) and w.winfo_exists()), None)

    def open_employee(self, geometry=None):
        win = self._track(EmployeePortal(self))
        if geometry: win.geometry(geometry)
        win.lift(); return win

    def open_manager(self, geometry=None):
        win = self._live(ManagerPortal)
        if win is None:
            win = self._track(ManagerPortal(self))
            if geometry: win.geometry(geometry)
        win.deiconify(); win.lift(); win.focus_force(); return win

    def open_both(self):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = max(860, min(1000, sw // 2 - 10)), max(640, min(780, sh - 120))
        self.open_employee(f"{w}x{h}+0+20"); self.open_manager(f"{w}x{h}+{w + 8}+20")

    def _show_bootstrap_credentials(self):
        if not DEMO_BOOTSTRAP_CREDENTIALS or not self.winfo_exists(): return
        lines = ["EMPLOYEE CREDENTIALS", ""]
        for user, password, role, secret in DEMO_BOOTSTRAP_CREDENTIALS:
            lines.append(f"{user:<8} role={role:<10} password={password}  TOTP secret={secret}")
        win = tk.Toplevel(self); win.title("Employee credentials"); win.geometry("900x560"); win.transient(self); win.configure(background=WHITE)
        band = ttk.Frame(win, style="Band.TFrame", padding=(20, 14)); band.pack(fill="x")
        ttk.Label(band, text="Employee credentials", style="BandTitle.TLabel", font=(UI_FONT, 16, "bold")).pack(anchor="w")
        box = Panel(win, padding=8); box.pack(fill="both", expand=True, padx=18, pady=14)
        txt = tk.Text(box.body, wrap="none", font=("Consolas", 10), background=WHITE, foreground=BLUE_TEXT, relief="flat", bd=0, highlightthickness=0)
        txt.pack(fill="both", expand=True); txt.insert("1.0", "\n".join(lines)); txt.configure(state="disabled")
        btn = ttk.Frame(win); btn.pack(fill="x", padx=18, pady=(0, 14))
        def copy_all():
            self.clipboard_clear(); self.clipboard_append("\n".join(lines)); messagebox.showinfo("Copied", "Credentials copied to the clipboard. Store them securely.", parent=win)
        ttk.Button(btn, text="Copy all credentials", command=copy_all).pack(side="left")
        ttk.Button(btn, text="Close", style="Primary.TButton", command=win.destroy).pack(side="right")

    def on_close(self):
        for win in list(self.portals):
            try: win.close()
            except Exception: pass
        self._cancel_jobs()
        self.destroy()


def main(argv=None):
    global REQUESTED_MODE, DEMO
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["gui"]
    if argv[0] in {"-h", "--help"}:
        print(USAGE)
        return 0

    mode = argv[0].lower()
    mode = "enterprise" if mode == "api" else mode
    if mode not in VALID_MODES:
        print(USAGE)
        return 2

    REQUESTED_MODE = mode
    _configure_logging()
    if mode == "probe":
        return run_probe(argv[1:])
    if mode == "dns":
        return run_dns_cli(argv[1:])
    if mode == "cli":
        return run_admin_cli(argv[1:])
    if mode == "systemd":
        return print_systemd_unit(argv[1:])

    # GUI checks happen before init_runtime(): a missing Tk package or display
    # must not create databases, audit files, or other persistent state.
    if mode == "gui":
        if ttk is None or messagebox is None:
            raise SystemExit("tkinter is not available (install python3-tk)")

        # The desktop entry point opens the integrated GUI directly. This GUI
        # is local-only and does not start an HTTP listener. Production users can
        # explicitly set ZTNA_DEMO=0 and configure their provisioned user store.
        os.environ.setdefault("ZTNA_DEMO", "1")
        if os.environ.get("ZTNA_DEMO") == "1":
            os.environ.setdefault("ZTNA_DEMO_OTP", "1")

    init_runtime(mode)

    if mode == "gui" and DEMO:
        logger.warning("LOCAL DEMO MODE enabled: preset lab credentials are active")
        if DEMO_OTP:
            logger.warning(
                "DEMO OTP GENERATOR enabled: use only for an isolated local lab"
            )

    if mode == "adduser":
        add_user_cli(argv[1:])
    elif mode == "enterprise":
        run_enterprise_api()
    elif mode == "gui":
        try:
            app = App()
        except tk.TclError as exc:
            raise SystemExit(
                f"cannot open a display for the GUI: {exc}"
            ) from None
        app.mainloop()
    elif mode == "server":
        run_legacy_server()
    elif mode == "attack":
        ok = attack(
            argv[1] if len(argv) > 1
            else f"{'http' if DEMO else 'https'}://{HOST_ENV}:{PORT}"
        )
        return 0 if ok else 1
    elif mode == "bench":
        bench(
            argv[1] if len(argv) > 1
            else f"{'http' if DEMO else 'https'}://{HOST_ENV}:{PORT}"
        )
    elif mode == "agent":
        if len(argv) < 3:
            raise SystemExit("usage: agent DEVICE key=value ... [URL]")
        has_url = argv[-1].startswith(("http://", "https://"))
        base = argv[-1] if has_url else f"{'http' if DEMO else 'https'}://{HOST_ENV}:{PORT}"
        kv = argv[2:-1] if has_url else argv[2:]
        return 0 if agent(argv[1], kv, base) else 1
    elif mode == "iptables":
        print("\n".join(firewall_rules()))
    elif mode == "compose":
        out = Path(os.environ.get("ZTNA_COMPOSE_FILE", "docker-compose.yml"))
        if out.exists() and os.environ.get("ZTNA_COMPOSE_FORCE") != "1":
            raise SystemExit(
                f"{out} exists; set ZTNA_COMPOSE_FORCE=1 to overwrite"
            )
        out.write_text(
            COMPOSE.replace("%SCRIPT%", os.path.basename(__file__)),
            encoding="utf-8",
        )
        print(out)
    elif mode == "verify":
        result = verify_chain()
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1
    elif mode == "selftest":
        return 0 if selftest() else 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


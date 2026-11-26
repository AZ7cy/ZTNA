# Part 21 of ztna.py - remote admin console (cli) and the systemd unit generator.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

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

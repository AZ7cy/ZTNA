# Part 18 of ztna.py - server entry points (enterprise API, legacy gateway) and the adduser command.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

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

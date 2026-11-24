# Part 16 of ztna_lab_v2.py - enterprise API: SIEM outbox, lifespan, middleware, OIDC identity, enterprise audit chain.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# Everything below exists only when the optional enterprise dependencies import (FASTAPI_AVAILABLE).
# pyright: reportUndefinedVariable=false

if FASTAPI_AVAILABLE:
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

    def _read_text_shared(path, attempts=40, delay=0.025):
        """Read a small ASCII file. On Windows, opening it fails with PermissionError for the moment another thread
        replaces it, which is not evidence of tampering: retry briefly (as _replace_file does for the writer)."""
        for attempt in range(attempts):
            try: return Path(path).read_text(encoding="ascii")
            except PermissionError:
                if os.name != "nt" or attempt == attempts - 1: raise
                time.sleep(delay)

    def _enterprise_anchor_mac(c,h):
        return hmac.new(ENTERPRISE_AUDIT_SECRET.encode(),f"{c}:{h}".encode(),hashlib.sha256).hexdigest()

    def _enterprise_external_anchor_read():
        """Return (count, hash) of the external anchor, None if the file is absent; raise EnterpriseAnchorTamper if invalid."""
        path=ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE
        if not os.path.exists(path): return None
        try:
            parts=_read_text_shared(path).strip().split(":")
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
                _replace_file(tmp,path); _fsync_dir(path)
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

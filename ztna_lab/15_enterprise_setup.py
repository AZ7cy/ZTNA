# Part 15 of ztna.py - optional FastAPI enterprise API: imports, settings, database models, replay and rate limits, request models.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

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

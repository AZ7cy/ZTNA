"""Enterprise API regression tests for signed body integrity and audit rollback.

These tests run against an isolated SQLite database and exercise real local-demo
session tokens and proof-of-possession signatures. OIDC production device binding
is explicitly out of scope and remains documented as a limitation.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

try:
    from fastapi.testclient import TestClient
    from sqlalchemy import event as sqlalchemy_event
except ImportError as exc:  # pragma: no cover - optional dependency suite
    raise unittest.SkipTest(f"enterprise test dependencies unavailable: {exc}")

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "ztna.py"
_TEST_HOME = Path(tempfile.mkdtemp(prefix="ztna_enterprise_tests_"))
_DATA_DIR = _TEST_HOME / "data"
_DATABASE = _TEST_HOME / "enterprise.db"
_ANCHOR = _TEST_HOME / "enterprise_audit.monotonic"

_ENV_KEYS = (
    "ZTNA_DEMO", "ZTNA_DEMO_OTP", "ZTNA_DATA_DIR", "DATABASE_URL",
    "ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE", "OIDC_ALLOW_LOCAL",
    "OIDC_REQUIRED", "ZTNA_ENTERPRISE_ALLOWED_HOSTS", "LOG_LEVEL",
)
_OLD_ENV = {key: os.environ.get(key) for key in _ENV_KEYS}
os.environ.update({
    "ZTNA_DEMO": "1",
    "ZTNA_DEMO_OTP": "1",
    "ZTNA_DATA_DIR": str(_DATA_DIR),
    "DATABASE_URL": f"sqlite:///{_DATABASE}",
    "ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE": str(_ANCHOR),
    "OIDC_ALLOW_LOCAL": "true",
    "OIDC_REQUIRED": "false",
    "ZTNA_ENTERPRISE_ALLOWED_HOSTS": "localhost:8443,127.0.0.1:8443,testserver",
    "LOG_LEVEL": "WARNING",
})

spec = importlib.util.spec_from_file_location("ztna_enterprise_test_module", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
ztna = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ztna
spec.loader.exec_module(ztna)
ztna.init_runtime("enterprise", asgi=True)
ztna.USERS = ztna.load_users()
# Provision only the legacy session table needed by this API integration fixture;
# avoid calling db_init(), which also opens the legacy thread-local telemetry DB.
_legacy_db = sqlite3.connect(ztna.DB_FILE)
try:
    _legacy_db.execute(
        "CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, user TEXT, device TEXT, location TEXT, created REAL, expires REAL, revoked INTEGER DEFAULT 0, pop_key TEXT, mfa_at REAL)"
    )
    _legacy_db.commit()
finally:
    _legacy_db.close()
ztna.enterprise_init_db()

# Module configuration and engine/paths have now been initialized from the test
# environment. Restore process environment so other tests inherit their own config.
for _key, _value in _OLD_ENV.items():
    if _value is None:
        os.environ.pop(_key, None)
    else:
        os.environ[_key] = _value


class EnterpriseSecurityRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(ztna.enterprise_app, raise_server_exceptions=False)
        now = time.time()
        cls.sid = secrets.token_hex(12)
        cls.device = "laptop-carol"
        cls.username = "carol"  # demo admin role
        cls.salt = ztna._new_session_salt()
        cls.key = ztna._derive_session_key(cls.sid, cls.salt)
        cls.exp = now + 3600
        conn = sqlite3.connect(ztna.DB_FILE)
        try:
            conn.execute(
                "INSERT INTO sessions(sid,user,device,location,created,expires,revoked,pop_key,mfa_at) "
                "VALUES(?,?,?,?,?,?,0,?,?)",
                (cls.sid, cls.username, cls.device, "office", now, cls.exp, cls.salt, now),
            )
            conn.commit()
        finally:
            conn.close()

    def _settle_anchor(self):
        """Bring the external anchor and DB back into agreement via the production reconcile (verifies the DB chain
        and local anchor, repairs an exactly-one-behind external checkpoint). Never restore an old anchor file by
        hand: that desynchronises it from the committed DB state and makes later valid writes return 503."""
        ztna._ENT_ANCHOR_STATE.update(degraded=None, last=None, pending=None)
        ztna._enterprise_reconcile_external_anchor()

    def setUp(self):
        self._settle_anchor()

    def tearDown(self):
        self._settle_anchor()

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        try:
            legacy_conn = getattr(ztna.DB_LOCAL, "conn", None)
            if legacy_conn is not None:
                legacy_conn.close()
                del ztna.DB_LOCAL.conn
        except Exception:
            pass
        try:
            ztna.enterprise_engine.dispose()
        except Exception:
            pass
        try:
            import shutil
            shutil.rmtree(_TEST_HOME, ignore_errors=True)
        except Exception:
            pass

    def headers_for(self, method: str, path: str, signed_body: bytes) -> dict[str, str]:
        ts = time.time()
        ts_header = f"{ts:.3f}"
        nonce = secrets.token_urlsafe(18)
        digest = hashlib.sha256(signed_body).hexdigest()
        token = ztna.jwt_encode({
            "sid": self.sid,
            "sub": self.username,
            "dev": self.device,
            "iat": int(ts),
            "exp": self.exp,
            "cnf": ztna.sha_bytes(self.key),
        })
        proof = hmac.new(
            self.key,
            ztna.proof_message(method, path, digest, float(ts_header), nonce),
            hashlib.sha256,
        ).hexdigest()
        return {
            "host": "localhost:8443",
            "authorization": f"Bearer {token}",
            "x-device-id": self.device,
            "x-device-timestamp": ts_header,
            "x-device-nonce": nonce,
            "x-content-sha256": digest,
            "x-device-proof": proof,
            "content-type": "application/json",
        }

    @staticmethod
    def policy_body(name: str, action: str = "allow") -> bytes:
        return json.dumps({
            "name": name,
            "priority": 100,
            "resource": "wiki",
            "action": action,
            "min_device_score": 0,
            "max_risk_score": 100,
            "require_mfa": False,
            "enabled": True,
        }, separators=(",", ":")).encode()

    def policy_by_name(self, name: str):
        with ztna.EnterpriseSession() as db:
            return db.query(ztna.EPolicy).filter(ztna.EPolicy.name == name).first()

    def test_valid_signed_policy_is_accepted(self):
        body = self.policy_body("it-signed-valid-policy")
        response = self.client.post(
            "/enterprise/admin/policies", content=body,
            headers=self.headers_for("POST", "/enterprise/admin/policies", body),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNotNone(self.policy_by_name("it-signed-valid-policy"))

    def _anchor_attack(self, forged_text, name):
        """Replace the external anchor, post a policy, expect 503 with NO committed change, then restore the anchor.
        No audit row is committed while the anchor is bad, so restoring the old anchor leaves DB and anchor consistent."""
        anchor = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE); good = anchor.read_text()
        entries_before = self.audit_count()
        try:
            anchor.write_text(forged_text(good)); evidence = anchor.read_text()
            body = self.policy_body(name)
            r = self.client.post("/enterprise/admin/policies", content=body, headers=self.headers_for("POST", "/enterprise/admin/policies", body))
            self.assertEqual(r.status_code, 503, r.text)
            self.assertIsNone(self.policy_by_name(name))                 # triggering mutation was refused, not committed
            self.assertEqual(self.audit_count(), entries_before)         # no audit row either
            self.assertEqual(anchor.read_text(), evidence)               # evidence preserved
            self.assertIsNotNone(ztna._ENT_ANCHOR_STATE["degraded"])     # persistent fail-closed state
            body2 = self.policy_body(name + "-2")
            r2 = self.client.post("/enterprise/admin/policies", content=body2, headers=self.headers_for("POST", "/enterprise/admin/policies", body2))
            self.assertEqual(r2.status_code, 503)                        # later writes also refused
        finally:
            anchor.write_text(good); ztna._ENT_ANCHOR_STATE.update(degraded=None, last=None, pending=None)
            ztna._enterprise_reconcile_external_anchor()                 # prove DB + anchor agree before reuse
        ok = self.policy_body(name + "-ok")                              # fixture is consistent again
        self.assertEqual(self.client.post("/enterprise/admin/policies", content=ok, headers=self.headers_for("POST", "/enterprise/admin/policies", ok)).status_code, 200)

    def audit_count(self):
        with ztna.EnterpriseSession() as db:
            return db.query(ztna.EAudit).count()

    def test_corrupt_anchor_refuses_triggering_mutation(self):
        self._anchor_attack(lambda good: f"{good.split(':')[0]}:{'0' * 64}:{'f' * 64}", "it-anchor-corrupt")

    def test_stale_validly_signed_anchor_refuses_triggering_mutation(self):
        def stale(good):
            h = "a" * 64; c = max(0, int(good.split(":")[0]) - 1)
            return f"{c}:{h}:" + hmac.new(ztna.ENTERPRISE_AUDIT_SECRET.encode(), f"{c}:{h}".encode(), hashlib.sha256).hexdigest()
        self._anchor_attack(stale, "it-anchor-stale")

    def test_tampered_policy_create_rejected_before_database_change(self):
        signed = self.policy_body("it-policy-original")
        altered = self.policy_body("it-policy-altered")
        response = self.client.post(
            "/enterprise/admin/policies", content=altered,
            headers=self.headers_for("POST", "/enterprise/admin/policies", signed),
        )
        self.assertEqual(response.status_code, 401, response.text)
        self.assertIsNone(self.policy_by_name("it-policy-altered"))

    def test_tampered_policy_update_and_delete_do_not_mutate_record(self):
        create = self.policy_body("it-policy-update-base", "allow")
        created = self.client.post(
            "/enterprise/admin/policies", content=create,
            headers=self.headers_for("POST", "/enterprise/admin/policies", create),
        )
        self.assertEqual(created.status_code, 200, created.text)
        policy_id = created.json()["id"]

        update_path = f"/enterprise/admin/policies/{policy_id}"
        signed_update = self.policy_body("it-policy-update-signed", "allow")
        altered_update = self.policy_body("it-policy-update-altered", "deny")
        update_response = self.client.put(
            update_path, content=altered_update,
            headers=self.headers_for("PUT", update_path, signed_update),
        )
        self.assertEqual(update_response.status_code, 401, update_response.text)
        record = self.policy_by_name("it-policy-update-base")
        self.assertIsNotNone(record)
        self.assertEqual(record.action, "allow")
        self.assertIsNone(self.policy_by_name("it-policy-update-altered"))

        signed_delete = b'{"confirmation":"delete"}'
        altered_delete = b'{"confirmation":"altered"}'
        delete_response = self.client.request(
            "DELETE", update_path, content=altered_delete,
            headers=self.headers_for("DELETE", update_path, signed_delete),
        )
        self.assertEqual(delete_response.status_code, 401, delete_response.text)
        self.assertIsNotNone(self.policy_by_name("it-policy-update-base"))

    def test_tampered_posture_rejected_before_device_change(self):
        path = "/enterprise/api/device/posture"
        original = json.dumps({
            "device_id": "posture-original", "compliant": True,
            "encrypted_disk": True, "firewall_enabled": True,
            "antivirus_enabled": True,
        }, separators=(",", ":")).encode()
        tampered = original.replace(b"posture-original", b"posture-altered")
        response = self.client.post(
            path, content=tampered,
            headers=self.headers_for("POST", path, original),
        )
        self.assertEqual(response.status_code, 401, response.text)
        with ztna.EnterpriseSession() as db:
            self.assertIsNone(db.query(ztna.EDevice).filter(ztna.EDevice.device_id == "posture-altered").first())

    def test_tampered_ids_ingest_rejected_before_alert_insert(self):
        path = "/enterprise/admin/ids/ingest"
        original = b'{"event_type":"alert","alert":{"severity":2,"signature":"original"}}'
        tampered = b'{"event_type":"alert","alert":{"severity":1,"signature":"altered"}}'
        response = self.client.post(
            path, content=tampered,
            headers=self.headers_for("POST", path, original),
        )
        self.assertEqual(response.status_code, 401, response.text)
        with ztna.EnterpriseSession() as db:
            self.assertEqual(db.query(ztna.EIDSAlert).count(), 0)

    def test_firewall_intent_is_committed_before_external_commands(self):
        path = "/enterprise/admin/firewall/apply"
        body = json.dumps({
            "source_ip": "192.0.2.10", "destination_ip": "192.0.2.20",
            "destination_port": 443, "protocol": "tcp", "action": "deny",
            "remove": False, "ttl_seconds": 0,
        }, separators=(",", ":")).encode()
        old_enforce = ztna.ZTNA_ENFORCE_FIREWALL
        ztna.ZTNA_ENFORCE_FIREWALL = True
        calls = []

        def fake_run(command, **kwargs):
            # Every attempted host command must see a durable request-intent row first.
            with ztna.EnterpriseSession() as db:
                latest = db.query(ztna.EAudit).order_by(ztna.EAudit.id.desc()).first()
                self.assertIsNotNone(latest)
                self.assertEqual(latest.action, "firewall_apply_requested")
            calls.append(list(command))
            if len(command) > 1 and command[1] in {"-N", "-D"}:
                return type("Completed", (), {"returncode": 1})()
            if len(command) > 1 and command[1] == "-C" and len(command) > 2 and command[2] == ztna.FIREWALL_CHAIN:
                return type("Completed", (), {"returncode": 1})()
            return type("Completed", (), {"returncode": 0})()

        try:
            with mock.patch.object(ztna.subprocess, "run", side_effect=fake_run):
                response = self.client.post(
                    path, content=body, headers=self.headers_for("POST", path, body)
                )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(calls, "firewall command path should have been exercised")
            with ztna.EnterpriseSession() as db:
                events = db.query(ztna.EAudit).filter(
                    ztna.EAudit.action.in_(["firewall_apply_requested", "firewall_apply_result"])
                ).order_by(ztna.EAudit.id.asc()).all()
                self.assertEqual([e.action for e in events], ["firewall_apply_requested", "firewall_apply_result"])
        finally:
            ztna.ZTNA_ENFORCE_FIREWALL = old_enforce

    def test_tampered_firewall_rule_rejected_before_audit_or_enforcement(self):
        path = "/enterprise/admin/firewall/apply"
        original = b'{"source_ip":"192.0.2.10","destination_ip":"192.0.2.20","destination_port":443,"protocol":"tcp","action":"allow","remove":false,"ttl_seconds":0}'
        tampered = original.replace(b'"action":"allow"', b'"action":"deny"')
        with ztna.EnterpriseSession() as db:
            before = db.query(ztna.EAudit).filter(ztna.EAudit.action == "firewall_apply").count()
        response = self.client.post(
            path, content=tampered,
            headers=self.headers_for("POST", path, original),
        )
        self.assertEqual(response.status_code, 401, response.text)
        with ztna.EnterpriseSession() as db:
            after = db.query(ztna.EAudit).filter(ztna.EAudit.action == "firewall_apply").count()
        self.assertEqual(after, before, "tampered firewall request must not write an audit event or run the handler")

    def test_audit_persistence_failure_rolls_back_policy_row(self):
        name = "it-policy-audit-write-failure"
        body = self.policy_body(name)
        path = "/enterprise/admin/policies"
        with ztna.EnterpriseSession() as db:
            before_audit = db.query(ztna.EAudit).count()
            before_anchor_intents = db.query(ztna.EAnchorOutbox).count()
            before_delivery_intents = db.query(ztna.EDeliveryOutbox).count()

        def fail_when_audit_is_flushed(session, flush_context, instances):
            if any(isinstance(obj, ztna.EAudit) for obj in session.new):
                raise RuntimeError("injected audit persistence failure")

        sqlalchemy_event.listen(ztna.Session, "before_flush", fail_when_audit_is_flushed)
        try:
            with self.assertLogs(ztna.logger, level="ERROR"):
                response = self.client.post(
                    path, content=body,
                    headers=self.headers_for("POST", path, body),
                )
        finally:
            sqlalchemy_event.remove(ztna.Session, "before_flush", fail_when_audit_is_flushed)

        self.assertEqual(response.status_code, 503, response.text)
        self.assertIsNone(self.policy_by_name(name), "policy row must roll back when audit persistence fails")
        with ztna.EnterpriseSession() as db:
            self.assertEqual(
                db.query(ztna.EAudit).filter(ztna.EAudit.action == "policy_create", ztna.EAudit.details.contains(name)).count(),
                0,
            )
            self.assertEqual(db.query(ztna.EAudit).count(), before_audit)
            self.assertEqual(db.query(ztna.EAnchorOutbox).count(), before_anchor_intents)
            self.assertEqual(db.query(ztna.EDeliveryOutbox).count(), before_delivery_intents)

    def _post_policy(self, name):
        path = "/enterprise/admin/policies"; body = self.policy_body(name)
        return self.client.post(path, content=body, headers=self.headers_for("POST", path, body))

    def _anchor_state(self):
        raw = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE).read_text().strip().split(":")
        return int(raw[0]), raw[1]

    def _db_state(self):
        with ztna.EnterpriseSession() as db:
            last = db.query(ztna.EAudit).order_by(ztna.EAudit.id.desc()).first()
            return db.query(ztna.EAudit).count(), (last.event_hash if last else "GENESIS")

    def _simulate_outage(self, name):
        original = ztna._enterprise_external_anchor_update
        ztna._enterprise_external_anchor_update = lambda *_a, **_k: (_ for _ in ()).throw(OSError("injected anchor outage"))
        try:
            with self.assertLogs(ztna.logger, level="ERROR"):
                return self._post_policy(name)
        finally:
            ztna._enterprise_external_anchor_update = original

    def test_ids_alerts_roll_back_when_audit_persistence_fails(self):
        path = "/enterprise/admin/ids/ingest"
        body = json.dumps([{
            "event_type": "alert", "src_ip": "192.0.2.10", "dest_ip": "192.0.2.20",
            "alert": {"severity": 2, "signature": "atomic-audit-test"},
        }], separators=(",", ":")).encode()
        with ztna.EnterpriseSession() as db:
            before = db.query(ztna.EIDSAlert).count()

        def fail_when_audit_is_flushed(session, flush_context, instances):
            if any(isinstance(obj, ztna.EAudit) for obj in session.new):
                raise RuntimeError("injected audit persistence failure")

        sqlalchemy_event.listen(ztna.Session, "before_flush", fail_when_audit_is_flushed)
        try:
            response = self.client.post(
                path, content=body, headers=self.headers_for("POST", path, body)
            )
        finally:
            sqlalchemy_event.remove(ztna.Session, "before_flush", fail_when_audit_is_flushed)
        self.assertEqual(response.status_code, 503, response.text)
        with ztna.EnterpriseSession() as db:
            self.assertEqual(db.query(ztna.EIDSAlert).count(), before)
            self.assertEqual(
                db.query(ztna.EAudit).filter(ztna.EAudit.action == "ids_alert").count(), 0
            )

    def test_external_anchor_failure_does_not_turn_committed_change_into_error(self):
        name = "it-policy-anchor-best-effort"
        response = self._simulate_outage(name)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNotNone(self.policy_by_name(name))
        # DB advanced by exactly one; the external anchor is one behind and the outage is recorded as pending.
        self.assertEqual(self._db_state()[0], self._anchor_state()[0] + 1)
        self.assertEqual(ztna._ENT_ANCHOR_STATE["pending"], self._db_state())
        # tearDown reconciles the fixture; nothing leaks into later tests.

    def test_next_write_after_outage_reconciles_then_succeeds(self):
        self.assertEqual(self._simulate_outage("it-outage-recover-1").status_code, 200)
        self.assertIsNotNone(ztna._ENT_ANCHOR_STATE["pending"])
        r = self._post_policy("it-outage-recover-2")               # triggers verify + reconcile, then proceeds
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(ztna._ENT_ANCHOR_STATE["pending"])
        self.assertEqual(self._anchor_state(), self._db_state())    # external anchor fully caught up
        self.assertIsNotNone(self.policy_by_name("it-outage-recover-2"))

    def test_writes_refused_while_reconciliation_cannot_complete(self):
        self.assertEqual(self._simulate_outage("it-outage-blocked-1").status_code, 200)
        anchor = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE); good = anchor.read_text()
        before = self._db_state()[0]
        try:
            h = "a" * 64; c = max(0, self._anchor_state()[0] - 1)    # validly signed but two entries behind
            anchor.write_text(f"{c}:{h}:{ztna._enterprise_anchor_mac(c, h)}")
            with self.assertLogs(ztna.logger, level="ERROR"):
                r = self._post_policy("it-outage-blocked-2")
            self.assertEqual(r.status_code, 503, r.text)
            self.assertIsNone(self.policy_by_name("it-outage-blocked-2"))   # mutation rolled back
            self.assertEqual(self._db_state()[0], before)                   # no audit row either
            self.assertIsNotNone(ztna._ENT_ANCHOR_STATE["pending"])         # still blocked, will retry
        finally:
            anchor.write_text(good)                                         # the exact one-behind file we saved
        r = self._post_policy("it-outage-blocked-3")                        # recovery now possible -> unblocked
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._anchor_state(), self._db_state())

    def test_anchor_outbox_proves_crash_recovery_after_restart(self):
        """A post-commit anchor outage must leave a durable intent that startup can reconcile."""
        name = "it-anchor-outbox-restart-recovery"
        before_external = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE).read_text(encoding="ascii")
        with mock.patch.object(ztna, "_enterprise_external_anchor_update", side_effect=OSError("simulated anchor outage")):
            response = self._post_policy(name)
        self.assertEqual(response.status_code, 200, response.text)
        with ztna.EnterpriseSession() as db:
            policy = db.query(ztna.EPolicy).filter(ztna.EPolicy.name == name).one()
            event = db.query(ztna.EAudit).filter(ztna.EAudit.action == "policy_create").order_by(ztna.EAudit.id.desc()).first()
            self.assertIsNotNone(event)
            event_id, event_hash = event.event_id, event.event_hash
            outbox = db.query(ztna.EAnchorOutbox).filter(ztna.EAnchorOutbox.event_id == event_id).one()
            self.assertIsNone(outbox.delivered_at)
            self.assertEqual(outbox.entries, db.query(ztna.EAudit).count())
            self.assertEqual(outbox.last_hash, event_hash)
        self.assertNotEqual(Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE).read_text(encoding="ascii"), "")
        self.assertIsNotNone(ztna._ENT_ANCHOR_STATE["pending"])

        # Simulate process loss: in-memory pending state is gone, durable DB intent remains.
        ztna._ENT_ANCHOR_STATE.update(degraded=None, last=None, pending=None)
        checkpoint = ztna._enterprise_reconcile_external_anchor()
        with ztna.EnterpriseSession() as db:
            outbox = db.query(ztna.EAnchorOutbox).filter(ztna.EAnchorOutbox.event_id == event_id).one()
            self.assertIsNotNone(outbox.delivered_at)
            self.assertEqual(outbox.last_hash, checkpoint[1])
        self.assertEqual(ztna._enterprise_external_anchor_read(), checkpoint)
        self.assertEqual(before_external.split(":")[0], str(checkpoint[0] - 1))

    def test_validly_signed_one_entry_rollback_without_pending_outbox_is_rejected(self):
        """A valid old MAC isn't sufficient proof of a crash; an exact pending outbox row is required."""
        response = self._post_policy("it-anchor-rollback-baseline")
        self.assertEqual(response.status_code, 200, response.text)
        path = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE)
        original = path.read_text(encoding="ascii")
        old_state = dict(ztna._ENT_ANCHOR_STATE)
        with ztna.EnterpriseSession() as db:
            hashes = [r[0] for r in db.query(ztna.EAudit.event_hash).order_by(ztna.EAudit.id.asc()).all()]
            latest_event = db.query(ztna.EAudit).order_by(ztna.EAudit.id.desc()).first()
            latest_outbox = db.query(ztna.EAnchorOutbox).filter(ztna.EAnchorOutbox.event_id == latest_event.event_id).one()
            self.assertIsNotNone(latest_outbox.delivered_at)
        count = len(hashes)
        self.assertGreaterEqual(count, 1)
        prior_count = count - 1
        prior_hash = hashes[prior_count - 1] if prior_count else "GENESIS"
        stale = f"{prior_count}:{prior_hash}:{ztna._enterprise_anchor_mac(prior_count, prior_hash)}"
        try:
            path.write_text(stale, encoding="ascii")
            with self.assertRaises(RuntimeError):
                ztna._enterprise_reconcile_external_anchor()
            self.assertEqual(path.read_text(encoding="ascii"), stale, "validly MACed rollback must remain untouched")
        finally:
            path.write_text(original, encoding="ascii")
            ztna._ENT_ANCHOR_STATE.update(old_state)

    def test_siem_outbox_retries_durably_after_delivery_failure(self):
        old_url = ztna.SIEM_URL
        ztna.SIEM_URL = "https://siem.invalid/events"
        name = "it-siem-outbox-retry"
        try:
            with mock.patch.object(ztna, "_enterprise_deliver_outbox", side_effect=RuntimeError("simulated SIEM outage")) as deliver:
                response = self._post_policy(name)
                self.assertEqual(response.status_code, 200, response.text)
                with ztna.EnterpriseSession() as db:
                    event = db.query(ztna.EAudit).filter(ztna.EAudit.action == "policy_create").order_by(ztna.EAudit.id.desc()).first()
                    event_id = event.event_id
                    row = db.query(ztna.EDeliveryOutbox).filter(
                        ztna.EDeliveryOutbox.event_id == event_id,
                        ztna.EDeliveryOutbox.destination == "siem",
                    ).one()
                    self.assertIn(event_id, row.payload)
                    row.next_attempt_at = 0
                    db.commit()
                ztna._enterprise_drain_delivery_outbox()
                with ztna.EnterpriseSession() as db:
                    row = db.query(ztna.EDeliveryOutbox).filter(ztna.EDeliveryOutbox.event_id == event_id,
                                                               ztna.EDeliveryOutbox.destination == "siem").one()
                    self.assertGreaterEqual(row.attempts, 1)
                    self.assertIsNone(row.delivered_at)
                    self.assertIsNotNone(row.last_error)
                    row.next_attempt_at = 0
                    db.commit()
                deliver.side_effect = None
                deliver.return_value = None
                ztna._enterprise_drain_delivery_outbox()
                with ztna.EnterpriseSession() as db:
                    row = db.query(ztna.EDeliveryOutbox).filter(ztna.EDeliveryOutbox.event_id == event_id,
                                                               ztna.EDeliveryOutbox.destination == "siem").one()
                    self.assertIsNotNone(row.delivered_at)
                    self.assertIsNone(row.last_error)
        finally:
            ztna.SIEM_URL = old_url

    def test_concurrent_policy_audit_writes_keep_anchor_consistent(self):
        from concurrent.futures import ThreadPoolExecutor
        names = [f"it-concurrent-audit-{i}" for i in range(4)]
        def create(name):
            return self._post_policy(name)
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(create, names))
        self.assertTrue(all(r.status_code == 200 for r in responses), [(r.status_code, r.text) for r in responses])
        with ztna.EnterpriseSession() as db:
            chain = ztna._enterprise_stream_verify_chain(db, external_mode="exact", check_process_checkpoint=False)
        self.assertTrue(chain["ok"], chain)
        self.assertEqual(ztna._enterprise_external_anchor_read(), (chain["entries"], chain["last_hash"]))
        with ztna.EnterpriseSession() as db:
            rows = db.query(ztna.EPolicy).filter(ztna.EPolicy.name.in_(names)).count()
            self.assertEqual(rows, len(names))

    def test_non_tail_audit_record_tamper_blocks_sensitive_mutation(self):
        # Positive control first: an untouched complete log must verify.
        self.assertEqual(self._post_policy("it-nontail-seed-1").status_code, 200)
        self.assertEqual(self._post_policy("it-nontail-seed-2").status_code, 200)
        verify_path = "/enterprise/admin/audit/verify"
        good_verify = self.client.get(
            verify_path, headers=self.headers_for("GET", verify_path, b"")
        )
        self.assertEqual(good_verify.status_code, 200, good_verify.text)
        self.assertIs(good_verify.json().get("ok"), True, good_verify.text)

        before_count = self.audit_count()
        before_anchor = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE).read_text(encoding="ascii")
        con = sqlite3.connect(str(_DATABASE))
        try:
            row = con.execute(
                "SELECT id, action FROM enterprise_audit_events ORDER BY id ASC LIMIT 1"
            ).fetchone()
            tail = con.execute(
                "SELECT id FROM enterprise_audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertIsNotNone(tail)
            self.assertLess(row[0], tail[0], "fixture must mutate a non-tail event")
            con.execute("UPDATE enterprise_audit_events SET action=? WHERE id=?", ("tampered-non-tail", row[0]))
            con.commit()
        finally:
            con.close()

        try:
            bad_verify = self.client.get(
                verify_path, headers=self.headers_for("GET", verify_path, b"")
            )
            self.assertEqual(bad_verify.status_code, 200, bad_verify.text)
            self.assertIs(bad_verify.json().get("ok"), False, bad_verify.text)
            self.assertEqual(bad_verify.json().get("broken_at"), 0, bad_verify.text)

            name = "it-nontail-mutation-must-not-commit"
            with self.assertLogs(ztna.logger, level="CRITICAL"):
                response = self._post_policy(name)
            self.assertEqual(response.status_code, 503, response.text)
            self.assertIsNone(self.policy_by_name(name))
            self.assertEqual(self.audit_count(), before_count)
            self.assertEqual(
                Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE).read_text(encoding="ascii"),
                before_anchor,
                "a non-tail tamper must not advance or rewrite the external anchor",
            )
            self.assertIsNotNone(ztna._ENT_ANCHOR_STATE["degraded"])
        finally:
            # Restore the exact field for fixture hygiene; event_hash was deliberately left untouched.
            con = sqlite3.connect(str(_DATABASE))
            try:
                con.execute("UPDATE enterprise_audit_events SET action=? WHERE id=?", (row[1], row[0]))
                con.commit()
            finally:
                con.close()

    def test_corrupt_db_chain_blocks_writes_after_outage(self):
        self.assertEqual(self._simulate_outage("it-outage-chain-1").status_code, 200)
        import sqlite3 as _sq
        con = _sq.connect(str(_DATABASE))
        try:
            con.execute("UPDATE enterprise_audit_events SET action='tampered' WHERE id=(SELECT MAX(id) FROM enterprise_audit_events)")
            con.commit()
            with self.assertLogs(ztna.logger, level="ERROR"):
                r = self._post_policy("it-outage-chain-2")
            self.assertEqual(r.status_code, 503, r.text)
            self.assertIsNone(self.policy_by_name("it-outage-chain-2"))
        finally:
            con.execute("UPDATE enterprise_audit_events SET action='policy_create' WHERE action='tampered'")
            con.commit(); con.close()


    def _corrupt_local_anchor(self, **changes):
        """Alter EAuditAnchor columns directly (MAC left as-is unless given), return the original values."""
        with ztna.EnterpriseSession() as db:
            row = db.query(ztna.EAuditAnchor).filter(ztna.EAuditAnchor.id == 1).one()
            original = {k: getattr(row, k) for k in ("entries", "last_hash", "mac")}
            for k, v in changes.items(): setattr(row, k, v)
            db.commit()
        return original

    def _local_anchor_row(self):
        with ztna.EnterpriseSession() as db:
            row = db.query(ztna.EAuditAnchor).filter(ztna.EAuditAnchor.id == 1).one()
            return row.entries, row.last_hash, row.mac

    def _assert_local_anchor_corruption_refused(self, name, **changes):
        self.assertEqual(self._post_policy(name + "-seed").status_code, 200)   # ensure at least one real audit row
        ext_before = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE).read_text()
        rows_before = self._db_state()[0]
        original = self._corrupt_local_anchor(**changes)
        evidence = self._local_anchor_row()
        try:
            with self.assertLogs(ztna.logger, level="CRITICAL"):
                r = self._post_policy(name)
            self.assertEqual(r.status_code, 503, r.text)
            self.assertIsNone(self.policy_by_name(name))                           # mutation rolled back
            self.assertEqual(self._db_state()[0], rows_before)                     # no audit row committed
            self.assertEqual(self._local_anchor_row(), evidence)                   # bad row preserved, not re-MACed
            self.assertEqual(Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE).read_text(), ext_before)  # not advanced
            self.assertIsNotNone(ztna._ENT_ANCHOR_STATE["degraded"])               # fail-closed state entered
            self.assertEqual(self._post_policy(name + "-2").status_code, 503)      # later writes refused too
        finally:
            self._corrupt_local_anchor(**original)                                 # tearDown reconciles + clears state

    def test_local_anchor_count_altered_without_mac_refuses_mutation(self):
        entries = self._local_anchor_row()[0]
        self._assert_local_anchor_corruption_refused("it-local-anchor-count", entries=entries + 5)

    def test_local_anchor_count_and_mac_forged_but_chain_mismatch_refuses_mutation(self):
        entries, h, _ = self._local_anchor_row()
        forged = entries + 5      # valid MAC for a wrong count: still must not match the audit rows
        self._assert_local_anchor_corruption_refused("it-local-anchor-forged", entries=forged, mac=ztna._enterprise_anchor_mac(forged, h))

    def test_local_anchor_hash_mismatch_refuses_mutation(self):
        entries, _, _ = self._local_anchor_row()
        h = "b" * 64
        self._assert_local_anchor_corruption_refused("it-local-anchor-hash", last_hash=h, mac=ztna._enterprise_anchor_mac(entries, h))

    def test_local_anchor_bad_mac_refuses_mutation(self):
        self._assert_local_anchor_corruption_refused("it-local-anchor-mac", mac="f" * 64)

    def test_local_anchor_disagreeing_with_last_verified_checkpoint_refuses_mutation(self):
        self.assertEqual(self._post_policy("it-local-anchor-last-seed").status_code, 200)
        count, h = self._db_state()
        ztna._ENT_ANCHOR_STATE["last"] = (count - 1, "c" * 64)    # process memory says something else
        with self.assertLogs(ztna.logger, level="CRITICAL"):
            r = self._post_policy("it-local-anchor-last")
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIsNone(self.policy_by_name("it-local-anchor-last"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class FakeDB:
    def __init__(self, rules): self.rules = rules
    def query(self, *_): return self
    def filter(self, *_): return self
    def order_by(self, *_): return self
    def all(self): return list(self.rules)


class Rule:
    def __init__(self, action, priority=10, id=1, subject_pattern=None, role=None, min_device_score=0, max_risk_score=100, require_mfa=False):
        self.action, self.priority, self.id = action, priority, id
        self.subject_pattern, self.role = subject_pattern, role
        self.min_device_score, self.max_risk_score, self.require_mfa = min_device_score, max_risk_score, require_mfa


class Dev:
    def __init__(self, risk=10.0, age=0): self.risk_score = risk; self.last_seen = __import__("datetime").datetime.now(__import__("datetime").timezone.utc) - __import__("datetime").timedelta(seconds=age)


class EnterprisePolicyDecisionTable(unittest.TestCase):
    """One test per row of the documented decision model (see enterprise_policy docstring / README)."""
    ID = {"sub": "alice", "realm_access": {"roles": ["staff"]}}
    MFA = {**ID, "acr": "mfa", "auth_time": time.time()}

    def decide(self, rules, identity=None, device="ok"):
        dev = Dev() if device == "ok" else Dev(age=10**6) if device == "stale" else Dev(risk=90.0) if device == "risky" else None
        ztna.ENTERPRISE_POSTURE_TTL = 300; ztna.ENTERPRISE_MFA_MAX_AGE = 300
        return ztna.enterprise_policy(FakeDB(rules), identity or self.ID, "wiki", dev)[0]

    def test_no_rules_denies(self): self.assertEqual(self.decide([]), "deny")
    def test_invalid_action_fails_closed(self): self.assertEqual(self.decide([Rule("permit")]), "deny")
    def test_selector_mismatch_skips(self):
        self.assertEqual(self.decide([Rule("deny", 1, role="admin"), Rule("allow", 2)]), "allow")
        self.assertEqual(self.decide([Rule("allow", 1, subject_pattern="bob*")]), "deny")
    def test_missing_device_skips_all_rules_when_required(self):
        self.assertEqual(self.decide([Rule("allow")], device=None), "deny")
    def test_unconditional_deny_wins_by_priority(self):
        self.assertEqual(self.decide([Rule("deny", 1), Rule("allow", 2)]), "deny")
    def test_allow_before_deny_wins_by_priority(self):
        self.assertEqual(self.decide([Rule("allow", 1), Rule("deny", 2)]), "allow")
    def test_priority_tie_broken_by_id(self):
        self.assertEqual(self.decide([Rule("deny", 5, id=1), Rule("allow", 5, id=2)]), "deny")
    def test_conditional_deny_not_triggered_falls_through_to_allow(self):
        self.assertEqual(self.decide([Rule("deny", 1, max_risk_score=50), Rule("allow", 2)]), "allow")
    def test_conditional_deny_triggered_by_risk_or_score(self):
        self.assertEqual(self.decide([Rule("deny", 1, max_risk_score=50), Rule("allow", 2)], device="risky"), "deny")
        self.assertEqual(self.decide([Rule("deny", 1, min_device_score=95), Rule("allow", 2)]), "deny")
    def test_stale_posture_denies_on_deny_rule_and_skips_allow_rule(self):
        self.assertEqual(self.decide([Rule("deny", 1, max_risk_score=50), Rule("allow", 2)], device="stale"), "deny")
        self.assertEqual(self.decide([Rule("allow")], device="stale"), "deny")
    def test_allow_thresholds(self):
        self.assertEqual(self.decide([Rule("allow", max_risk_score=50)], device="risky"), "deny")
        self.assertEqual(self.decide([Rule("allow", min_device_score=95)]), "deny")
    def test_mfa_required_is_step_up_and_terminal(self):
        self.assertEqual(self.decide([Rule("allow", 1, require_mfa=True), Rule("allow", 2)]), "step_up")
        self.assertEqual(self.decide([Rule("allow", 1, require_mfa=True)], identity=self.MFA), "allow")
        self.assertEqual(self.decide([Rule("allow", 1, require_mfa=True)], identity={**self.MFA, "auth_time": time.time() - 10**6}), "step_up")


class EnterpriseAnchorTamper(unittest.TestCase):
    def test_corrupt_anchor_is_preserved_and_not_overwritten_by_later_append(self):
        anchor = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE)
        good = anchor.read_text()
        n = int(good.split(":")[0])
        anchor.write_text(f"{n}:{'0' * 64}:{'f' * 64}")
        evidence = anchor.read_text()
        try:
            with self.assertRaises(ztna.EnterpriseAnchorTamper):
                ztna._enterprise_external_anchor_update(n + 1, "a" * 64, (n, "0" * 64))
            self.assertEqual(anchor.read_text(), evidence)
        finally:
            anchor.write_text(good)


class EnterpriseAnchorRollback(unittest.TestCase):
    def setUp(self):
        self.anchor = Path(ztna.ENTERPRISE_AUDIT_EXTERNAL_ANCHOR_FILE)
        self.good = self.anchor.read_text()
        self.mac = lambda c, h: hmac.new(ztna.ENTERPRISE_AUDIT_SECRET.encode(), f"{c}:{h}".encode(), hashlib.sha256).hexdigest()

    def tearDown(self):
        self.anchor.write_text(self.good)
        ztna._ENT_ANCHOR_STATE.update(degraded=None, last=None)

    def test_validly_signed_but_stale_anchor_is_not_overwritten(self):
        self.anchor.write_text(f"10:{'a' * 64}:{self.mac(10, 'a' * 64)}")
        evidence = self.anchor.read_text()
        with self.assertRaises(ztna.EnterpriseAnchorTamper):
            ztna._enterprise_external_anchor_update(12, "c" * 64, (11, "b" * 64))
        self.assertEqual(self.anchor.read_text(), evidence)

    def test_wrong_previous_hash_and_missing_anchor_are_rejected(self):
        self.anchor.write_text(f"11:{'a' * 64}:{self.mac(11, 'a' * 64)}")
        with self.assertRaises(ztna.EnterpriseAnchorTamper):
            ztna._enterprise_external_anchor_update(12, "c" * 64, (11, "b" * 64))
        self.anchor.unlink()
        with self.assertRaises(ztna.EnterpriseAnchorTamper):
            ztna._enterprise_external_anchor_update(12, "c" * 64, (11, "a" * 64))
        self.assertFalse(self.anchor.exists())

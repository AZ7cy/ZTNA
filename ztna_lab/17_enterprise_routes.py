# Part 17 of ztna.py - enterprise API: policy decisions, routes, reverse proxy, Suricata ingestion, fallback when unavailable.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# Everything below exists only when the optional enterprise dependencies import (FASTAPI_AVAILABLE).
# pyright: reportUndefinedVariable=false

if FASTAPI_AVAILABLE:
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

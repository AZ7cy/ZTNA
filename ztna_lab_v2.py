#!/usr/bin/env python3
"""ZTNA Enterprise Lab - stdlib legacy server + Tkinter GUI + optional FastAPI enterprise API.
The source is split into ordered parts in ztna_lab/ (see ztna_lab/README.md); this file is the entry point that loads them.
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
    _version_error = "Python 3.10+ is required by this build"
    if __name__ == "__main__":
        raise SystemExit(_version_error)
    raise ImportError(_version_error)


# The implementation lives in ztna_lab/ as ordered parts. They are executed in this order, all in THIS module's
# namespace, so together they behave exactly like the original single file: module-level settings are rebound with
# `global` at runtime and tests patch attributes such as ztna_lab_v2.audit, which separate modules could not share.
_SOURCE_PARTS = (
    "01_config_and_runtime.py",
    "02_crypto_and_credentials.py",
    "03_users_and_devices.py",
    "04_state_database_alerts.py",
    "05_access_rules_and_throttling.py",
    "06_audit_chain.py",
    "07_policy_engine.py",
    "08_http_gateway.py",
    "09_client_tools.py",
    "10_web_pages_and_http_server.py",
    "11_decision_explanations.py",
    "12_approval_queues.py",
    "13_desktop_engine.py",
    "14_legacy_gui_unused.py",
    "15_enterprise_setup.py",
    "16_enterprise_security.py",
    "17_enterprise_routes.py",
    "18_server_runners_and_adduser.py",
    "19_selftest.py",
    "20_dns.py",
    "21_admin_cli_and_systemd.py",
    "22_gui_common.py",
    "23_gui_employee.py",
    "24_gui_siem_dashboard.py",
    "25_gui_manager.py",
    "26_gui_launcher.py",
    "27_main.py",
)


def _load_source_parts():
    """Run every part of ztna_lab/ in order in this module's namespace.

    SourceFileLoader.get_code() compiles each part under its real file name (tracebacks point at the part) and
    reuses the bytecode cache in ztna_lab/__pycache__/ the same way a normal import does.
    """
    import os
    from importlib.machinery import SourceFileLoader
    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ztna_lab")
    namespace = globals()
    for part in _SOURCE_PARTS:
        name = "ztna_lab." + part[:-3]
        path = os.path.join(folder, part)
        try:
            code = SourceFileLoader(name, path).get_code(name)
        except OSError as exc:
            raise ImportError(f"cannot read {path} ({exc}); keep the ztna_lab folder next to ztna_lab_v2.py") from None
        exec(code, namespace)


_load_source_parts()

if __name__ == "__main__":
    raise SystemExit(main())

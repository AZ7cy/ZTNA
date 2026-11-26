# `ztna_lab/` — source parts of `ztna.py`

The application used to be one 10,300-line file. It is now split into the ordered parts below so that it is
reviewable in git (smaller files, focused diffs and blame). `ztna.py` is still the only entry point and the
only import name:

```powershell
python ztna.py gui          # or server, selftest, dns serve, ... (see python ztna.py --help)
python tests/run_suite.py
```

## How the parts are loaded

`ztna.py` runs every file listed in its `_SOURCE_PARTS` tuple, in that order, **in its own module
namespace**. Together they behave exactly like the original single file:

* A name defined in an earlier part is used in a later one without an import.
* Settings that `init_runtime()` rebinds with `global` (`DATA_DIR`, `DEMO`, `USERS`, ...) are seen by every part.
* `import ztna as z; z.audit = fake` still replaces `audit` for all code, which the tests rely on.
* Each part is compiled under its own file name, so tracebacks point at the part and the right line. Bytecode is
  cached in `ztna_lab/__pycache__/` like for a normal import.

The parts are **not** standalone modules: `import ztna_lab.xyz` does not work, and the file names start with a
number so that nobody tries. Splitting them into real modules would mean replacing the shared module-level state
with explicit objects; that is a larger refactor that can now be done one part at a time.

## Parts

| File | Contents |
|------|----------|
| `01_config_and_runtime.py` | imports, optional Tk stub, logging, settings parsing, JWT keyring, `init_runtime()` |
| `02_crypto_and_credentials.py` | crypto helpers, JWT, TOTP, password hashing, device posture keys, device-proof format |
| `03_users_and_devices.py` | roles and demo roster, file locks, atomic JSON writes, TOTP secret encryption, user and device stores |
| `04_state_database_alerts.py` | resource catalogue, in-memory state, GUI event bus, SQLite store, security alerts, session revocation |
| `05_access_rules_and_throttling.py` | RBAC and micro-segments, temporary grants, policy load/save, posture score, login throttling |
| `06_audit_chain.py` | tamper-evident audit log: HMAC hash chain, anchors, verification, recovery, plain-English text, export |
| `07_policy_engine.py` | adaptive policy engine (`evaluate`), firewall rules, safe upstream fetching |
| `08_http_gateway.py` | legacy stdlib HTTP/TLS gateway: request handler `H` and its routes |
| `09_client_tools.py` | red-team attack suite, benchmark, posture agent, latency probe |
| `10_web_pages_and_http_server.py` | docker-compose template, embedded web pages, pooled HTTP server |
| `11_decision_explanations.py` | plain-English access decisions and demo resource previews |
| `12_approval_queues.py` | sign-in approval queue and temporary application exceptions |
| `13_desktop_engine.py` | `DesktopZTNA`, the engine adapter used by the desktop portals |
| `14_legacy_gui_unused.py` | previous single-window Tk GUI (`LegacyApp`); no entry point uses it |
| `15_enterprise_setup.py` | optional FastAPI enterprise API: imports, settings, database models, replay and rate limits |
| `16_enterprise_security.py` | enterprise API: SIEM outbox, lifespan, middleware, OIDC identity, enterprise audit chain |
| `17_enterprise_routes.py` | enterprise API: policy decisions, routes, reverse proxy, Suricata ingestion |
| `18_server_runners_and_adduser.py` | `server` / `enterprise` entry points and the `adduser` command |
| `19_selftest.py` | built-in self-test (`python ztna.py selftest`) |
| `20_dns.py` | lab DNS server and the `dns` command |
| `21_admin_cli_and_systemd.py` | remote admin console (`cli`) and the systemd unit generator |
| `22_gui_common.py` | desktop GUI shared pieces: theme, panels, scrolling, formatting, portal base class |
| `23_gui_employee.py` | desktop GUI: employee portal |
| `24_gui_siem_dashboard.py` | desktop GUI: SIEM data layer, charts and the manager Dashboard tab |
| `25_gui_manager.py` | desktop GUI: manager console |
| `26_gui_launcher.py` | desktop GUI: launcher (hub) window |
| `27_main.py` | command-line entry point `main()` |

Parts 16 and 17 start with `if FASTAPI_AVAILABLE:` because they continue the optional enterprise block that
part 15 opens; without the enterprise dependencies they define nothing (part 17's `else:` adds the fallbacks).

## Editing rules

* Code that runs **at load time** (module-level statements, class bodies, decorators, default arguments) may only use
  names from the same or an earlier part. Code inside functions may use names from any part.
* To add a part, create the file and add it to `_SOURCE_PARTS` in `ztna.py` at the right position.
* Do not start a part with a string literal: it would replace the module docstring of `ztna`.
* Keep the `# pyright: reportUndefinedVariable=false` header line. Pyright/Pylance cannot see names from other
  parts and would otherwise flag almost every line. For a real undefined-name check, run pyflakes on all parts
  joined together:

  ```powershell
  python -c "import pathlib; open('combined_check.py','w',encoding='utf-8').write('import sys\n' + '\n'.join(p.read_text(encoding='utf-8') for p in sorted(pathlib.Path('ztna_lab').glob('[0-9][0-9]_*.py'))))"
  python -m pyflakes combined_check.py; Remove-Item combined_check.py
  ```

# ZTNA Access Workspace — Native Desktop GUI

This package integrates the employee portal and ZTNA manager console into the main `ztna_lab_v2.py` application as a **native Tkinter desktop GUI**. It does not open a browser, use a localhost URL, or start an HTTP listener for the GUI.

## Start on Windows

1. Extract the ZIP completely.
2. Install Python 3.10 or newer from python.org. Make sure the standard Tk/Tcl component is included.
3. Double-click `START_ZTNA_GUI.bat`.
4. On first launch, a one-time dialog displays generated employee passwords and TOTP enrollment secrets. Save them securely; the application stores password hashes and encrypted TOTP values, not plaintext passwords.
5. Dismiss the credentials dialog to reach the role selection screen.

You can also launch from a terminal:

```powershell
$env:ZTNA_DEMO = "1"
$env:ZTNA_DEMO_OTP = "1"
python ztna_lab_v2.py gui
```

## Manager demo credentials

- Username: `Ztna`
- Password: `Ztna123`

These credentials are hard-coded for the isolated desktop demonstration only. Do not use them in a production deployment or expose demo mode to untrusted users. For non-demo mode, configure `ZTNA_DEMO=0`, a provisioned user store, and `ZTNA_MANAGER_USER` / `ZTNA_MANAGER_PASSWORD` for the separate desktop manager login.

## What's new: employee + manager consoles

- The launcher opens **separate Employee and Manager windows** that share the same in-process policy engine and audit chain.
- An employee's sign-in (password + authenticator code + registered device) appears in the manager's **Sign-in requests** tab. Approval opens one session; denial and manager notes are shown to the employee. Requests expire after 10 minutes, approvals after 5.
- An in-process event queue wakes the manager UI quickly when sign-ins, session controls, or temporary app exceptions change; a slower refresh remains as a recovery/safety net.
- Manager session controls include **revoke session**, **sign user out everywhere**, **require fresh MFA on the next app request**, and **block a device** (including ending sessions on that device for the running lab).
- The sign-in request context includes recent failed logins, device management/health, recent location signal and the last approved sign-in. A deliberate bulk-approval action is limited to pending office requests from managed devices scoring 90+ health; the manager must confirm it.
- Employees can request a **temporary app exception** with a business justification when role/segment assignment excludes an application. Manager approval grants only that application for one hour and does not bypass device, MFA, location, time, risk or audit checks.
- Employee workspace includes **My activity**, a session-expiry warning with optional fresh-MFA extension, and remembers the last username/device/location (never the password or OTP).
- Manager Events, Audit and Sign-in requests support text filtering. Sign-in requests can be exported to CSV; Audit has a daily summary. Alert actions distinguish reviewed, false alarm, and incident confirmed (which signs the user out everywhere).
- All windows must run in the **same process** (one launcher): the audit chain is single-writer, so separate program instances cannot safely share this local state.

## Employee sign-in

Employee accounts are provisioned with random passwords on first launch. The startup dialog shows each username, role, password and TOTP secret once. The employee sign-in form supports all seeded roles and registered demo devices. For a quick isolated demonstration, select **Generate demo code** to fill the current TOTP code. The helper is intended only for a local lab; in real deployments, employees should use their enrolled authenticator and production identity provider.

The demo roster includes engineering, DevOps, security, HR, finance, sales, support, legal, executive and admin roles. The available resource catalogue includes the wiki, HR database, admin panel, source code, CI/CD, CRM, finance ledger, support desk, legal vault, SIEM console and executive reports.

## Employee workspace

The employee UI shows identity/session context, device trust score, and role-eligible resources. Clicking **Request access** invokes the same policy engine used by the main application. A resource request evaluates role-based access, micro-segmentation, device posture, location, allowed hours, MFA freshness, risk, and audit availability. A successful decision displays synthetic sample content; blocked requests do not return resource content. Step-up MFA can be verified and then the request retried.

## Manager console

The manager view contains:

- Overview and recent decisions
- Sign-in approval queue with context and CSV export
- Temporary application exception queue (one-hour scoped grants)
- Access event log with search/filter
- Active sessions, session revocation, sign-out-everywhere, forced step-up MFA, and device blocking
- Identity and micro-segmentation eligibility
- Device posture profiles
- Resource policy editor
- Security alerts with reviewed / false-alarm / incident-confirmed outcomes
- Audit log view, integrity verification, JSONL export, search/filter, and daily summary

Alert acknowledgement means “reviewed/seen”; it does not approve access or resolve an incident. The audit chain is intended as tamper-evident lab evidence. If verification fails, preserve the original log and anchor files; do not edit hashes to force a pass.

## Security and demo limitations

This is a **desktop lab/simulation**, not a production-ready remote access gateway. The policy and audit logic is exercised locally, while resource previews are synthetic data. Device posture checkboxes in demo mode simulate endpoint signals and are not genuine endpoint attestation. Production requires a real identity provider, managed-device attestation, secure deployment, key management, TLS, centralized monitoring and operational incident response.

Because the desktop GUI is standalone and intentionally does not run a network service, windows opened from one launcher share live state, but a separate launcher on another laptop does not. Cross-laptop live operation requires a shared authenticated backend over the LAN or a central service; it cannot be achieved by a standalone GUI alone.

This package does **not** yet implement cross-laptop synchronization or a persistent manager account store with mandatory manager TOTP. The manager demo login (`Ztna` / `Ztna123`) remains demo-only. Device blocks are in-memory for the current process; use the database-backed enterprise/admin control plane for persistent production enforcement.

## Source layout

`ztna_lab_v2.py` is the entry point and import name, as before. The code itself is split into 27 ordered parts in
[`ztna_lab/`](ztna_lab/README.md) (configuration, crypto, audit chain, policy engine, HTTP gateway, enterprise API,
DNS, GUI portals, ...). The entry point runs them in order in one shared namespace, so the program behaves exactly
like the former single file. Keep the `ztna_lab` folder next to `ztna_lab_v2.py`.

## Tests

Built-in self-test:

```powershell
$env:ZTNA_DEMO = "1"
$env:ZTNA_DEMO_OTP = "1"
python ztna_lab_v2.py selftest
```

The packaged code was checked for Python syntax. Targeted tests for sign-in approvals, temporary app exceptions, forced MFA, and the native GUI passed under a virtual display. The built-in self-test reported 9 passed, 5 skipped, 0 failed. The complete all-module test suite exceeded the available execution window and should be run locally before relying on this lab.

Optional enterprise API dependencies are listed in `requirements-enterprise.txt`; the native Tkinter GUI itself uses Python's standard library.


## Manager console: Dashboard tab (SIEM view)

The first tab of the manager console, driven by the real audit chain, alert table, sessions and device blocks:

- **Security metrics** - denied requests, failed sign-ins, open alerts, active sessions, and an event-volume chart. Windows: 15 min / 1 h / 6 h / 24 h.
- **Event stream** - newest first, severity colour-coded, with pause/resume.
- **Threat monitoring** - a 0-100 threat level with every point explained, highest-risk identities, and active containment.
- **Alerts** - open-alert queue with Reviewed / False alarm / Confirm incident.
- **Audit integrity** - background chain verification (on open, on demand, every 5 min), anchors, a linked-block ribbon, and a red banner on failure.

Data-layer tests: `python tests/test_siem_dashboard.py`.

## Manager console: Devices tab

Lists **every** employee in the directory with the devices enrolled to them (employees with no device are shown as "No device enrolled"; devices whose owner is not in the directory are grouped separately). Each device shows health score, the five posture checks and a status (Healthy / Below score 70 / Report is stale / No report yet / Blocked). Use the search box to find an employee or device. In the lab, click a PASS/FAIL cell to flip that check (audited).

## Sign-in requests: history, logging and live counters

- **Every outcome is closed out in the audit chain.** Besides PENDING / approved / denied, a request that is superseded by a newer one, cancelled by the employee, left unanswered (10 min) or approved but never used (5 min) now writes a closing `REVOKE` entry, so nothing stays "PENDING" in the log forever.
- **Persistence.** `signin_requests` gained `closed_at` and `closed_reason` (existing databases are migrated automatically). An unused approval stays recorded as "approved by X, not used". The old behaviour of deleting all requests older than 7 days at every start is replaced by `ZTNA_SIGNIN_HISTORY_DAYS` (default 90; only closed requests are ever pruned, never pending ones). The audit chain remains the permanent record.
- **Approval history.** The Sign-in requests tab has a Waiting / History / All switch, shows the outcome, who decided, when it was decided or closed, and the reason, and a timeline line for the selected request. Export CSV includes the new columns and a readable outcome.
- **Live counters.** Tab headings show `Sign-in requests (n)`, `App exceptions (n)` and `Alerts (n · m high)`; the header band summarises them; the Dashboard's Alerts heading shows the open count. They refresh immediately on sign-in, exception and alert events.

## Extra-access alerts, and the audit-fix report

Employee requests for access beyond their role raise a tracked alert (HIGH for sensitive apps, unmanaged or weak devices, or a pattern of requests), closed automatically by the manager's decision, with expiry and a timeline on the App-exceptions tab. New settings: `ZTNA_EXCEPTION_REQUEST_TTL` (seconds an unanswered request stays open, default 86400). The history retention setting `ZTNA_SIGNIN_HISTORY_DAYS` now also applies to extra-access requests.

See **FIXES.md** for the 24 audited bugs (authentication, OTP ordering, throttling, races, sessions, database errors), the evidence for each, and the actual test results. Run everything with `python tests/run_suite.py`.

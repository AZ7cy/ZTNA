# Audit findings and fixes

**Scope and honesty note.** No list of previously reported bugs was included in the package, so this is the result of an
audit of the areas named in the request (authentication, throttling, transaction races, session handling, OTP ordering,
database errors, other). Every item below was **reproduced against the real engine first**, then fixed, then covered by a
test in `tests/test_regressions.py` or `tests/test_extra_access.py`. Nothing here is theoretical.

## Findings

| # | Area | What was wrong (reproduced) | Fix |
|---|------|------------------------------|-----|
| 1 | OTP ordering | A correct password + valid code on the **wrong device** spent the code; the same code then failed on the right device. Same flaw in the HTTP gateway. | Order is now password → device → blocked → code **last**. |
| 2 | OTP / storage | If the replay-state file could not be written, `OSError` escaped the login, and the code was marked spent **in memory only** (replayable after a restart). | State is saved first; on failure the code is not spent and login/step-up return "state unavailable" (HTTP 503). It does not count against the employee. |
| 3 | Throttling | 300 login attempts from a blocked device wrote **300 audit entries** (log-flood / `AuditFull` DoS). | Blocked-device attempts are audited at most 3 per user+device per minute (the gateway's existing limiter). |
| 4 | Throttling | `refund_auth_attempt` reset the lock timer, wiping an active **60 s hard lock** to 0 s. | A refund only drops its own short backoff. |
| 5 | Throttling | Unexpected errors after a reservation left the attempt counted against the employee. | Reservations are refunded on any unexpected error. |
| 6 | Session handling | An approved sign-in completed **after a manager blocked the device** still opened a session. | Device ownership and block status are re-checked at completion; the approval is not consumed by a refused attempt. |
| 7 | Session handling | The **HTTP gateway ignored manager device blocks entirely**: a blocked device got `200` and a token. | `evaluate()` denies blocked devices and gateway login returns 403 (before any code is spent). |
| 8 | Session handling | A blocked device with forced step-up was offered MFA instead of being refused. | Block is checked before step-up. |
| 9 | Session handling | "Sign out everywhere" ignored a failed database write: the gateway reads the revoked flag from the DB, so the session could survive. | `revoke_user_sessions_report()` ends live sessions regardless and **reports** the failure; the manager UI warns. |
| 10 | Transaction races | 12 simultaneous identical extra-access requests created **12 pending rows**; 12 simultaneous sign-in requests created 12 pending rows. | Partial unique indexes (one pending per employee / per employee+app), in-process locks, retry on conflict; duplicates left by old versions are closed on upgrade. |
| 11 | Database errors | Extra-access code used raw `execute()`: errors escaped as `sqlite3` exceptions the UI does not catch, and a failed statement left an open write transaction that made **every other writer fail with "database is locked"**. | Rollback-on-error helpers; all state reads/writes raise `StateStoreError`. |
| 12 | Database errors | The manager's 10-second refresh called those functions unguarded: one database error stopped the whole console updating. | Refresh survives, keeps the visible tables, shows a "Database unavailable" warning. |
| 13 | Database errors | A failed alert insert was reported as success, announced to the GUI, and **consumed the dedupe window**, silently suppressing the next real alert. | `db_alert` returns the id or `None`; a failed insert releases the dedupe slot and announces nothing. |
| 14 | Other | "False alarm" and "Confirm incident" were both stored as plain "Reviewed". | Stored as 2 / 3 and shown in both alert lists. |
| 15 | Other | Bulk-acknowledge skipped `HIGH` but would close `CRITICAL` alerts. | Both are excluded. |
| 16 | Other | Extra-access request/decision entries named an application, so they fed access telemetry and attack detection: approvals counted as "allowed", and 5 manager denials could raise a false `REPEATED_DENIALS` alert against the employee. Audit text read "alice opened wiki". | Such entries are manager workflow: excluded from telemetry/detection, worded correctly, filed as "Response" in the dashboard. |
| 17 | Other | Re-initialising the runtime in one process kept writing audit entries to the previous file and used the previous database connection. | Audit writer/counters reset and the DB connection follows `DB_FILE`. |
| 18 | Authentication | Manager sign-in compared credentials with `hmac.compare_digest(str, str)`, which raises on **any non-ASCII character**: with a non-ASCII configured credential the manager could never sign in (HTTP 500), and non-ASCII attempts were neither audited nor counted by the lockout limiter. The success entry also named a hard-coded user ("puja") instead of the configured manager. Same flaw in the desktop manager sign-in. | `_ct_eq()` compares UTF-8 bytes; attempts are counted and audited; the real manager name is logged. |
| 19 | Authentication | Setting a password containing an accented letter crashed the Add-user dialog and the admin CLI (same `compare_digest` flaw). | Same `_ct_eq()`. |
| 20 | Authentication | A **correct** password raised `RuntimeError` when the optional hash-upgrade step could not get KDF capacity (legacy-format hashes); stored upper-case hex hashes never matched. | The upgrade is best-effort (retried at the next login); hex case is normalised. |
| 21 | OTP | `totp(secret, 0)` used the current time because `t or time.time()` treats 0 as missing. | `None` check. |
| 22 | Other | `/api/metrics` and the manager's "Daily security summary" counted every log line (logins, admin changes, manager responses, extra-access decisions) as an access event; failed logins appeared as "Denied". | Only access decisions are counted; failed sign-ins are listed separately. |
| 23 | Other (employee portal) | One transient database error froze the employee **waiting screen for good** (its 1-second poll was never re-armed); cancelling then crashed the callback; `complete_signin` could raise into the loop; after the first session the "your session is expiring" prompt never appeared again. | Poll retries and keeps waiting, the approval is kept until it is really used or expires, cancel reports instead of crashing, the warning is re-armed per session. |
| 24 | Hardening | `_fmt_ts` and `_to_int` could raise `OverflowError`; `posture()` raised `KeyError` for an unknown device; asking for an app you already hold temporarily said "assigned to your role". | Tolerant helpers; accurate message. |

## New: extra-access alerts

Every request an employee makes for access beyond their role raises an `EXTRA_ACCESS_REQUEST` alert, linked to the
request. **HIGH** for a sensitive app (min posture >= 80), an unmanaged device or weak device health; otherwise MEDIUM.
Three different apps in one hour raise an `EXTRA_ACCESS_PATTERN` HIGH alert. Tracking: the manager's decision closes the
alert and appends the outcome; unanswered requests lapse (`ZTNA_EXCEPTION_REQUEST_TTL`, default 24 h) and approved access
ends on time, each with an audit entry; the App-exceptions tab shows the alert state, outcome and a timeline; the
Dashboard shows the alert and "Extra access in use".

## What the second, broader sweep covered

Found problems are the rows 18-24 above. These areas were checked and **found clean** (so they are not in the table):

* **Static analysis** of the whole 10,000-line file with a purpose-built checker (undefined names, `self.` attributes never
  assigned, duplicate definitions that silently override each other, mutable default arguments, bare `except`): nothing.
* **Tokens and replay:** JWT encode/decode (algorithm pinned, expiry, malformed input), proof-of-possession nonces (replay,
  expiry, capacity), the audit rate limiter.
* **Sessions:** per-user cap (oldest evicted and denied), idle expiry, logout (revoked flag persisted), dead-session reaping.
* **Audit chain:** 8 threads x 60 writes with rotation (480 entries over 38 segments): no errors, chain verifies, links
  consistent, in-memory tail matches.
* **HTTP gateway:** 4,627 malformed requests (random JSON types, oversized and deeply nested bodies, bad headers and
  methods, path-traversal attempts) over every route: **no 5xx**; `/download/N` accepts digits only.
* **Every manager-console handler** called in an empty system and in a busy one (all four dashboard windows): no exceptions.

One change from this round was **reverted**: returning 405 for DELETE/PATCH/OPTIONS looked more consistent, but the
project's own test deliberately requires 501 for unimplemented methods (valid HTTP), so it was not a bug.

## Test results (actual)

* Full suite, final code: **147 run, 0 failures, 0 errors, 2 skipped** (the same 2 skips as in the original), 175.6 s.
  Growth: 72 original -> 88 -> 135 -> 147 tests. This round added 7 helper regressions, 3 gateway regressions, 1 behaviour
  guard, and the headless GUI scenario suite (`tests/gui_scenarios.py`, run by `tests/test_gui_scenarios.py`).
* The new round-2 regression tests, run against the engine **before** this round's fixes: **11 fail** (7 failures, 4 errors
  from helpers that did not exist yet); the rest are controls.
* The GUI scenarios against the engine before the employee-portal fix crash at the first database error; against the
  original upload they fail at the first check (no Dashboard).
* Earlier result still holds: of the first 30 regression tests, 21 fail on the original engine.
* The GUI is exercised under a stand-in for Tk (`tests/faketk.py`) with real engine data; there is no real window in the
  test environment, so a manual look at the real screens is still needed.

## Not changed / known limits

* Logout and the step-up-expiry path still write the revoked flag best-effort (logged on failure).
* All unknown usernames share one throttle bucket (by design: avoids account enumeration).
* Windows-specific behaviour (file locking) was not exercised.
* "All bugs" cannot be proven: this is a bounded sweep (areas and methods listed above). Layout/appearance bugs need a real display.

# Bug Fixes Applied

This document summarizes the bugs fixed after the initial import and module split.

## Commit Structure

1. **4d1e04e** Split ztna.py into 27 ordered source parts
2. **ad4bcc0** Fix audit-log failures on Windows and after write errors
3. **38ba420** Fix desktop sign-in, session and throttling bugs

## Fixed Issues

### Audit Chain and Windows File Operations (ad4bcc0)

**A1. Segment rotation crashed on Windows when the verifier held a file open**
- **Impact**: Sign-in approvals stayed "approved" with no audit entry (the raw OSError skipped the caller's rollback).
- **Fix**: The verifier now opens segments with FILE_SHARE_DELETE, rotation renames are retried briefly, and any I/O error before the write is raised as AuditFull.

**A3. Failed write or fsync broke the chain permanently**
- **Impact**: A partial line or bytes that never became the chain head stayed in the file, so the next entry broke the chain and the next start refused to run.
- **Fix**: The file is cut back to the last complete entry and buffered bytes are dropped.

**A_anchor. Failed anchor update after a durable write raised a raw OSError**
- **Impact**: The entry was recorded but the action's HTTP response said it wasn't.
- **Fix**: The entry now stands; the next audit() re-anchors first and refuses to append if it still cannot. Anchors never trail by more than the one entry startup recovery already repairs.

**A5. Lone surrogates in a field made the hash crash**
- **Impact**: A failed login with a device id containing "\ud800" (legal JSON from an HTTP body) was a 500 and was never audited.
- **Fix**: surrogatepass encodes every other string to the same bytes, so existing chains verify unchanged.

**A4. Verifier crashed on tampered lines that are valid JSON but not objects**
- **Impact**: AttributeError/RecursionError instead of reporting the line as broken.
- **Fix**: Non-object lines and deeply nested JSON are now reported as broken.

**Windows file replace across the board**
- **Impact**: Atomic file updates (users, TOTP state, device keys, anchors, GUI preferences, enterprise anchor) could raise PermissionError when another handle (antivirus scan, backup, the verifier) briefly held the file open.
- **Fix**: os.replace() is retried briefly on Windows in every atomic update, and the enterprise anchor read retries the matching PermissionError instead of reporting it as tampering.

### Desktop Sign-In, Sessions and Throttling (38ba420)

**B1. Plain `python ztna.py` gave 4 hard-coded devices, not 20**
- **Impact**: 17 of the 20 demo employees could not sign in.
- **Fix**: The full fixture list is now added whenever demo mode is on (regardless of when it was turned on).

**C2/G11. Approved sign-in could raise StateStoreError after the approval was marked used**
- **Impact**: Pruning another user's expired session needed the database; the employee's waiting screen froze and every retry said "already used".
- **Fix**: Expired sessions are revoked best-effort, the session cap is enforced before the approval is claimed, and the claim is released if no session opens. The HTTP login uses the same pruning and refunds the attempt on a state-store error.

**C6. Manager could approve an expired sign-in request**
- **Impact**: An approval given after the 10-minute lifetime opened a session.
- **Fix**: Requests past their lifetime are closed as expired before the manager's decision is recorded.

**G1. Revoked/expired session left the employee identity set**
- **Impact**: A stale window could still file requests in that employee's name.
- **Fix**: access() and stepup() now clear user and device when the session ends.

**C3. Windows file lock gave up after ~10 s**
- **Impact**: msvcrt LK_LOCK raised "Resource deadlock avoided" instead of waiting.
- **Fix**: The lock now polls LK_NBLCK, so it waits as documented.

**C4. ZTNA_AUTH_HARD_LOCK_SECONDS above 600 was cut to 600 s**
- **Impact**: A configured hard lock longer than 10 minutes was ignored.
- **Fix**: Ten quiet minutes reset the counter only when no hard lock is running.

**C5. After ~1,000 throttled attempts, 2.0**n raised OverflowError**
- **Impact**: Every further login for that user and source was an internal error.
- **Fix**: The exponent is capped at 16.

**B2. evaluate() counted the burst deque while other threads appended**
- **Impact**: "deque mutated during iteration", HTTP 500 with no audit entry.
- **Fix**: The count is now taken while holding LOCK.

**B3. Bad tunables broke every access decision or ended the GUI**
- **Impact**: ZTNA_RISK_BURST_N=40.5 raised SystemExit from a Tk callback.
- **Fix**: ZTNA_RISK_BURST_N, ZTNA_EXCEPTION_REQUEST_TTL, ZTNA_MAX_AUDIT_SEGMENTS and ZTNA_TELEMETRY_RETENTION_DAYS are validated at startup.

**C7. Missing `cryptography` blamed the wrapping key or Python/Tkinter**
- **Impact**: The GUI provisioned credentials and then crashed; the launcher's error text didn't name the missing package.
- **Fix**: The GUI now checks before provisioning and says so, a decrypt failure no longer blames the key, and the launcher's error names the package.

**selftest H5. Impossible fixture (hard lock running 10 minutes after the last attempt)**
- **Fix**: The test now uses the state a real lock leaves (the lock ran out long ago, as it always has after 10 idle minutes with the default setting).

## Test Results

- All targeted tests pass (access_exceptions, extra_access, gui_scenarios, regressions, siem_dashboard, signin_approval, signin_history, enterprise).
- Selftest: 14 passed, 0 failed.
- Full suite: 188 tests run, 185 passed, 3 pre-existing failures (Windows systemd unit path quoting).

## Verification Approach

Each fix group was tested against reproduction scripts that:
1. Confirm the bug exists on the pre-fix code.
2. Confirm the fix resolves it.
3. Verify the fix doesn't break existing tests.

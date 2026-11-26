"""Headless GUI scenarios (run in their own process by test_gui_scenarios.py).

tkinter is replaced by tests/faketk.py *before* the engine is imported, then the real ManagerPortal / EmployeePortal /
SiemDashboard code is driven against the real engine. Every check is an assertion; the script prints ALL OK at the end.
"""
import os, sys, tempfile, time, types
os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-gui-"))
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import faketk
tk = faketk.build()
fd = types.SimpleNamespace(asksaveasfilename=lambda **k: os.path.join(os.environ["ZTNA_DATA_DIR"], "export.csv")); tk.filedialog = fd; sys.modules["tkinter.filedialog"] = fd
import ztna as z
z.REQUESTED_MODE = "gui"; z.init_runtime("gui")
cr = {u: p for u, p, _r, _s in z.DEMO_BOOTSTRAP_CREDENTIALS}
dev = lambda u: next(d for d, v in z.DEVICES.items() if v["owner"] == u)
outside = lambda u, hi=None: next(r for r in z.RESOURCES if not (z.rbac_allows(u, r) and z.segment_allows(u, r)) and (hi is None or (z.RESOURCES[r]["min_posture"] >= 80) == hi))
dialogs = []
for n in ("showinfo", "showwarning", "showerror"): setattr(z.messagebox, n, (lambda n: lambda *a, **k: dialogs.append(n))(n))
z.messagebox.askyesno = lambda *a, **k: True
tabs = {}
class NB(faketk.FakeWidget):
    def add(self, child, text=None, **k): tabs[child] = text
    def tab(self, child, text=None, **k):
        if text is not None: tabs[child] = text
    def select(self, *a): return ".none"
z.ttk.Notebook = NB
class App(faketk.FakeWidget):
    def refresh_hub(self): pass
def fresh(u):
    with z.LOCK: z.LAST_TOTP.pop(u, None); z.FAILS.clear()
def broken(table):
    conn = z._db_connection(); conn.execute(f"ALTER TABLE {table} RENAME TO {table}_x"); conn.commit()
    return lambda: (conn.execute(f"ALTER TABLE {table}_x RENAME TO {table}"), conn.commit())

# ============================================================ manager console
mgr = z.ManagerPortal(App()); mgr.manager_user = "puja"; mgr._show_workspace()
assert list(tabs.values())[0] == "Dashboard", tabs
assert tabs[mgr.t_requests] == "Sign-in requests" and mgr.v_badge.get() == "All clear"

# --- devices: every employee and every device, including employees with none
t = mgr.dev_tree
emps = [i for i in t._items if i.startswith("u:")]; devs = [i for i in t._items if i.startswith("d:")]
assert len(emps) == len(z.USERS) and len(devs) == len(z.DEVICES), (len(emps), len(devs))
z.USERS["zed"] = dict(z.USERS["alice"]); mgr._refresh_posture()
assert t._items["u:zed"]["values"][-1] == "No device enrolled"; del z.USERS["zed"]; mgr._refresh_posture()

# --- sign-in requests: live counters, history, outcomes
reqs = {}
for u in ("frank", "grace", "jack"):
    fresh(u); e = z.DesktopZTNA(); ok, rid = e.request_signin(u, cr[u], e.demo_otp(u), dev(u), "office"); assert ok, rid; reqs[u] = (e, rid)
mgr._refresh()
assert tabs[mgr.t_requests] == "Sign-in requests (3)", tabs[mgr.t_requests]
assert "3 sign-ins waiting" in mgr.v_badge.get() and mgr.rb_view["Waiting"].kw["text"] == "Waiting (3)"
z.decide_signin_request(reqs["grace"][1], True, "puja", "ok"); reqs["grace"][0].complete_signin(reqs["grace"][1])
z.decide_signin_request(reqs["jack"][1], False, "puja", "unknown device")
mgr._refresh(); assert tabs[mgr.t_requests] == "Sign-in requests (1)"
mgr.v_req_view.set("History"); mgr._refresh()
outcomes = {v["values"][1]: v["values"][8] for v in mgr.req_tree._items.values()}
assert outcomes["grace"] == "Approved - session opened" and outcomes["jack"] == "Denied by puja", outcomes
mgr.req_tree._sel = (reqs["jack"][1],); mgr._request_context(); assert "unknown device" in mgr.v_req_context.get() and "Denied by puja" in mgr.v_req_context.get()
mgr.v_req_view.set("Waiting"); mgr._refresh(); assert [v["values"][1] for v in mgr.req_tree._items.values()] == ["frank"]
mgr.v_req_view.set("All"); mgr._refresh()
mgr._export_signins(); assert os.path.getsize(fd.asksaveasfilename()) > 100

# --- extra-access requests: alert, tracking, counters
r_low = z.create_access_exception_request("mia", dev("mia"), outside("mia", False), "figures for the review")
r_high = z.create_access_exception_request("tom", dev("tom"), outside("tom", True), "hotfix")
z.GUI_EVENTS.put({"kind": "exception-created"}); mgr._watch_gui_events()
assert tabs[mgr.t_exceptions] == "App exceptions (2)", tabs[mgr.t_exceptions]
assert tabs[mgr.t_alerts].startswith("Alerts (") and "1 high" in tabs[mgr.t_alerts], tabs[mgr.t_alerts]
assert {v["values"][7] for v in mgr.exc_tree._items.values()} == {"Needs a decision"}
mgr.exc_tree._sel = (r_low,); mgr._decide_exception(True); mgr.exc_tree._sel = (r_high,); mgr._decide_exception(False)
assert tabs[mgr.t_exceptions] == "App exceptions", tabs[mgr.t_exceptions]
assert {v["values"][7] for v in mgr.exc_tree._items.values()} == {"Closed"} and mgr.exc_tree._items[r_low]["values"][8].startswith("Approved by puja until")
mgr.exc_tree._sel = (r_low,); mgr._exception_detail(); assert "approved by puja" in mgr.v_exc_detail.get()

# --- alerts: "false alarm" / "incident" are stored and shown as such
fresh("nina"); e = z.DesktopZTNA(); e.login("nina", cr["nina"], e.demo_otp("nina"), dev("nina"), "office"); [e.access(r) for r in z.RESOURCES]
z.GUI_EVENTS.put({"kind": "alert-raised"}); mgr._watch_gui_events()
new = [i for i, v in mgr.al_tree._items.items() if v["values"][5] == "NEW" and v["values"][2].startswith("Blocked")]; assert len(new) >= 2
mgr.al_tree._sel = (new[0],); mgr._alert_outcome("false_alarm"); mgr.al_tree._sel = (new[1],); mgr._alert_outcome("incident_confirmed")
with z.TELEMETRY_CACHE_LOCK: z.TELEMETRY_CACHE["alerts_ts"] = 0.0
status = {str(a["id"]): a["status"] for a in z.recent_alerts(500)}
assert (status[new[0]], status[new[1]]) == (2, 3), status
assert (mgr.al_tree._items[new[0]]["values"][5], mgr.al_tree._items[new[1]]["values"][5]) == ("FALSE ALARM", "INCIDENT")

# --- dashboard
d = mgr.siem
while d.verifier.running: time.sleep(0.02)
d.refresh()
assert d.integrity_ok is True and d.pill.kw["text"] == "CHAIN INTACT"
assert len(d.stream._items) <= d.STREAM_LIMIT and d.tiles["alerts"].v_val.get() == str(len([a for a in z.recent_alerts(500) if not a["acknowledged"]]))
d._toggle_pause(); n = len(d.stream._items); fresh("alice"); e = z.DesktopZTNA(); e.login("alice", cr["alice"], e.demo_otp("alice"), dev("alice"), "office"); d.refresh()
assert len(d.stream._items) == n and "new" in d.btn_pause.kw["text"]; d._toggle_pause()
for w in ("15 minutes", "6 hours", "24 hours", "1 hour"): d.cb_window.set(w); d._window_changed()

# --- a database outage must not stop the console or blank its tables
rows_before = len(mgr.exc_tree._items); restore = broken("access_exception_requests")
try:
    mgr._refresh(); assert "Database unavailable" in mgr.v_badge.get() and len(mgr.exc_tree._items) == rows_before
finally: restore()
mgr._refresh(); assert "Database unavailable" not in mgr.v_badge.get()

# ============================================================ employee portal
sched = {}
class EP(z.EmployeePortal):
    def _schedule(self, key, ms, fn): sched[key] = (ms, fn)
ep = EP(App()); fresh("alice")
ep.v_user.set("alice"); ep._user_changed(); ep.v_pass.set(cr["alice"]); ep._demo_otp(); ep._submit()
assert ep.request_id and "poll" in sched
restore = broken("signin_requests")
try:
    sched.clear(); ep._poll()
    assert "poll" in sched and "retrying" in ep.v_elapsed.get(), "a database error must not freeze the waiting screen"
    dialogs.clear(); ep._cancel_request(); assert dialogs == ["showwarning"]
finally: restore()
fresh("alice"); ep.request_id = None; ep._show_login(); ep.v_user.set("alice"); ep._user_changed(); ep.v_pass.set(cr["alice"]); ep._demo_otp(); ep._submit(); rid = ep.request_id
z.decide_signin_request(rid, True, "puja", "ok")
real = z.claim_signin_request
def flaky(r): raise z.StateStoreError("database is locked")
z.claim_signin_request = flaky; sched.clear()
try:
    ep._poll(); assert "poll" in sched and ep.engine.session is None
finally: z.claim_signin_request = real
sched.clear(); ep._poll(); assert ep.engine.session, "the same approval must still work once the database recovers"
ep._session_warning_shown = True; ep.engine.logout(); fresh("alice"); ep._show_login(); ep.v_user.set("alice"); ep._user_changed(); ep.v_pass.set(cr["alice"]); ep._demo_otp(); ep._submit()
z.decide_signin_request(ep.request_id, True, "puja", "ok"); ep._poll(); assert ep._session_warning_shown is False, "the expiry warning must be re-armed for every session"
print("ALL OK")

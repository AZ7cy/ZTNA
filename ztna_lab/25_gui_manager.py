# Part 25 of ztna.py - desktop GUI: manager console.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ------------------------------------------------------------------------------ manager side
class ManagerPortal(PortalWindow):
    MANAGER_DEMO_USER = "Ztna"
    MANAGER_DEMO_PASSWORD = "Ztna123"

    def __init__(self, app):
        super().__init__(app, "ZTNA Access Workspace — Manager Console", "1180x780", (940, 640))
        self.manager_user = None
        self._seen_pending = set()
        self._show_login()

    def _show_login(self):
        self._clear(); self.title("ZTNA Access Workspace — Manager sign-in")
        self._band("ZTNA manager console", "")
        wrap = ttk.Frame(self, padding=(30, 26)); wrap.pack(fill="both", expand=True)
        panel = Panel(wrap, "Operator authentication", padding=22); panel.pack(pady=4)
        g = panel.body; g.columnconfigure(1, weight=1)
        self.v_mu, self.v_mp = tk.StringVar(), tk.StringVar()
        eu = self._form_row(g, 0, "Manager username", lambda p: ttk.Entry(p, textvariable=self.v_mu, width=34))
        self._form_row(g, 1, "Password", lambda p: ttk.Entry(p, textvariable=self.v_mp, show="•", width=34))
        ttk.Separator(g).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 12))
        a = ttk.Frame(g); a.grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Button(a, text="Close", command=self.close).pack(side="left")
        ttk.Button(a, text="Sign in to manager console", style="Primary.TButton", command=self._signin).pack(side="right")
        self.bind("<Return>", lambda _e: self._signin())
        eu.focus_set()

    def _signin(self):
        u, p = self.v_mu.get().strip(), self.v_mp.get()
        if DEMO: eu, ep = self.MANAGER_DEMO_USER, self.MANAGER_DEMO_PASSWORD
        else: eu, ep = os.environ.get("ZTNA_MANAGER_USER", ""), os.environ.get("ZTNA_MANAGER_PASSWORD", "")
        ok = bool(eu and ep and (_ct_eq(u, eu) & _ct_eq(p, ep)))
        if not ok:
            try: audit(user=u or "unknown", device="manager-desktop", resource="manager-login", decision="DENY", reasons=["manager authentication failed"])
            except Exception: pass
            messagebox.showerror("Sign in failed", "Manager credentials were not accepted.", parent=self); return
        try: audit(user=u, device="manager-desktop", resource="manager-login", decision="ALLOW", reasons=["manager authentication verified"])
        except (AuditFull, AuditTamper):
            messagebox.showerror("Audit unavailable", "The audit system is unavailable, so manager access is refused. Preserve the log and investigate integrity before retrying.", parent=self); return
        self.unbind("<Return>")
        self.manager_user = u
        self._show_workspace()

    def _show_workspace(self):
        self._clear(); self.title("ZTNA Access Workspace — Manager Console")
        right = self._band("Security operations center", f"Signed in as {self.manager_user}")
        self.v_badge = tk.StringVar()
        ttk.Label(right, textvariable=self.v_badge, style="BandSub.TLabel", font=(UI_FONT, 10, "bold")).pack(side="left", padx=(0, 14))
        ttk.Button(right, text="Sign out", style="Ghost.TButton", command=self._sign_out).pack(side="left")
        wrap = ttk.Frame(self, padding=(18, 14, 18, 16)); wrap.pack(fill="both", expand=True)
        self.nb = ttk.Notebook(wrap); self.nb.pack(fill="both", expand=True)
        self._dev_sig = None
        for build in (self._tab_dashboard, self._tab_requests, self._tab_exceptions, self._tab_overview, self._tab_events, self._tab_sessions, self._tab_identity,
                      self._tab_posture, self._tab_policies, self._tab_alerts, self._tab_audit):
            build()
        self._refresh()

    def _tab(self, text):
        t = ttk.Frame(self.nb, padding=14); self.nb.add(t, text=text); return t

    def _tab_dashboard(self):
        t = ttk.Frame(self.nb, padding=(6, 8, 2, 4)); self.nb.add(t, text="Dashboard"); self.t_dashboard = t
        self.siem = SiemDashboard(t, self); self.siem.pack(fill="both", expand=True)

    # ---- sign-in requests
    def _tab_requests(self):
        t = self._tab("Sign-in requests"); self.t_requests = t
        top = ttk.Frame(t); top.pack(fill="x", pady=(0, 10))
        self.v_req_sum = tk.StringVar()
        ttk.Label(top, textvariable=self.v_req_sum, style="Section.TLabel").pack(side="left")
        self.v_req_view = tk.StringVar(value="Waiting"); self.rb_view = {}
        views = ttk.Frame(top); views.pack(side="right")
        ttk.Label(views, text="Show:", style="Muted.TLabel").pack(side="left", padx=(0, 4))
        for name in ("Waiting", "History", "All"):
            rb = ttk.Radiobutton(views, text=name, value=name, variable=self.v_req_view, command=self._refresh); rb.pack(side="left", padx=6); self.rb_view[name] = rb
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 10))
        self.btn_approve = ttk.Button(bar, text="Approve selected", style="Primary.TButton", command=lambda: self._decide(True))
        self.btn_approve.pack(side="left")
        self.btn_deny = ttk.Button(bar, text="Deny selected", command=lambda: self._decide(False)); self.btn_deny.pack(side="left", padx=8)
        ttk.Button(bar, text="Approve low-risk managed", command=self._approve_managed).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="Export CSV", command=self._export_signins).pack(side="left", padx=(0, 8))
        ttk.Label(bar, text="Filter:", style="Muted.TLabel").pack(side="left", padx=(4, 4))
        self.v_req_filter = tk.StringVar()
        ent_filter = ttk.Entry(bar, textvariable=self.v_req_filter, width=18); ent_filter.pack(side="left")
        ent_filter.bind("<KeyRelease>", lambda _e: self._refresh())
        ttk.Label(bar, text="Reason (optional):", style="Muted.TLabel").pack(side="left", padx=(16, 6))
        self.v_note = tk.StringVar(); ttk.Entry(bar, textvariable=self.v_note, width=34).pack(side="left")
        self.v_req_context = tk.StringVar(value="Select a request to see its context (waiting) or its full timeline (decided).")
        ttk.Label(t, textvariable=self.v_req_context, style="Muted.TLabel", wraplength=1100, justify="left").pack(side="bottom", fill="x", pady=(8, 0))
        self.req_tree = self._tree(t, ("time", "emp", "name", "role", "dev", "trust", "loc", "status", "outcome", "by", "at", "note"),
                                   ("Requested", "Employee", "Name", "Role", "Device", "Health", "Network", "Status", "Outcome", "Decided by", "Decided / closed", "Reason"),
                                   (140, 70, 115, 70, 105, 60, 65, 80, 270, 80, 140, 200), stretch="note")
        self.req_tree.bind("<<TreeviewSelect>>", lambda _e: (self._sync_buttons(), self._request_context()))
        self.req_tree.bind("<Double-1>", lambda _e: self._request_context())

    @staticmethod
    def _dur(seconds):
        seconds = max(0, int(seconds))
        return f"{seconds} s" if seconds < 60 else f"{seconds // 60} min {seconds % 60} s" if seconds < 3600 else f"{seconds // 3600} h {seconds % 3600 // 60} min"

    def _signin_timeline(self, r):
        steps = [f"Requested {_fmt_ts(r['ts'])} from {r['device']} ({r['location']})"]
        if r.get("decided_by") and r.get("decided_at"):
            word = "denied" if r["status"] == "denied" else "approved"
            steps.append(f"{word} by {r['decided_by']} at {_fmt_ts(r['decided_at'])}, {self._dur(r['decided_at'] - r['ts'])} after the request")
        if r.get("note"): steps.append(f"reason given: \"{r['note']}\"")
        end = f" ({_fmt_ts(r['closed_at'])})" if r.get("closed_at") else ""
        steps.append(f"outcome: {signin_outcome(r)}{end}")
        return "  →  ".join(steps)

    def _request_context(self):
        sel = self.req_tree.selection() if hasattr(self, "req_tree") else ()
        if not sel: return
        row = get_signin_request(sel[0])
        if not row: return
        if row["status"] != "pending":
            self.v_req_context.set("Timeline: " + self._signin_timeline(row)); return
        user, device = row.get("user", ""), row.get("device", "")
        fails = recent_fails(user, "desktop") if user else 0
        previous = LASTLOC.get(user)
        location_note = "no recent location change recorded"
        if previous and time.time() - previous[1] < 3600:
            location_note = f"last observed location {previous[0]} at {_fmt_ts(previous[1])}"
        approved = _db_connection().execute("SELECT MAX(decided_at) FROM signin_requests WHERE user=? AND status='approved'", (user,)).fetchone()[0]
        approved_note = _fmt_ts(approved) if approved else "never"
        health = posture(device) if device in DEVICES else 0
        managed = bool(DEVICES.get(device, {}).get("corporate_managed"))
        self.v_req_context.set(f"Context: {fails} recent failed authentication(s) · device {'managed' if managed else 'BYOD/unknown'} · health {health}/100 · {location_note} · last manager approval: {approved_note}. Review context before approving.")

    def _approve_managed(self):
        eligible = []
        for iid in self.req_tree.get_children():
            if self.req_tree.set(iid, "status") != "PENDING": continue
            row = get_signin_request(iid)
            d = DEVICES.get(row.get("device", ""), {}) if row else {}
            if row and row.get("location") == "office" and d.get("corporate_managed") and posture(row.get("device", "")) >= 90 and row.get("device") not in BLOCKED_DEVICES:
                eligible.append(iid)
        if not eligible:
            messagebox.showinfo("Low-risk approvals", "No pending request meets all criteria: office connection, managed device, health ≥90, and not blocked.", parent=self); return
        if not messagebox.askyesno("Approve low-risk requests", f"Approve {len(eligible)} request(s) from managed devices with health ≥90 on the office network?", parent=self): return
        done = 0
        for rid in eligible:
            try:
                if decide_signin_request(rid, True, self.manager_user, "Bulk approved: office + managed device + health >= 90"): done += 1
            except (AuditFull, AuditTamper, StateStoreError) as exc:
                messagebox.showerror("Audit failure", str(exc), parent=self); break
        self._refresh()
        messagebox.showinfo("Low-risk approvals", f"Approved {done} request(s).", parent=self)

    def _export_signins(self):
        from tkinter import filedialog
        target = filedialog.asksaveasfilename(parent=self, title="Export sign-in requests", defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="ztna_signin_requests.csv")
        if not target: return
        try:
            with open(target, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f); w.writerow(_SIGNIN_COLS + ("outcome",))
                for row in list_signin_requests(100000):
                    w.writerow([(_fmt_ts(row[k]) if k in ("ts", "decided_at", "closed_at") and row.get(k) else row.get(k, "")) for k in _SIGNIN_COLS] + [signin_outcome(row)])
            messagebox.showinfo("Export complete", f"Sign-in requests exported to:\n{target}", parent=self)
        except OSError as exc: messagebox.showerror("Export failed", str(exc), parent=self)

    def _sync_buttons(self):
        ok = any(self.req_tree.set(i, "status") == "PENDING" for i in self.req_tree.selection())
        for b in (self.btn_approve, self.btn_deny): b.state(["!disabled"] if ok else ["disabled"])

    def _decide(self, approve):
        ids = [i for i in self.req_tree.selection() if self.req_tree.set(i, "status") == "PENDING"]
        if not ids:
            messagebox.showinfo("Sign-in requests", "Select a pending request first.", parent=self); return
        done = 0
        for rid in ids:
            try:
                if decide_signin_request(rid, approve, self.manager_user, self.v_note.get().strip()): done += 1
            except (AuditFull, AuditTamper, StateStoreError):
                messagebox.showerror("Audit failure", "The decision could not be recorded in the audit log, so it was not applied.", parent=self); break
        self.v_note.set(""); self._refresh()
        if done < len(ids): messagebox.showinfo("Sign-in requests", "Some requests were already handled or expired.", parent=self)

    def _tab_exceptions(self):
        t = self._tab("App exceptions"); self.t_exceptions = t
        top = ttk.Frame(t); top.pack(fill="x", pady=(0, 8))
        self.v_exc_sum = tk.StringVar(); ttk.Label(top, textvariable=self.v_exc_sum, style="Section.TLabel").pack(side="left")
        ttk.Button(top, text="Approve 1 hour", style="Primary.TButton", command=lambda: self._decide_exception(True)).pack(side="right")
        ttk.Button(top, text="Deny", command=lambda: self._decide_exception(False)).pack(side="right", padx=6)
        self.v_exc_detail = tk.StringVar(value="Every request raises an alert. Your decision closes it, and the outcome is tracked here until the access ends.")
        ttk.Label(t, textvariable=self.v_exc_detail, style="Muted.TLabel", wraplength=1100, justify="left").pack(side="bottom", fill="x", pady=(8, 0))
        self.exc_tree = self._tree(t, ("time","user","role","resource","device","reason","status","alert","outcome","by","expires"),
                                   ("Requested","User","Role","Application","Device","Business reason","Status","Alert","Outcome","Decided by","Access ends"),
                                   (140,70,80,110,110,230,80,110,230,80,130), stretch="reason")
        self.exc_tree.bind("<<TreeviewSelect>>", lambda _e: self._exception_detail())
        self._exc_rows = {}

    def _exception_detail(self):
        sel = self.exc_tree.selection(); r = self._exc_rows.get(sel[0]) if sel else None
        if not r: return
        steps = [f"Requested {_fmt_ts(r['ts'])} by {_person(r['user'])[0]} for {r['resource']}: \"{r['reason']}\""]
        if r.get("decided_by") and r.get("decided_at"): steps.append(f"{'denied' if r['status'] == 'denied' else 'approved'} by {r['decided_by']} at {_fmt_ts(r['decided_at'])}")
        steps.append(f"outcome: {exception_outcome(r)}" + (f" ({_fmt_ts(r['closed_at'])})" if r.get("closed_at") else ""))
        self.v_exc_detail.set("Timeline: " + "  →  ".join(steps))

    def _decide_exception(self, approve):
        selected = self.exc_tree.selection()
        if not selected: messagebox.showinfo("App exceptions", "Select a request first.", parent=self); return
        done = 0
        for rid in selected:
            try:
                row = decide_access_exception_request(rid, approve, self.manager_user, 3600)
                if row: done += 1
            except (AuditFull, AuditTamper, StateStoreError) as exc:
                messagebox.showerror("Audit failure", str(exc), parent=self); break
        self._refresh()
        messagebox.showinfo("App exceptions", f"{'Approved for one hour' if approve else 'Denied'}: {done} request(s).", parent=self)

    # ---- other tabs
    def _tab_overview(self):
        t = self._tab("Overview")
        tiles = ttk.Frame(t); tiles.pack(fill="x", pady=(0, 14))
        self.v_kpi = {k: tk.StringVar(value="–") for k in ("events", "allow", "stepup", "deny", "risk", "alerts", "sessions", "pending")}
        for i, (key, label) in enumerate((("events", "Decisions (60 min)"), ("allow", "Allowed"), ("stepup", "Step-up"), ("deny", "Denied"),
                                          ("risk", "Average risk"), ("alerts", "Alerts"), ("sessions", "Active sessions"), ("pending", "Sign-ins waiting"))):
            p = Panel(tiles, label, padding=(12, 8)); p.grid(row=i // 4, column=i % 4, sticky="nsew", padx=(0 if i % 4 == 0 else 8, 0), pady=(0 if i < 4 else 8, 0))
            tiles.columnconfigure(i % 4, weight=1, uniform="kpi")
            ttk.Label(p.body, textvariable=self.v_kpi[key], style="Big.TLabel").pack(anchor="w")
        ttk.Label(t, text="Recent decisions", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.ov_tree = self._tree(t, ("time", "user", "resource", "decision", "risk"), ("Time", "Identity", "Resource", "Decision", "Risk"), (150, 110, 160, 100, 70))

    def _tab_events(self):
        t = self._tab("Events")
        self.v_ev_filter = tk.StringVar(); efilter = ttk.Entry(t, textvariable=self.v_ev_filter); efilter.pack(fill="x", pady=(0, 8)); efilter.bind("<KeyRelease>", lambda _e: self._refresh())
        self.ev_tree = self._tree(t, ("time", "user", "device", "resource", "decision", "what"), ("Time", "User", "Device", "Resource", "Decision", "What happened"), (150, 90, 120, 130, 90, 500), stretch="what")

    def _tab_sessions(self):
        t = self._tab("Sessions")
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="Revoke selected session", style="Primary.TButton", command=self._revoke).pack(side="left")
        ttk.Button(bar, text="Sign user out everywhere", command=self._signout_everywhere).pack(side="left", padx=6)
        ttk.Button(bar, text="Require step-up MFA", command=self._require_stepup).pack(side="left", padx=6)
        ttk.Button(bar, text="Block selected device", command=self._block_selected_device).pack(side="left", padx=6)
        self.ss_tree = self._tree(t, ("sid", "user", "device", "loc", "exp", "mfa"), ("Session", "User", "Device", "Connection", "Expires in", "MFA age"), (170, 110, 140, 100, 100, 100), stretch="mfa")

    def _revoke(self):
        sel = self.ss_tree.selection()
        if not sel: messagebox.showinfo("Revoke session", "Select an active session first.", parent=self); return
        for sid in sel:
            with LOCK: sess = SESSIONS.pop(sid, None)
            if not sess: continue
            db_exec("UPDATE sessions SET revoked=1 WHERE sid=?", (sid,))
            try: audit(user=self.manager_user, device="manager-desktop", resource="session", decision="REVOKE", reasons=[f"manager revoked session for {sess.get('user', 'unknown')}"], risk=0)
            except (AuditFull, AuditTamper): messagebox.showerror("Audit failure", "The session was removed, but the audit write failed. Preserve logs and investigate.", parent=self)
        self._refresh()

    def _selected_session_values(self):
        sel = self.ss_tree.selection()
        if not sel: return None, None, None
        sid = sel[0]
        with LOCK: sess = SESSIONS.get(sid)
        if not sess: return sid, None, None
        return sid, sess.get("user"), sess.get("device")

    def _signout_everywhere(self):
        _sid, user, _dev = self._selected_session_values()
        if not user: messagebox.showinfo("Sign out everywhere", "Select a live session first.", parent=self); return
        n, err = revoke_user_sessions_report(user)
        if err: messagebox.showwarning("Sign out everywhere", f"{n} live session(s) were ended, but the revocation could not be saved to the database ({err}). Retry once the database is healthy.", parent=self)
        try: audit(user=self.manager_user, device="manager-desktop", resource="sessions", decision="REVOKE", reasons=[f"manager signed out {user} everywhere ({n} session(s))"])
        except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit failure", str(exc), parent=self)
        publish_gui_event("sessions-revoked", user=user)
        self._refresh()

    def _require_stepup(self):
        _sid, user, _dev = self._selected_session_values()
        if not user: messagebox.showinfo("Require step-up", "Select a live session first.", parent=self); return
        STEPUP_REQUIRED_USERS.add(user)
        try: audit(user=self.manager_user, device="manager-desktop", resource="stepup-control", decision="POLICY", reasons=[f"manager required fresh MFA for {user} on next application request"])
        except (AuditFull, AuditTamper) as exc:
            STEPUP_REQUIRED_USERS.discard(user); messagebox.showerror("Audit failure", str(exc), parent=self); return
        publish_gui_event("stepup-required", user=user)
        messagebox.showinfo("Step-up required", f"{user} must verify fresh MFA before the next application request.", parent=self)

    def _block_selected_device(self):
        _sid, _user, device = self._selected_session_values()
        if not device: messagebox.showinfo("Block device", "Select a live session first.", parent=self); return
        if not messagebox.askyesno("Block device", f"Block {device} and terminate its active sessions?", parent=self): return
        try: set_device_blocked(device, True, actor=self.manager_user)
        except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit failure", str(exc), parent=self); return
        self._refresh()
        messagebox.showinfo("Device blocked", f"{device} is blocked for this running lab session.", parent=self)

    def _tab_identity(self):
        t = self._tab("Identity")
        self.id_tree = self._tree(t, ("user", "name", "role", "dept", "res", "seg"), ("User", "Name", "Role", "Department", "Eligible applications", "Segments"), (80, 140, 90, 120, 340, 260), stretch="res")

    DEVICE_CHECKS = (("os_updated", "OS current"), ("disk_encrypted", "Disk encrypted"), ("firewall", "Firewall"), ("antivirus", "Antivirus"), ("corporate_managed", "Managed"))

    def _tab_posture(self):
        t = self._tab("Devices")
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        self.v_dev_sum = tk.StringVar(); ttk.Label(bar, textvariable=self.v_dev_sum, style="Strong.TLabel").pack(side="left")
        self.v_dev_filter = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.v_dev_filter, width=26); e.pack(side="right"); e.bind("<KeyRelease>", lambda _e: self._refresh_posture())
        ttk.Label(bar, text="Find employee or device", style="Muted.TLabel").pack(side="right", padx=(0, 6))
        ttk.Label(t, text=("Every employee and the devices enrolled to them. Click a PASS/FAIL cell to flip that check (lab only)." if DEMO
                           else "Every employee and the devices enrolled to them. Posture is read-only: it comes from endpoint attestation."), style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        frame = ttk.Frame(t); frame.pack(fill="both", expand=True)
        cols = ("role", "dept", "health", "os_updated", "disk_encrypted", "firewall", "antivirus", "corporate_managed", "status")
        tree = ttk.Treeview(frame, columns=cols, show="tree headings", selectmode="browse")
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview); x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew"); y.grid(row=0, column=1, sticky="ns"); x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        heads = {"role": ("Role", 80), "dept": ("Department", 110), "health": ("Health", 80), "status": ("Status", 130)}
        tree.heading("#0", text="Employee / device", anchor="w"); tree.column("#0", width=230, minwidth=160, anchor="w", stretch=False)
        for c in cols:
            title, width = heads.get(c) or (dict(self.DEVICE_CHECKS)[c], 95)
            tree.heading(c, text=title, anchor="w"); tree.column(c, width=width, minwidth=60, anchor="w", stretch=(c == "status"))
        tree.tag_configure("emp", font=(UI_FONT, 9, "bold"), foreground=BLUE_DARK, background=BLUE_PALE)
        tree.tag_configure("nodev", foreground=BLUE_MUTED, background=BLUE_PALE, font=(UI_FONT, 9, "bold"))
        tree.tag_configure("weak", foreground=BAD_RED); tree.tag_configure("blocked", foreground=BAD_RED, font=(UI_FONT, 9, "bold"))
        tree.tag_configure("waiting", foreground=BLUE_MUTED)
        self.dev_tree = tree; self._dev_sig = None
        if DEMO: tree.bind("<Button-1>", self._device_click)

    def _tab_policies(self):
        t = self._tab("Policies")
        right = Panel(t, "Edit policy", padding=16); right.pack(side="right", fill="y", padx=(14, 0))
        left = ttk.Frame(t); left.pack(side="left", fill="both", expand=True)
        self.pol_tree = self._tree(left, ("res", "roles", "score", "managed", "hours", "mfa"), ("Application", "Roles", "Health", "Managed", "Hours", "MFA min"), (115, 200, 55, 70, 90, 60), stretch="roles")
        self.pol_tree.configure(selectmode="browse")
        self.pol_tree.bind("<<TreeviewSelect>>", lambda _e: self._load_policy())
        g = right.body
        self.v_pol = {k: tk.StringVar() for k in ("res", "score", "mfa", "start", "end")}; self.v_managed = tk.BooleanVar()
        ttk.Label(g, textvariable=self.v_pol["res"], style="Section.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        for i, (label, key) in enumerate((("Min health score", "score"), ("MFA age (sec)", "mfa"), ("From hour (0–23)", "start"), ("Until hour (1–24)", "end")), 1):
            ttk.Label(g, text=label).grid(row=i, column=0, sticky="w", pady=6, padx=(0, 10))
            ttk.Entry(g, textvariable=self.v_pol[key], width=10).grid(row=i, column=1, sticky="w", pady=6)
        ttk.Checkbutton(g, text="Managed device only", variable=self.v_managed).grid(row=5, column=0, columnspan=2, sticky="w", pady=8)
        ttk.Button(g, text="Save policy", style="Primary.TButton", command=self._save_policy).grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 4))
        self._policy_sel = None

    def _policy_rows(self):
        rows = []
        for n, r in RESOURCES.items():
            rows.append((n, ", ".join(r["roles"]), r["min_posture"], "yes" if r["managed"] else "no", _fmt_hours(r), r["mfa_age"] // 60))
        return rows

    def _load_policy(self):
        sel = self.pol_tree.selection()
        if not sel: return
        name = self.pol_tree.item(sel[0], "values")[0]
        r = RESOURCES[name]; self._policy_sel = name
        self.v_pol["res"].set(name)
        self.v_pol["score"].set(str(r.get("min_posture", 0))); self.v_pol["mfa"].set(str(r.get("mfa_age", 3600)))
        self.v_pol["start"].set(str(r.get("hours", [0, 24])[0])); self.v_pol["end"].set(str(r.get("hours", [0, 24])[1]))
        self.v_managed.set(bool(r.get("managed", False)))

    def _save_policy(self):
        name = self._policy_sel
        if not name: messagebox.showinfo("Policy", "Select an application in the table first.", parent=self); return
        try:
            data = {"min_posture": int(self.v_pol["score"].get()), "mfa_age": int(self.v_pol["mfa"].get()),
                    "hours": [int(self.v_pol["start"].get()), int(self.v_pol["end"].get())], "managed": bool(self.v_managed.get())}
            validate_policy_data({name: data})
            RESOURCES[name].update(data); save_policy()
            db_exec("INSERT INTO policy_changes(ts,actor,resource,policy_json) VALUES(?,?,?,?)", (time.time(), self.manager_user, name, json.dumps(data, sort_keys=True)))
            audit(user=self.manager_user, device="manager-desktop", resource=name, decision="POLICY", reasons=[f"policy updated: {data}"])
            messagebox.showinfo("Policy saved", f"Policy for {name} saved and audited.", parent=self)
            self._refresh()
        except (ValueError, tk.TclError, AuditFull, AuditTamper) as exc:
            messagebox.showerror("Policy not saved", f"Invalid policy or audit failure: {exc}", parent=self)

    def _tab_alerts(self):
        t = self._tab("Alerts"); self.t_alerts = t
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        self.v_alert_sum = tk.StringVar(); ttk.Label(bar, textvariable=self.v_alert_sum, style="Strong.TLabel").pack(side="left")
        ttk.Button(bar, text="Mark reviewed", command=self._ack_alert).pack(side="right")
        ttk.Button(bar, text="False alarm", command=lambda: self._alert_outcome("false_alarm")).pack(side="right", padx=6)
        ttk.Button(bar, text="Confirm incident + sign out", command=lambda: self._alert_outcome("incident_confirmed")).pack(side="right", padx=6)
        self.al_tree = self._tree(t, ("time", "sev", "kind", "user", "device", "state", "details"), ("Time", "Severity", "Type", "User", "Device", "State", "Details"), (80, 80, 190, 90, 120, 70, 420), stretch="details")

    def _selected_alert(self, tree=None):
        sel = (tree or self.al_tree).selection()
        if not sel: return None
        try: aid = int(sel[0])
        except (TypeError, ValueError): return None
        return next((a for a in recent_alerts(limit=120) if int(a.get("id", -1)) == aid), None)

    def _ack_alert(self, tree=None):
        try:
            alert = self._selected_alert(tree)
            if not alert:
                messagebox.showinfo("Alerts", "Select an alert first.", parent=self); return
            acknowledge_alerts(ids=[alert["id"]], status=1, include_high=True)
            try: audit(user=self.manager_user, device="manager-desktop", resource="alert", decision="REVIEWED", reasons=[f"alert {alert['id']} acknowledged; no approval implied"])
            except (AuditFull, AuditTamper): pass
            self._refresh()
        except Exception as exc: messagebox.showerror("Alert acknowledgement", str(exc), parent=self)

    def _alert_outcome(self, outcome, tree=None):
        alert = self._selected_alert(tree)
        if not alert: messagebox.showinfo("Alert outcome", "Select an alert first.", parent=self); return
        if outcome == "incident_confirmed" and not messagebox.askyesno("Confirm incident", f"Confirm the incident for {alert.get('user') or 'unknown user'} and sign them out everywhere?", parent=self): return
        try:
            acknowledge_alerts(ids=[alert["id"]], status={"false_alarm": 2, "incident_confirmed": 3}.get(outcome, 1), include_high=True)
            user = alert.get("user")
            if outcome == "incident_confirmed" and user:
                n, err = revoke_user_sessions_report(user)
                if err: messagebox.showwarning("Incident response", f"{n} live session(s) were ended, but the revocation could not be saved to the database ({err}).", parent=self)
                try: audit(user=self.manager_user, device=alert.get("device"), resource="alert-response", decision="REVOKE", reasons=[f"incident confirmed from alert {alert['id']}; signed out {user} ({n} sessions)"])
                except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit warning", f"Sessions were revoked, but audit write failed: {exc}", parent=self)
                publish_gui_event("incident-confirmed", user=user, alert_id=alert["id"])
            else:
                try: audit(user=self.manager_user, device=alert.get("device"), resource="alert-response", decision="FALSE_ALARM", reasons=[f"alert {alert['id']} marked false alarm"])
                except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit warning", str(exc), parent=self)
            self._refresh()
        except Exception as exc: messagebox.showerror("Alert outcome", str(exc), parent=self)

    def _tab_audit(self):
        t = self._tab("Audit"); self.t_audit = t
        bar = ttk.Frame(t); bar.pack(fill="x", pady=(0, 8))
        self.v_audit = tk.StringVar(value="Not yet verified")
        ttk.Button(bar, text="Verify audit chain", style="Primary.TButton", command=self._verify).pack(side="left")
        ttk.Button(bar, text="Export audit JSONL", command=self._export).pack(side="left", padx=8)
        ttk.Button(bar, text="Daily summary", command=self._daily_summary).pack(side="left", padx=8)
        ttk.Label(bar, textvariable=self.v_audit, style="Accent.TLabel").pack(side="left", padx=10)
        self.v_au_filter = tk.StringVar(); af = ttk.Entry(t, textvariable=self.v_au_filter); af.pack(fill="x", pady=(0, 8)); af.bind("<KeyRelease>", lambda _e: self._refresh())
        self.au_tree = self._tree(t, ("time", "user", "device", "resource", "decision", "risk", "what"), ("Time", "User", "Device", "Resource", "Decision", "Risk", "What happened"), (150, 90, 120, 130, 90, 50, 460), stretch="what")

    def _daily_summary(self):
        messagebox.showinfo("Daily security summary", daily_summary_text(), parent=self)

    def _verify(self):
        r = verify_chain()
        if r.get("ok"): self.v_audit.set(f"VERIFIED · {r.get('entries', 0)} entries")
        else:
            self.v_audit.set(f"FAILED · entry {r.get('broken_at', '?')}")
            messagebox.showerror("Audit integrity failure", "The audit chain did not verify. Preserve the original log and anchor files and compare with a trusted backup; do not edit the chain.", parent=self)
        self._refresh()

    def _export(self):
        from tkinter import filedialog
        target = filedialog.asksaveasfilename(parent=self, title="Export audit JSONL", defaultextension=".jsonl", filetypes=[("JSON Lines", "*.jsonl")], initialfile="ztna_audit_export.jsonl")
        if not target: return
        try:
            shutil.copy2(AUDIT_FILE, target)
            messagebox.showinfo("Audit exported", f"A copy was exported to:\n{target}", parent=self)
        except OSError as exc: messagebox.showerror("Export failed", str(exc), parent=self)

    # ---- device posture (scrollable, updated in place)
    def _device_rows(self):
        """-> list of (employee iid, label, summary values, [(device iid, device id, values, tags)], tags) for EVERY employee."""
        now = time.time(); stale_after = POSTURE_TTL
        by_owner = {}
        for dev, rec in DEVICES.items(): by_owner.setdefault(rec.get("owner", ""), []).append(dev)
        owners = sorted(USERS, key=lambda u: (_person(u)[0].lower(), u)) + sorted(o for o in by_owner if o not in USERS)
        out = []
        for u in owners:
            devs = sorted(by_owner.get(u, []))
            known = u in USERS
            label = f"{_person(u)[0]} ({u})" if known else f"{u or 'unassigned'} (not in directory)"
            role = USERS[u].get("role", "") if known else ""
            dept = USER_PROFILE.get(u, {}).get("dept", "") if known else ""
            kids = []
            for dev in devs:
                rec = DEVICES[dev]; score = posture(dev)
                if dev in BLOCKED_DEVICES: status, tag = "Blocked", "blocked"
                elif not rec.get("last_report"): status, tag = "No report yet", "waiting"
                elif stale_after > 0 and now - rec.get("last_report", 0) > stale_after: status, tag = "Report is stale", "weak"
                elif score < 70: status, tag = "Below score 70", "weak"
                else: status, tag = "Healthy", ""
                checks = tuple("PASS" if rec.get(f) else "FAIL" for f, _l in self.DEVICE_CHECKS)
                kids.append((f"d:{dev}", dev, ("", "", f"{score}/100") + checks + (status,), (tag,) if tag else ()))
            summary = (role, dept, f"{len(devs)} device{'s' if len(devs) != 1 else ''}" if devs else "", "", "", "", "", "", "" if devs else "No device enrolled")
            out.append((f"u:{u}", label, summary, kids, ("emp",) if devs else ("nodev",)))
        return out

    def _device_click(self, event):
        tree = self.dev_tree
        if tree.identify_region(event.x, event.y) != "cell": return
        row, col = tree.identify_row(event.y), tree.identify_column(event.x)
        fields = {f"#{i}": f for i, f in enumerate(("role", "dept", "health") + tuple(f for f, _l in self.DEVICE_CHECKS), 1)}
        field = fields.get(col)
        if row.startswith("d:") and field in dict(self.DEVICE_CHECKS) and row[2:] in DEVICES:
            self._set_posture(row[2:], field, not DEVICES[row[2:]].get(field, False))

    def _refresh_posture(self):
        tree = getattr(self, "dev_tree", None)
        if tree is None or not tree.winfo_exists(): return
        needle = self.v_dev_filter.get().strip().lower()
        rows = []
        for iid, label, summary, kids, tags in self._device_rows():
            if needle:
                kids = [k for k in kids if needle in k[1].lower()] if needle not in label.lower() else kids
                if needle not in label.lower() and not kids: continue
            rows.append((iid, label, summary, kids, tags))
        n_emp = len(USERS); n_dev = len(DEVICES); weak = sum(1 for d in DEVICES if posture(d) < 70)
        none = sum(1 for u in USERS if not any(r.get("owner") == u for r in DEVICES.values()))
        self.v_dev_sum.set(f"{n_emp} employees · {n_dev} devices · {weak} below score 70" + (f" · {none} with no device" if none else ""))
        sig = tuple((r[0], r[1], r[2], tuple((k[0], k[2], k[3]) for k in r[3]), r[4]) for r in rows)
        if sig == self._dev_sig: return
        first = self._dev_sig is None; self._dev_sig = sig
        closed = set() if first else {i for i in tree.get_children() if str(tree.item(i, "open")).lower() in ("0", "false")}
        keep = set(tree.selection()); top = tree.yview()[0]
        tree.delete(*tree.get_children())
        for iid, label, summary, kids, tags in rows:
            tree.insert("", "end", iid=iid, text=label, values=summary, tags=tags, open=iid not in closed)
            for kid, dev, values, ktags in kids: tree.insert(iid, "end", iid=kid, text="   " + dev, values=values, tags=ktags)
        still = [i for i in keep if tree.exists(i)]
        if still: tree.selection_set(still)
        tree.yview_moveto(top)

    def _set_posture(self, device, field, value):
        if not DEMO:
            messagebox.showwarning("Read-only", "Production posture must come from authenticated endpoint attestation.", parent=self); return
        DEVICES[device][field] = bool(value); DEVICES[device]["last_report"] = time.time()
        try: audit(user=self.manager_user, device=device, resource="posture", decision="POLICY", reasons=[f"{field}={bool(value)}"])
        except (AuditFull, AuditTamper) as exc: messagebox.showerror("Audit failure", str(exc), parent=self)
        self._refresh()

    # ---- refresh loop
    def _log_rows(self, limit=250):
        rows = []
        for e in list(LOG)[:limit]:
            try: what = describe_audit_event(e)[2]
            except Exception: what = "; ".join(map(str, e.get("reasons", [])))
            rows.append((_fmt_ts(e.get("ts", "")).replace("T", " ").replace("Z", ""), e.get("user", ""), e.get("device", ""), e.get("resource", ""), e.get("decision", ""), e.get("risk", ""), what))
        return rows

    def _update_counters(self, n_signin, n_exc, n_alerts, n_high):
        """Live counts beside the tab headings and in the header band. Called from every refresh, which every
        sign-in / exception / alert event also triggers, so the numbers follow the queues as they change."""
        def label(base, n, extra=""): return f"{base} ({n}{extra})" if n else base
        self.nb.tab(self.t_requests, text=label("Sign-in requests", n_signin))
        self.nb.tab(self.t_exceptions, text=label("App exceptions", n_exc))
        self.nb.tab(self.t_alerts, text=label("Alerts", n_alerts, f" · {n_high} high" if n_high else ""))
        parts = []
        if n_signin: parts.append(f"● {n_signin} sign-in{'s' if n_signin != 1 else ''} waiting")
        if n_exc: parts.append(f"{n_exc} exception{'s' if n_exc != 1 else ''} waiting")
        if n_alerts: parts.append(f"{n_alerts} alert{'s' if n_alerts != 1 else ''} unreviewed")
        self.v_badge.set("   ·   ".join(parts) if parts else "All clear")

    def _refresh(self):
        if not self.winfo_exists() or not self.manager_user: return
        db_error = None
        try: reqs = list_signin_requests(1000)
        except StateStoreError as exc: reqs, db_error = [], str(exc)
        pending = [r for r in reqs if r["status"] == "pending"]
        new = [r for r in pending if r["id"] not in self._seen_pending]
        self._seen_pending |= {r["id"] for r in pending}
        if new:
            try: self.bell()
            except tk.TclError: pass
        n = len(pending)
        self.v_req_sum.set(f"{n} waiting for your approval" if n else "No sign-in requests are waiting")
        past = len(reqs) - n
        self.rb_view["Waiting"].configure(text=f"Waiting ({n})" if n else "Waiting"); self.rb_view["History"].configure(text=f"History ({past})" if past else "History")
        view = self.v_req_view.get()
        rows, tags = [], []
        req_iids = []
        req_filter = self.v_req_filter.get().strip().lower() if hasattr(self, "v_req_filter") else ""
        for r in reqs:
            if (view == "Waiting" and r["status"] != "pending") or (view == "History" and r["status"] == "pending"): continue
            name, _t, _d = _person(r["user"])
            by = r["decided_by"] or ("employee" if r["status"] == "cancelled" and "employee" in (r.get("closed_reason") or "") else "system" if r["status"] in ("expired", "cancelled") else "")
            when = r["decided_at"] if r["decided_by"] and r["status"] in ("approved", "denied") else r.get("closed_at") or r["decided_at"]
            row_values = (_fmt_ts(r["ts"]), r["user"], name, USERS.get(r["user"], {}).get("role", ""), r["device"], f"{posture(r['device'])}/100" if r["device"] in DEVICES else "–", r["location"], r["status"].upper(), signin_outcome(r), by, _fmt_ts(when) if when else "", r["note"] or "")
            if req_filter and req_filter not in " ".join(map(str, row_values)).lower(): continue
            rows.append(row_values); req_iids.append(r["id"])
            tags.append(("pending",) if r["status"] == "pending" else ("blocked",) if r["status"] == "denied" else ())
        if db_error is None:                                  # never replace the visible queue with an empty one because of a database error
            self._fill_tree(self.req_tree, rows, iids=req_iids, tags=tags); self._sync_buttons()
            self._request_context()
        try: exceptions = list_access_exception_requests(200)
        except StateStoreError as exc: exceptions, db_error = [], db_error or str(exc)
        if not any(x.get("id") for x in exceptions) and db_error: pass
        else:
            self._exc_rows = {x["id"]: x for x in exceptions}
            alert_text = {None: "–", 0: "Needs a decision", 1: "Closed", 2: "False alarm", 3: "Incident"}
            ex_rows = [(_fmt_ts(x["ts"]), x["user"], USERS.get(x["user"], {}).get("role", ""), x["resource"], x["device"], x["reason"], x["status"].upper(), alert_text.get(x.get("alert_status"), "–"),
                        exception_outcome(x), x["decided_by"] or ("system" if x["status"] in ("expired", "cancelled") else ""), (_fmt_ts(x["expires_at"]) if x["expires_at"] else "–")) for x in exceptions]
            self._fill_tree(self.exc_tree, ex_rows, iids=[x["id"] for x in exceptions], tags=[("pending",) if x["status"] == "pending" else () for x in exceptions])
            n_wait = sum(1 for x in exceptions if x["status"] == "pending")
            with LOCK: active = sum(1 for v in TEMP_RESOURCE_GRANTS.values() if v > time.time())
            self.v_exc_sum.set(f"{n_wait} waiting for a decision" + (f" · {active} extra access grant{'s' if active != 1 else ''} in use" if active else "") if n_wait or active else "No extra-access requests are waiting")
        try:
            t = telemetry_summary()
            now = time.time()
            with LOCK: live = [s for s in SESSIONS.values() if s.get("exp", 0) > now and s.get("abs_exp", 0) > now]
            vals = {"events": t.get("events", 0), "allow": t.get("allow", 0), "stepup": t.get("stepup", 0), "deny": t.get("deny", 0), "risk": t.get("avg_risk", 0), "alerts": t.get("alerts", 0), "sessions": len(live), "pending": n}
            for k, v in vals.items(): self.v_kpi[k].set(str(v))
        except Exception: pass
        log = self._log_rows(250)
        self._fill_tree(self.ov_tree, [(r[0], r[1], r[3], r[4], r[5]) for r in log[:100]])
        ev_filter = self.v_ev_filter.get().strip().lower() if hasattr(self, "v_ev_filter") else ""
        ev_rows = [(r[0], r[1], r[2], r[3], r[4], r[6]) for r in log]
        if ev_filter: ev_rows = [r for r in ev_rows if ev_filter in " ".join(map(str, r)).lower()]
        self._fill_tree(self.ev_tree, ev_rows)
        au_filter = self.v_au_filter.get().strip().lower() if hasattr(self, "v_au_filter") else ""
        au_rows = [r for r in log if not au_filter or au_filter in " ".join(map(str, r)).lower()]
        self._fill_tree(self.au_tree, au_rows)
        now = time.time(); srows, sids = [], []
        with LOCK: snap = list(SESSIONS.items())
        for sid, s in snap:
            if s.get("exp", 0) <= now or s.get("abs_exp", 0) <= now or s.get("device") in BLOCKED_DEVICES: continue
            sids.append(sid); srows.append((sid, s.get("user", ""), s.get("device", ""), s.get("location", ""), f"{max(0, int(s.get('exp', now) - now))} s", f"{max(0, int(now - s.get('mfa_at', now)))} s"))
        self._fill_tree(self.ss_tree, srows, iids=sids)
        irows = []
        for u, rec in sorted(USERS.items()):
            role = rec.get("role", "unknown")
            irows.append((u, _person(u)[0], role, USER_PROFILE.get(u, {}).get("dept", "–"), ", ".join(r for r in RESOURCES if rbac_allows(u, r) and segment_allows(u, r)) or "None", ", ".join(sorted(SEGMENT_ALLOW.get(role, set())))))
        self._fill_tree(self.id_tree, irows)
        names = list(RESOURCES)
        self._fill_tree(self.pol_tree, self._policy_rows(), iids=names)
        if self._policy_sel is None and names:
            self.pol_tree.selection_set(names[0]); self._load_policy()
        alerts = []
        al = recent_alerts(limit=120)
        for a in al:
            alerts.append((_fmt_ts(a.get("ts", ""), "%H:%M:%S"), a.get("severity", ""), describe_alert(a)[0], a.get("user", ""), a.get("device", ""), {0: "NEW", 1: "REVIEWED", 2: "FALSE ALARM", 3: "INCIDENT"}.get(a.get("status", 0), "SEEN"), a.get("details", "")))
        self._fill_tree(self.al_tree, alerts, iids=[str(a.get("id", "")) for a in al])
        self.v_alert_sum.set(f"{sum(1 for a in al if not a.get('acknowledged'))} unreviewed · {len(al)} recent")
        open_al = [a for a in recent_alerts(limit=500) if not a.get("acknowledged")]
        if db_error:
            self.v_badge.set("⚠ Database unavailable: queues below may be out of date")
        else:
            self._update_counters(n, sum(1 for x in exceptions if x["status"] == "pending"), len(open_al), sum(1 for a in open_al if str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL")))
        self._refresh_posture()
        siem = getattr(self, "siem", None)
        if siem is not None:
            try: siem.refresh()
            except tk.TclError: pass
            except Exception: logger.exception("SIEM dashboard refresh failed")
        self.app.refresh_hub()
        self._schedule("refresh", 10000, self._refresh)
        self._schedule("event-watch", 100, self._watch_gui_events)

    def _watch_gui_events(self):
        if not self.winfo_exists() or not self.manager_user: return
        changed = False
        try:
            while True:
                event = GUI_EVENTS.get_nowait()
                if event.get("kind", "").startswith(("signin-", "exception-", "sessions-", "device-", "stepup-", "incident-", "alert-")):
                    changed = True
        except queue.Empty: pass
        if changed:
            try: self._refresh()
            except (tk.TclError, sqlite3.Error): pass
        else:
            self._schedule("event-watch", 100, self._watch_gui_events)

    def _sign_out(self):
        if self.manager_user:
            try: audit(user=self.manager_user, device="manager-desktop", resource="manager-logout", decision="REVOKE", reasons=["manager signed out"])
            except Exception: pass
        self.manager_user = None; self._show_login()

    def close(self):
        if self.manager_user: self._sign_out_quiet()
        super().close()

    def _sign_out_quiet(self):
        try: audit(user=self.manager_user, device="manager-desktop", resource="manager-logout", decision="REVOKE", reasons=["manager signed out"])
        except Exception: pass
        self.manager_user = None

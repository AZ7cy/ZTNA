# Part 23 of ztna.py - desktop GUI: employee portal.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ------------------------------------------------------------------------------ employee side
class EmployeePortal(PortalWindow):
    def __init__(self, app):
        super().__init__(app, "ZTNA Access Workspace — Employee", "1000x740", (860, 620))
        self.engine = DesktopZTNA()
        self.request_id = None
        self._session_warning_shown = False
        self._show_login()

    # ---- sign-in form
    def _show_login(self):
        self._clear(); self.title("ZTNA Access Workspace — Employee sign-in")
        self.request_id = None
        self._band("Employee sign-in", "")
        wrap = ttk.Frame(self, padding=(30, 22)); wrap.pack(fill="both", expand=True)
        panel = Panel(wrap, "Employee identity", padding=22); panel.pack(pady=4)
        grid = panel.body; grid.columnconfigure(1, weight=1)
        remembered = _load_gui_preferences()
        self.v_user = tk.StringVar(value=remembered.get("username") if remembered.get("username") in USERS else (sorted(USERS)[0] if USERS else ""))
        self.v_pass, self.v_otp = tk.StringVar(), tk.StringVar()
        self.v_dev, self.v_loc = tk.StringVar(), tk.StringVar(value=remembered.get("location", "office"))
        self.v_who = tk.StringVar(); self.v_devinfo = tk.StringVar()
        self.cb_user = self._form_row(grid, 0, "Username", lambda p: ttk.Combobox(p, textvariable=self.v_user, values=sorted(USERS), state="readonly", width=34))
        self.cb_user.bind("<<ComboboxSelected>>", self._user_changed)
        ttk.Label(grid, textvariable=self.v_who, style="Muted.TLabel").grid(row=1, column=1, sticky="w", pady=(0, 4))
        pw = self._form_row(grid, 2, "Password", lambda p: ttk.Entry(p, textvariable=self.v_pass, show="•", width=36))
        otp_row = ttk.Frame(grid)
        ttk.Label(grid, text="Authenticator code", style="Strong.TLabel").grid(row=3, column=0, sticky="w", padx=(0, 14), pady=7)
        otp_row.grid(row=3, column=1, sticky="ew", pady=7)
        ttk.Entry(otp_row, textvariable=self.v_otp, width=16).pack(side="left", fill="x", expand=True)
        b = ttk.Button(otp_row, text="Generate code", command=self._demo_otp)
        b.pack(side="left", padx=(8, 0))
        if not DEMO_OTP: b.state(["disabled"])
        self.cb_dev = self._form_row(grid, 4, "Registered device", lambda p: ttk.Combobox(p, textvariable=self.v_dev, state="readonly", width=34))
        self.cb_dev.bind("<<ComboboxSelected>>", lambda _e: self.v_devinfo.set(_device_summary(self.v_dev.get())))
        ttk.Label(grid, textvariable=self.v_devinfo, style="Muted.TLabel").grid(row=5, column=1, sticky="w", pady=(0, 4))
        self._form_row(grid, 6, "Connection", lambda p: ttk.Combobox(p, textvariable=self.v_loc, values=["office", "home"], state="readonly", width=14))
        ttk.Separator(grid).grid(row=7, column=0, columnspan=2, sticky="ew", pady=(14, 12))
        actions = ttk.Frame(grid); actions.grid(row=8, column=0, columnspan=2, sticky="ew")
        ttk.Button(actions, text="Close", command=self.close).pack(side="left")
        ttk.Button(actions, text="Request sign-in  →", style="Primary.TButton", command=self._submit).pack(side="right")
        self.bind("<Return>", lambda _e: self._submit())
        self._user_changed()
        pw.focus_set()

    def _user_changed(self, _e=None):
        user = self.v_user.get().strip()
        name, title, dept = _person(user)
        role = USERS.get(user, {}).get("role", "")
        self.v_who.set(f"{name} · {title} · {dept} · role: {role}" if role else "")
        devices = sorted(d for d, v in DEVICES.items() if v.get("owner") == user)
        self.cb_dev.configure(values=devices)
        remembered = _load_gui_preferences()
        preferred = remembered.get("device")
        self.v_dev.set(preferred if preferred in devices else (devices[0] if devices else ""))
        self.v_devinfo.set(_device_summary(self.v_dev.get()))

    def _demo_otp(self):
        user = self.v_user.get().strip()
        try: self.v_otp.set(self.engine.demo_otp(user))
        except Exception as exc: messagebox.showerror("Demo code", str(exc), parent=self)

    def _submit(self):
        user, dev = self.v_user.get().strip(), self.v_dev.get().strip()
        if not user or not dev:
            messagebox.showerror("Sign in", "Choose an employee account that has a registered device.", parent=self); return
        _save_gui_preferences({"username": user, "device": dev, "location": self.v_loc.get()})
        ok, res = self.engine.request_signin(user, self.v_pass.get(), self.v_otp.get().strip(), dev, self.v_loc.get())
        if not ok:
            messagebox.showerror("Sign-in request failed", res, parent=self); return
        self.unbind("<Return>")
        self.request_id = res
        self.app.refresh_hub()
        self._show_waiting()

    # ---- waiting for the manager
    def _show_waiting(self):
        self._clear(); self.title("ZTNA Access Workspace — Waiting for approval")
        try: row = get_signin_request(self.request_id) or {}
        except StateStoreError: row = {}
        self._band("Waiting for manager approval", "")
        wrap = ttk.Frame(self, padding=(30, 26)); wrap.pack(fill="both", expand=True)
        panel = Panel(wrap, "Sign-in request", padding=24); panel.pack(pady=4)
        body = panel.body
        self.v_wait = tk.StringVar(value="Waiting for a manager to review your request…")
        ttk.Label(body, textvariable=self.v_wait, style="Section.TLabel", wraplength=520).pack(anchor="w")
        bar = ttk.Progressbar(body, mode="indeterminate", length=520, style="Blue.Horizontal.TProgressbar")
        bar.pack(fill="x", pady=(14, 14)); bar.start(14)
        info = ttk.Frame(body); info.pack(fill="x")
        name, title, _dept = _person(row.get("user", ""))
        for i, (k, v) in enumerate((("Request ID", self.request_id), ("Employee", f"{name} ({row.get('user','')})"),
                                    ("Device", row.get("device", "")), ("Connection", row.get("location", "")),
                                    ("Submitted", _fmt_ts(row.get("ts"))))):
            ttk.Label(info, text=k, style="Strong.TLabel").grid(row=i, column=0, sticky="w", padx=(0, 18), pady=3)
            ttk.Label(info, text=v).grid(row=i, column=1, sticky="w", pady=3)
        self.v_elapsed = tk.StringVar()
        ttk.Label(body, textvariable=self.v_elapsed, style="Muted.TLabel").pack(anchor="w", pady=(12, 0))
        ttk.Separator(body).pack(fill="x", pady=14)
        ttk.Button(body, text="Cancel request", command=self._cancel_request).pack(anchor="w")
        self._poll()

    def _cancel_request(self):
        if self.request_id:
            try: cancel_signin_request(self.request_id)
            except StateStoreError: messagebox.showwarning("Cancel request", "The request could not be cancelled right now (database unavailable). It will expire on its own.", parent=self)
        self.app.refresh_hub(); self._show_login()

    def _poll(self):
        try: row = get_signin_request(self.request_id) if self.request_id else None
        except StateStoreError:                    # a transient database error must not end the loop: keep waiting and retry
            self.v_elapsed.set("Cannot reach the sign-in service right now; retrying…")
            self._schedule("poll", 2000, self._poll); return
        if not row: self._show_login(); return
        st = row["status"]
        if st == "pending":
            self.v_elapsed.set(f"Waiting {int(time.time() - row['ts'])} s · requests expire after {SIGNIN_REQUEST_TTL // 60} minutes")
            self._schedule("poll", 1000, self._poll); return
        if st == "approved":
            ok, msg = self.engine.complete_signin(self.request_id)
            self.app.refresh_hub()
            if ok: self._show_workspace()
            elif "temporarily unavailable" in msg:                 # the approval is still valid: retry rather than throw it away
                self.v_elapsed.set(msg); self._schedule("poll", 2000, self._poll)
            else:
                messagebox.showerror("Sign-in", msg, parent=self); self._show_login()
            return
        text = {"denied": "A manager denied your sign-in request.", "expired": "Your request expired before a manager answered.",
                "cancelled": "This sign-in request was cancelled."}.get(st, f"Request ended: {st}")
        if st == "denied" and row.get("note"): text += f"\n\nManager note: {row['note']}"
        messagebox.showwarning("Sign-in not approved", text, parent=self)
        self._show_login()

    # ---- workspace
    def _show_workspace(self):
        self._session_warning_shown = False                       # a new session: the "about to expire" prompt may show again
        self._clear()
        sid, sess = self.engine.session
        user = sess["user"]; name, title, dept = _person(user); role = USERS[user].get("role", "employee")
        self.title(f"ZTNA Access Workspace — {name}")
        right = self._band(f"Welcome, {name}", f"{title} · {dept} · Role: {role.upper()} · Device: {sess['device']} · Connection: {sess['location']}")
        ttk.Button(right, text="Sign out", style="Ghost.TButton", command=self._sign_out).pack()
        page = ScrollFrame(self); page.pack(fill="both", expand=True)
        body = page.body; body.configure(padding=(26, 20))
        # status tiles
        tiles = ttk.Frame(body); tiles.pack(fill="x", pady=(0, 18))
        self.v_tiles = {k: tk.StringVar() for k in ("score", "left", "mfa")}
        for i, (label, key) in enumerate((("Device trust", "score"), ("Session time left", "left"), ("Last MFA", "mfa"))):
            p = Panel(tiles, label, padding=(14, 10)); p.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            tiles.columnconfigure(i, weight=1, uniform="tile")
            ttk.Label(p.body, textvariable=self.v_tiles[key], style="Big.TLabel").pack(anchor="w")
        ttk.Label(body, text="Applications", style="Section.TLabel").pack(anchor="w", pady=(0, 10))
        grid = ttk.Frame(body); grid.pack(fill="x")
        self.resource_access_buttons = {}
        names = sorted(RESOURCES, key=lambda r: (not (rbac_allows(user, r) and segment_allows(user, r)), r))
        for c in range(3): grid.columnconfigure(c, weight=1, uniform="res")
        for idx, res in enumerate(names):
            assigned = rbac_allows(user, res) and segment_allows(user, res)
            p = Panel(grid, _res_title(res), padding=(14, 10))
            p.grid(row=idx // 3, column=idx % 3, sticky="nsew", padx=5, pady=5)
            ttk.Label(p.body, text=RESOURCES[res]["desc"], wraplength=215, justify="left").pack(anchor="w")
            ttk.Label(p.body, text="ASSIGNED TO YOUR ROLE" if assigned else "NOT ASSIGNED TO YOUR ROLE",
                      style="Accent.TLabel" if assigned else "Muted.TLabel").pack(anchor="w", pady=(0, 8))
            if assigned:
                btn = ttk.Button(p.body, text="Request access", style="Primary.TButton", command=lambda r=res: self._request(r))
            else:
                btn = ttk.Button(p.body, text="Request temporary exception", command=lambda r=res: self._request_exception(r))
            btn.pack(anchor="w")
            self.resource_access_buttons[res] = btn
        # decision output
        out = Panel(body, "Access decision", padding=12); out.pack(fill="x", pady=(18, 0))
        self.out = tk.Text(out.body, height=13, wrap="word", font=("Consolas", 10), background=WHITE, foreground=BLUE_TEXT,
                           relief="flat", bd=0, highlightthickness=0, padx=10, pady=8, selectbackground=BLUE_LINE)
        sb = ttk.Scrollbar(out.body, orient="vertical", command=self.out.yview); self.out.configure(yscrollcommand=sb.set)
        self.out.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        self.out.tag_configure("allow", background=BLUE, foreground=WHITE, font=("Consolas", 11, "bold"), spacing1=4, spacing3=4)
        self.out.tag_configure("stepup", background=BLUE_LINE, foreground=BLUE_DARK, font=("Consolas", 11, "bold"), spacing1=4, spacing3=4)
        self.out.tag_configure("deny", background=BLUE_DARK, foreground=WHITE, font=("Consolas", 11, "bold"), spacing1=4, spacing3=4)
        self.out.tag_configure("head", foreground=BLUE_DARK, font=("Consolas", 10, "bold"))
        self._write_out([("Choose an application above and press “Request access”. The decision and its reasons appear here.", "")])
        # Employee-only activity view: show only this identity's own recent events.
        activity = Panel(body, "My activity", padding=12); activity.pack(fill="x", pady=(14, 4))
        self.my_activity = tk.Text(activity.body, height=5, wrap="word", font=(UI_FONT, 9), background=WHITE, foreground=BLUE_TEXT, relief="flat", bd=0, highlightthickness=0)
        self.my_activity.pack(fill="x")
        own_events = [e for e in list(LOG) if e.get("user") == user][:12]
        if own_events:
            self.my_activity.insert("1.0", "\n".join(f"{_fmt_ts(e.get('ts'))} · {e.get('resource','')} · {e.get('decision','')} · {', '.join(map(str, e.get('reasons', [])))[:160]}" for e in own_events))
        else: self.my_activity.insert("1.0", "Your recent access and audit events will appear here.")
        self.my_activity.configure(state="disabled")
        # step-up
        step = Panel(body, "Step-up verification", padding=12); step.pack(fill="x", pady=(14, 4))
        self.v_step = tk.StringVar()
        ttk.Button(step.body, text="Verify MFA", style="Primary.TButton", command=self._stepup).pack(side="right")
        b2 = ttk.Button(step.body, text="Generate code", command=self._step_demo); b2.pack(side="right", padx=8)
        if not DEMO_OTP: b2.state(["disabled"])
        ttk.Entry(step.body, textvariable=self.v_step, width=11).pack(side="right")
        self._tick()

    def _write_out(self, segments):
        if not self.out.winfo_exists(): return
        self.out.configure(state="normal"); self.out.delete("1.0", "end")
        for text, tag in segments: self.out.insert("end", text, tag)
        self.out.configure(state="disabled")

    def _request_exception(self, res):
        reason = simpledialog.askstring("Request temporary access", f"Why do you need temporary access to {_res_title(res)}?\nInclude a short business justification:", parent=self)
        if not reason or not reason.strip(): return
        try:
            rid = create_access_exception_request(self.engine.user, self.engine.device, res, reason.strip())
            messagebox.showinfo("Request submitted", f"Your temporary access request ({rid}) was sent to the ZTNA manager. It does not grant access until approved.", parent=self)
        except (ValueError, StateStoreError, AuditFull, AuditTamper) as exc:
            messagebox.showerror("Request not submitted", str(exc), parent=self)

    def _request(self, res):
        result = self.engine.access(res)
        verdict, headline, lines, _tips = explain_decision(res, result)
        tag = {"ALLOW": "allow", "STEPUP": "stepup"}.get(verdict, "deny")
        seg = [(f" {headline} \n", tag),
               (f"\nApplication: {RESOURCES.get(res, {}).get('desc', res)}\nNetwork segment: {result.get('segment', SEGMENTS.get(res, '-'))}"
                f"   Risk: {result.get('risk', 'n/a')}/100   Device: {result.get('device', self.engine.device or '-')}\n", "")]
        if verdict == "ALLOW":
            pv = result.get("preview") or {}
            seg.append((f"\n{pv.get('title', '')}\n", "head"))
            cols, rows = list(pv.get("columns", ())), [list(map(str, r)) for r in pv.get("rows", ())]
            if cols:
                widths = [max(len(str(x)) for x in col) for col in zip(cols, *rows)]
                fmt = lambda r: "  " + "   ".join(str(v).ljust(w) for v, w in zip(r, widths)) + "\n"
                seg.append((fmt(cols), "head")); seg.extend((fmt(r), "") for r in rows)
            if result.get("upstream_error"): seg.append(("\nThe configured upstream is currently unavailable.\n", ""))
        self._write_out(seg)
        if verdict == "STEPUP":
            messagebox.showinfo("Extra verification needed", "Verify a fresh authenticator code in Step-up verification, then request access again.", parent=self)

    @staticmethod
    def _tips(result):
        err = str(result.get("error", ""))
        if err in ("session revoked", "session expired", "authentication required"): return ["Sign out and request sign-in again."]
        if result.get("decision") == "STEPUP": return ["Verify a fresh code under Step-up verification, then request access again."]
        tips = []
        for t in map(str, result.get("reasons", [])):
            if t.startswith(("RBAC", "micro-segmentation")): s = "This application is not part of your role. Ask your manager if you need it."
            elif t.startswith(("posture", "corporate-managed")): s = "Your device does not meet this application's health rules. Ask a ZTNA manager to review it."
            elif t.startswith("outside allowed hours"): s = "Try again during the allowed hours shown on the application card."
            elif t.startswith("location"): s = "Sign in again from an allowed connection (see the application card)."
            elif t.startswith("MFA older"): s = "Verify a fresh code under Step-up verification, then request access again."
            elif t.startswith("risk score"): s = "Risk is too high right now. Ask a ZTNA manager to review your session."
            else: continue
            if s not in tips: tips.append(s)
        return tips

    def _step_demo(self):
        try: self.v_step.set(self.engine.demo_otp(self.engine.user))
        except Exception as exc: messagebox.showerror("Demo code", str(exc), parent=self)

    def _stepup(self):
        ok, msg = self.engine.stepup(self.v_step.get().strip())
        if ok: messagebox.showinfo("MFA verified", "Fresh MFA recorded. Request the application again.", parent=self)
        else: messagebox.showerror("MFA verification failed", msg, parent=self)

    def _tick(self):
        """Live tiles; also notices when a manager revoked the session or it expired."""
        if not self.engine.session: return
        sid, sess = self.engine.session
        with LOCK: alive = sid in SESSIONS
        now = time.time()
        if not alive or sess["exp"] <= now or sess["abs_exp"] <= now:
            why = "A manager ended your session." if not alive else "Your session expired."
            self.engine.logout(); self.app.refresh_hub()
            messagebox.showwarning("Signed out", why + " Request sign-in again to continue.", parent=self)
            self._show_login(); return
        if sess.get("device") in BLOCKED_DEVICES:
            self.engine.logout(); self.app.refresh_hub()
            messagebox.showwarning("Device blocked", "The manager blocked this device. Your session has ended.", parent=self)
            self._show_login(); return
        remaining = max(0, int(sess["exp"] - now))
        if remaining <= 120 and remaining > 0 and not self._session_warning_shown:
            self._session_warning_shown = True
            if messagebox.askyesno("Session expiring", f"Your session expires in {remaining} seconds. Verify MFA now to extend it?", parent=self):
                code = simpledialog.askstring("Fresh MFA required", "Enter your current authenticator code:", parent=self)
                if code:
                    ok, msg = self.engine.stepup(code.strip())
                    if not ok: messagebox.showwarning("Session not extended", msg, parent=self)
                    else: self._session_warning_shown = False
        for resource, button in getattr(self, "resource_access_buttons", {}).items():
            assigned = rbac_allows(sess["user"], resource) and segment_allows(sess["user"], resource)
            if assigned:
                button.configure(text="Request access", command=lambda r=resource: self._request(r), style="Primary.TButton")
            else:
                button.configure(text="Request temporary exception", command=lambda r=resource: self._request_exception(r), style="TButton")
        self.v_tiles["score"].set(f"{posture(sess['device'])}/100")
        self.v_tiles["left"].set(f"{max(0, int(sess['exp'] - now))} s")
        self.v_tiles["mfa"].set(f"{int(now - sess['mfa_at'])} s ago")
        self._schedule("tick", 1000, self._tick)

    def _sign_out(self):
        try: self.engine.logout()
        finally:
            self.app.refresh_hub(); self._show_login()

    def close(self):
        try:
            if self.request_id and not self.engine.session: cancel_signin_request(self.request_id)
            if self.engine.session: self.engine.logout()
        except Exception: pass
        super().close(); self.app.refresh_hub()

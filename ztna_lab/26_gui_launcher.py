# Part 26 of ztna_lab_v2.py - desktop GUI: launcher (hub) window.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ------------------------------------------------------------------------------ hub window
class App(_PortalUI, tk.Tk):
    """Launcher. Employee and manager windows are opened from here and share one policy engine and audit chain."""

    def __init__(self):
        tk.Tk.__init__(self)
        self._init_ui()
        self.title("ZTNA Access Workspace")
        self.geometry("1000x740"); self.minsize(880, 680)
        if DEMO:
            load_persisted_devices()
            if not POSTURE_KEYS: POSTURE_KEYS.update(_demo_posture_keys())
        apply_blue_white_theme(self)
        self.portals = []
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build_hub()
        self._schedule("hub", 1500, self._hub_tick)
        if DEMO and DEMO_BOOTSTRAP_CREDENTIALS: self.after(450, self._show_bootstrap_credentials)

    def _build_hub(self):
        self._band("Secure access to your work", "")
        page = ttk.Frame(self, padding=(26, 22)); page.pack(fill="both", expand=True)
        cards = ttk.Frame(page); cards.pack(fill="x", expand=True)
        cards.columnconfigure(0, weight=1, uniform="c"); cards.columnconfigure(1, weight=1, uniform="c")
        emp = Panel(cards, "Employee", padding=22); emp.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        ttk.Label(emp.body, text="Employee access", style="Section.TLabel").pack(anchor="w", pady=(0, 14))
        ttk.Button(emp.body, text="Open employee sign-in  →", style="Primary.TButton", command=self.open_employee).pack(anchor="w")
        mgr = Panel(cards, "Manager", padding=22); mgr.grid(row=0, column=1, sticky="nsew", padx=(9, 0))
        ttk.Label(mgr.body, text="ZTNA manager console", style="Section.TLabel").pack(anchor="w", pady=(0, 14))
        ttk.Button(mgr.body, text="Open manager console  →", style="Primary.TButton", command=self.open_manager).pack(anchor="w")
        both = ttk.Frame(page); both.pack(fill="x", pady=(14, 0))
        ttk.Button(both, text="Open both side by side", command=self.open_both).pack(side="left")
        self.v_hub = tk.StringVar()
        ttk.Label(page, textvariable=self.v_hub, style="Accent.TLabel").pack(anchor="w", pady=(16, 0))
        self.refresh_hub()

    def refresh_hub(self):
        try:
            now = time.time()
            with LOCK: sessions = sum(1 for s in SESSIONS.values() if s.get("exp", 0) > now and s.get("abs_exp", 0) > now)
            self.v_hub.set(f"Sign-ins waiting for approval: {count_pending_signins()}   ·   Active sessions: {sessions}   ·   Open windows: {len(self.portals)}")
        except Exception: pass

    def _hub_tick(self):
        self.refresh_hub(); self._schedule("hub", 1500, self._hub_tick)

    def _track(self, win):
        self.portals.append(win); self.refresh_hub(); return win

    def portal_closed(self, win):
        if win in self.portals: self.portals.remove(win)

    def _live(self, cls):
        return next((w for w in self.portals if isinstance(w, cls) and w.winfo_exists()), None)

    def open_employee(self, geometry=None):
        win = self._track(EmployeePortal(self))
        if geometry: win.geometry(geometry)
        win.lift(); return win

    def open_manager(self, geometry=None):
        win = self._live(ManagerPortal)
        if win is None:
            win = self._track(ManagerPortal(self))
            if geometry: win.geometry(geometry)
        win.deiconify(); win.lift(); win.focus_force(); return win

    def open_both(self):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = max(860, min(1000, sw // 2 - 10)), max(640, min(780, sh - 120))
        self.open_employee(f"{w}x{h}+0+20"); self.open_manager(f"{w}x{h}+{w + 8}+20")

    def _show_bootstrap_credentials(self):
        if not DEMO_BOOTSTRAP_CREDENTIALS or not self.winfo_exists(): return
        lines = ["EMPLOYEE CREDENTIALS", ""]
        for user, password, role, secret in DEMO_BOOTSTRAP_CREDENTIALS:
            lines.append(f"{user:<8} role={role:<10} password={password}  TOTP secret={secret}")
        win = tk.Toplevel(self); win.title("Employee credentials"); win.geometry("900x560"); win.transient(self); win.configure(background=WHITE)
        band = ttk.Frame(win, style="Band.TFrame", padding=(20, 14)); band.pack(fill="x")
        ttk.Label(band, text="Employee credentials", style="BandTitle.TLabel", font=(UI_FONT, 16, "bold")).pack(anchor="w")
        box = Panel(win, padding=8); box.pack(fill="both", expand=True, padx=18, pady=14)
        txt = tk.Text(box.body, wrap="none", font=("Consolas", 10), background=WHITE, foreground=BLUE_TEXT, relief="flat", bd=0, highlightthickness=0)
        txt.pack(fill="both", expand=True); txt.insert("1.0", "\n".join(lines)); txt.configure(state="disabled")
        btn = ttk.Frame(win); btn.pack(fill="x", padx=18, pady=(0, 14))
        def copy_all():
            self.clipboard_clear(); self.clipboard_append("\n".join(lines)); messagebox.showinfo("Copied", "Credentials copied to the clipboard. Store them securely.", parent=win)
        ttk.Button(btn, text="Copy all credentials", command=copy_all).pack(side="left")
        ttk.Button(btn, text="Close", style="Primary.TButton", command=win.destroy).pack(side="right")

    def on_close(self):
        for win in list(self.portals):
            try: win.close()
            except Exception: pass
        self._cancel_jobs()
        self.destroy()

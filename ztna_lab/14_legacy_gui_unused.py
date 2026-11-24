# Part 14 of ztna_lab_v2.py - previous single-window Tk GUI (Card, ScrollTab, LegacyApp). No entry point uses it.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

class Card(tk.Frame):
    """White, thin-bordered panel with an optional title row; put content in ``.body``."""

    def __init__(self, parent, title=None, subtitle=None, padding=14):
        super().__init__(parent, background="#d6e1ee", highlightthickness=0, bd=0)
        self._inner = ttk.Frame(self, style="Card.TFrame", padding=padding)
        self._inner.pack(fill="both", expand=True, padx=1, pady=1)
        self.head = None
        if title:
            self.head = ttk.Frame(self._inner, style="Card.TFrame")
            self.head.pack(fill="x", pady=(0, 10))
            ttk.Label(self.head, text=title, style="CardTitle.TLabel").pack(side="left")
            if subtitle:
                ttk.Label(self.head, text=subtitle, style="CardHint.TLabel").pack(side="left", padx=(10, 0))
        self.body = ttk.Frame(self._inner, style="Card.TFrame")
        self.body.pack(fill="both", expand=True)


class ScrollTab(tk.Frame):
    """Notebook page whose content always fills the page, and scrolls only when the window is too small."""

    def __init__(self, parent, background):
        super().__init__(parent, background=background, highlightthickness=0, bd=0)
        self.canvas = tk.Canvas(self, background=background, highlightthickness=0, bd=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body = ttk.Frame(self.canvas, padding=(20, 16))
        self._win = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self._vbar_shown = False
        self.body.bind("<Configure>", self._fit)
        self.canvas.bind("<Configure>", self._fit)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(seq, self._on_wheel, add="+")
        self._last_need = -1
        self.after(200, self._watch)

    def _watch(self):
        try:
            if self.body.winfo_reqheight() != self._last_need:
                self._fit()
            self.after(200, self._watch)
        except tk.TclError:
            pass

    def _fit(self, _event=None):
        cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
        if cw < 2 or ch < 2:
            return
        need = self._last_need = self.body.winfo_reqheight()
        height = max(ch, need)
        self.canvas.itemconfigure(self._win, width=cw, height=height)
        self.canvas.configure(scrollregion=(0, 0, cw, height))
        scrollable = need > ch + 1
        if scrollable and not self._vbar_shown:
            self.vbar.pack(side="right", fill="y", before=self.canvas); self._vbar_shown = True
        elif not scrollable and self._vbar_shown:
            self.vbar.pack_forget(); self._vbar_shown = False; self.canvas.yview_moveto(0)

    def _on_wheel(self, event):
        if not self._vbar_shown or not self.winfo_ismapped():
            return
        widget = event.widget
        try:
            if widget.winfo_class() in ("Treeview", "Text", "Listbox", "TCombobox", "TSpinbox", "Toplevel"):
                return
        except Exception:
            return
        node = widget
        while node is not None and node is not self:
            node = getattr(node, "master", None)
        if node is None:
            return
        if getattr(event, "num", None) == 4: step = -2
        elif getattr(event, "num", None) == 5: step = 2
        else: step = -2 if event.delta > 0 else 2
        self.canvas.yview_scroll(step, "units")


class LegacyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ZTNA Enterprise Lab — Zero Trust Security Control Center")
        # Size to the screen (leaving room for the taskbar/title bar) so the window can always be grabbed and moved.
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(1280, int(sw * 0.86)), min(780, int(sh * 0.80))
        self.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, int((sh - h) * 0.25))}")
        self.minsize(min(860, w), min(520, h))
        self.resizable(True, True)
        self.bind("<F11>", lambda _e: self.attributes("-fullscreen", not self.attributes("-fullscreen")))
        self.bind("<Escape>", lambda _e: self.attributes("-fullscreen", False))
        self.engine = DesktopZTNA()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build_style()
        if DEMO:
            # The runtime user store is authoritative; enrollments survive restarts.
            load_persisted_devices()
            if not POSTURE_KEYS:
                POSTURE_KEYS.update(_demo_posture_keys())
        self._build_ui()
        self.refresh_all()

    # ------------------------------------------------------------------ layout helpers
    GAP = 12

    def _build_style(self):
        """Light, enterprise-style dashboard theme; presentation only."""
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        C = self.C = dict(bg="#edf3f9", panel="#ffffff", panel2="#f3f7fc", border="#d6e1ee", fg="#12294b", muted="#607a9b",
                          blue="#0878e8", blue_hover="#0866c7", green="#07966b", red="#d83b4b", amber="#b26a00")
        bg, panel, panel2, border, fg, muted = C["bg"], C["panel"], C["panel2"], C["border"], C["fg"], C["muted"]
        blue, blue_hover, red = C["blue"], C["blue_hover"], C["red"]
        F = "Segoe UI"

        self.configure(background=bg)
        style.configure(".", font=(F, 10), background=bg, foreground=fg)
        style.configure("TFrame", background=bg)
        style.configure("Card.TFrame", background=panel)
        style.configure("Header.TFrame", background=panel)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Sub.TLabel", font=(F, 10), background=bg, foreground=muted)
        style.configure("PageStrong.TLabel", font=(F, 11, "bold"), background=bg, foreground=fg)
        style.configure("Card.TLabel", background=panel, foreground=fg)
        style.configure("CardStrong.TLabel", font=(F, 10, "bold"), background=panel, foreground=fg)
        style.configure("CardTitle.TLabel", font=(F, 11, "bold"), background=panel, foreground="#102d55")
        style.configure("CardHint.TLabel", font=(F, 9), background=panel, foreground=muted)
        style.configure("CardBanner.TLabel", font=(F, 13, "bold"), background=panel, foreground=fg)
        style.configure("KpiTitle.TLabel", font=(F, 9, "bold"), background=panel, foreground=muted)
        style.configure("KpiValue.TLabel", font=(F, 22, "bold"), background=panel, foreground=blue)
        style.configure("Score.TLabel", font=(F, 20, "bold"), background=panel, foreground=blue)
        style.configure("HeaderTitle.TLabel", font=(F, 19, "bold"), background=panel, foreground="#10284b")
        style.configure("HeaderSub.TLabel", font=(F, 10), background=panel, foreground=muted)
        # kept for compatibility with any caller that still uses the old names
        style.configure("Title.TLabel", font=(F, 23, "bold"), background=bg, foreground="#10284b")
        style.configure("Card.TLabelframe", background=panel, bordercolor=border, relief="solid", padding=15)
        style.configure("Card.TLabelframe.Label", font=(F, 11, "bold"), background=panel, foreground="#102d55")
        style.configure("TLabelframe", background=panel, bordercolor=border, relief="solid", padding=12)
        style.configure("TLabelframe.Label", background=panel, foreground="#102d55", font=(F, 10, "bold"))

        style.configure("TNotebook", background=bg, bordercolor=border, borderwidth=0, tabmargins=(0, 6, 0, 0))
        style.configure("TNotebook.Tab", background="#e3ecf7", foreground="#45617f", padding=(11, 8), bordercolor=border, font=(F, 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", blue), ("active", "#d3e8ff")], foreground=[("selected", "#ffffff"), ("active", fg)])

        style.configure("TButton", background="#f0f5fb", foreground=fg, bordercolor=border, padding=(12, 7), relief="flat", font=(F, 10))
        style.map("TButton", background=[("active", "#dcecff"), ("pressed", "#c9e0fb"), ("disabled", "#edf1f6")], foreground=[("disabled", "#9aa9ba")])
        style.configure("Action.TButton", font=(F, 10, "bold"), padding=(14, 8), background=blue, foreground="#ffffff", bordercolor=blue)
        style.map("Action.TButton", background=[("active", blue_hover), ("pressed", "#0758ac")], foreground=[("disabled", "#dce8f6")])
        style.configure("Danger.TButton", font=(F, 10, "bold"), padding=(12, 8), background=red, foreground="#ffffff", bordercolor=red)
        style.map("Danger.TButton", background=[("active", "#b92e3e")])
        style.configure("Link.TButton", font=(F, 9, "bold"), padding=(10, 4), background=panel, foreground=blue, bordercolor=border)
        style.map("Link.TButton", background=[("active", "#eaf3ff")])

        style.configure("TEntry", fieldbackground="#ffffff", foreground=fg, insertcolor=fg, bordercolor=border, lightcolor=border, darkcolor=border, padding=6)
        style.map("TEntry", bordercolor=[("focus", blue)])
        style.configure("TSpinbox", fieldbackground="#ffffff", foreground=fg, bordercolor=border, lightcolor=border, darkcolor=border, arrowcolor=blue, padding=5)
        style.map("TSpinbox", bordercolor=[("focus", blue)])
        style.configure("TCombobox", fieldbackground="#ffffff", background="#eaf2fb", foreground=fg, arrowcolor=blue, bordercolor=border, lightcolor=border, darkcolor=border, padding=5)
        style.map("TCombobox", fieldbackground=[("readonly", "#ffffff")], foreground=[("readonly", fg)], selectbackground=[("readonly", "#ffffff")],
                  selectforeground=[("readonly", fg)], bordercolor=[("focus", blue)])
        style.configure("TCheckbutton", background=panel, foreground=fg, indicatorbackground="#ffffff", indicatorforeground="#ffffff", bordercolor=border, lightcolor=border, darkcolor=border, upperbordercolor=border, lowerbordercolor=border)
        style.map("TCheckbutton", background=[("active", panel)], indicatorbackground=[("selected", blue), ("active", "#eaf3ff"), ("!selected", "#ffffff")],
                  indicatorforeground=[("selected", "#ffffff")])
        style.configure("Page.TCheckbutton", background=bg, foreground=fg, indicatorbackground="#ffffff", indicatorforeground="#ffffff", bordercolor=border, lightcolor=border, darkcolor=border)
        style.map("Page.TCheckbutton", background=[("active", bg)], indicatorbackground=[("selected", blue), ("!selected", "#ffffff")], indicatorforeground=[("selected", "#ffffff")])
        style.configure("TRadiobutton", background=panel, foreground=fg)
        style.configure("TSeparator", background=border)
        style.configure("TPanedwindow", background=bg)
        style.configure("TProgressbar", troughcolor=panel2, background=blue, bordercolor=border, lightcolor=blue, darkcolor=blue, thickness=10)
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", background="#c9d8ea", troughcolor=panel2, bordercolor=border, arrowcolor=muted, relief="flat")
            style.map(f"{orient}.TScrollbar", background=[("active", "#a9c3e0")])

        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground=fg, bordercolor=border, lightcolor=border, darkcolor=border, rowheight=28, font=(F, 9))
        style.configure("Treeview.Heading", background="#eaf1f9", foreground="#19385f", relief="flat", padding=(10, 7), font=(F, 9, "bold"))
        style.configure("Compact.Treeview", rowheight=24)
        style.configure("Compact.Treeview.Heading", background="#eaf1f9", foreground="#19385f", relief="flat", padding=(8, 5), font=(F, 9, "bold"))
        style.map("Treeview", background=[("selected", "#d6eaff")], foreground=[("selected", "#10284b")])
        style.map("Compact.Treeview", background=[("selected", "#d6eaff")], foreground=[("selected", "#10284b")])
        style.map("Treeview.Heading", background=[("active", "#dcecff")])

        self.option_add("*Text.background", "#ffffff")
        self.option_add("*Text.foreground", fg)
        self.option_add("*Text.insertBackground", fg)
        self.option_add("*Text.selectBackground", "#d6eaff")
        self.option_add("*Listbox.background", "#ffffff")
        self.option_add("*Listbox.foreground", fg)
        self.option_add("*Listbox.selectBackground", "#d6eaff")
        self.option_add("*TCombobox*Listbox.background", "#ffffff")
        self.option_add("*TCombobox*Listbox.foreground", fg)
        self.option_add("*TCombobox*Listbox.selectBackground", "#d6eaff")
        self.option_add("*TCombobox*Listbox.selectForeground", fg)
        self.option_add("*TCombobox*Listbox.font", (F, 10))

    def _new_tab(self, title):
        tab = ScrollTab(self.nb, self.C["bg"])
        self.nb.add(tab, text=title)
        return tab, tab.body

    def _lbl(self, parent, text="", kind="card", wrap=False, **kw):
        style = {"card": "Card.TLabel", "strong": "CardStrong.TLabel", "hint": "CardHint.TLabel", "page": "TLabel",
                 "pagehint": "Sub.TLabel", "pagestrong": "PageStrong.TLabel", "title": "CardTitle.TLabel"}[kind]
        lab = ttk.Label(parent, text=text, style=style, **kw)
        if wrap:
            self._wrap_label(lab)
        return lab

    @staticmethod
    def _wrap_label(lab):
        """Make a label re-wrap to whatever width its container gives it.
        width=1 stops the label's own text width from feeding back into the layout (no resize loops)."""
        lab.configure(wraplength=360, justify="left", width=1)
        def rewrap(event, w=lab):
            target = max(120, event.width - 4)
            if abs(int(float(str(w.cget("wraplength")))) - target) > 1:
                w.configure(wraplength=target)
        lab.bind("<Configure>", rewrap, add="+")
        return lab

    def _tree(self, parent, columns, *, height=6, hscroll=False, selectmode="browse", compact=False):
        """columns = (id, title, width, anchor, stretch). Returns (frame, tree) with scrollbars wired up."""
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height, selectmode=selectmode,
                            style="Compact.Treeview" if compact else "Treeview")
        for cid, title, width, anchor, stretch in columns:
            tree.heading(cid, text=title, anchor="w" if anchor == "w" else "center")
            tree.column(cid, width=width, minwidth=min(width, 60), anchor=anchor, stretch=stretch)
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew"); ys.grid(row=0, column=1, sticky="ns")
        if hscroll:
            xs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
            tree.configure(xscrollcommand=xs.set); xs.grid(row=1, column=0, sticky="ew")
        return frame, tree

    def _text(self, parent, height=5, *, mono=False, wrap="word", hscroll=False):
        """Read-only inset text panel with padding, a soft border and scrollbars. Returns (frame, text)."""
        C = self.C
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        t = tk.Text(frame, height=height, wrap=wrap, state="disabled", background=C["panel2"], foreground=C["fg"], relief="flat", bd=0,
                    highlightthickness=1, highlightbackground=C["border"], highlightcolor=C["blue"], padx=12, pady=10,
                    font=("Consolas", 10) if mono else ("Segoe UI", 10), spacing1=1, spacing3=3, insertbackground=C["fg"],
                    selectbackground="#d6eaff", selectforeground=C["fg"])
        ys = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=ys.set)
        t.grid(row=0, column=0, sticky="nsew"); ys.grid(row=0, column=1, sticky="ns")
        if hscroll:
            xs = ttk.Scrollbar(frame, orient="horizontal", command=t.xview)
            t.configure(xscrollcommand=xs.set); xs.grid(row=1, column=0, sticky="ew")
        return frame, t

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal"); widget.delete("1.0", "end"); widget.insert("1.0", text); widget.configure(state="disabled")

    def _guide(self, parent, headline, details):
        # Explanatory/help text is intentionally omitted from the operational UI.
        frame = ttk.Frame(parent, height=0)
        frame.grid_propagate(False)
        return frame

    # ------------------------------------------------------------------ shell
    def _build_ui(self):
        C = self.C
        header = ttk.Frame(self, style="Header.TFrame", padding=(24, 12))
        header.pack(fill="x")
        logo = tk.Label(header, text="ZT", background=C["blue"], foreground="#ffffff", font=("Segoe UI", 13, "bold"), padx=10, pady=4)
        logo.pack(side="left", padx=(0, 14))
        titles = ttk.Frame(header, style="Header.TFrame"); titles.pack(side="left")
        ttk.Label(titles, text="ZTNA Enterprise Lab", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(titles, text="Desktop Security Control Center  \u00b7  verify every request, trust nothing by default", style="HeaderSub.TLabel").pack(anchor="w")
        self.status = tk.Label(header, text="\u25cf Logged out", background="#e3ecf7", foreground=C["muted"], font=("Segoe UI", 10, "bold"), padx=14, pady=6)
        self.status.pack(side="right")
        tk.Frame(self, height=1, background=C["border"]).pack(fill="x")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14, pady=(8, 14))
        self._build_dashboard_tab()
        self._build_identity_devices_tab()
        self._build_roles_tab()
        self._build_access_tab()
        self._build_posture_tab()
        self._build_policy_tab()
        self._build_security_tab()
        self._build_audit_tab()

    # ------------------------------------------------------------------ Overview
    def _build_dashboard_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Overview"); self.overview_tab = tab
        body.columnconfigure(0, weight=3, uniform="ov"); body.columnconfigure(1, weight=2, uniform="ov")
        body.rowconfigure(2, weight=1)

        kpis = ttk.Frame(body); kpis.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.kpi_vars = {k: tk.StringVar(value="\u2014") for k in ("identities", "devices", "compliant", "totp")}
        items = (("identities", "IDENTITIES", "accounts in the directory"), ("devices", "REGISTERED DEVICES", "enrolled endpoints"),
                 ("compliant", "COMPLIANT DEVICES", "posture score 80 or higher"), ("totp", "TOTP ENABLED", "accounts with MFA configured"))
        for col, (key, title, caption) in enumerate(items):
            kpis.columnconfigure(col, weight=1, uniform="kpi")
            card = Card(kpis, padding=(16, 9))
            card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else G // 2, 0 if col == 3 else G // 2))
            ttk.Label(card.body, text=title, style="KpiTitle.TLabel").pack(anchor="w")
            ttk.Label(card.body, textvariable=self.kpi_vars[key], style="KpiValue.TLabel").pack(anchor="w", pady=(2, 0))
            ttk.Label(card.body, text=caption, style="CardHint.TLabel").pack(anchor="w")

        login = Card(body, "Identity & MFA")
        login.grid(row=1, column=0, sticky="nsew", padx=(0, G // 2), pady=(0, G))
        form = login.body; form.columnconfigure(1, weight=1)
        self.user_var = tk.StringVar(value="alice")
        self.pass_var = tk.StringVar(value="")
        self.otp_var = tk.StringVar()
        self.device_var = tk.StringVar(value="laptop-alice")
        self.location_var = tk.StringVar(value="office")
        self.user_combo = self._field(form, "User", self.user_var, 0, sorted(USERS))
        self.user_combo.bind("<<ComboboxSelected>>", self._on_user_pick)
        self._field(form, "Password", self.pass_var, 1, None, show="*")
        self._field(form, "TOTP", self.otp_var, 2)
        self.device_combo = self._field(form, "Device", self.device_var, 3, sorted(DEVICES))
        self._field(form, "Location", self.location_var, 4, ["office", "home"])
        btns = ttk.Frame(form, style="Card.TFrame"); btns.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        for c in range(3): btns.columnconfigure(c, weight=1, uniform="lb")
        self.demo_otp_btn = ttk.Button(btns, text="Generate demo OTP", command=self.generate_otp)
        self.demo_otp_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.demo_otp_btn.configure(state=("normal" if DEMO_OTP else "disabled"))
        ttk.Button(btns, text="Login", style="Action.TButton", command=self.do_login).grid(row=0, column=1, sticky="ew", padx=3)
        ttk.Button(btns, text="Logout", command=self.do_logout).grid(row=0, column=2, sticky="ew", padx=(6, 0))
        tip = ttk.Label(form, style="CardHint.TLabel", text="Demo tip: use the one-time generated password printed at provisioning, your authenticator TOTP, and your own device.")
        self._wrap_label(tip).grid(row=6, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        info = Card(body, "Current session")
        info.grid(row=1, column=1, sticky="nsew", padx=(G // 2, 0), pady=(0, G))
        self.session_text = tk.StringVar(value="Not authenticated")
        ttk.Label(info.body, textvariable=self.session_text, style="CardStrong.TLabel").pack(anchor="w")
        ttk.Separator(info.body).pack(fill="x", pady=10)
        grid = ttk.Frame(info.body, style="Card.TFrame"); grid.pack(fill="x"); grid.columnconfigure(1, weight=1)
        self.session_vars = {}
        for r, (key, label) in enumerate((("user", "User"), ("device", "Device"), ("location", "Location"), ("mfa", "MFA age"), ("ttl", "Session TTL"), ("travel", "Travel flag"))):
            self.session_vars[key] = tk.StringVar(value="\u2014")
            ttk.Label(grid, text=label, style="CardHint.TLabel").grid(row=r, column=0, sticky="w", pady=4, padx=(0, 16))
            ttk.Label(grid, textvariable=self.session_vars[key], style="CardStrong.TLabel").grid(row=r, column=1, sticky="w", pady=4)

        activity = Card(body, "Security activity", "latest decisions and events")
        activity.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2))
        ttk.Button(activity.head, text="Refresh", style="Link.TButton", command=self.refresh_dashboard_activity).pack(side="right")
        frame, self.activity_tree = self._tree(activity.body, (
            ("time", "Time", 70, "w", False), ("decision", "Decision", 90, "w", False), ("user", "User", 80, "w", False),
            ("device", "Device", 120, "w", False), ("resource", "Resource", 110, "w", False), ("risk", "Risk", 60, "w", False),
            ("details", "Details", 260, "w", True)), height=4)
        for tag, color in (("ALLOW", "#0a7d33"), ("DENY", "#c62828"), ("STEPUP", "#b26a00"), ("POLICY", "#0b5cad")):
            self.activity_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)

        summary = Card(body, "Security summary", "what just happened")
        summary.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0))
        frame, self.summary = self._text(summary.body, height=6)
        frame.pack(fill="both", expand=True)

    def _field(self, parent, label, var, row, values=None, show=None):
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, padx=(0, 16), pady=3, sticky="w")
        if values:
            w = ttk.Combobox(parent, textvariable=var, values=values, state="readonly", width=18)
        else:
            w = ttk.Entry(parent, textvariable=var, width=20, show=show or "")
        w.grid(row=row, column=1, pady=3, sticky="ew")
        return w

    @staticmethod
    def _devices_of(user):
        mine = sorted(d for d, v in DEVICES.items() if v.get("owner") == user)
        return mine or sorted(DEVICES)

    def _on_user_pick(self, _event=None):
        user = self.user_var.get()
        devs = self._devices_of(user)
        self.device_combo.configure(values=devs)
        self.device_var.set(devs[0] if devs else "")
        if DEMO and user in USER_PROFILE: self.pass_var.set(user + "123")
        self.otp_var.set("")

    # ------------------------------------------------------------------ Identity & Devices
    def _build_identity_devices_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Identity & Devices"); self.identity_tab = tab
        body.columnconfigure(0, weight=1, uniform="idv", minsize=320); body.columnconfigure(1, weight=3, uniform="idv")
        body.rowconfigure(1, weight=1)
        intro = ttk.Label(body, style="Sub.TLabel", text="Review existing identities and enroll endpoints into the shared policy, posture, MFA and audit engine.")
        self._wrap_label(intro).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))

        left = ttk.Frame(body); left.grid(row=1, column=0, sticky="nsew", padx=(0, G // 2))
        right = ttk.Frame(body); right.grid(row=1, column=1, sticky="nsew", padx=(G // 2, 0))
        right.columnconfigure(0, weight=1); right.rowconfigure(0, weight=1); right.rowconfigure(1, weight=1)

        admin = Card(left, "User administration"); admin.pack(fill="x", pady=(0, G))
        ttk.Button(admin.body, text="Add user\u2026", style="Action.TButton", command=self.add_user_ui).pack(fill="x", pady=(0, 6))
        ttk.Button(admin.body, text="Bulk-enroll missing devices", command=self.bulk_enroll_devices_ui).pack(fill="x")
        self._lbl(admin.body, "Bulk-enroll creates one demo device for every user that has none. Local demo administration only.", "hint", wrap=True).pack(fill="x", pady=(8, 0))

        dev = Card(left, "Enroll device"); dev.pack(fill="x")
        form = dev.body; form.columnconfigure(1, weight=1)
        self.new_device_id = tk.StringVar(); self.new_device_owner = tk.StringVar(); self.new_device_managed = tk.BooleanVar(value=True)
        ttk.Label(form, text="Device ID", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=5, padx=(0, 12))
        ttk.Entry(form, textvariable=self.new_device_id, width=20).grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Label(form, text="a-z, 0-9 and hyphen only", style="CardHint.TLabel").grid(row=1, column=1, sticky="w")
        ttk.Label(form, text="Owner", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=5, padx=(0, 12))
        self.new_device_owner.set(sorted(USERS)[0] if USERS else "")
        self.device_owner_combo = ttk.Combobox(form, textvariable=self.new_device_owner, values=sorted(USERS), state="readonly", width=18)
        self.device_owner_combo.grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Checkbutton(form, text="Corporate-managed device", variable=self.new_device_managed).grid(row=3, column=0, columnspan=2, sticky="w", pady=6)
        ttk.Button(form, text="Enroll device + key", style="Action.TButton", command=self.enroll_device_ui).grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 2))
        self._lbl(form, "New devices start with current posture signals set to compliant. Toggle them in Device Posture to test policy decisions.", "hint", wrap=True).grid(row=5, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        users = Card(right, "Identity overview", "select a user to inspect"); users.grid(row=0, column=0, sticky="nsew", pady=(0, G))
        frame, self.identity_tree = self._tree(users.body, (
            ("username", "Username", 100, "w", False), ("name", "Name / title", 240, "w", True), ("role", "Role", 100, "w", False),
            ("hash", "Password hash fingerprint", 220, "w", False), ("totp", "TOTP status", 120, "w", False)), height=5)
        frame.pack(fill="both", expand=True)
        self.identity_tree.bind("<<TreeviewSelect>>", self.show_identity_details)

        devs = Card(right, "Enrolled devices", "select a device to inspect"); devs.grid(row=1, column=0, sticky="nsew", pady=(0, G))
        frame, self.device_tree = self._tree(devs.body, (
            ("device", "Device ID", 160, "w", True), ("owner", "Owner", 110, "w", False), ("score", "Posture", 80, "w", False),
            ("managed", "Managed", 90, "w", False), ("key", "Key fingerprint", 170, "w", False)), height=5)
        frame.pack(fill="both", expand=True)
        self.device_tree.bind("<<TreeviewSelect>>", self.show_device_details)

        detail = Card(right, "Details", "stored hash and TOTP secret are sensitive lab material \u2013 keep this window private")
        detail.grid(row=2, column=0, sticky="ew")
        frame, self.identity_detail = self._text(detail.body, height=4)
        frame.pack(fill="x")
        self._set_text(self.identity_detail, "Select an identity or a device above to see its details.")
        self.refresh_identity_devices()
        self.refresh_dashboard_overview()

    def refresh_dashboard_overview(self):
        configured = sum(bool(u.get("totp")) for u in USERS.values())
        compliant = sum(1 for device_id in DEVICES if posture(device_id) >= 80)
        if hasattr(self, "kpi_vars"):
            self.kpi_vars["identities"].set(str(len(USERS)))
            self.kpi_vars["devices"].set(str(len(DEVICES)))
            self.kpi_vars["compliant"].set(f"{compliant} / {len(DEVICES)}")
            self.kpi_vars["totp"].set(f"{configured} / {len(USERS)}")

    def refresh_dashboard_activity(self):
        if not hasattr(self, "activity_tree"): return
        rows = []
        for idx, event in enumerate(list(LOG)[:25]):
            ts = event.get("ts", "")
            try:
                time_text = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
            except (TypeError, ValueError, OSError):
                time_text = str(ts)
            details = "; ".join(map(str, event.get("reasons", [])))
            rows.append((f"activity:{idx}", str(event.get("decision", "")), (
                time_text, event.get("decision", ""), event.get("user", ""),
                event.get("device", "") or "—", event.get("resource", "") or "—",
                event.get("risk", ""), details,
            )))
        if rows == getattr(self, "_activity_rows", None): return
        self._activity_rows = rows
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
        for iid, decision, values in rows:
            self.activity_tree.insert("", "end", iid=iid, values=values, tags=(decision,))

    def _confirm_admin_password(self):
        if not DEMO:
            messagebox.showerror("Administrator verification",
                                 "GUI user administration is available only in local demo mode.",
                                 parent=self)
            return False
        admin_password = simpledialog.askstring(
            "Administrator verification",
            "Enter the password for an existing admin account:",
            show="*",
            parent=self,
        )
        if admin_password is None:
            return False
        for _name, record in USERS.items():
            if record.get("role") != "admin":
                continue
            try:
                if pw_verify(admin_password, record.get("pw", {})):
                    return True
            except Exception:
                continue
        messagebox.showerror("Access denied", "The administrator password was incorrect.",
                             parent=self)
        return False

    def add_user_ui(self):
        if not self._confirm_admin_password():
            return
        dialog = tk.Toplevel(self)
        dialog.title("Add ZTNA user")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(background=self.C["bg"])
        body = ttk.Frame(dialog, padding=22)
        body.pack(fill="both", expand=True)
        username_var, role_var = tk.StringVar(), tk.StringVar(value="engineer")
        password_var, confirm_var = tk.StringVar(), tk.StringVar()
        ttk.Label(body, text="Username").grid(row=0, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Entry(body, textvariable=username_var, width=28).grid(row=0, column=1, pady=5)
        ttk.Label(body, text="Role").grid(row=1, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Combobox(body, textvariable=role_var, values=tuple(ROLES),
                     state="readonly", width=25).grid(row=1, column=1, pady=5)
        ttk.Label(body, text="New password").grid(row=2, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Entry(body, textvariable=password_var, show="*", width=28).grid(row=2, column=1, pady=5)
        ttk.Label(body, text="Confirm password").grid(row=3, column=0, sticky="w", pady=5, padx=(0, 10))
        ttk.Entry(body, textvariable=confirm_var, show="*", width=28).grid(row=3, column=1, pady=5)
        ttk.Label(body, text="Minimum 8 characters. A unique TOTP secret is generated.", style="Sub.TLabel",
                  wraplength=340).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 14))

        def create():
            username, role = username_var.get().strip(), role_var.get().strip()
            password, confirm = password_var.get(), confirm_var.get()
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
                messagebox.showerror("Add user", "Use 1–64 letters, numbers, dots, underscores, @ or hyphens.", parent=dialog); return
            if username in USERS:
                messagebox.showerror("Add user", "That username already exists.", parent=dialog); return
            if role not in ROLES:
                messagebox.showerror("Add user", "Choose a supported role.", parent=dialog); return
            if len(password) < 8:
                messagebox.showerror("Add user", "Password must be at least 8 characters.", parent=dialog); return
            if not _ct_eq(password, confirm):
                messagebox.showerror("Add user", "Passwords do not match.", parent=dialog); return
            try:
                pwrec = _pw_record(password)
                totp_secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
                USERS[username] = {"pw": pwrec, "role": role, "totp": totp_secret}
                _persist_users()
                audit(user="admin", device="", resource="identity-create", decision="POLICY",
                      reasons=[f"created local demo identity {username} with role {role}"])
            except Exception as exc:
                USERS.pop(username, None)
                messagebox.showerror("Add user", f"Could not save user: {exc}", parent=dialog); return
            self.refresh_identity_devices()
            self.refresh_dashboard_overview()
            self._write_summary(f"Created user {username} ({role}); TOTP secret generated.")
            dialog.destroy()
            messagebox.showinfo("User created",
                f"User: {username}\nRole: {role}\nTOTP secret: {totp_secret}\n\n"
                "Store this secret securely and enroll it in an authenticator app. "
                "You can now enroll a device for this user.", parent=self)

        buttons = ttk.Frame(body)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="Create user", style="Action.TButton", command=create).pack(side="right")
        dialog.bind("<Return>", lambda _event: create())
        dialog.update_idletasks()
        dialog.geometry(f"+{self.winfo_rootx() + (self.winfo_width() - dialog.winfo_reqwidth()) // 2}+{self.winfo_rooty() + (self.winfo_height() - dialog.winfo_reqheight()) // 3}")
        dialog.wait_window()

    def bulk_enroll_devices_ui(self):
        if not self._confirm_admin_password():
            return
        owners_with_devices = {item.get("owner") for item in DEVICES.values()}
        pending = [username for username in sorted(USERS) if username not in owners_with_devices]
        if not pending:
            messagebox.showinfo("Bulk enrollment", "Every user already has at least one device.", parent=self); return
        if not messagebox.askyesno(
            "Confirm bulk enrollment",
            f"Enroll one demo device for each of {len(pending)} users without a device?\n\n"
            "These local demo records are not proof that real endpoints completed enrollment.",
            parent=self):
            return
        created = []
        try:
            if not DEMO:
                raise RuntimeError("Bulk enrollment is available only in local demo mode.")
            if not POSTURE_KEYS:
                POSTURE_KEYS.update(_demo_posture_keys())
            for username in pending:
                base = re.sub(r"[^a-z0-9-]+", "-", username.lower()).strip("-") or "user"
                device_id = f"laptop-{base}"[:64]
                suffix = 2
                while device_id in DEVICES:
                    tail = f"-{suffix}"
                    device_id = f"laptop-{base}"[:64-len(tail)] + tail
                    suffix += 1
                DEVICES[device_id] = {
                    "owner": username, "os_updated": True, "disk_encrypted": True,
                    "firewall": True, "antivirus": True, "corporate_managed": True,
                    "last_report": time.time(),
                }
                POSTURE_KEYS[device_id] = secrets.token_bytes(32)
                created.append(device_id)
            _persist_demo_device_keys()
            save_persisted_devices()
            for device_id in created:
                audit(user="admin", device=device_id, resource="device-enrollment", decision="POLICY",
                      reasons=[f"demo device bulk-enrolled for {DEVICES[device_id]['owner']}"])
        except Exception as exc:
            for device_id in created:
                DEVICES.pop(device_id, None); POSTURE_KEYS.pop(device_id, None)
            messagebox.showerror("Bulk enrollment", f"Could not save devices: {exc}", parent=self); return
        self.refresh_all()
        self.refresh_identity_devices()
        self.refresh_dashboard_overview()
        self._write_summary(f"Bulk-enrolled {len(created)} demo devices.")
        messagebox.showinfo("Bulk enrollment complete",
            f"Created {len(created)} demo devices.\n\n" + "\n".join(created[:12]) +
            (f"\n…and {len(created)-12} more" if len(created) > 12 else ""), parent=self)

    def enroll_device_ui(self):
        device_id = self.new_device_id.get().strip().lower()
        owner = self.new_device_owner.get().strip()
        if not DEMO:
            messagebox.showerror("Enroll device", "GUI enrollment is currently available only in local demo mode.", parent=self); return
        if not re.fullmatch(r"[a-z0-9-]{1,64}", device_id):
            messagebox.showerror("Enroll device", "Device ID must use lowercase letters, digits and hyphens (1–64 chars).", parent=self); return
        if device_id in DEVICES:
            messagebox.showerror("Enroll device", "That device ID already exists.", parent=self); return
        if owner not in USERS:
            messagebox.showerror("Enroll device", "Select an existing owner. Create the user first if needed.", parent=self); return
        record = {"owner": owner, **{k: True for k in POSTURE_W}, "corporate_managed": bool(self.new_device_managed.get()), "last_report": time.time()}
        try:
            DEVICES[device_id] = record
            if not POSTURE_KEYS:
                POSTURE_KEYS.update(_demo_posture_keys())
            POSTURE_KEYS[device_id] = secrets.token_bytes(32)
            _persist_demo_device_keys()
            save_persisted_devices()
            audit(user="admin", device=device_id, resource="device-enrollment", decision="POLICY", reasons=[f"device enrolled for {owner}"])
        except Exception as exc:
            DEVICES.pop(device_id, None); POSTURE_KEYS.pop(device_id, None)
            messagebox.showerror("Enroll device", f"Could not enroll device: {exc}", parent=self); return
        self.new_device_id.set(""); self.device_var.set(device_id)
        fingerprint = hashlib.sha256(POSTURE_KEYS[device_id]).hexdigest()[:16]
        self.refresh_all(); self.refresh_identity_devices(); self.refresh_dashboard_overview()
        self._write_summary(f"Device {device_id} enrolled for {owner}; posture key fingerprint {fingerprint}.")
        messagebox.showinfo("Device enrolled", f"Device: {device_id}\nOwner: {owner}\nPosture key fingerprint: {fingerprint}\nDevice is now available in login, posture, resource access and audit views.", parent=self)

    def refresh_identity_devices(self):
        if not hasattr(self, "identity_tree"): return
        selected = self.identity_tree.selection(); dev_selected = self.device_tree.selection()
        user_rows = []
        for username, user in sorted(USERS.items()):
            digest = user.get("pw", {}).get("hash", "")
            user_rows.append((username, (username, (USER_PROFILE.get(username, {}).get("name", "-") + (" - " + USER_PROFILE[username]["title"] if username in USER_PROFILE else "")), user.get("role", "?"), (digest[:16] + "…") if digest else "not set", "Configured" if user.get("totp") else "Missing")))
        dev_rows = []
        for device_id, dev in sorted(DEVICES.items()):
            key = POSTURE_KEYS.get(device_id)
            fingerprint = hashlib.sha256(key).hexdigest()[:16] if key else "not provisioned"
            dev_rows.append((device_id, (device_id, dev.get("owner", "?"), posture(device_id), "Yes" if dev.get("corporate_managed") else "No", fingerprint)))
        if user_rows != getattr(self, "_identity_rows", None):
            self._identity_rows = user_rows
            for item in self.identity_tree.get_children(): self.identity_tree.delete(item)
            for iid, values in user_rows: self.identity_tree.insert("", "end", iid=iid, values=values)
            for key in selected:
                if self.identity_tree.exists(key): self.identity_tree.selection_set(key)
        if dev_rows != getattr(self, "_device_rows", None):
            self._device_rows = dev_rows
            for item in self.device_tree.get_children(): self.device_tree.delete(item)
            for iid, values in dev_rows: self.device_tree.insert("", "end", iid=iid, values=values)
            for key in dev_selected:
                if self.device_tree.exists(key): self.device_tree.selection_set(key)
        owners = sorted(USERS)
        self.device_owner_combo.configure(values=owners)
        if self.new_device_owner.get() not in owners:
            self.new_device_owner.set(owners[0] if owners else "")
        if not self.new_device_owner.get() and USERS: self.new_device_owner.set(sorted(USERS)[0])
        if hasattr(self, "user_combo"):
            self.user_combo.configure(values=sorted(USERS))
        if hasattr(self, "device_combo"):
            self.device_combo.configure(values=self._devices_of(self.user_var.get()))

    def show_identity_details(self, _event=None):
        sel = self.identity_tree.selection()
        if not sel: return
        username = sel[0]; user = USERS.get(username, {}); pw = user.get("pw", {})
        detail = (f"USER: {username}\nROLE: {user.get('role', '?')}\nPASSWORD HASH: {pw.get('hash', 'not set')}\nSALT: {pw.get('salt', 'not set')}\nTOTP SECRET: {user.get('totp', 'not set')}\n\nThe password itself is not stored. Hash and TOTP are sensitive lab material.")
        self._set_text(self.identity_detail, detail)

    def show_device_details(self, _event=None):
        sel = self.device_tree.selection()
        if not sel: return
        device_id = sel[0]; dev = DEVICES.get(device_id, {}); key = POSTURE_KEYS.get(device_id)
        detail = f"DEVICE: {device_id}\nOWNER: {dev.get('owner', '?')}\nPOSTURE SCORE: {posture(device_id)}\nKEY FINGERPRINT: {hashlib.sha256(key).hexdigest() if key else 'not provisioned'}\nPOSTURE: " + ", ".join(f"{k}={bool(dev.get(k))}" for k in POSTURE_W)
        self._set_text(self.identity_detail, detail)

    # ------------------------------------------------------------------ Roles & Access
    def _build_roles_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Roles & Access"); self.roles_tab = tab
        body.columnconfigure(0, weight=1); body.rowconfigure(2, weight=1)
        names = list(RESOURCES)
        matrix = Card(body, "Role-to-resource matrix", "a tick = the ROLE is allowed; device, location, time and MFA rules must still pass \u00b7 click a role for details")
        matrix.grid(row=0, column=0, sticky="ew", pady=(0, G))
        cols = [("role", "Role", 110, "w", False), ("people", "People", 70, "center", False)] + [(n, self._SEG_ABBR.get(n, n[:7]), 76, "center", True) for n in names]
        frame, self.matrix_tree = self._tree(matrix.body, cols, height=len(ROLES), compact=True)
        frame.pack(fill="x")
        info = Card(body, "Selected role"); info.grid(row=1, column=0, sticky="ew", pady=(0, G))
        frame, self.role_info = self._text(info.body, height=3)
        frame.pack(fill="x")
        self._set_text(self.role_info, "Select a role in the matrix to see who holds it and what it can request.")
        reqs = Card(body, "What each system demands", "besides the role \u00b7 full system names")
        reqs.grid(row=2, column=0, sticky="nsew")
        frame, self.req_tree = self._tree(reqs.body, (
            ("res", "System", 120, "w", False), ("desc", "What it is", 280, "w", True), ("score", "Min score", 90, "center", False),
            ("managed", "Managed only", 110, "center", False), ("hours", "Open hours", 110, "center", False),
            ("where", "Allowed from", 130, "center", False), ("mfa", "MFA max age", 110, "center", False)), height=4, compact=True)
        frame.pack(fill="both", expand=True)
        self.matrix_tree.bind("<<TreeviewSelect>>", self._show_role_info)
        self.refresh_roles()

    def refresh_roles(self):
        if not hasattr(self, "matrix_tree"): return
        count = Counter(u.get("role") for u in USERS.values())
        snap = (tuple(sorted(count.items())), tuple((r, v["min_posture"], v["managed"], tuple(v["hours"]), v["mfa_age"]) for r, v in RESOURCES.items()))
        if snap == getattr(self, "_roles_snap", None): return
        self._roles_snap = snap
        sel = self.matrix_tree.selection()
        for i in self.matrix_tree.get_children(): self.matrix_tree.delete(i)
        for role in ROLES:
            self.matrix_tree.insert("", "end", iid=role, values=(role, count.get(role, 0), *("\u2714" if role in RESOURCES[r]["roles"] else "\u2013" for r in RESOURCES)))
        for i in self.req_tree.get_children(): self.req_tree.delete(i)
        for r, v in RESOURCES.items():
            self.req_tree.insert("", "end", values=(r, v["desc"], v["min_posture"], "Yes" if v["managed"] else "No", _fmt_hours(v), " / ".join(v["locations"]), f"{v['mfa_age'] // 60} min"))
        for k in sel:
            if self.matrix_tree.exists(k): self.matrix_tree.selection_set(k)

    def _show_role_info(self, _event=None):
        sel = self.matrix_tree.selection()
        if not sel: return
        role = sel[0]
        people = ", ".join(f"{u} ({USER_PROFILE[u]['name']})" if u in USER_PROFILE else u for u, v in sorted(USERS.items()) if v.get("role") == role)
        opens = ", ".join(r for r, v in RESOURCES.items() if role in v["roles"])
        text = f"ROLE: {role}\n{ROLES[role]}\nCAN REQUEST: {opens}\nPEOPLE: {people or 'nobody yet'}"
        self.role_info.configure(state="normal"); self.role_info.delete("1.0", "end"); self.role_info.insert("1.0", text); self.role_info.configure(state="disabled")

    # ------------------------------------------------------------------ Resource Access
    @staticmethod
    def _req_short(resource):
        r = RESOURCES[resource]
        return (f"Score {r['min_posture']}+ \u00b7 " + ("Managed device" if r["managed"] else "Any device") + f" \u00b7 {_fmt_hours(r)} \u00b7 "
                + " / ".join(r["locations"]) + f" \u00b7 MFA \u2264 {r['mfa_age'] // 60} min")

    def _place_res_cards(self, cols):
        """Lay the system cards out in 2-4 columns depending on the width available."""
        if cols == self._res_cols: return
        self._res_cols = cols
        grid, G, n = self._res_grid, self.GAP, len(self._res_cards)
        rows = (n + cols - 1) // cols
        for c in range(6): grid.columnconfigure(c, weight=0, uniform="")
        for r in range(n): grid.rowconfigure(r, weight=0)
        for c in range(cols): grid.columnconfigure(c, weight=1, uniform="rescard")
        for r in range(rows): grid.rowconfigure(r, weight=1)
        for i, card in enumerate(self._res_cards):
            r, c = divmod(i, cols)
            card.grid(row=r, column=c, sticky="nsew", padx=(0 if c == 0 else G // 2, 0 if c == cols - 1 else G // 2),
                      pady=(0 if r == 0 else G // 2, 0 if r == rows - 1 else G // 2))

    def _build_access_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Resource Access"); self.access_tab = tab
        body.columnconfigure(0, weight=7, uniform="acc"); body.columnconfigure(1, weight=3, uniform="acc")
        body.rowconfigure(1, weight=1)
        head = ttk.Frame(body); head.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.access_who = tk.StringVar(value="Not signed in. Go to Overview, pick a user and log in.")
        self._wrap_label(ttk.Label(head, textvariable=self.access_who, style="PageStrong.TLabel")).pack(fill="x")
        self._wrap_label(ttk.Label(head, style="Sub.TLabel", text="Pick a system. Each click is a fresh policy check of identity, device health, location, time and MFA. What you can open is different for each employee.")).pack(fill="x", pady=(2, 0))

        grid = ttk.Frame(body); grid.grid(row=1, column=0, sticky="nsew", padx=(0, G // 2))
        self.res_status = {}; self._res_cards = []; self._res_cols = 0; self._res_grid = grid
        for i, r in enumerate(RESOURCES):
            card = Card(grid, padding=11)
            ttk.Button(card.body, text="Open", style="Action.TButton", command=lambda x=r: self.request_access(x)).pack(side="bottom", fill="x", pady=(8, 0))
            top = ttk.Frame(card.body, style="Card.TFrame"); top.pack(fill="x")
            ttk.Label(top, text=r, style="CardTitle.TLabel").pack(side="left")
            lab = ttk.Label(top, text="", style="CardStrong.TLabel", font=("Segoe UI", 9, "bold")); lab.pack(side="right"); self.res_status[r] = lab
            self._lbl(card.body, RESOURCES[r]["desc"], "card", wrap=True).pack(fill="x", pady=(2, 0))
            self._lbl(card.body, self._req_short(r), "hint", wrap=True).pack(fill="x", pady=(4, 0))
            self._res_cards.append(card)
        self._place_res_cards(4)
        grid.bind("<Configure>", lambda e: self._place_res_cards(max(2, min(4, e.width // 205))), add="+")

        side = ttk.Frame(body); side.grid(row=1, column=1, sticky="nsew", padx=(G // 2, 0))
        side.columnconfigure(0, weight=1); side.rowconfigure(1, weight=1); side.rowconfigure(2, weight=1)
        step = Card(side, "Step-up MFA")
        step.grid(row=0, column=0, sticky="ew", pady=(0, G))
        self.step_otp = tk.StringVar()
        row = ttk.Frame(step.body, style="Card.TFrame"); row.pack(fill="x")
        row.columnconfigure(0, weight=1, uniform="su"); row.columnconfigure(1, weight=1, uniform="su")
        ttk.Entry(row, textvariable=self.step_otp, width=10).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Button(row, text="Generate OTP", command=self.generate_step_otp).grid(row=1, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(row, text="Verify", style="Action.TButton", command=self.do_stepup).grid(row=1, column=1, sticky="ew", padx=(4, 0))

        res = Card(side, "Result in plain English"); res.grid(row=1, column=0, sticky="nsew", pady=(0, G))
        frame, self.access_log = self._text(res.body, height=4)
        frame.pack(fill="both", expand=True)
        for tag, color, bold in (("ok", "#0a7d33", True), ("warn", "#b26a00", True), ("bad", "#c62828", True), ("fix", "#0b5cad", False), ("dim", "#667085", False)):
            self.access_log.tag_configure(tag, foreground=color, font=("Segoe UI", 10, "bold") if bold else ("Segoe UI", 10))

        prev = Card(side, "Preview of what you opened"); prev.grid(row=2, column=0, sticky="nsew")
        self.preview_title = tk.StringVar(value="Nothing opened yet.")
        self.preview_note = tk.StringVar(value="Open a system you are allowed to use and its content appears here.")
        ttk.Label(prev.body, textvariable=self.preview_title, style="CardStrong.TLabel").pack(anchor="w")
        self._wrap_label(ttk.Label(prev.body, textvariable=self.preview_note, style="CardHint.TLabel")).pack(fill="x", pady=(0, 8))
        frame, self.preview_tree = self._tree(prev.body, (("a", "", 300, "w", True),), height=3)
        frame.pack(fill="both", expand=True)

    def refresh_access_cards(self):
        if not hasattr(self, "res_status"): return
        if self.engine.session:
            _, s = self.engine.session
            u = USERS.get(s["user"], {}); role = u.get("role", "?"); prof = USER_PROFILE.get(s["user"], {})
            self.access_who.set(f"Signed in as {prof.get('name', s['user'])} ({s['user']})  |  role: {role}  |  device: {s['device']} (health {posture(s['device']) if s['device'] in DEVICES else 0}/100)  |  from: {s['location']}")
            for r, lab in self.res_status.items():
                if rbac_allows(s["user"], r): lab.configure(text="\u2714 allowed", foreground="#0a7d33")
                else: lab.configure(text="\u2716 blocked", foreground="#c62828")
        else:
            self.access_who.set("Not signed in. Go to Overview, pick a user and log in.")
            for lab in self.res_status.values(): lab.configure(text="sign in", foreground="#667085")

    def _show_preview(self, preview=None, why=""):
        for i in self.preview_tree.get_children(): self.preview_tree.delete(i)
        if not preview:
            self.preview_title.set("Nothing to show"); self.preview_note.set(why or "Access was not granted, so no content is shown.")
            self.preview_tree.configure(columns=("a",)); self.preview_tree.heading("a", text=""); return
        cols = tuple(f"c{i}" for i in range(len(preview["columns"])))
        self.preview_tree.configure(columns=cols)
        for c, name in zip(cols, preview["columns"]):
            self.preview_tree.heading(c, text=name); self.preview_tree.column(c, width=max(80, 520 // len(cols)), anchor="w")
        for row in preview["rows"]: self.preview_tree.insert("", "end", values=row)
        self.preview_title.set(preview["title"]); self.preview_note.set(preview["summary"] + "  (demo data)")

    def _show_access_result(self, resource, result):
        verdict, headline, lines, tips = explain_decision(resource, result)
        tag = {"ALLOW": "ok", "STEPUP": "warn", "DENY": "bad"}[verdict]
        pieces = [(f"{time.strftime('%H:%M:%S')}  {headline}\n", tag)]
        pieces += [(f"   \u2022 {x}\n", None) for x in lines]
        pieces += [(f"   How to fix: {x}\n", "fix") for x in tips]
        pieces.append(("\n", None))
        off = 0
        self.access_log.configure(state="normal")
        for text, t in pieces:
            self.access_log.insert(f"1.0+{off}c", text, t or ()); off += len(text)
        self.access_log.configure(state="disabled")
        if verdict == "ALLOW": self._show_preview(result.get("preview"))
        else: self._show_preview(None, "Access was not granted, so no content is shown.")

    # ------------------------------------------------------------------ Device Posture
    def _build_posture_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Device Posture"); self.posture_tab = tab
        body.columnconfigure(0, weight=3, uniform="pos"); body.columnconfigure(1, weight=2, uniform="pos")
        body.rowconfigure(2, weight=1)
        guide = self._guide(body, "Device posture is a 0-100 health score for the laptop or phone someone logs in from. Weak devices are refused even with the right password.", (
            "WHAT: a health check of the laptop or phone someone logs in from. Five checks add up to a score out of 100: "
            + ", ".join(f"{POSTURE_LABELS[k]} +{w}" for k, w in POSTURE_W.items())
            + ". Every system needs a minimum score (for example hr-db 70, admin-panel 90), so a weak device is refused even with the right password.\n\n"
            "IS IT AUTOMATIC? In a real company a small agent on each device measures these settings and reports them every few minutes. "
            "This lab has no real devices, so the agent is SIMULATED: the switch below re-sends every device's status once a minute. "
            "You can still tick or untick a check to pretend a device got a weakness or a fix, and watch access change immediately. "
            + ("A report older than %d minutes counts as 'stale' and scores 0.\n\n" % (POSTURE_TTL // 60) if POSTURE_TTL > 0 else
               "In this demo reports never expire; in production a report older than ZTNA_POSTURE_TTL (default 5 minutes) counts as 'stale' and scores 0.\n\n")
            + "TRY IT: pick a device on the left, untick 'Antivirus running' and 'Disk is encrypted', then open hr-db on the Resource Access tab."))
        guide.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))

        bar = ttk.Frame(body); bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.agent_on = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Simulated posture agent: auto-report every 60 s", variable=self.agent_on, style="Page.TCheckbutton").pack(side="left")
        self.agent_status = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.agent_status, style="Sub.TLabel").pack(side="left", padx=14)
        ttk.Button(bar, text="Select my device", command=self.posture_select_mine).pack(side="right")

        left = Card(body, "Devices", "select one to inspect and change"); left.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2))
        frame, self.posture_tree = self._tree(left.body, (
            ("device", "Device", 150, "w", True), ("owner", "Owner", 90, "w", False), ("score", "Score", 70, "w", False),
            ("status", "Health", 110, "w", False), ("report", "Last report", 100, "w", False)), height=7)
        for tag, color in (("good", "#0a7d33"), ("fair", "#b26a00"), ("bad", "#c62828"), ("stale", "#667085")):
            self.posture_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)
        self.posture_tree.bind("<<TreeviewSelect>>", lambda _e: self.refresh_posture(force=True))

        right = Card(body, "Selected device"); right.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0))
        rb = right.body
        self.pd_title = tk.StringVar(value="Select a device on the left")
        self.pd_score = tk.StringVar(value="")
        ttk.Label(rb, textvariable=self.pd_title, style="CardStrong.TLabel").pack(anchor="w")
        ttk.Label(rb, textvariable=self.pd_score, style="Score.TLabel").pack(anchor="w", pady=(2, 4))
        self.pd_bar = ttk.Progressbar(rb, maximum=100); self.pd_bar.pack(fill="x", pady=(0, 10))
        self.posture_vars = {}
        for field, w in POSTURE_W.items():
            var = tk.BooleanVar(value=False); self.posture_vars[field] = var
            ttk.Checkbutton(rb, text=f"{POSTURE_LABELS[field]}   (+{w} points)", variable=var,
                            command=lambda f=field, v=var: self.set_posture(self.posture_sel(), f, v.get())).pack(anchor="w", pady=2)
        btns = ttk.Frame(rb, style="Card.TFrame"); btns.pack(fill="x", pady=(10, 0))
        btns.columnconfigure(0, weight=1, uniform="pb"); btns.columnconfigure(1, weight=1, uniform="pb")
        ttk.Button(btns, text="Make healthy", command=lambda: self.posture_preset("healthy")).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(btns, text="Scan for vulnerabilities", command=self.posture_scan).grid(row=0, column=1, sticky="ew", padx=(4, 0))
        ttk.Button(btns, text="Send report now", style="Action.TButton", command=self.posture_report_now).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Separator(rb).pack(fill="x", pady=12)
        ttk.Label(rb, text="What can this device open?", style="CardStrong.TLabel").pack(anchor="w")
        self._lbl(rb, "Device rules only; role, hours and location also apply.", "hint", wrap=True).pack(fill="x", pady=(0, 6))
        frame, self.pd_caps = self._text(rb, height=5)
        self.pd_caps.tag_configure("ok", foreground="#0a7d33"); self.pd_caps.tag_configure("bad", foreground="#c62828")
        frame.pack(fill="both", expand=True)
        self._pd_loaded = None
        self.refresh_posture(force=True)
        kids = self.posture_tree.get_children()
        if kids:
            self.posture_tree.selection_set("laptop-alice" if "laptop-alice" in kids else kids[0])
            self.refresh_posture(force=True)

    # ------------------------------------------------------------------ Policy
    def _build_policy_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Policy"); self.policy_tab = tab
        body.columnconfigure(0, weight=1, uniform="pol"); body.columnconfigure(1, weight=1, uniform="pol")
        guide = self._guide(body, "A policy is the rulebook for ONE system: even with an allowed role, every rule must pass at that moment.", (
            "A POLICY is the rulebook for ONE system. Even when a person's role is allowed, they only get in if every rule below passes at that moment.\n\n"
            "HOW TO USE: 1) pick a system   2) change the rules (or press a quick preset)   3) press Save. It applies to the very next request; nobody has to log in again. "
            "Blocked requests are written to the audit log."))
        guide.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))

        pick = Card(body, padding=(14, 10)); pick.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, G))
        ttk.Label(pick.body, text="System", style="CardStrong.TLabel").pack(side="left")
        self.policy_resource = tk.StringVar(value="wiki")
        self.policy_combo = ttk.Combobox(pick.body, textvariable=self.policy_resource, values=list(RESOURCES), state="readonly", width=18)
        self.policy_combo.pack(side="left", padx=10)
        self.policy_combo.bind("<<ComboboxSelected>>", lambda _e: self.load_policy_fields())
        self.policy_desc = tk.StringVar(); ttk.Label(pick.body, textvariable=self.policy_desc, style="CardHint.TLabel").pack(side="left", padx=8)

        rules = Card(body, "Rules you can change"); rules.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2), pady=(0, G))
        rb = rules.body; rb.columnconfigure(2, weight=1)
        self.pv = {k: tk.StringVar() for k in ("mp", "lo", "hi", "mfa")}; self.pv_managed = tk.BooleanVar()
        rows = (("Minimum device health score", "mp", 0, 100, 1, "0-100. Weaker devices are refused. 40 = basic, 70 = good, 90 = excellent."),
                ("Open from hour", "lo", 0, 24, 1, "24-hour clock. 0 to 24 means all day; 9 to 18 means 09:00-18:00."),
                ("Open until hour", "hi", 0, 24, 1, ""),
                ("Re-verify identity (MFA) every (minutes)", "mfa", 0, 1440, 1, "After this long, the person must enter a fresh code. Shorter = safer."))
        for i, (label, key, lo, hi, inc, hint) in enumerate(rows):
            ttk.Label(rb, text=label, style="Card.TLabel").grid(row=i * 2, column=0, sticky="w", pady=(6, 0), padx=(0, 12))
            ttk.Spinbox(rb, from_=lo, to=hi, increment=inc, textvariable=self.pv[key], width=8).grid(row=i * 2, column=1, pady=(6, 0), sticky="w")
            if hint:
                self._lbl(rb, hint, "hint", wrap=True).grid(row=i * 2 + 1, column=0, columnspan=3, sticky="ew")
        ttk.Checkbutton(rb, text="Only company-managed devices (no personal laptops or phones)", variable=self.pv_managed).grid(row=8, column=0, columnspan=3, sticky="w", pady=(12, 0))
        self.policy_fixed = tk.StringVar()
        self._wrap_label(ttk.Label(rb, textvariable=self.policy_fixed, style="CardHint.TLabel")).grid(row=9, column=0, columnspan=3, sticky="ew", pady=(8, 0))

        summary = Card(body, "What this means in plain English"); summary.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0), pady=(0, G))
        self.policy_summary = tk.StringVar(); self.policy_state = tk.StringVar()
        self._wrap_label(ttk.Label(summary.body, textvariable=self.policy_summary, style="Card.TLabel")).pack(fill="x")
        ttk.Separator(summary.body).pack(fill="x", pady=12)
        ttk.Label(summary.body, textvariable=self.policy_state, style="CardStrong.TLabel").pack(anchor="w")
        for v in (*self.pv.values(), self.pv_managed): v.trace_add("write", lambda *_: self._policy_update_summary())

        actions = Card(body, padding=(14, 10)); actions.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, G))
        ttk.Label(actions.body, text="Quick presets (fill the form, then Save):", style="Card.TLabel").pack(side="left", padx=(0, 6))
        for text, kind in (("Relaxed", "relaxed"), ("Standard", "standard"), ("Strict", "strict"), ("Restore default", "default")):
            ttk.Button(actions.body, text=text, command=lambda k=kind: self.policy_preset(k)).pack(side="left", padx=3)
        ttk.Button(actions.body, text="Save policy", style="Action.TButton", command=self.save_policy_fields).pack(side="right")
        ttk.Button(actions.body, text="Undo unsaved changes", command=self.load_policy_fields).pack(side="right", padx=8)

        sim = Card(body, "Test the hours rule", "pretend it is a different time"); sim.grid(row=4, column=0, columnspan=2, sticky="ew")
        row = ttk.Frame(sim.body, style="Card.TFrame"); row.pack(fill="x")
        self.hour_var = tk.StringVar(value="")
        ttk.Label(row, text="Hour (0-23)", style="Card.TLabel").pack(side="left", padx=(0, 8))
        ttk.Spinbox(row, from_=0, to=23, textvariable=self.hour_var, width=6).pack(side="left")
        ttk.Button(row, text="Set pretend hour", command=self.apply_hour).pack(side="left", padx=8)
        ttk.Button(row, text="Use the real clock", command=self.use_real_clock).pack(side="left")
        self.clock_text = tk.StringVar(); ttk.Label(row, textvariable=self.clock_text, style="CardStrong.TLabel").pack(side="left", padx=16)
        self._lbl(sim.body, "Example: set 22, then try hr-db on Resource Access (it is open 09-18) and read the explanation.", "hint", wrap=True).pack(fill="x", pady=(8, 0))
        self._policy_loading = False
        self.load_policy_fields()

    # ------------------------------------------------------------------ Security & Segmentation
    def _build_security_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Security & Segmentation"); self.security_tab = tab
        body.columnconfigure(0, weight=1, uniform="sec"); body.columnconfigure(1, weight=1, uniform="sec")
        body.rowconfigure(2, weight=1)
        self._wrap_label(ttk.Label(body, style="Sub.TLabel", text="Which network segments each person can reach, and what the system flagged as suspicious.")).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, G))
        kp = Card(body, padding=(14, 10)); kp.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, G))
        self.sec_kpis = tk.StringVar()
        self._wrap_label(ttk.Label(kp.body, textvariable=self.sec_kpis, style="CardStrong.TLabel")).pack(fill="x")

        left = Card(body, "RBAC + micro-segmentation", "\u2714 = role and network segment both allow it")
        left.grid(row=2, column=0, sticky="nsew", padx=(0, G // 2))
        frame, self.seg_text = self._text(left.body, mono=True, wrap="none", hscroll=True, height=12)
        frame.pack(fill="both", expand=True)

        right = Card(body, "Security alerts", "suspicious things that need a human decision")
        right.grid(row=2, column=1, sticky="nsew", padx=(G // 2, 0))
        rb = right.body
        self._lbl(rb, ("Normal blocked requests (wrong role, outside hours...) are NOT alerts: they are simply recorded in the audit log. "
                       "An alert means something looked like an attack. Choose what it was: 'Reviewed' (looked, nothing to do), 'False alarm' (harmless), "
                       "or 'Confirm incident' (real problem: the user is signed out everywhere). Low/medium alerts can be cleared in bulk; high-severity ones need your individual decision."),
                  "hint", wrap=True).pack(fill="x", pady=(0, 8))
        top = ttk.Frame(rb, style="Card.TFrame"); top.pack(fill="x", pady=(0, 6))
        self.show_handled = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Also show alerts already handled", variable=self.show_handled, command=lambda: self.refresh_security(force=True)).pack(side="left")
        ttk.Button(top, text="Clear all low/medium", command=self.ack_alerts).pack(side="right")
        frame, self.alert_tree = self._tree(rb, (
            ("time", "Time", 70, "w", False), ("sev", "Severity", 80, "w", False), ("what", "What happened", 200, "w", True),
            ("who", "Who", 90, "w", False), ("status", "Status", 120, "w", False)), height=5)
        for tag, color in (("HIGH", "#c62828"), ("MEDIUM", "#b26a00"), ("LOW", "#667085"), ("done", "#667085")):
            self.alert_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)
        self.alert_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_alert_detail())
        frame, self.alert_text = self._text(rb, height=5); frame.pack(fill="x", pady=(8, 0))
        b = ttk.Frame(rb, style="Card.TFrame"); b.pack(fill="x", pady=(8, 0))
        ttk.Button(b, text="Reviewed", command=lambda: self.handle_selected_alerts(1)).pack(side="left", padx=(0, 6))
        ttk.Button(b, text="False alarm", command=lambda: self.handle_selected_alerts(2)).pack(side="left", padx=(0, 6))
        ttk.Button(b, text="Confirm incident + sign user out", style="Action.TButton", command=lambda: self.handle_selected_alerts(3)).pack(side="left")
        self.refresh_security(force=True)

    _SEG_ABBR = {"wiki": "wiki", "hr-db": "hr-db", "admin-panel": "admin", "source-code": "code", "ci-cd": "cicd", "crm": "crm",
                 "finance-ledger": "fin", "support-desk": "supp", "legal-vault": "legal", "siem-console": "siem", "exec-reports": "exec"}

    def refresh_security(self, force=False):
        t = telemetry_summary()
        self.sec_kpis.set(f"Last 60 min: {t['events']} decisions   ALLOW {t['allow']}   STEP-UP {t['stepup']}   DENY {t['deny']}   Avg risk {t['avg_risk']}   Alerts needing a decision: {t['alerts']}")
        snap = (tuple((u, v.get("role")) for u, v in sorted(USERS.items())), tuple(RESOURCES))
        if force or snap != getattr(self, "_seg_snap", None):
            self._seg_snap = snap
            ab = [self._SEG_ABBR.get(r, r[:5]) for r in RESOURCES]
            lines = ["USER     ROLE       " + " ".join(f"{a:<5}" for a in ab), "-" * (19 + 6 * len(ab))]
            for u, v in sorted(USERS.items()):
                lines.append(f"{u:<8} {v.get('role', '?'):<10} " + " ".join(f"{_TICK if (rbac_allows(u, r) and segment_allows(u, r)) else _CROSS:<5}" for r in RESOURCES))
            lines += ["", "Segments each role can reach:"]
            for role in ROLES:
                lines.append(f"  {role:<10} " + ", ".join(sorted(SEGMENT_ALLOW.get(role, set()))))
            lines += ["", "Lateral movement: a role can never reach a segment outside its own allow-list.", "A permitted request must still pass device, hours, location, MFA and risk checks."]
            self.seg_text.configure(state="normal"); self.seg_text.delete("1.0", "end"); self.seg_text.insert("1.0", "\n".join(lines)); self.seg_text.configure(state="disabled")
        alerts = [a for a in recent_alerts() if self.show_handled.get() or a.get("status", 0) == 0]
        asnap = tuple((a["id"], a["status"]) for a in alerts)
        if force or asnap != getattr(self, "_alert_snap", None):
            self._alert_snap = asnap; self._alerts_by_id = {str(a["id"]): a for a in alerts}
            sel = self.alert_tree.selection()
            for i in self.alert_tree.get_children(): self.alert_tree.delete(i)
            for a in alerts:
                title = describe_alert(a)[0]
                self.alert_tree.insert("", "end", iid=str(a["id"]), tags=(a["severity"] if a["status"] == 0 else "done",),
                                       values=(datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S"), a["severity"], title, a.get("user") or "-", ALERT_STATUS.get(a["status"], "?")))
            for k in sel:
                if self.alert_tree.exists(k): self.alert_tree.selection_set(k)
            self._show_alert_detail()

    def _show_alert_detail(self):
        sel = self.alert_tree.selection() if hasattr(self, "alert_tree") else ()
        a = getattr(self, "_alerts_by_id", {}).get(sel[0]) if sel else None
        if a:
            title, why, advice = describe_alert(a)
            text = f"{title}\nWhat it means: {why}\nDetails: {a.get('details') or '-'}  (user: {a.get('user') or '-'}, device: {a.get('device') or '-'})\nWhat to do: {advice}"
        else:
            text = "Select an alert to see what it means and what to do. No alerts needing a decision." if not getattr(self, "_alerts_by_id", None) else "Select an alert to see what it means and what to do."
        self.alert_text.configure(state="normal"); self.alert_text.delete("1.0", "end"); self.alert_text.insert("1.0", text); self.alert_text.configure(state="disabled")

    def handle_selected_alerts(self, status):
        sel = [i for i in self.alert_tree.selection() if self._alerts_by_id.get(i, {}).get("status", 1) == 0]
        if not sel:
            messagebox.showinfo("Security alerts", "Select one or more open alerts in the list first."); return
        label = ALERT_STATUS[status]; users = sorted({self._alerts_by_id[i].get("user") for i in sel if self._alerts_by_id[i].get("user")})
        if status == 3 and users and not messagebox.askyesno("Confirm incident", f"Sign out everywhere: {', '.join(users)}?\nThey must log in again."): return
        ended = 0
        if status == 3:
            for u in users:
                n_u, err_u = revoke_user_sessions_report(u); ended += n_u
                if err_u: messagebox.showwarning("Confirm incident", f"Sessions for {u} were ended, but the revocation could not be saved to the database ({err_u}).")
        acknowledge_alerts(sel, status)
        for i in sel:
            a = self._alerts_by_id[i]
            try: audit(user="admin", device=a.get("device"), resource="alert-review", decision="POLICY", reasons=[f"alert {a['kind']} for {a.get('user') or '-'} marked '{label}'" + (f"; {ended} session(s) ended" if status == 3 else "")])
            except (AuditFull, AuditTamper): pass
        self._write_summary(f"{len(sel)} alert(s) marked '{label}'" + (f"; {ended} session(s) ended" if status == 3 else ""))
        self.refresh_all()

    def ack_alerts(self):
        acknowledge_alerts(None, 1, include_high=False); self.refresh_security(force=True)
        self._write_summary("Low/medium alerts cleared. High-severity alerts still need an individual decision.")

    # ------------------------------------------------------------------ Audit & Integrity
    def _build_audit_tab(self):
        G = self.GAP
        tab, body = self._new_tab("Audit & Integrity"); self.audit_tab = tab
        body.columnconfigure(0, weight=1); body.rowconfigure(2, weight=1)
        guide = self._guide(body, "Every decision is written to a tamper-evident log: each line is sealed to the one before it, so any edit, deletion or insertion breaks the chain.", (
            "THE LOG: every decision (who, what, allowed or blocked, and why) is written to a log nobody can quietly change. Each line carries a cryptographic 'seal' that depends on the line before it, "
            "and separate anchor files remember how many lines exist and the latest seal. Edit, delete or insert a line and the seals stop matching.\n\n"
            "VERIFY re-checks every seal and both anchors (this tab also does it automatically every minute). If it reports a problem, treat it as a security event and use the numbered steps below. "
            "The app also stops all new actions by itself if it notices the log file shrank or vanished while running."))
        guide.grid(row=0, column=0, sticky="ew", pady=(0, G))

        status = Card(body, "Integrity status"); status.grid(row=1, column=0, sticky="ew", pady=(0, G))
        sb = status.body
        top = ttk.Frame(sb, style="Card.TFrame"); top.pack(fill="x")
        self.audit_banner = tk.StringVar(value="\u25cf Not checked yet - press 'Verify now'")
        self.audit_banner_lbl = ttk.Label(top, textvariable=self.audit_banner, style="CardBanner.TLabel"); self.audit_banner_lbl.pack(side="left")
        self.audit_auto = tk.BooleanVar(value=True); self._audit_ok_last = None; self._audit_auto_at = time.time()
        ttk.Checkbutton(top, text="Auto-verify every minute", variable=self.audit_auto).pack(side="right")
        self.audit_detail = tk.StringVar(value="")
        self._wrap_label(ttk.Label(sb, textvariable=self.audit_detail, style="Card.TLabel")).pack(fill="x", pady=(6, 0))
        row = ttk.Frame(sb, style="Card.TFrame"); row.pack(fill="x", pady=(12, 0))
        ttk.Button(row, text="1  Verify now", style="Action.TButton", command=self.verify_audit).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="2  Save evidence copy", command=self.export_evidence_ui).pack(side="left", padx=6)
        ttk.Button(row, text="3  Safe repair", command=self.repair_audit_ui).pack(side="left", padx=6)
        ttk.Button(row, text="4  Archive damaged log + start fresh", command=self.reset_audit_ui).pack(side="left", padx=6)
        self._lbl(sb, ("1 Verify: checks the whole chain (safe, changes nothing).   2 Evidence copy: copies every audit file plus a report into a new folder - do this first if anything is wrong.   "
                       "3 Safe repair: fixes only the harmless case where an anchor lags exactly one entry behind a valid log (e.g. a crash); it refuses anything that looks like tampering.   "
                       "4 Archive and start fresh: demo mode only; moves the damaged files to an archive folder (nothing is deleted) and begins a new chain. In production, restore from backup and investigate instead."),
                  "hint", wrap=True).pack(fill="x", pady=(10, 0))

        log = Card(body, "Audit log"); log.grid(row=2, column=0, sticky="nsew")
        lb = log.body
        bar = ttk.Frame(lb, style="Card.TFrame"); bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Show", style="Card.TLabel").pack(side="left")
        self.audit_filter = tk.StringVar(value="Everything")
        cb = ttk.Combobox(bar, textvariable=self.audit_filter, state="readonly", width=30, values=("Everything", "Blocked or needs MFA", "Sign-ins and sign-outs", "Admin and policy changes", "Resource access only"))
        cb.pack(side="left", padx=8); cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh_audit(force=True))
        self.audit_count = tk.StringVar(); ttk.Label(bar, textvariable=self.audit_count, style="CardHint.TLabel").pack(side="left", padx=8)
        ttk.Button(bar, text="Refresh", style="Link.TButton", command=lambda: self.refresh_audit(force=True)).pack(side="right")
        frame, self.audit_tree = self._tree(lb, (("time", "Time", 80, "w", False), ("result", "Result", 120, "w", False), ("what", "What happened", 600, "w", True)), height=5)
        for tag, color in (("ok", "#0a7d33"), ("bad", "#c62828"), ("warn", "#b26a00"), ("info", "#0b5cad"), ("dim", "#667085")):
            self.audit_tree.tag_configure(tag, foreground=color)
        frame.pack(fill="both", expand=True)
        self.audit_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_audit_detail())
        frame, self.audit_text = self._text(lb, height=4); frame.pack(fill="x", pady=(8, 0))
        self._audit_by_iid = {}
        try: self.verify_audit()
        except Exception: pass

    def generate_otp(self):
        if not DEMO_OTP: return
        user = self.user_var.get().strip()
        if user in USERS:
            code = self.engine.demo_otp(user)
            self.otp_var.set(code)
            self._write_summary(f"Demo TOTP generated for {user}: {code}")

    def generate_step_otp(self):
        if DEMO_OTP and self.engine.user:
            self.step_otp.set(self.engine.demo_otp(self.engine.user))

    def do_login(self):
        ok, msg = self.engine.login(self.user_var.get(), self.pass_var.get(), self.otp_var.get(), self.device_var.get(), self.location_var.get())
        self._write_summary(msg)
        if not ok:
            messagebox.showerror("Login", msg)
        self.refresh_all()

    def do_stepup(self):
        ok, msg = self.engine.stepup(self.step_otp.get())
        self._write_access(msg)
        if not ok: messagebox.showerror("Step-up", msg)
        self.refresh_all()

    def do_logout(self):
        self.engine.logout(); self._write_summary("Logged out")
        self.refresh_all()

    def request_access(self, resource):
        result = self.engine.access(resource)
        self._show_access_result(resource, result)
        self.refresh_all()
        if result["decision"] == "STEPUP":
            self.nb.select(self.access_tab)

    def refresh_clock(self):
        if not hasattr(self, "clock_text"): return
        self.clock_text.set(f"Policy clock now: {now_hour():02d}:00 " + ("(PRETEND hour)" if SIM["hour"] is not None else "(real clock)"))

    def apply_hour(self):
        raw = self.hour_var.get().strip()
        try:
            hour = None if raw == "" else int(raw)
            if hour is not None and not 0 <= hour <= 23: raise ValueError
        except ValueError:
            messagebox.showerror("Time simulation", "Enter a whole number from 0 to 23.")
            return
        SIM["hour"] = hour
        audit(user="admin", device=None, resource="sim", decision="POLICY", reasons=[f"hour={hour}"])
        self.refresh_all()

    def use_real_clock(self):
        self.hour_var.set(""); self.apply_hour()

    def _policy_read_form(self):
        """Form -> policy dict, with friendly errors."""
        try:
            mp, lo, hi = int(self.pv["mp"].get()), int(self.pv["lo"].get()), int(self.pv["hi"].get())
            mfa = float(self.pv["mfa"].get())
        except (ValueError, tk.TclError):
            raise ValueError("Please enter whole numbers in the number boxes.")
        if lo == hi: raise ValueError("'Open from' and 'Open until' cannot be the same hour (use 0 and 24 for all day).")
        data = {"min_posture": mp, "mfa_age": int(round(mfa * 60)), "hours": [lo, hi], "managed": bool(self.pv_managed.get())}
        try: validate_policy_data({self.policy_resource.get(): data})
        except ValueError as exc: raise ValueError(f"Value out of range ({exc}). Score is 0-100, hours are 0-24, minutes cannot be negative.")
        return data

    def _policy_update_summary(self):
        if getattr(self, "_policy_loading", False) or not hasattr(self, "policy_summary"): return
        rname = self.policy_resource.get(); r = RESOURCES[rname]
        try: d = self._policy_read_form()
        except ValueError as exc:
            self.policy_summary.set(str(exc)); self.policy_state.set("Cannot save yet"); return
        people = [u for u, v in sorted(USERS.items()) if v.get("role") in r["roles"]]
        self.policy_summary.set(
            f"People with the role {', '.join(r['roles'])} ({len(people)} people) can open {rname} only:\n"
            f"  - from: {' or '.join(r['locations'])}\n  - during: {_fmt_hours({'hours': d['hours']})}\n"
            f"  - on: {'a company-managed device' if d['managed'] else 'any enrolled device'}\n"
            f"  - with a device health score of at least {d['min_posture']}/100\n"
            f"  - if they confirmed their identity (MFA) in the last {d['mfa_age'] / 60:g} minutes\n"
            "Anything else is blocked and written to the audit log.")
        saved = {k: r[k] for k in POLICY_KEYS}
        same = saved["min_posture"] == d["min_posture"] and saved["mfa_age"] == d["mfa_age"] and list(saved["hours"]) == d["hours"] and saved["managed"] == d["managed"]
        self.policy_state.set("Saved - this is exactly what is enforced now." if same else "Unsaved changes - press 'Save policy' to enforce them.")

    def load_policy_fields(self):
        rname = self.policy_resource.get(); r = RESOURCES[rname]
        self._policy_fill(r)
        self.policy_desc.set(r["desc"])
        self.policy_fixed.set(f"Fixed by design (not editable here): roles allowed = {', '.join(r['roles'])}; allowed from = {' or '.join(r['locations'])}.")
        self._policy_update_summary()

    def _policy_fill(self, d):
        self._policy_loading = True
        try:
            self.pv["mp"].set(str(d["min_posture"])); self.pv["lo"].set(str(d["hours"][0])); self.pv["hi"].set(str(d["hours"][1]))
            self.pv["mfa"].set(f"{d['mfa_age'] / 60:g}"); self.pv_managed.set(bool(d["managed"]))
        finally:
            self._policy_loading = False
        self._policy_update_summary()

    def policy_preset(self, kind):
        base = {"relaxed": {"min_posture": 40, "mfa_age": 3600, "hours": [0, 24], "managed": False},
                "standard": {"min_posture": 70, "mfa_age": 900, "hours": [9, 18], "managed": True},
                "strict": {"min_posture": 90, "mfa_age": 120, "hours": [9, 18], "managed": True},
                "default": POLICY_DEFAULTS[self.policy_resource.get()]}[kind]
        self._policy_fill(base)

    def save_policy_fields(self):
        rname = self.policy_resource.get(); r = RESOURCES[rname]
        try: data = self._policy_read_form()
        except ValueError as e:
            messagebox.showerror("Policy", str(e)); return
        r.update(data); save_policy()
        db_exec("INSERT INTO policy_changes(ts,actor,resource,policy_json) VALUES(?,?,?,?)",(time.time(),"admin",rname,json.dumps(data,sort_keys=True)))
        audit(user="admin", device=None, resource=rname, decision="POLICY", reasons=["policy updated: " + json.dumps(data, sort_keys=True, separators=(",", ":"))])
        self._write_summary(f"Policy saved for {rname}")
        self.refresh_all()
        self._policy_update_summary()

    def _audit_auto_verify(self):
        if not hasattr(self, "audit_auto") or not self.audit_auto.get() or time.time() - self._audit_auto_at < 60: return
        self._audit_auto_at = time.time()
        was = self._audit_ok_last
        ok = self.verify_audit()
        if was is True and not ok:
            self._write_summary("WARNING: the audit log failed its integrity check. Open Audit & Integrity.")
            try: self.nb.select(self.audit_tab)
            except Exception: pass

    def verify_audit(self):
        v = verify_chain(); ok, head, lines = verify_report(v); self._audit_ok_last = ok; self._audit_auto_at = time.time()
        self.audit_banner.set(("\u2714 " if ok else "\u2716 ") + head + f"   (checked {time.strftime('%H:%M:%S')})")
        self.audit_banner_lbl.configure(foreground="#0a7d33" if ok else "#c62828")
        self.audit_detail.set("\n".join(lines) + ("" if ok else "\nWhat to do: 2 save an evidence copy, then 3 try Safe repair; if it is still broken, 4 archive the damaged log (demo) or restore from backup (production)."))
        self.refresh_audit(force=True)
        return ok

    def export_evidence_ui(self):
        try: path = export_audit_evidence()
        except Exception as exc: messagebox.showerror("Evidence copy", f"Could not save evidence: {exc}"); return
        self._write_summary(f"Audit evidence saved to {os.path.basename(path)}")
        messagebox.showinfo("Evidence saved", f"A copy of every audit file and a report were saved to:\n{path}\n\nThe originals were not touched.")

    def repair_audit_ui(self):
        ok, msg = repair_chain_safe()
        (messagebox.showinfo if ok else messagebox.showwarning)("Safe repair", msg)
        self.verify_audit()

    def reset_audit_ui(self):
        if not DEMO:
            messagebox.showinfo("Archive and start fresh", "Only available in local demo mode. In production, restore the log from backup and investigate who changed it."); return
        if not self._confirm_admin_password(): return
        if not messagebox.askyesno("Archive damaged log?", "This moves the current audit log and anchors into an archive folder (nothing is deleted) and starts a NEW chain.\n\nOnly do this after saving evidence and confirming the damage cannot be repaired.\n\nContinue?"): return
        try: path = archive_and_reset_audit()
        except Exception as exc: messagebox.showerror("Archive and start fresh", f"Failed: {exc}"); return
        self._write_summary(f"Audit log archived to {os.path.basename(path)}; new chain started")
        self.verify_audit()
        messagebox.showinfo("New audit chain started", f"Old files are in:\n{path}\n\nThe new log starts with an entry recording this reset.")

    def posture_sel(self):
        sel = self.posture_tree.selection()
        return sel[0] if sel and sel[0] in DEVICES else None

    def posture_select_mine(self):
        dev = self.engine.device if self.engine.session else None
        if dev and self.posture_tree.exists(dev):
            self.posture_tree.selection_set(dev); self.posture_tree.see(dev)
        else:
            messagebox.showinfo("Device posture", "Log in first (Overview tab) and your device will be selected for you.")

    @staticmethod
    def _posture_state(dev):
        d = DEVICES[dev]; age = time.time() - d.get("last_report", 0)
        if not d.get("last_report"): return "stale", "Not signed in", age
        if POSTURE_TTL > 0 and age > POSTURE_TTL: return "stale", "Stale report", age
        sc = posture(dev)
        return ("good", "Healthy", age) if sc >= 80 else (("fair", "Fair", age) if sc >= 60 else ("bad", "At risk", age))

    def _posture_agent_beat(self):
        """Simulated endpoint agent: re-sends every device's CURRENT status (it never changes the checks themselves)."""
        if not self.agent_on.get(): return
        now = time.time()
        if now - getattr(self, "_agent_last", 0) < 60: return
        self._agent_last = now
        with LOCK: live = {s.get("device") for s in SESSIONS.values()}
        for name, d in DEVICES.items():
            if name in live: d["last_report"] = now

    def posture_report_now(self):
        dev = self.posture_sel()
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); return
        DEVICES[dev]["last_report"] = time.time()
        audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=["posture report sent"])
        self.refresh_all()

    @staticmethod
    def scan_findings(dev):
        """Simulated vulnerability / malware scan: derived from the device's current checks (no real endpoint here).
        -> list of (severity, title, detail, fix_field or None)."""
        d = DEVICES[dev]; out = []
        if not d.get("os_updated"): out.append(("HIGH", "Operating system is out of date", "Missing security patches leave known vulnerabilities open to attack.", "os_updated"))
        if not d.get("antivirus"): out.append(("HIGH", "No antivirus running - malware scan could not run", "Without an active scanner the device cannot be proven free of viruses, so it is treated as possibly infected.", "antivirus"))
        if not d.get("disk_encrypted"): out.append(("HIGH", "Disk is not encrypted", "Anyone who steals the device can read its data.", "disk_encrypted"))
        if not d.get("firewall"): out.append(("MEDIUM", "Firewall is switched off", "Incoming connections are not filtered, which exposes services on the device.", "firewall"))
        if not d.get("corporate_managed"): out.append(("LOW", "Device is not company-managed", "The company cannot enforce settings or remove it remotely. Not fixable by the scan; enrol the device.", None))
        return out

    def posture_scan(self):
        dev = self.posture_sel()
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); return
        win = tk.Toplevel(self); win.title(f"Vulnerability scan - {dev}"); win.transient(self); win.geometry("560x420")
        win.configure(background=self.C["bg"] if "bg" in self.C else "#f4f6f9")
        head = tk.StringVar(value=f"Scanning {dev} ..."); ttk.Label(win, textvariable=head, style="PageStrong.TLabel").pack(anchor="w", padx=14, pady=(14, 4))
        bar = ttk.Progressbar(win, maximum=5); bar.pack(fill="x", padx=14)
        step_txt = tk.StringVar(); ttk.Label(win, textvariable=step_txt, style="Sub.TLabel").pack(anchor="w", padx=14, pady=(4, 6))
        frame, out = self._text(win, height=10); frame.pack(fill="both", expand=True, padx=14)
        for tag, color in (("HIGH", "#c62828"), ("MEDIUM", "#b26a00"), ("LOW", "#667085"), ("OK", "#0a7d33")):
            out.tag_configure(tag, foreground=color, font=("Segoe UI", 10, "bold"))
        btns = ttk.Frame(win); btns.pack(fill="x", padx=14, pady=12)
        fix_btn = ttk.Button(btns, text="Fix all fixable issues", style="Action.TButton", state="disabled")
        fix_btn.pack(side="right"); ttk.Button(btns, text="Close", command=win.destroy).pack(side="right", padx=8)
        steps = ("Checking operating system patches", "Checking disk encryption", "Checking firewall", "Scanning for malware (antivirus)", "Checking device management")
        findings = self.scan_findings(dev)

        def finish():
            if not win.winfo_exists(): return
            bar["value"] = 5; step_txt.set("Scan complete"); fixable = [f for f in findings if f[3]]
            head.set(f"{dev}: {len(findings)} finding(s)" if findings else f"{dev}: no vulnerabilities or infections found")
            out.configure(state="normal"); out.delete("1.0", "end")
            if not findings: out.insert("end", "OK  ", "OK"); out.insert("end", "All checks passed and the antivirus scan is clean.\n")
            for sev, title, detail, _f in findings:
                out.insert("end", f"{sev}  ", sev); out.insert("end", f"{title}\n    {detail}\n\n")
            out.insert("end", "(Simulated scan: results come from the device's reported checks, not a real endpoint.)\n"); out.configure(state="disabled")
            audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=[f"vulnerability scan: {len(findings)} finding(s)"])
            if fixable:
                def fix_all():
                    for _s, _t, _d, f in fixable: DEVICES[dev][f] = True
                    DEVICES[dev]["last_report"] = time.time()
                    if dev not in FIXTURE_DEVICES:
                        try: save_persisted_devices()
                        except Exception: pass
                    audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=["scan: issues fixed"])
                    win.destroy(); self.refresh_all()
                fix_btn.configure(state="normal", command=fix_all)
            self.refresh_all()

        def tick(i=0):
            if not win.winfo_exists(): return
            if i >= len(steps): finish(); return
            bar["value"] = i; step_txt.set(steps[i] + " ..."); win.after(350, lambda: tick(i + 1))
        tick()

    def posture_preset(self, kind):
        dev = self.posture_sel()
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); return
        vals = {"healthy": dict(os_updated=True, disk_encrypted=True, firewall=True, antivirus=True)}[kind]
        DEVICES[dev].update(vals); DEVICES[dev]["last_report"] = time.time()
        audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=[f"preset {kind}"])
        self.refresh_all()

    def refresh_posture(self, force=False):
        if not hasattr(self, "posture_tree"): return
        tree = self.posture_tree
        for iid in tree.get_children():
            if iid not in DEVICES: tree.delete(iid)
        for dev, d in sorted(DEVICES.items()):
            tag, label, age = self._posture_state(dev)
            vals = (dev, d["owner"], posture(dev), label, f"{int(age)}s ago" if d.get("last_report") else "never")
            if tree.exists(dev): tree.item(dev, values=vals, tags=(tag,))
            else: tree.insert("", "end", iid=dev, values=vals, tags=(tag,))
        if self.agent_on.get():
            nxt = max(0, 60 - int(time.time() - getattr(self, "_agent_last", 0)))
            self.agent_status.set(f"Agent ON - next automatic report in {nxt}s")
        else:
            self.agent_status.set("Agent OFF - devices go stale after %d minutes and then score 0 (try it!)" % (POSTURE_TTL // 60) if POSTURE_TTL > 0
                                  else "Agent OFF - 'Last report' stops updating (demo mode never expires reports)")
        dev = self.posture_sel()
        if not dev:
            self.pd_title.set("Select a device on the left"); self.pd_score.set(""); self.pd_bar["value"] = 0; return
        d = DEVICES[dev]; tag, label, age = self._posture_state(dev); sc = posture(dev)
        self.pd_title.set(f"{dev}  -  owner: {d['owner']}")
        self.pd_score.set(f"{sc}/100  ({label})")
        self.pd_bar["value"] = sc
        for f, v in self.posture_vars.items():
            if v.get() != bool(d.get(f)): v.set(bool(d.get(f)))
        lines = []
        for r, v in RESOURCES.items():
            ok = sc >= v["min_posture"] and (not v["managed"] or d.get("corporate_managed"))
            need = f"needs {v['min_posture']}" + (" + company-managed" if v["managed"] else "")
            lines.append((("\u2714 " if ok else "\u2716 ") + f"{r}  ({need})\n", "ok" if ok else "bad"))
        key = repr(lines)
        if key != getattr(self, "_pd_caps_key", None):
            self._pd_caps_key = key
            self.pd_caps.configure(state="normal"); self.pd_caps.delete("1.0", "end")
            for text, t in lines: self.pd_caps.insert("end", text, t)
            self.pd_caps.configure(state="disabled")

    def set_posture(self, dev, field, value):
        if not dev: messagebox.showinfo("Device posture", "Select a device first."); self.refresh_posture(); return
        DEVICES[dev][field] = bool(value)
        DEVICES[dev]["last_report"] = time.time()
        audit(user="admin", device=dev, resource="posture", decision="POLICY", reasons=[f"{field}={bool(value)}"])
        if dev not in FIXTURE_DEVICES:
            try: save_persisted_devices()
            except Exception: pass
        self.refresh_all()

    def _audit_matches(self, e, label, tag):
        f = self.audit_filter.get(); res = str(e.get("resource", ""))
        if f == "Blocked or needs MFA": return e.get("decision") in ("DENY", "STEPUP")
        if f == "Sign-ins and sign-outs": return res in ("login", "stepup", "session")
        if f == "Admin and policy changes": return e.get("decision") == "POLICY"
        if f == "Resource access only": return res in RESOURCES and e.get("decision") != "POLICY"
        return True

    def refresh_audit(self, force=False):
        if not hasattr(self, "audit_tree"): return
        snap = (AUDIT.get("entries"), self.audit_filter.get())
        if not force and snap == getattr(self, "_audit_snap", None): return
        self._audit_snap = snap
        sel = self.audit_tree.selection()
        for i in self.audit_tree.get_children(): self.audit_tree.delete(i)
        self._audit_by_iid = {}; shown = 0
        for e in list(LOG)[:400]:
            label, tag, text = describe_audit_event(e)
            if not self._audit_matches(e, label, tag): continue
            try: when = datetime.fromisoformat(str(e.get("ts", "")).replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
            except ValueError: when = str(e.get("ts", ""))[-9:-1]
            iid = str(e.get("hash", ""))[:24] or f"row{shown}"
            if self.audit_tree.exists(iid): continue
            self.audit_tree.insert("", "end", iid=iid, values=(when, label, text), tags=(tag,)); self._audit_by_iid[iid] = e; shown += 1
        self.audit_count.set(f"showing {shown} of the latest {min(len(LOG), 400)} entries  |  {AUDIT.get('entries', 0)} entries in the chain")
        for k in sel:
            if self.audit_tree.exists(k): self.audit_tree.selection_set(k)
        self._show_audit_detail()

    def _show_audit_detail(self):
        sel = self.audit_tree.selection()
        e = self._audit_by_iid.get(sel[0]) if sel else None
        text = "Select a line to see the technical details behind it." if not e else (
            f"Time (UTC): {e.get('ts')}   User: {e.get('user') or '-'}   Device: {e.get('device') or '-'}   System/action: {e.get('resource')}   Decision: {e.get('decision')}   Risk: {e.get('risk', '-')}\n"
            f"Reasons recorded: {'; '.join(map(str, e.get('reasons', []))) or '-'}\nRisk signals: {'; '.join(map(str, e.get('signals', []))) or '-'}\n"
            f"Seal (HMAC-SHA256): {e.get('hash')}\nPrevious line's seal: {e.get('prev')}")
        self.audit_text.configure(state="normal"); self.audit_text.delete("1.0", "end"); self.audit_text.insert("1.0", text); self.audit_text.configure(state="disabled")

    def _write_summary(self, text):
        self.summary.configure(state="normal"); self.summary.insert("1.0", f"{time.strftime('%H:%M:%S')}  {text}\n"); self.summary.configure(state="disabled")

    def _write_access(self, text):
        self.access_log.configure(state="normal"); self.access_log.insert("1.0", f"{time.strftime('%H:%M:%S')}  {text}\n"); self.access_log.configure(state="disabled")

    def refresh_all(self):
        if self.engine.session:
            _, s = self.engine.session
            self.status.config(text=f"● {s['user']}  ·  {s['device']}  ·  {s['location']}", background="#dcf3ea", foreground="#056b4c")
            age = int(time.time() - s["mfa_at"])
            self.session_text.set("Authenticated")
            for key, val in (("user", s["user"]), ("device", s["device"]), ("location", s["location"]), ("mfa", f"{age}s"),
                             ("ttl", f"{max(0, int(s['exp'] - time.time()))}s"), ("travel", str(s.get("travel", False)))):
                self.session_vars[key].set(val)
        else:
            self.status.config(text="● Logged out", background="#e3ecf7", foreground=self.C["muted"])
            self.session_text.set("Not authenticated")
            for var in self.session_vars.values(): var.set("—")
        self.refresh_posture()
        self.refresh_access_cards()
        self.refresh_clock()
        self.refresh_audit()
        self.refresh_security()
        self.refresh_identity_devices()
        self.refresh_roles()
        self.refresh_dashboard_overview()
        self.refresh_dashboard_activity()
        if not getattr(self,"_refresh_scheduled",False): self._refresh_scheduled=True; self.after(1500,self._tick)

    def _tick(self):
        self._refresh_scheduled=False
        if self.winfo_exists():
            self._posture_agent_beat()
            self._audit_auto_verify()
            self.refresh_all()

    def on_close(self):
        try: self.engine.logout()
        finally: self.destroy()

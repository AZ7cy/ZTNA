# Part 22 of ztna.py - desktop GUI shared pieces: theme, panels, scrolling, formatting helpers, portal base class, preferences.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# =====================================================================================================
#  Blue & white desktop GUI.  One hub window opens an Employee window and a Manager window that run side
#  by side in the same process, so an employee's sign-in request lands live in the manager's queue.
# =====================================================================================================
BLUE_DARK, BLUE, BLUE_MID = "#0b3d91", "#1d4ed8", "#3b82f6"
BLUE_SOFT, BLUE_LINE, BLUE_PALE = "#eaf2ff", "#bcd3f7", "#f5f9ff"
BLUE_TEXT, BLUE_MUTED, WHITE = "#0b2a63", "#4b6aa3", "#ffffff"
UI_FONT = "Segoe UI"


def apply_blue_white_theme(root):
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except tk.TclError: pass
    root.configure(background=WHITE)
    root.option_add("*TCombobox*Listbox.background", WHITE)
    root.option_add("*TCombobox*Listbox.foreground", BLUE_TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", BLUE)
    root.option_add("*TCombobox*Listbox.selectForeground", WHITE)
    style.configure(".", background=WHITE, foreground=BLUE_TEXT, font=(UI_FONT, 10), bordercolor=BLUE_LINE,
                    lightcolor=WHITE, darkcolor=WHITE, troughcolor=BLUE_SOFT, focuscolor=BLUE, insertcolor=BLUE_TEXT)
    style.configure("TFrame", background=WHITE)
    style.configure("Soft.TFrame", background=BLUE_SOFT)
    style.configure("Band.TFrame", background=BLUE)
    for name, bg, fg, font in (
        ("TLabel", WHITE, BLUE_TEXT, (UI_FONT, 10)),
        ("Muted.TLabel", WHITE, BLUE_MUTED, (UI_FONT, 9)),
        ("Title.TLabel", WHITE, BLUE_DARK, (UI_FONT, 18, "bold")),
        ("Section.TLabel", WHITE, BLUE_DARK, (UI_FONT, 13, "bold")),
        ("Strong.TLabel", WHITE, BLUE_TEXT, (UI_FONT, 10, "bold")),
        ("Accent.TLabel", WHITE, BLUE, (UI_FONT, 10, "bold")),
        ("Big.TLabel", WHITE, BLUE_DARK, (UI_FONT, 16, "bold")),
        ("Soft.TLabel", BLUE_SOFT, BLUE_TEXT, (UI_FONT, 10)),
        ("PanelTitle.TLabel", BLUE_SOFT, BLUE_DARK, (UI_FONT, 11, "bold")),
        ("SoftMuted.TLabel", BLUE_SOFT, BLUE_MUTED, (UI_FONT, 9)),
        ("BandKicker.TLabel", BLUE, "#cfe0ff", (UI_FONT, 9, "bold")),
        ("BandTitle.TLabel", BLUE, WHITE, (UI_FONT, 20, "bold")),
        ("BandSub.TLabel", BLUE, "#dce9ff", (UI_FONT, 10)),
        ("Badge.TLabel", WHITE, BLUE, (UI_FONT, 10, "bold")),
    ):
        style.configure(name, background=bg, foreground=fg, font=font)
    style.configure("TButton", padding=(10, 5), font=(UI_FONT, 10), background=WHITE, foreground=BLUE,
                    bordercolor=BLUE, relief="flat")
    style.map("TButton", background=[("active", BLUE_SOFT), ("disabled", BLUE_PALE)],
              foreground=[("disabled", "#9db6e0")], bordercolor=[("disabled", BLUE_LINE)])
    style.configure("Primary.TButton", padding=(14, 8), font=(UI_FONT, 10, "bold"), background=BLUE,
                    foreground=WHITE, bordercolor=BLUE)
    style.map("Primary.TButton", background=[("active", BLUE_DARK), ("disabled", "#a9c1ee")],
              foreground=[("disabled", WHITE)], bordercolor=[("disabled", "#a9c1ee")])
    style.configure("Ghost.TButton", padding=(12, 6), background=BLUE, foreground=WHITE, bordercolor="#cfe0ff")
    style.map("Ghost.TButton", background=[("active", BLUE_DARK)])
    style.configure("TEntry", padding=6, fieldbackground=WHITE, bordercolor=BLUE_LINE)
    style.map("TEntry", bordercolor=[("focus", BLUE)])
    style.configure("TCombobox", padding=5, fieldbackground=WHITE, background=BLUE_SOFT, arrowcolor=BLUE,
                    bordercolor=BLUE_LINE)
    style.map("TCombobox", fieldbackground=[("readonly", WHITE)], selectbackground=[("readonly", WHITE)],
              selectforeground=[("readonly", BLUE_TEXT)], bordercolor=[("focus", BLUE)])
    style.configure("TCheckbutton", background=WHITE, foreground=BLUE_TEXT, indicatorcolor=WHITE)
    style.map("TCheckbutton", indicatorcolor=[("selected", BLUE)], background=[("active", WHITE)])
    style.configure("TSeparator", background=BLUE_LINE)
    style.configure("TNotebook", background=WHITE, borderwidth=0, tabmargins=(0, 0, 0, 0))
    style.configure("TNotebook.Tab", padding=(13, 8), font=(UI_FONT, 10, "bold"), background=BLUE_SOFT, foreground=BLUE)
    style.map("TNotebook.Tab", background=[("selected", BLUE), ("active", BLUE_LINE)], foreground=[("selected", WHITE)])
    style.configure("Treeview", rowheight=28, font=(UI_FONT, 9), background=WHITE, fieldbackground=WHITE,
                    foreground=BLUE_TEXT, bordercolor=BLUE_LINE)
    style.map("Treeview", background=[("selected", BLUE)], foreground=[("selected", WHITE)])
    style.configure("Treeview.Heading", font=(UI_FONT, 9, "bold"), background=BLUE_SOFT, foreground=BLUE_DARK,
                    bordercolor=BLUE_LINE, padding=(6, 6))
    style.map("Treeview.Heading", background=[("active", BLUE_LINE)])
    style.configure("Vertical.TScrollbar", background=BLUE_LINE, troughcolor=BLUE_SOFT, arrowcolor=BLUE, bordercolor=BLUE_SOFT)
    style.configure("Horizontal.TScrollbar", background=BLUE_LINE, troughcolor=BLUE_SOFT, arrowcolor=BLUE, bordercolor=BLUE_SOFT)
    style.configure("Blue.Horizontal.TProgressbar", troughcolor=BLUE_SOFT, background=BLUE, bordercolor=BLUE_LINE,
                    lightcolor=BLUE, darkcolor=BLUE)


class Panel(tk.Frame):
    """White panel with a thin blue border and an optional soft-blue title bar. Put content in ``.body``."""

    def __init__(self, parent, title=None, subtitle=None, padding=16):
        super().__init__(parent, background=BLUE_LINE, bd=0, highlightthickness=0)
        inner = ttk.Frame(self)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        if title:
            bar = ttk.Frame(inner, style="Soft.TFrame", padding=(14, 9))
            bar.pack(fill="x")
            ttk.Label(bar, text=title, style="PanelTitle.TLabel").pack(side="left")
            if subtitle:
                ttk.Label(bar, text=subtitle, style="SoftMuted.TLabel").pack(side="left", padx=(10, 0))
        self.body = ttk.Frame(inner, padding=padding)
        self.body.pack(fill="both", expand=True)


class ScrollFrame(tk.Frame):
    """Page whose content fills the width and scrolls vertically only when the window is too short."""

    def __init__(self, parent):
        super().__init__(parent, background=WHITE, bd=0, highlightthickness=0)
        self.canvas = tk.Canvas(self, background=WHITE, bd=0, highlightthickness=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self._bar_shown = False
        self.body.bind("<Configure>", self._fit)
        self.canvas.bind("<Configure>", self._fit)
        _install_wheel_router(self)

    def scrollable(self):
        return self.body.winfo_reqheight() > self.canvas.winfo_height() + 1

    def _fit(self, _e=None):
        cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
        if cw < 2 or ch < 2: return
        need = self.body.winfo_reqheight()
        self.canvas.itemconfigure(self._win, width=cw)
        self.canvas.configure(scrollregion=(0, 0, cw, max(need, ch)))
        if need > ch + 1 and not self._bar_shown:
            self.vbar.pack(side="right", fill="y", before=self.canvas); self._bar_shown = True
        elif need <= ch + 1 and self._bar_shown:
            self.vbar.pack_forget(); self._bar_shown = False; self.canvas.yview_moveto(0)


def _install_wheel_router(widget):
    root = widget._root()
    if getattr(root, "_ztna_wheel", False): return
    root._ztna_wheel = True

    def route(event):
        w = event.widget
        if not isinstance(w, tk.Misc): return
        try:
            if w.winfo_class() in ("Treeview", "Text", "Listbox", "TCombobox", "TSpinbox"): return
        except tk.TclError: return
        node = w
        while node is not None and not isinstance(node, ScrollFrame): node = getattr(node, "master", None)
        if node is None or not node.scrollable(): return
        num = getattr(event, "num", None)
        step = -2 if num == 4 else 2 if num == 5 else (-2 if event.delta > 0 else 2)
        node.canvas.yview_scroll(step, "units")

    for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"): root.bind_all(seq, route, add="+")


def _fmt_ts(ts, fmt="%Y-%m-%d %H:%M:%S"):
    if isinstance(ts, (int, float)):
        try: return datetime.fromtimestamp(ts).strftime(fmt)
        except (ValueError, OSError, OverflowError): return str(ts)
    return str(ts or "")


def _person(user):
    p = USER_PROFILE.get(user, {})
    return p.get("name", user), p.get("title", ""), p.get("dept", "")


_RES_TITLES = {"hr-db": "HR Database", "ci-cd": "CI/CD Pipelines", "crm": "CRM", "siem-console": "SIEM Console",
               "exec-reports": "Executive Reports", "wiki": "Wiki", "admin-panel": "Admin Panel", "source-code": "Source Code",
               "finance-ledger": "Finance Ledger", "support-desk": "Support Desk", "legal-vault": "Legal Vault"}


def _res_title(res):
    return _RES_TITLES.get(res, res.replace("-", " ").title())


def _req_lines(res):
    r = RESOURCES[res]
    hrs = "any time" if tuple(r["hours"]) == (0, 24) else f"{r['hours'][0]:02d}:00–{r['hours'][1]:02d}:00"
    return [f"Device health {r['min_posture']}+ · " + ("company-managed device" if r["managed"] else "any enrolled device"),
            f"Open {hrs} · from " + " or ".join(r["locations"]), f"Fresh MFA within {max(1, r['mfa_age'] // 60)} min"]


def _device_summary(device):
    d = DEVICES.get(device)
    if not d: return ""
    kind = "company-managed" if d.get("corporate_managed") else "personal (BYOD)"
    return f"Device health {posture(device)}/100 · {kind}"


class _PortalUI:
    """Shared helpers for the hub and the portal windows."""

    def _init_ui(self):
        self._jobs = {}

    def _schedule(self, key, ms, fn):
        old = self._jobs.pop(key, None)
        if old:
            try: self.after_cancel(old)
            except Exception: pass
        self._jobs[key] = self.after(ms, fn)

    def _cancel_jobs(self):
        for job in self._jobs.values():
            try: self.after_cancel(job)
            except Exception: pass
        self._jobs.clear()

    def _clear(self):
        self._cancel_jobs()
        for child in self.winfo_children(): child.destroy()

    def _band(self, title, subtitle, kicker="ZERO TRUST ACCESS"):
        band = ttk.Frame(self, style="Band.TFrame", padding=(26, 16))
        band.pack(fill="x")
        right = ttk.Frame(band, style="Band.TFrame"); right.pack(side="right", padx=(12, 0))
        left = ttk.Frame(band, style="Band.TFrame"); left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text=kicker, style="BandKicker.TLabel").pack(anchor="w")
        ttk.Label(left, text=title, style="BandTitle.TLabel").pack(anchor="w", pady=(3, 2))
        if str(subtitle or "").strip():
            ttk.Label(left, text=subtitle, style="BandSub.TLabel", wraplength=600, justify="left").pack(anchor="w")
        return right

    def _tree(self, parent, columns, headings, widths, stretch=None):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew"); y.grid(row=0, column=1, sticky="ns"); x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        for c, h, w in zip(columns, headings, widths):
            tree.heading(c, text=h, anchor="w")
            tree.column(c, width=w, minwidth=50, anchor="w", stretch=(c == (stretch or columns[-1])))
        tree.tag_configure("strong", font=(UI_FONT, 9, "bold"), foreground=BLUE_DARK)
        tree.tag_configure("pending", font=(UI_FONT, 9, "bold"), background=BLUE_SOFT, foreground=BLUE_DARK)
        tree.tag_configure("blocked", font=(UI_FONT, 9, "bold"), foreground=BLUE_DARK, background=BLUE_PALE)
        return tree

    def _fill_tree(self, tree, rows, iids=None, tags=None):
        """Rebuild only when the data changed; keep selection and scroll position."""
        if not tree or not tree.winfo_exists(): return
        sig = (tuple(map(tuple, rows)), tuple(iids or ()))
        if getattr(tree, "_sig", None) == sig: return
        tree._sig = sig
        keep = set(tree.selection()); top = tree.yview()[0]
        tree.delete(*tree.get_children())
        for i, row in enumerate(rows):
            iid = iids[i] if iids else None
            kw = {"iid": iid} if iid else {}
            tag = tags[i] if tags else ()
            tree.insert("", "end", values=tuple(str(v)[:800] for v in row), tags=tag, **kw)
        if iids:
            still = [i for i in iids if i in keep]
            if still: tree.selection_set(still)
        tree.yview_moveto(top)

    def _form_row(self, grid, row, label, widget_factory):
        ttk.Label(grid, text=label, style="Strong.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 14), pady=7)
        w = widget_factory(grid)
        w.grid(row=row, column=1, sticky="ew", pady=7)
        return w


class PortalWindow(_PortalUI, tk.Toplevel):
    def __init__(self, app, title, size, minsize):
        tk.Toplevel.__init__(self, app)
        self._init_ui()
        self.app = app
        self.base_title = title
        self.title(title)
        self.geometry(size)
        self.minsize(*minsize)
        self.configure(background=WHITE)
        self.protocol("WM_DELETE_WINDOW", self.close)

    def close(self):
        self._cancel_jobs()
        self.app.portal_closed(self)
        try: self.destroy()
        except tk.TclError: pass


# Persist only convenience preferences; never store passwords or OTPs.
def _gui_preferences_path():
    return os.path.join(DATA_DIR, "desktop_gui_preferences.json")

def _load_gui_preferences():
    try:
        with open(_gui_preferences_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError): return {}

def _save_gui_preferences(data):
    safe = {k: str(data.get(k, ""))[:100] for k in ("username", "device", "location")}
    path = _gui_preferences_path(); os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(safe, f)
    _replace_file(tmp, path)

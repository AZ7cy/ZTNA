# Part 24 of ztna_lab_v2.py - desktop GUI: SIEM data layer, charts and the manager Dashboard tab.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ------------------------------------------------------------------------------ SIEM dashboard (manager side)
# Everything below reads the live engine state (audit chain, alert table, sessions, device blocks). Nothing is invented:
# an empty window renders as an empty chart.
SEV_COLOR = {"INFO": "#64748b", "LOW": "#2563eb", "MEDIUM": "#d97706", "HIGH": "#dc2626", "CRITICAL": "#991b1b"}
OUTCOME_COLOR = {"allowed": "#16a34a", "challenged": "#f59e0b", "blocked": "#dc2626", "other": "#cbd5e1"}
OUTCOME_LABEL = {"allowed": "Allowed", "challenged": "Challenged", "blocked": "Blocked", "other": "Other"}
OK_GREEN, WARN_AMBER, BAD_RED = "#15803d", "#b45309", "#b91c1c"
SIEM_WINDOWS = (("15 minutes", 900), ("1 hour", 3600), ("6 hours", 21600), ("24 hours", 86400))
SIEM_AUTH_FAIL_RES = ("login", "stepup", "manager-login")
SIEM_ADMIN_RES = {"posture", "sim", "policy", "identity-create", "device-enrollment", "audit-repair", "audit-reset", "audit-export", "firewall"}
SIEM_RESPONSE_RES = {"alert", "alert-review", "alert-response", "device-control", "stepup-control", "sessions"}
SIEM_THREAT_LEVELS = ((20, "LOW", "#16a34a"), (45, "GUARDED", "#2563eb"), (70, "ELEVATED", "#d97706"), (101, "SEVERE", "#dc2626"))


def _evt_epoch(e):
    """Unix time of an audit entry (ISO-8601 string) or alert (float). 0.0 if unreadable."""
    ts = e.get("ts") if isinstance(e, dict) else e
    if isinstance(ts, (int, float)): return float(ts)
    try: return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        try: return float(ts)
        except (ValueError, TypeError): return 0.0


def _to_int(v, default=0):
    try: return int(float(v))
    except (ValueError, TypeError, OverflowError): return default


def _tint(color, amount=0.85):
    """Blend a #rrggbb colour towards white (amount 0..1)."""
    c = color.lstrip("#")
    r, g, b = (int(c[i:i + 2], 16) for i in (0, 2, 4))
    return "#%02x%02x%02x" % tuple(int(x + (255 - x) * amount) for x in (r, g, b))


def siem_category(e):
    res, dec = str(e.get("resource", "")), str(e.get("decision", ""))
    if dec == "POLICY" or res in SIEM_ADMIN_RES: return "Admin"
    if _is_exception_record(e): return "Response"
    if res in RESOURCES: return "Access"
    if res in SIEM_AUTH_FAIL_RES or res == "signin-request": return "Authentication"
    if res in ("session", "manager-logout"): return "Session"
    # Manager actions on names outside the audit allow-list are stored as "unknown:<hash>", so the decision identifies them.
    if res in SIEM_RESPONSE_RES or dec in ("REVOKE", "FALSE_ALARM", "REVIEWED"): return "Response"
    return "Other"


def siem_event_severity(e, cat):
    dec, res, risk = str(e.get("decision", "")), str(e.get("resource", "")), _to_int(e.get("risk"))
    if res in ("audit-reset", "audit-repair") or dec == "ERROR": return "HIGH"
    if dec == "DENY":
        if cat == "Access": return "HIGH" if risk >= 80 else "MEDIUM"
        return "MEDIUM" if cat == "Authentication" else "LOW"
    if dec in ("STEPUP", "PENDING", "POLICY"): return "LOW"
    if dec == "REVOKE" and cat == "Response": return "LOW"
    return "INFO"


def siem_outcome(dec):
    return {"ALLOW": "allowed", "DENY": "blocked", "STEPUP": "challenged", "PENDING": "challenged"}.get(str(dec), "other")


_SIEM_DESC = OrderedDict()


def _siem_describe(e):
    """(label, plain-English sentence) for an audit entry; cached by entry hash."""
    key = e.get("hash") or id(e)
    hit = _SIEM_DESC.get(key)
    if hit: return hit
    try:
        label, _tag, sentence = describe_audit_event(e)
    except Exception:
        label, sentence = str(e.get("decision", "")).title(), "; ".join(map(str, e.get("reasons") or [])) or str(e.get("resource", ""))
    _SIEM_DESC[key] = (label, sentence)
    while len(_SIEM_DESC) > 1500: _SIEM_DESC.popitem(last=False)
    return label, sentence


def _siem_aggregate(rows):
    access = [x for x in rows if x["cat"] == "Access"]
    risks = [x["risk"] for x in access]
    return {"events": len(rows), "access": len(access),
            "allow": sum(1 for x in access if x["decision"] == "ALLOW"),
            "stepup": sum(1 for x in access if x["decision"] == "STEPUP"),
            "deny": sum(1 for x in access if x["decision"] == "DENY"),
            "failed_auth": sum(1 for x in rows if x["resource"] in SIEM_AUTH_FAIL_RES and x["decision"] == "DENY"),
            "avg_risk": round(sum(risks) / len(risks), 1) if risks else 0.0}


def siem_threat(open_alerts, cur, integrity_ok=None):
    """Transparent 0-100 threat score. Every point comes from a listed factor."""
    sev = Counter(str(a.get("severity", "")).upper() for a in open_alerts)
    high, med, low = sev["HIGH"] + sev["CRITICAL"], sev["MEDIUM"], sev["LOW"]
    factors = []

    def add(label, pts, detail):
        if pts >= 0.5: factors.append((label, int(round(pts)), detail))
    add("Open high-severity alerts", min(45, 15 * high), f"{high} awaiting a decision")
    add("Open medium alerts", min(24, 6 * med), f"{med} awaiting a decision")
    add("Open low alerts", min(6, 2 * low), f"{low} awaiting a decision")
    if cur["access"] >= 5:
        add("Share of access requests denied", min(15, cur["deny"] / cur["access"] * 30), f"{round(cur['deny'] * 100 / cur['access'])}% of {cur['access']} requests")
    add("Average access risk", cur["avg_risk"] / 100 * 10, f"{cur['avg_risk']}/100")
    if integrity_ok is False: add("Audit chain failed verification", 40, "evidence may have been altered")
    score = min(100, sum(f[1] for f in factors))
    for limit, name, color in SIEM_THREAT_LEVELS:
        if score < limit: return {"score": score, "level": name, "color": color, "factors": factors}


def siem_snapshot(window_s=3600, buckets=30, now=None, integrity_ok=None):
    """Aggregate live engine state for one dashboard window. Pure read; safe to call from the Tk thread."""
    now = time.time() if now is None else now
    W = float(window_s); start, prev_start = now - W, now - 2 * W
    with LOCK: log = list(LOG)
    evs = []
    for e in log:
        cat = siem_category(e)
        evs.append({"raw": e, "ts": _evt_epoch(e), "user": str(e.get("user") or ""), "device": str(e.get("device") or ""),
                    "resource": str(e.get("resource", "")), "decision": str(e.get("decision", "")), "risk": _to_int(e.get("risk")),
                    "cat": cat, "sev": siem_event_severity(e, cat), "outcome": siem_outcome(e.get("decision"))})
    oldest = min((x["ts"] for x in evs), default=None)
    full = bool(LOG.maxlen) and len(log) >= LOG.maxlen
    truncated = bool(full and oldest is not None and oldest > start)
    prev_ok = not (full and oldest is not None and oldest > prev_start)
    cur = [x for x in evs if x["ts"] >= start]
    prev = [x for x in evs if prev_start <= x["ts"] < start]
    cur_agg, prev_agg = _siem_aggregate(cur), (_siem_aggregate(prev) if prev_ok else None)
    try: al = [dict(a) for a in recent_alerts(limit=500)]
    except Exception: al = []
    for a in al: a["_ts"] = _evt_epoch(a); a["_sev"] = str(a.get("severity", "")).upper()
    cur_alerts = [a for a in al if a["_ts"] >= start]
    open_alerts = [a for a in al if not a.get("acknowledged")]
    bw = W / buckets
    bk = [{"t0": start + i * bw, "ev": 0, "alerts": 0, "allowed": 0, "challenged": 0, "blocked": 0, "other": 0} for i in range(buckets)]
    for x in cur:
        b = bk[max(0, min(buckets - 1, int((x["ts"] - start) / bw)))]; b["ev"] += 1; b[x["outcome"]] += 1
    for a in cur_alerts: bk[max(0, min(buckets - 1, int((a["_ts"] - start) / bw)))]["alerts"] += 1
    # identities with risk signals
    ident = {}
    def slot(u): return ident.setdefault(u, {"user": u, "deny": 0, "stepup": 0, "high": 0, "med": 0, "low": 0, "max_risk": 0})
    for x in cur:
        if x["user"] and x["decision"] in ("DENY", "STEPUP") and x["cat"] in ("Access", "Authentication"):
            s = slot(x["user"]); s["deny" if x["decision"] == "DENY" else "stepup"] += 1; s["max_risk"] = max(s["max_risk"], x["risk"])
    for a in cur_alerts:
        if a.get("user"):
            s = slot(a["user"]); s["high" if a["_sev"] in ("HIGH", "CRITICAL") else "med" if a["_sev"] == "MEDIUM" else "low"] += 1
    people = []
    for s in ident.values():
        s["score"] = min(100, int(4 * s["deny"] + 2 * s["stepup"] + 20 * s["high"] + 6 * s["med"] + 3 * s["low"] + 0.2 * s["max_risk"]))
        s["alerts"] = s["high"] + s["med"] + s["low"]; s["name"] = _person(s["user"])[0]; people.append(s)
    people.sort(key=lambda s: (-s["score"], s["user"]))
    with LOCK:
        live = [s for s in SESSIONS.values() if s.get("exp", 0) > now and s.get("abs_exp", 0) > now and s.get("device") not in BLOCKED_DEVICES]
    try: pending = count_pending_signins()
    except Exception: pending = 0
    return {"now": now, "start": start, "window": W, "cur": cur, "cur_agg": cur_agg, "prev_agg": prev_agg, "truncated": truncated,
            "buckets": bk, "alerts": al, "open_alerts": open_alerts, "people": people[:5], "sessions": len(live), "pending": pending,
            "blocked": sorted(BLOCKED_DEVICES), "stepup_users": sorted(STEPUP_REQUIRED_USERS),
            "temp_grants": sorted((u, r, int((exp - now) // 60) + 1) for (u, r), exp in list(TEMP_RESOURCE_GRANTS.items()) if exp > now),
            "threat": siem_threat(open_alerts, cur_agg, integrity_ok)}


def siem_integrity_state():
    """Cheap, in-memory integrity facts. The full cryptographic scan is verify_chain(), run in the background."""
    with LOCK:
        entries = AUDIT.get("entries", 0); log = list(LOG)
    blocks = []
    for i, e in enumerate(log[:8]):
        ok = (i + 1 >= len(log)) or e.get("prev") == log[i + 1].get("hash")
        blocks.append({"seq": entries - i, "hash": str(e.get("hash", "")), "ok": bool(ok)})
    blocks.reverse()
    return {"entries": entries, "linked": all(b["ok"] for b in blocks), "blocks": blocks,
            "anchors": os.path.exists(AUDIT_ANCHOR_FILE) and os.path.exists(AUDIT_EXTERNAL_ANCHOR_FILE)}


class _Verifier:
    """Runs verify_chain() off the Tk thread; the dashboard polls .result from its timer."""

    def __init__(self):
        self.running, self.result = False, None

    def start(self):
        if self.running: return False
        self.running = True
        threading.Thread(target=self._run, name="siem-verify", daemon=True).start()
        return True

    def _run(self):
        t0 = time.time()
        try: r = verify_chain()
        except Exception as exc: r = {"ok": False, "error": str(exc), "entries": 0}
        self.result = (time.time(), r, time.time() - t0)
        self.running = False


# ---- canvas charts (stdlib Tk has no charting; these are small, resize-aware and theme-matched)
class _Chart(tk.Canvas):
    def __init__(self, parent, height):
        super().__init__(parent, height=height, background=WHITE, bd=0, highlightthickness=0)
        self._args = None
        self.bind("<Configure>", lambda _e: self.draw())

    def set(self, *args, **kw):
        self._args = (args, kw); self.draw()

    def draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if self._args is None or w < 30 or h < 10: return
        self._paint(w, h, *self._args[0], **self._args[1])

    def _empty(self, w, h, text):
        self.create_text(w / 2, h / 2, text=text, fill=BLUE_MUTED, font=(UI_FONT, 9))


def _nice_step(top, ticks=4):
    raw = max(top, 1) / ticks
    for s in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000):
        if s >= raw: return s
    return 1000


class TimelineChart(_Chart):
    ORDER = ("allowed", "challenged", "blocked", "other")

    def _paint(self, w, h, buckets=(), window=3600):
        L, R, T, B = 34, 8, 34, 20
        pw, ph = w - L - R, h - T - B
        totals = [sum(b[k] for k in self.ORDER) for b in buckets]
        if not buckets or not any(totals): return self._empty(w, h, "No events in this window")
        step = _nice_step(max(totals)); top = step * math.ceil(max(totals) / step)
        for v in range(0, top + 1, step):
            y = T + ph - ph * v / top
            self.create_line(L, y, w - R, y, fill=BLUE_SOFT if v else BLUE_LINE)
            self.create_text(L - 5, y, text=str(v), anchor="e", fill=BLUE_MUTED, font=(UI_FONT, 7))
        n = len(buckets); slot = pw / n; bw = max(2, slot - 2)
        for i, b in enumerate(buckets):
            x0, base = L + i * slot + (slot - bw) / 2, T + ph
            for k in self.ORDER:
                if not b[k]: continue
                y1 = base - ph * b[k] / top
                self.create_rectangle(x0, y1, x0 + bw, base, fill=OUTCOME_COLOR[k], outline="")
                base = y1
            if b["alerts"]:
                cx, cy = x0 + bw / 2, T - 9
                self.create_polygon(cx, cy - 5, cx + 5, cy, cx, cy + 5, cx - 5, cy, fill=SEV_COLOR["HIGH"], outline=WHITE)
        self.create_text(4, T - 9, text="alerts", anchor="w", fill=BLUE_MUTED, font=(UI_FONT, 7))
        x = L
        for k in self.ORDER:
            self.create_rectangle(x, 7, x + 9, 16, fill=OUTCOME_COLOR[k], outline="")
            self.create_text(x + 13, 11, text=OUTCOME_LABEL[k], anchor="w", fill=BLUE_TEXT, font=(UI_FONT, 8)); x += 22 + 7 * len(OUTCOME_LABEL[k])
        fmt = "%a %H:%M" if window > 21600 else "%H:%M"
        for i in range(5):
            f = i / 4; ts = buckets[0]["t0"] + f * (buckets[-1]["t0"] + window / n - buckets[0]["t0"])
            self.create_text(L + f * pw, h - 9, text=_fmt_ts(ts, fmt), anchor="e" if i == 4 else "w" if i == 0 else "center", fill=BLUE_MUTED, font=(UI_FONT, 7))


class HBars(_Chart):
    ROW = 26

    def set_rows(self, rows, empty="Nothing to show", vmax=None):
        self.configure(height=max(34, self.ROW * len(rows) + 6) if rows else 34)
        self.set(rows=rows, empty=empty, vmax=vmax)

    def _paint(self, w, h, rows=(), empty="", vmax=None):
        if not rows: return self._empty(w, h, empty)
        vmax = vmax or max(r[1] for r in rows) or 1
        lw = min(130, int(w * 0.34)); rw = min(int(w * 0.45), max(34, 6 * max(len(r[3]) for r in rows) + 12)); bx0, bx1 = lw + 6, w - rw - 4
        for i, (label, value, color, note) in enumerate(rows):
            y = 4 + i * self.ROW + self.ROW / 2
            self.create_text(2, y, text=(label if len(label) <= 17 else label[:16] + "…"), anchor="w", fill=BLUE_TEXT, font=(UI_FONT, 9))
            self.create_rectangle(bx0, y - 5, bx1, y + 5, fill=BLUE_SOFT, outline="")
            if value > 0: self.create_rectangle(bx0, y - 5, bx0 + max(3, (bx1 - bx0) * min(1, value / vmax)), y + 5, fill=color, outline="")
            self.create_text(w - 2, y, text=note, anchor="e", fill=BLUE_MUTED, font=(UI_FONT, 8))


class Gauge(_Chart):
    def _paint(self, w, h, score=0, level="", color=BLUE):
        cy = h - 50; r = max(30, min(w / 2 - 16, cy - 8)); cx = w / 2
        box = (cx - r + 7, cy - r + 7, cx + r - 7, cy + r - 7)
        prev = 0
        for limit, _n, c in SIEM_THREAT_LEVELS:
            top = min(limit, 100)
            self.create_arc(*box, start=180 - prev * 1.8, extent=-(top - prev) * 1.8, style="arc", outline=_tint(c, 0.35), width=14); prev = top
        a = math.radians(180 - max(0, min(100, score)) * 1.8)
        self.create_line(cx, cy, cx + (r - 20) * math.cos(a), cy - (r - 20) * math.sin(a), fill=BLUE_DARK, width=3)
        self.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, fill=BLUE_DARK, outline=WHITE)
        self.create_text(cx, cy + 20, text=str(score), fill=color, font=(UI_FONT, 20, "bold"))
        self.create_text(cx, cy + 40, text=level, fill=color, font=(UI_FONT, 9, "bold"))
        self.create_text(cx - r + 7, cy + 12, text="0", fill=BLUE_MUTED, font=(UI_FONT, 7)); self.create_text(cx + r - 7, cy + 12, text="100", fill=BLUE_MUTED, font=(UI_FONT, 7))


class ChainRibbon(_Chart):
    def _paint(self, w, h, blocks=()):
        if not blocks: return self._empty(w, h, "The audit chain is empty")
        n = len(blocks); gap = 18; bw = (w - 8 - gap * (n - 1)) / n
        for i, b in enumerate(blocks):
            x0 = 4 + i * (bw + gap); col = OK_GREEN if b["ok"] else BAD_RED
            if i: self.create_line(x0 - gap, h / 2, x0, h / 2, fill=col, width=2)
            self.create_rectangle(x0, 6, x0 + bw, h - 6, fill=_tint(col, 0.92), outline=col, width=2)
            self.create_text(x0 + bw / 2, h / 2 - 8, text=f"#{b['seq']}", fill=BLUE_DARK, font=(UI_FONT, 9, "bold"))
            self.create_text(x0 + bw / 2, h / 2 + 9, text=b["hash"][:8] or "–", fill=BLUE_MUTED, font=("Consolas", 8))


class _KpiTile(tk.Frame):
    def __init__(self, parent, caption):
        super().__init__(parent, background=BLUE_LINE, bd=0, highlightthickness=0)
        inner = tk.Frame(self, background=WHITE); inner.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Label(inner, text=caption.upper(), font=(UI_FONT, 8, "bold"), foreground=BLUE_MUTED, background=WHITE, anchor="w").pack(fill="x", padx=12, pady=(9, 0))
        self.v_val, self.v_sub = tk.StringVar(value="–"), tk.StringVar()
        self.val = tk.Label(inner, textvariable=self.v_val, font=(UI_FONT, 22, "bold"), foreground=BLUE_DARK, background=WHITE, anchor="w"); self.val.pack(fill="x", padx=12)
        self.sub = tk.Label(inner, textvariable=self.v_sub, font=(UI_FONT, 8), foreground=BLUE_MUTED, background=WHITE, anchor="w"); self.sub.pack(fill="x", padx=12, pady=(0, 9))

    def set(self, value, sub="", sub_color=BLUE_MUTED, value_color=BLUE_DARK):
        self.v_val.set(str(value)); self.v_sub.set(sub); self.sub.configure(foreground=sub_color); self.val.configure(foreground=value_color)


def _delta(cur, prev, polarity="bad_up"):
    """-> (text, colour). Increases are painted red because every tile that uses this is a 'bad if up' count."""
    if prev is None: return "no earlier data", BLUE_MUTED
    if cur == prev: return "same as previous window", BLUE_MUTED
    if not prev: return "▲ from 0 in previous window", BAD_RED
    pct = round(abs(cur - prev) * 100 / prev); up = cur > prev
    return f"{'▲' if up else '▼'} {pct}% vs previous window", BAD_RED if up else OK_GREEN


def daily_summary_text(now=None):
    """The manager's 24-hour summary. 'Access events' are access decisions only: logins, admin changes and manager
    responses are counted separately (they used to be lumped into the access numbers)."""
    now = time.time() if now is None else now; since = now - 86400
    rows = [e for e in list(LOG) if _evt_epoch(e) >= since]
    access = [e for e in rows if siem_category(e) == "Access"]
    counts = Counter(str(e.get("decision", "UNKNOWN")) for e in access)
    failed_logins = sum(1 for e in rows if e.get("resource") in SIEM_AUTH_FAIL_RES and e.get("decision") == "DENY")
    pending = count_pending_signins()
    alerts = [a for a in recent_alerts(limit=500) if _evt_epoch(a) >= since]
    high = sum(1 for a in alerts if str(a.get("severity", "")).upper() in ("HIGH", "CRITICAL"))
    return (f"Last 24 hours\n\nAccess events: {len(access)}\nAllowed: {counts.get('ALLOW', 0)}\n"
            f"Step-up: {counts.get('STEPUP', 0)}\nDenied: {counts.get('DENY', 0)}\nFailed sign-ins: {failed_logins}\n"
            f"Alerts: {len(alerts)} (high/critical: {high})\nPending sign-in requests: {pending}\n"
            f"Audit integrity: {'verified' if verify_chain().get('ok') else 'CHECK REQUIRED'}")


class SiemDashboard(tk.Frame):
    """Manager-console security dashboard: metrics, event stream, threat monitoring, alerts, audit integrity."""
    STREAM_LIMIT = 100
    AUTO_VERIFY_S = 300

    def __init__(self, parent, portal):
        super().__init__(parent, background=WHITE, bd=0, highlightthickness=0)
        self.p = portal
        self.window_s = 3600
        self.paused = False; self._pause_ids = set(); self._prev_ids = None; self._sig = None
        self.verifier = _Verifier(); self.integrity_ok = None; self._verify_detail = ("", []); self._verified_at = None
        self._failure_shown = False; self._last_verify_start = time.time()
        self.snap = None; self._seen_alert_ids = None; self._had_fresh = False
        self._build()
        self.verifier.start()
        self.refresh()
        self.p._schedule("siem", 2000, self._tick)

    # ---- layout
    def _section(self, title, subtitle, badge=None):
        box = ttk.Frame(self.page.body); box.pack(fill="x", pady=(16, 0), padx=2)
        head = ttk.Frame(box); head.pack(fill="x", pady=(0, 6))
        ttk.Label(head, text=title, style="Section.TLabel").pack(side="left")
        if badge is not None: ttk.Label(head, textvariable=badge, style="Accent.TLabel").pack(side="left", padx=(8, 0), pady=(3, 0))
        ttk.Label(head, text=subtitle, style="Muted.TLabel").pack(side="left", padx=(10, 0), pady=(3, 0))
        inner = ttk.Frame(box); inner.pack(fill="x")
        return inner

    def _build(self):
        self.page = ScrollFrame(self); self.page.pack(fill="both", expand=True)
        body = self.page.body; body.configure(padding=(4, 4, 10, 16))
        self.banner = tk.Label(body, text="", background=BAD_RED, foreground=WHITE, font=(UI_FONT, 10, "bold"), anchor="w", justify="left", padx=14, pady=10, wraplength=1000)
        bar = ttk.Frame(body); bar.pack(fill="x"); self.toolbar = bar
        self.live = tk.Canvas(bar, width=12, height=12, background=WHITE, bd=0, highlightthickness=0); self.live.pack(side="left", padx=(0, 6), pady=(2, 0))
        self.live.create_oval(1, 1, 11, 11, fill="#16a34a", outline="", tags="dot")
        self.v_updated = tk.StringVar(value="Loading…"); ttk.Label(bar, textvariable=self.v_updated, style="Muted.TLabel").pack(side="left")
        self.cb_window = ttk.Combobox(bar, state="readonly", width=11, values=[n for n, _ in SIEM_WINDOWS]); self.cb_window.set("1 hour")
        self.cb_window.pack(side="right"); self.cb_window.bind("<<ComboboxSelected>>", self._window_changed)
        ttk.Label(bar, text="Time window", style="Muted.TLabel").pack(side="right", padx=(0, 6))
        self.v_trunc = tk.StringVar(); ttk.Label(body, textvariable=self.v_trunc, style="Muted.TLabel").pack(anchor="w")
        self._build_metrics(); self._build_stream(); self._build_threats(); self._build_alerts(); self._build_integrity()

    def _build_metrics(self):
        f = self._section("Security metrics", "for the selected time window")
        grid = ttk.Frame(f); grid.pack(fill="x")
        self.tiles = {}
        for i, (key, label) in enumerate((("deny", "Denied requests"), ("failed_auth", "Failed sign-ins"), ("alerts", "Open alerts"), ("sessions", "Active sessions"))):
            t = _KpiTile(grid, label); self.tiles[key] = t
            t.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0)); grid.columnconfigure(i, weight=1, uniform="kpi")
        panel = Panel(f, "Event volume by outcome", padding=(8, 6)); panel.pack(fill="x", pady=(10, 0))
        self.timeline = TimelineChart(panel.body, 170); self.timeline.pack(fill="both", expand=True)

    def _build_stream(self):
        f = self._section("Event stream", "newest first, from the tamper-evident audit chain")
        bar = ttk.Frame(f); bar.pack(fill="x", pady=(0, 6))
        self.btn_pause = ttk.Button(bar, text="⏸ Pause", command=self._toggle_pause); self.btn_pause.pack(side="left")
        self.v_rate = tk.StringVar(); ttk.Label(bar, textvariable=self.v_rate, style="Muted.TLabel").pack(side="right")
        self.stream = self.p._tree(f, ("time", "sev", "user", "resource", "decision", "what"), ("Time", "Severity", "User", "Resource", "Decision", "What happened"),
                                   (70, 75, 80, 110, 80, 600), stretch="what")
        self.stream.configure(height=9, selectmode="browse")
        for sev, col in SEV_COLOR.items(): self.stream.tag_configure(f"sev_{sev}", foreground=col if sev != "INFO" else BLUE_TEXT)
        for sev in ("HIGH", "CRITICAL"): self.stream.tag_configure(f"sev_{sev}", foreground=SEV_COLOR[sev], font=(UI_FONT, 9, "bold"))
        self.stream.tag_configure("new", background="#fff7d6")

    def _build_threats(self):
        f = self._section("Threat monitoring", "what looks like an attack right now")
        row = ttk.Frame(f); row.pack(fill="x")
        for c, wt in enumerate((4, 4, 3)): row.columnconfigure(c, weight=wt, uniform="thr")
        p1 = Panel(row, "Threat level", padding=(10, 8)); p1.grid(row=0, column=0, sticky="nsew")
        self.gauge = Gauge(p1.body, 178); self.gauge.pack(fill="x")
        self.factor_box = ttk.Frame(p1.body); self.factor_box.pack(fill="x", pady=(4, 0))
        p2 = Panel(row, "Highest-risk identities", padding=(10, 8)); p2.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self.people_bars = HBars(p2.body, 60); self.people_bars.pack(fill="x")
        p3 = Panel(row, "Active containment", padding=(12, 8)); p3.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
        self.contain = {}
        for i, (key, label) in enumerate((("blocked", "Blocked devices"), ("stepup", "Forced step-up MFA"), ("grants", "Extra access in use"), ("signins", "Sign-ins waiting"))):
            ttk.Label(p3.body, text=label, style="Strong.TLabel").grid(row=i, column=0, sticky="nw", pady=3, padx=(0, 12))
            v = tk.StringVar(value="–"); ttk.Label(p3.body, textvariable=v, wraplength=170, justify="left").grid(row=i, column=1, sticky="nw", pady=3); self.contain[key] = v
        p3.body.columnconfigure(1, weight=1)

    def _build_alerts(self):
        self.v_alert_badge = tk.StringVar()
        f = self._section("Alerts", "open alerts first", badge=self.v_alert_badge)
        bar = ttk.Frame(f); bar.pack(fill="x", pady=(0, 6))
        self.v_alert_sum = tk.StringVar(); ttk.Label(bar, textvariable=self.v_alert_sum, style="Strong.TLabel").pack(side="left")
        ttk.Button(bar, text="Mark reviewed", command=lambda: self.p._ack_alert(self.al_tree)).pack(side="right")
        ttk.Button(bar, text="False alarm", command=lambda: self.p._alert_outcome("false_alarm", self.al_tree)).pack(side="right", padx=6)
        ttk.Button(bar, text="Confirm incident + sign out", style="Primary.TButton", command=lambda: self.p._alert_outcome("incident_confirmed", self.al_tree)).pack(side="right", padx=6)
        self.al_tree = self.p._tree(f, ("time", "sev", "kind", "user", "device", "state"), ("Time", "Severity", "Alert", "User", "Device", "State"), (70, 75, 330, 90, 120, 60), stretch="kind")
        self.al_tree.configure(height=6, selectmode="browse")
        for sev, col in SEV_COLOR.items(): self.al_tree.tag_configure(f"sev_{sev}", foreground=col)
        self.al_tree.tag_configure("seen", foreground=BLUE_MUTED); self.al_tree.tag_configure("fresh", background="#fff7d6")
        self.al_tree.bind("<<TreeviewSelect>>", self._alert_selected)
        self.v_al_detail = tk.StringVar(value="Select an alert to see why it was raised and what to do.")
        ttk.Label(f, textvariable=self.v_al_detail, style="Muted.TLabel", wraplength=1000, justify="left").pack(anchor="w", pady=(6, 0))

    def _build_integrity(self):
        f = self._section("Audit integrity", "hash chain plus two independent anchors")
        panel = Panel(f, padding=14); panel.pack(fill="x")
        top = ttk.Frame(panel.body); top.pack(fill="x"); top.columnconfigure(1, weight=1)
        self.pill = tk.Label(top, text="NOT VERIFIED", font=(UI_FONT, 11, "bold"), foreground=WHITE, background="#64748b", padx=14, pady=8); self.pill.grid(row=0, column=0, sticky="nw", padx=(0, 16))
        self.v_int_head, self.v_int_lines = tk.StringVar(), tk.StringVar()
        txt = ttk.Frame(top); txt.grid(row=0, column=1, sticky="nw")
        ttk.Label(txt, textvariable=self.v_int_head, style="Strong.TLabel").pack(anchor="w")
        ttk.Label(txt, textvariable=self.v_int_lines, style="Muted.TLabel", wraplength=620, justify="left").pack(anchor="w", pady=(2, 0))
        btns = ttk.Frame(top); btns.grid(row=0, column=2, sticky="ne")
        self.btn_verify = ttk.Button(btns, text="Verify now", style="Primary.TButton", command=self._verify_now); self.btn_verify.pack(side="left")
        ttk.Button(btns, text="Export JSONL", command=self.p._export).pack(side="left", padx=(6, 0))
        self.v_int_facts = tk.StringVar(); ttk.Label(panel.body, textvariable=self.v_int_facts, style="Muted.TLabel").pack(anchor="w", pady=(12, 4))
        self.ribbon = ChainRibbon(panel.body, 62); self.ribbon.pack(fill="x")

    # ---- actions
    def _window_changed(self, _e=None):
        self.window_s = dict(SIEM_WINDOWS).get(self.cb_window.get(), 3600); self._prev_ids = None; self.refresh()

    def _verify_now(self):
        if self.verifier.start(): self._last_verify_start = time.time(); self.btn_verify.state(["disabled"]); self._paint_integrity()

    def _toggle_pause(self):
        self.paused = not self.paused
        if self.paused: self._pause_ids = set(self._prev_ids or ())
        self._paint_stream(force=True)

    def _alert_selected(self, _e=None):
        a = self.p._selected_alert(self.al_tree)
        if not a: return
        title, why, advice = describe_alert(a)
        self.v_al_detail.set(f"{title}. {why}  Detail: {a.get('details') or '–'}  Next step: {advice}")

    # ---- refresh
    def _tick(self):
        try:
            if not self.winfo_exists(): return
            al = recent_alerts(limit=1)
            sig = (AUDIT.get("entries"), al[0]["id"] if al else 0)
            if sig != getattr(self, "_tick_sig", None) or self.verifier.result is not None or self.verifier.running:
                self._tick_sig = sig; self.refresh()
        except tk.TclError: return
        except Exception: logger.exception("SIEM dashboard tick failed")
        self.p._schedule("siem", 2000, self._tick)

    def refresh(self):
        self._poll_verifier()
        self.snap = s = siem_snapshot(self.window_s, integrity_ok=self.integrity_ok)
        self.v_updated.set(f"Live · updated {_fmt_ts(s['now'], '%H:%M:%S')}")
        self.live.itemconfigure("dot", fill="#f59e0b" if self.paused else "#16a34a")
        self.v_trunc.set("Showing the most recent 500 audit entries; the selected window reaches further back than the in-memory log." if s["truncated"] else "")
        self._paint_metrics(s); self._paint_stream(); self._paint_threats(s); self._paint_alerts(s); self._paint_integrity()

    def _poll_verifier(self):
        res = self.verifier.result
        if res is None: return
        self.verifier.result = None
        at, r, _took = res
        ok, headline, lines = verify_report(r) if not r.get("error") else (False, f"Verification error: {r['error']}", [])
        self.integrity_ok = bool(ok); self._verify_detail = (headline, lines); self._verified_at = at
        self.btn_verify.state(["!disabled"])
        if not ok and not self._failure_shown:
            self._failure_shown = True
            try: messagebox.showerror("Audit integrity failure", "The audit chain did not verify. Preserve the original log and anchor files and compare with a trusted backup; do not edit the chain.", parent=self.p)
            except tk.TclError: pass
        if ok: self._failure_shown = False

    def _paint_metrics(self, s):
        cur, prev = s["cur_agg"], s["prev_agg"]
        for key in ("deny", "failed_auth"):
            text, color = _delta(cur[key], prev[key] if prev else None)
            self.tiles[key].set(cur[key], text, color, BAD_RED if cur[key] else BLUE_DARK)
        high = sum(1 for a in s["open_alerts"] if a["_sev"] in ("HIGH", "CRITICAL"))
        self.tiles["alerts"].set(len(s["open_alerts"]), f"{high} high severity" if high else "none high severity", BAD_RED if high else BLUE_MUTED, BAD_RED if high else BLUE_DARK)
        self.tiles["sessions"].set(s["sessions"])
        self.timeline.set(buckets=s["buckets"], window=s["window"])

    def _stream_rows(self, s):
        rows, seen = [], set()
        for x in s["cur"][:self.STREAM_LIMIT]:
            label, sentence = _siem_describe(x["raw"])
            h = str(x["raw"].get("hash", "")); iid = h[:20] or f"e{len(rows)}"
            while iid in seen: iid += "_"
            seen.add(iid)
            rows.append({**x, "iid": iid, "label": label, "sentence": sentence})
        return rows

    def _paint_stream(self, force=False):
        s = self.snap
        if s is None: return
        recent = sum(1 for x in s["cur"] if x["ts"] >= s["now"] - 300)
        self.v_rate.set(f"{recent / 5:.1f} events/min · {len(s['cur'])} in window")
        rows = self._stream_rows(s); ids = {r["iid"] for r in rows}
        if self.paused:
            fresh = len(ids - self._pause_ids)
            self.btn_pause.configure(text=f"▶ Resume ({fresh} new)" if fresh else "▶ Resume"); return
        self.btn_pause.configure(text="⏸ Pause")
        fresh = set() if self._prev_ids is None else ids - self._prev_ids
        self._prev_ids = ids
        tags = [(f"sev_{r['sev']}",) + (("new",) if r["iid"] in fresh else ()) for r in rows]
        sig = (tuple(r["iid"] for r in rows), tuple(tags))
        if sig == self._sig and not force: return
        self._sig = sig
        top = self.stream.yview()[0]
        self.stream.delete(*self.stream.get_children())
        for r, tg in zip(rows, tags):
            self.stream.insert("", "end", iid=r["iid"], tags=tg, values=(_fmt_ts(r["ts"], "%H:%M:%S"), r["sev"], r["user"], r["resource"], r["label"], r["sentence"][:300]))
        self.stream.yview_moveto(top)

    def _paint_threats(self, s):
        th = s["threat"]
        self.gauge.set(score=th["score"], level=th["level"], color=th["color"])
        sig = tuple(th["factors"])
        if sig != getattr(self, "_factor_sig", None):
            self._factor_sig = sig
            for w in self.factor_box.winfo_children(): w.destroy()
            if not th["factors"]: ttk.Label(self.factor_box, text="No open alerts or risky traffic are raising the score.", style="Muted.TLabel", wraplength=260).pack(anchor="w")
            for label, pts, detail in th["factors"]:
                r = ttk.Frame(self.factor_box); r.pack(fill="x", pady=1)
                tk.Label(r, text=f"+{pts}", font=(UI_FONT, 9, "bold"), foreground=th["color"], background=WHITE, width=4, anchor="w").pack(side="left")
                ttk.Label(r, text=f"{label} — {detail}", style="Muted.TLabel", wraplength=250, justify="left").pack(side="left")
        self.people_bars.set_rows([(p["name"], p["score"], SEV_COLOR["HIGH"] if p["score"] >= 60 else SEV_COLOR["MEDIUM"] if p["score"] >= 25 else SEV_COLOR["LOW"],
                                    f"{p['deny']} denied · {p['alerts']} alert{'' if p['alerts'] == 1 else 's'}") for p in s["people"]], "No identities with risk signals", 100)
        c = self.contain
        c["blocked"].set(", ".join(s["blocked"]) or "none"); c["stepup"].set(", ".join(s["stepup_users"]) or "none"); c["signins"].set(str(s["pending"]))
        c["grants"].set(", ".join(f"{u} → {r} ({m} min)" for u, r, m in s["temp_grants"]) or "none")

    def _paint_alerts(self, s):
        al = s["alerts"][:120]
        order = sorted(range(len(al)), key=lambda i: (bool(al[i].get("acknowledged")), -al[i]["_ts"]))
        ids = {a.get("id") for a in al}
        fresh = set() if self._seen_alert_ids is None else ids - self._seen_alert_ids
        self._seen_alert_ids = ids
        rows, tags = [], []
        for i in order:
            a = al[i]; seen = bool(a.get("acknowledged"))
            rows.append((_fmt_ts(a["_ts"], "%H:%M:%S"), a["_sev"], describe_alert(a)[0], a.get("user") or "", a.get("device") or "", {0: "NEW", 1: "REVIEWED", 2: "FALSE ALARM", 3: "INCIDENT"}.get(a.get("status", 0), "SEEN")))
            base = ("seen",) if seen or a["_sev"] not in SEV_COLOR else (f"sev_{a['_sev']}",)
            tags.append(base + (("fresh",) if a.get("id") in fresh and not seen else ()))
        # tags are not part of _fill_tree's change signature, so make a highlight change count as a change
        if fresh or self._had_fresh: self.al_tree._sig = None
        self._had_fresh = bool(fresh)
        self.p._fill_tree(self.al_tree, rows, iids=[str(al[i].get("id", "")) for i in order], tags=tags)
        n_open = len(s["open_alerts"]); high = sum(1 for a in s["open_alerts"] if a["_sev"] in ("HIGH", "CRITICAL"))
        text = f"{n_open} open ({high} high)" if n_open else "No open alerts"
        self.v_alert_sum.set(text + (f"  ·  {len(fresh)} new just now" if fresh else ""))
        self.v_alert_badge.set(f"● {n_open}" if n_open else "")

    def _paint_integrity(self):
        st = siem_integrity_state(); running = self.verifier.running
        if running: pill, color, head, lines = "VERIFYING…", "#2563eb", "Scanning every entry and both anchors", []
        elif self.integrity_ok is None: pill, color, head, lines = "NOT VERIFIED", "#64748b", "No full verification has finished yet", []
        else:
            head, lines = self._verify_detail
            pill, color = ("CHAIN INTACT", OK_GREEN) if self.integrity_ok else ("CHAIN BROKEN", BAD_RED)
        self.pill.configure(text=pill, background=color); self.v_int_head.set(head); self.v_int_lines.set("\n".join(lines))
        if self.integrity_ok is False and not running:
            self.banner.configure(text=f"AUDIT INTEGRITY FAILURE — {head}. Preserve the audit log and both anchor files as they are; do not edit hashes to force a pass.")
            if not self.banner.winfo_ismapped(): self.banner.pack(fill="x", pady=(0, 8), before=self.toolbar)
        elif self.banner.winfo_ismapped(): self.banner.pack_forget()
        verified = _fmt_ts(self._verified_at, "%H:%M:%S") if self._verified_at else "never"
        self.v_int_facts.set(f"{st['entries']:,} entries · last full verification {verified} · anchors {'present' if st['anchors'] else 'MISSING'} · recent links {'consistent' if st['linked'] else 'BROKEN'} · latest 8 entries, newest at right:")
        self.ribbon.set(blocks=st["blocks"])
        if self.AUTO_VERIFY_S and not running and time.time() - self._last_verify_start >= self.AUTO_VERIFY_S:
            self._last_verify_start = time.time(); self.verifier.start()

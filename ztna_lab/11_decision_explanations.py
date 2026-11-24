# Part 11 of ztna_lab_v2.py - plain-English access decisions and demo resource previews.
# Not a standalone module: ztna_lab_v2.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ---------- plain-English decisions and per-employee resource previews (demo content) ----------
def _seeded(user, resource):
    return random.Random(int(hashlib.sha256(f"{user}|{resource}".encode()).hexdigest()[:12], 16))

_P_REPOS = ["payments-api", "web-frontend", "mobile-app", "auth-service", "data-pipeline", "search-index", "billing-engine", "notifications", "design-system", "infra-modules"]
_P_COMMITS = ["Fix race condition in retry logic", "Add pagination to list endpoint", "Bump dependencies (security patch)", "Refactor config loader", "Improve error messages", "Add unit tests for edge cases", "Cache expensive lookups", "Remove dead feature flag"]
_P_PIPES = ["build-main", "deploy-staging", "deploy-prod", "nightly-tests", "terraform-plan", "container-scan", "db-migrate", "rollback-check"]
_P_CUST = ["Acme Corp", "Globex", "Initech", "Umbrella Ltd", "Hooli", "Stark Industries", "Wayne Enterprises", "Soylent Co", "Vandelay Imports", "Pied Piper", "Cyberdyne", "Wonka Foods"]
_P_ACCT = ["Accounts payable", "Accounts receivable", "Payroll clearing", "Cloud hosting", "Travel & expenses", "Software licences", "Office lease", "Marketing spend"]
_P_TICKET = ["Cannot reset password", "Invoice shows wrong amount", "App crashes on login", "Export to CSV is empty", "Need to change account owner", "Slow dashboard loading", "Two-factor code not arriving", "Refund request"]
_P_DOCS = ["Master services agreement", "Mutual NDA", "Data processing addendum", "Vendor contract", "Office lease renewal", "Employment template", "Partner agreement", "Privacy policy v4"]
_P_RULES = ["Impossible travel", "Brute-force login", "Unusual data download", "New admin created", "Malware signature hit", "Port scan from guest Wi-Fi", "Disabled endpoint protection", "Off-hours VPN login"]
_P_KPIS = [("Monthly recurring revenue", "$4.82M", "+3.1%"), ("Active customers", "12,480", "+1.4%"), ("Gross margin", "71.2%", "+0.6 pt"), ("Cash runway", "27 months", "no change"), ("Net revenue retention", "112%", "+2 pt"), ("Support CSAT", "94%", "-1 pt"), ("Hiring plan filled", "68%", "+5 pt"), ("Security incidents (30d)", "3", "-2")]
_P_WIKI = {
    "engineer": ["Coding standards", "How to review a pull request", "On-call handbook", "Architecture decision records", "Local dev environment setup"],
    "devops": ["Runbook: failed deploy", "Kubernetes cluster map", "Terraform conventions", "Incident command guide", "Backup and restore drill"],
    "security": ["Incident response plan", "Phishing triage guide", "Vulnerability SLAs", "Zero Trust rollout plan", "Log retention policy"],
    "hr": ["Onboarding checklist", "Performance review calendar", "Leave and holiday policy", "Interview scorecards", "Benefits FAQ"],
    "finance": ["Month-end close checklist", "Expense policy", "Vendor payment terms", "Audit preparation", "Budget calendar"],
    "sales": ["Pricing and discount rules", "Competitor battlecards", "Demo script", "Deal desk process", "Territory map"],
    "support": ["Escalation matrix", "Macro library", "Refund policy", "Known issues", "Tone-of-voice guide"],
    "legal": ["Contract review checklist", "Data protection guide", "IP assignment policy", "Regulatory calendar", "Outside counsel panel"],
    "executive": ["Quarterly priorities", "Board calendar", "Org chart", "Strategy one-pager", "Company values"],
    "admin": ["Joiner / mover / leaver process", "Device enrolment guide", "Backup schedule", "License inventory", "Access review procedure"],
}

def resource_preview(user, resource):
    """A small, believable preview of what `user` sees inside `resource`. Deterministic per user, different for every
    employee. Demo content only (nothing here is real data)."""
    prof = USER_PROFILE.get(user, {}); role = USERS.get(user, {}).get("role", "?")
    who = prof.get("name", user); rnd = _seeded(user, resource)
    pick = lambda pool, n: rnd.sample(pool, min(n, len(pool)))
    if resource == "wiki":
        rows = [(t, rnd.choice(["Team space", "Company", "Handbook"]), f"{rnd.randint(1, 28)} days ago") for t in _P_WIKI.get(role, _P_WIKI["engineer"])[:4]]
        return {"title": f"Wiki pages recommended for {who}", "summary": f"Pages for the '{role}' role.", "columns": ("Page", "Space", "Last edited"), "rows": rows}
    if resource == "hr-db":
        others = [u for u in sorted(USER_PROFILE) if u != user]
        rows = [(USER_PROFILE[u]["name"], USER_PROFILE[u]["dept"], USER_PROFILE[u]["title"], rnd.choice(["Active", "Active", "Active", "On leave"])) for u in pick(others, 5)]
        return {"title": f"Employee records opened by {who}", "summary": "Showing 5 of %d employee records (sample)." % len(USER_PROFILE), "columns": ("Employee", "Department", "Title", "Status"), "rows": rows}
    if resource == "admin-panel":
        weak = sum(1 for d in DEVICES if posture(d) < 70)
        rows = [("Registered users", len(USERS)), ("Registered devices", len(DEVICES)), ("Devices below score 70", weak),
                ("Active sessions", sum(1 for x in list(SESSIONS.values()) if x["exp"] > time.time())), ("Admin signed in", who)]
        return {"title": "IT admin console - live system overview", "summary": "Counts come from the running lab.", "columns": ("Item", "Value"), "rows": rows}
    if resource == "source-code":
        rows = [(r, rnd.choice(["main", "develop", "release"]), rnd.choice(_P_COMMITS), rnd.randint(0, 9)) for r in pick(_P_REPOS, 4)]
        return {"title": f"Repositories visible to {who}", "summary": "Your recent repositories.", "columns": ("Repository", "Branch", "Latest commit", "Open PRs"), "rows": rows}
    if resource == "ci-cd":
        rows = [(n, rnd.choice(["passed", "passed", "passed", "failed", "running"]), f"{rnd.randint(1, 14)}m {rnd.randint(0, 59):02d}s", f"#{rnd.randint(1000, 9999)}") for n in pick(_P_PIPES, 5)]
        return {"title": f"Pipelines owned by {who}", "summary": "Latest runs.", "columns": ("Pipeline", "Status", "Duration", "Run"), "rows": rows}
    if resource == "crm":
        rows = [(c, rnd.choice(["Prospecting", "Demo", "Proposal", "Negotiation", "Closed won"]), f"${rnd.randint(8, 240)}k", who) for c in pick(_P_CUST, 5)]
        return {"title": f"Accounts in {who}'s view", "summary": "Accounts assigned to you.", "columns": ("Account", "Stage", "Deal value", "Owner"), "rows": rows}
    if resource == "finance-ledger":
        rows = [(f"JE-{rnd.randint(10000, 99999)}", a, f"${rnd.randint(1, 480) * 100:,}", rnd.choice(["Posted", "Posted", "Pending approval"])) for a in pick(_P_ACCT, 5)]
        return {"title": f"Ledger entries for {who}", "summary": "Recent journal entries.", "columns": ("Entry", "Account", "Amount", "Status"), "rows": rows}
    if resource == "support-desk":
        rows = [(f"T-{rnd.randint(1000, 9999)}", t, rnd.choice(["Low", "Normal", "High", "Urgent"]), rnd.choice(["Open", "Waiting on customer", "In progress"])) for t in pick(_P_TICKET, 5)]
        return {"title": f"Ticket queue for {who}", "summary": "Tickets assigned to you.", "columns": ("Ticket", "Subject", "Priority", "Status"), "rows": rows}
    if resource == "legal-vault":
        rows = [(d, rnd.choice(_P_CUST), rnd.choice(["Signed", "In review", "Awaiting signature"]), f"20{rnd.randint(27, 29)}-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}") for d in pick(_P_DOCS, 5)]
        return {"title": f"Documents shared with {who}", "summary": "Contracts needing attention.", "columns": ("Document", "Counterparty", "Status", "Expires"), "rows": rows}
    if resource == "siem-console":
        rows = [(rnd.choice(["Critical", "High", "Medium", "Low"]), r, f"host-{rnd.randint(10, 99)}", rnd.randint(1, 40)) for r in pick(_P_RULES, 5)]
        return {"title": f"Alert queue for {who}", "summary": "Open alerts.", "columns": ("Severity", "Rule", "Host", "Events"), "rows": rows}
    if resource == "exec-reports":
        rows = [(m, v, d) for m, v, d in pick(_P_KPIS, 5)]
        return {"title": f"Board dashboard for {who}", "summary": "Latest company KPIs.", "columns": ("Metric", "Value", "Change"), "rows": rows}
    return {"title": resource, "summary": "No preview available.", "columns": ("Info",), "rows": [("-",)]}

def _fmt_hours(r):
    lo, hi = r["hours"]
    return "any time" if (lo, hi) == (0, 24) else f"{lo:02d}:00-{hi:02d}:00"

_TICK, _CROSS = "\u2714", "\u2716"

def resource_requirements(resource):
    """One readable line: what this resource demands."""
    r = RESOURCES[resource]
    bits = [f"device health score {r['min_posture']}+", "company-managed device" if r["managed"] else "any device",
            f"hours: {_fmt_hours(r)}", "from: " + " or ".join(r["locations"]), f"MFA within {r['mfa_age'] // 60} min"]
    return " | ".join(bits)

def explain_decision(resource, result):
    """Turn a raw access result into (verdict, headline, lines, tips) in plain English.
    verdict is ALLOW, STEPUP or DENY; every reason becomes a sentence a non-expert can act on."""
    decision = result.get("decision", "DENY"); r = RESOURCES.get(resource, {})
    if decision == "ALLOW":
        return "ALLOW", f"ACCESS GRANTED - you are in {resource}", [f"All checks passed (risk score {result.get('risk', 0)}/100)."], []
    err = result.get("error", "")
    simple = {"authentication required": ("You are not signed in.", "Open the Overview tab, choose a user, click 'Generate demo OTP', then 'Login'."),
              "session revoked": ("Your session was ended by an administrator.", "Sign in again from the Overview tab."),
              "session expired": ("Your session expired.", "Sign in again from the Overview tab."),
              "unknown resource": ("That system does not exist.", "Pick one of the resource cards."),
              "audit unavailable; action refused": ("The audit log is damaged or unavailable, so every action is refused until it is fixed (fail-closed).", "Open Audit & Integrity: press Verify, then follow the recovery steps shown there.")}
    if err in simple and decision == "DENY" and not result.get("reasons"):
        line, tip = simple[err]
        return "DENY", f"ACCESS DENIED - {line}", [], [tip]
    lines, tips = [], []; role = result.get("role", "?")
    for reason in result.get("reasons", []):
        t = str(reason)
        if t.startswith("RBAC"):
            lines.append(f"Your role ({role}) is not allowed to use {resource}. Allowed roles: {', '.join(r.get('roles', []))}.")
            tips.append("Sign in as a user whose role is on that list (see the 'Roles & Access' tab).")
        elif t.startswith("micro-segmentation"):
            lines.append(f"The network segment for {resource} is closed to your role, so the connection is blocked even before other checks.")
        elif t == "unknown device":
            lines.append("This device is not enrolled, so it cannot be trusted.")
            tips.append("Enroll it in the Identity & Devices tab.")
        elif t == "device not owned by user":
            lines.append("This device belongs to someone else.")
            tips.append("Log in from your own device.")
        elif t.startswith("posture"):
            nums = re.findall(r"\d+", t)
            lines.append(f"Your device health score is {nums[0]}/100 but {resource} needs at least {nums[1]}.")
            d = DEVICES.get(result.get("device"))
            if d and POSTURE_TTL > 0 and time.time() - d.get("last_report", 0) > POSTURE_TTL:
                lines.append(f"Reason: the device has not sent a health report for over {POSTURE_TTL // 60} minutes, so it is treated as unknown (score 0).")
                tips.append("Open Device Posture and turn on the simulated agent, or press 'Send report now'.")
            else:
                tips.append("Open the Device Posture tab and fix the failing checks (OS update, disk encryption, firewall, antivirus).")
        elif t.startswith("corporate-managed"):
            lines.append(f"{resource} only accepts company-managed devices; this one is a personal (BYOD) device.")
            tips.append("Log in from a company laptop instead.")
        elif t.startswith("outside allowed hours"):
            lines.append(f"{resource} is only open {_fmt_hours(r)}; the policy clock reads {result.get('hour', now_hour()):02d}:00.")
            tips.append("Try within those hours, or change the simulated hour on the Policy tab.")
        elif t.startswith("location"):
            lines.append(f"{resource} cannot be opened from your current location. Allowed: {', '.join(r.get('locations', []))}.")
            tips.append("Log in again with an allowed location.")
        elif t.startswith("risk score"):
            lines.append(f"Your overall risk score is too high ({result.get('risk', '?')}/100; 80 or more is blocked).")
            tips.append("Improve device health, use the office, and avoid repeated failed logins.")
        elif t.startswith("MFA older"):
            lines.append(f"{resource} needs a recent MFA check and yours is too old ({t}).")
            tips.append("Use 'Generate OTP' then 'Verify step-up' below, then request access again.")
        else:
            lines.append(t)
    for sig in result.get("signals", []):
        lines.append(f"Risk signal: {sig}.")
    if decision == "STEPUP":
        return "STEPUP", f"EXTRA VERIFICATION NEEDED - {resource}", lines or ["Please confirm your identity again."], tips
    return "DENY", f"ACCESS DENIED - {resource}", lines or ["Policy denied this request."], tips

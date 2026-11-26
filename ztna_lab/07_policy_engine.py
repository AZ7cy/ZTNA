# Part 07 of ztna.py - adaptive policy engine (evaluate), firewall rules, safe upstream fetching.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ---------- adaptive policy engine ----------
REQ_TIMES={}      # "user|device" -> recent request timestamps (suspicious request frequency signal)
SEEN_DEV={}       # user -> devices that have completed a login for that account since start
def _burst_signal(sess,dev):
    """Return extra risk (0/15/30) and a signal text for an unusually high request rate on this user+device."""
    n_lim=_env_int("ZTNA_RISK_BURST_N",40,1,100000); now=time.time()
    # evaluate() runs on the gateway's worker threads: counting while another thread appends raised
    # "deque mutated during iteration" (an HTTP 500 with no audit entry).
    with LOCK:
        q=REQ_TIMES.setdefault(f"{sess.get('user')}|{dev}",deque(maxlen=max(500,n_lim*4))); q.append(now)
        n=sum(1 for t in q if now-t<10)
    if n>3*n_lim: return 30,f"request burst ({n} in 10s)"
    if n>n_lim: return 15,f"request burst ({n} in 10s)"
    return 0,None

def evaluate(sess, dev, res):
    """-> (ALLOW|DENY|STEPUP, reasons, risk 0-100, signals). Runs on EVERY request (continuous evaluation)."""
    r, why, sig, d = RESOURCES[res], [], [], DEVICES.get(dev)
    role, ps = USERS[sess["user"]]["role"], (posture(dev) if dev in DEVICES else 0)
    if not rbac_allows(sess["user"], res): why.append(f"RBAC: role '{role}' not permitted")
    if not segment_allows(sess["user"], res): why.append(f"micro-segmentation: {SEGMENTS[res]} blocked for role '{role}'")
    if dev in BLOCKED_DEVICES: why.append("device blocked by manager")
    if not d: why.append("unknown device")
    else:
        if d["owner"] != sess["user"]: why.append("device not owned by user")
        if ps < r["min_posture"]: why.append(f"posture {ps} < required {r['min_posture']}")
        if r["managed"] and not d["corporate_managed"]: why.append("corporate-managed device required")
    lo, hi = r["hours"]; h=now_hour(); inh = (lo <= h < hi) if lo < hi else (h >= lo or h < hi)
    if not inh: why.append(f"outside allowed hours {lo}:00-{hi}:00")
    if sess["location"] not in r["locations"]: why.append(f"location '{sess['location']}' not allowed")
    risk = 100 - ps + {"office": 0, "home": 5}.get(sess["location"], 25) + (0 if inh else 10)
    if recent_fails(sess["user"],sess.get("auth_ip")): n=recent_fails(sess["user"],sess.get("auth_ip")); risk += min(30,10*n); sig.append(f"{n} recent failed logins")
    if sess.get("travel"): risk += 30; sig.append("location change within 5 min")
    if sess.get("new_device"): risk += 10; sig.append("device first seen for this account")
    extra,txt=_burst_signal(sess,dev)
    if extra: risk += extra; sig.append(txt)
    risk = min(risk, 100)
    if why: return "DENY", why, risk, sig
    if risk >= 80: return "DENY", [f"risk score {risk} >= 80"], risk, sig
    max_age = min(r["mfa_age"], 60) if risk >= 50 else r["mfa_age"]      # risky context -> fresher MFA
    if time.time() - sess["mfa_at"] > max_age: return "STEPUP", [f"MFA older than {max_age}s"], risk, sig
    return "ALLOW", ["all policy checks passed"], risk, sig

SEG = {"wiki": "10.10.1.10", "hr-db": "10.10.2.10", "admin-panel": "10.10.3.10", "source-code": "10.10.4.10", "ci-cd": "10.10.5.10",
       "crm": "10.10.6.10", "finance-ledger": "10.10.7.10", "support-desk": "10.10.8.10", "legal-vault": "10.10.9.10",
       "siem-console": "10.10.10.10", "exec-reports": "10.10.11.10"}   # one micro-segment per protected resource
def firewall_rules(proxy="10.10.0.2"):
    return (["# dry run - review before applying on a gateway", "iptables -P FORWARD DROP",
             "iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP",
             "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
            + [f"iptables -A FORWARD -s {proxy} -d {ip} -p tcp --dport 80 -j ACCEPT  # ZTNA proxy -> {r} only" for r, ip in SEG.items()]
            + ["# no segment-to-segment rule exists => lateral movement is dropped", "iptables -A FORWARD -m limit --limit 5/min --limit-burst 20 -j LOG --log-prefix 'ZTNA-DROP '",
               "# IPv6 must use an equivalent ip6tables default-deny policy; do not leave IPv6 enabled without it."])

def net_acl_trusted(ip):
    """Conventional perimeter rule: anything on a trusted (private/loopback) network is allowed."""
    try: a=ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError: return False
    return a.is_loopback or any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))

pct = lambda v, p: (lambda s: round(s[min(len(s) - 1, int(len(s) * p))], 3) if s else 0)(sorted(list(v)))
AUDIT_SYSTEM_RESOURCES={"identity-create","device-enrollment","audit-repair","audit-reset","audit-export","alert-review","login","stepup","posture","session","sim","firewall","policy","inspect","headers","download","upload","manager-login","signin-request","manager-logout","-"}
def audit_resource(resource):
    if resource in RESOURCES or resource in AUDIT_SYSTEM_RESOURCES: return str(resource)
    raw=str(resource or "")[:512]
    return "unknown:"+sha(raw)[:16]

def safe(x):
    s=str(x)
    return "'"+s if s[:1] in ("=","+","-","@","\t","\r") else s

# ---------- upstream safety ----------
MAX_UPSTREAM_BODY=1048576
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise urllib.error.HTTPError(req.full_url,code,"redirects disabled",headers,fp)

class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that uses a previously validated IP instead of resolving the hostname again."""
    def __init__(self, host, connect_ip, **kwargs):
        self._connect_ip = connect_ip
        super().__init__(host, **kwargs)
    def connect(self):
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host: self._tunnel()

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated IP while retaining hostname SNI/certificate checks."""
    def __init__(self, host, connect_ip, **kwargs):
        self._connect_ip = connect_ip
        super().__init__(host, **kwargs)
    def connect(self):
        raw = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = raw
            self._tunnel()
            raw = self.sock
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)

class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, connect_ip): super().__init__(); self.connect_ip = connect_ip
    def http_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedHTTPConnection(host, self.connect_ip, **kw), req)

class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connect_ip): super().__init__(); self.connect_ip = connect_ip
    def https_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedHTTPSConnection(host, self.connect_ip, **kw), req,
                            context=self._context, check_hostname=self._check_hostname)

def fetch_upstream(url):
    """Fetch only explicitly allowlisted public upstreams; reject private, loopback, link-local and reserved IPs."""
    u=urlsplit(url or "")
    if u.scheme not in ("http","https") or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError("unsupported upstream URL")
    host = u.hostname.rstrip(".").lower()
    if not host or len(host) > 253: raise ValueError("invalid upstream host")
    allow = {x.strip().lower().rstrip(".") for x in os.environ.get("ZTNA_UPSTREAM_ALLOWLIST", "").split(",") if x.strip()}
    if not allow or host not in allow:
        raise ValueError("upstream host is not allowlisted")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError: raise ValueError("invalid upstream port") from None
    if not 1 <= port <= 65535: raise ValueError("invalid upstream port")
    try:
        addresses = {x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except OSError: raise ValueError("upstream DNS lookup failed") from None
    if not addresses: raise ValueError("upstream host did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%",1)[0])
        if not ip.is_global or ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("upstream resolved to a non-public address")
    # Pin the actual socket to the IP we validated, preventing DNS rebinding between validation and connect.
    pinned_ip = sorted(addresses)[0]
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect,
                                       _PinnedHTTPHandler(pinned_ip), _PinnedHTTPSHandler(pinned_ip))
    req=urllib.request.Request(url,method="GET",headers={"Connection":"close"})
    with opener.open(req,timeout=3) as r:
        data=r.read(MAX_UPSTREAM_BODY+1)
        if len(data)>MAX_UPSTREAM_BODY: raise ValueError("upstream response too large")
        return json.loads(data)

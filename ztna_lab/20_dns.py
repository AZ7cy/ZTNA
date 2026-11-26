# Part 20 of ztna.py - lab DNS server and the dns command.
# Not a standalone module: ztna.py runs every part in order in one shared namespace, so names
# defined in earlier parts are used here without imports. See ztna_lab/README.md.
# pyright: reportUndefinedVariable=false

# ============================================================
# Lab toolkit: DNS server, remote admin console, systemd unit
# (standalone: none of these touch the audit log, users or session state)
# ============================================================
_DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "ANY": 255}
_DNS_TYPE_NAMES = {v: k for k, v in _DNS_TYPES.items()}
_DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_DNS_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
DNS_MAX_RECORDS = 1000


def dns_norm_name(name):
    """Lower-case, strip the trailing dot and validate a DNS name (LDH + underscore, 63/253 length limits)."""
    n = str(name).strip().lower().rstrip(".")
    if not n or len(n) > 253 or not all(_DNS_LABEL_RE.match(label) for label in n.split(".")):
        raise ValueError(f"invalid DNS name: {str(name)[:80]!r}")
    return n


def dns_encode_name(name):
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_parse_name(buf, off, *, allow_pointers=True):
    """Parse a (possibly compressed) name at buf[off]; returns (name, offset just after it)."""
    labels, end, hops = [], None, 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if not allow_pointers or off + 1 >= len(buf):
                raise ValueError("bad compression pointer")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if end is None:
                end = off + 2
            hops += 1
            if hops > 16 or ptr >= len(buf):
                raise ValueError("bad compression pointer")
            off = ptr
            continue
        if ln & 0xC0:
            raise ValueError("bad label type")
        off += 1
        if off + ln > len(buf):
            raise ValueError("truncated label")
        labels.append(buf[off:off + ln].decode("ascii"))
        off += ln
        if sum(len(x) + 1 for x in labels) > 254:
            raise ValueError("name too long")
    return ".".join(labels).lower(), (end if end is not None else off)


class DnsRecords:
    """A/CNAME store persisted as JSON; one record per name. Edits from other processes (the `dns` CLI) are picked up live."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._sig = None
        self._table = {}
        self._checked = 0.0

    @staticmethod
    def validate(kind, name, value):
        kind = str(kind).upper()
        name = dns_norm_name(name)
        if kind == "A":
            ip = ipaddress.ip_address(str(value).strip())
            if ip.version != 4:
                raise ValueError("A record value must be an IPv4 address")
            value = str(ip)
        elif kind == "CNAME":
            value = dns_norm_name(value)
            if value == name:
                raise ValueError("a CNAME cannot point to itself")
        else:
            raise ValueError("record type must be A or CNAME")
        return kind, name, value

    def _read_file(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise ValueError(f"cannot read {self.path}: {exc}") from None
        items = raw.get("records") if isinstance(raw, dict) else None
        if not isinstance(items, list) or len(items) > DNS_MAX_RECORDS:
            raise ValueError(f"{self.path}: expected {{\"records\": [...]}} with at most {DNS_MAX_RECORDS} entries")
        table = {}
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{self.path}: record entries must be objects")
            kind, name, value = self.validate(item.get("type"), item.get("name"), item.get("value"))
            table[name] = (kind, value)
        return table

    def table(self, max_age=1.0):
        """Current {name: (type, value)} snapshot; the file is re-stat'ed at most once per max_age seconds."""
        now = time.monotonic()
        with self._lock:
            if now - self._checked >= max_age:
                self._checked = now
                try:
                    st = os.stat(self.path)
                    sig = (st.st_mtime_ns, st.st_size)
                except FileNotFoundError:
                    sig = None
                if sig != self._sig:
                    try:
                        self._table = self._read_file() if sig else {}
                        self._sig = sig
                    except ValueError as exc:
                        logger.error("DNS records not reloaded (keeping previous table): %s", exc)
                        self._sig = sig
            return self._table

    def _write(self, table):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        data = {"records": [{"type": k, "name": n, "value": v} for n, (k, v) in sorted(table.items())]}
        _atomic_json_replace(self.path, data)

    def add(self, kind, name, value):
        kind, name, value = self.validate(kind, name, value)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.path, timeout=10):
            table = self._read_file()
            if name not in table and len(table) >= DNS_MAX_RECORDS:
                raise ValueError(f"record limit reached ({DNS_MAX_RECORDS})")
            table[name] = (kind, value)
            self._write(table)
        self._checked = 0.0
        return kind, name, value

    def remove(self, name):
        name = dns_norm_name(name)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.path, timeout=10):
            table = self._read_file()
            existed = table.pop(name, None) is not None
            if existed:
                self._write(table)
        self._checked = 0.0
        return existed


class DnsQuery:
    __slots__ = ("raw", "txid", "flags", "opcode", "rd", "qname", "qtype", "qclass", "question")


def dns_parse_query(raw):
    """Return (DnsQuery or None, error rcode or None). (None, None) means drop silently (runt packet or a response)."""
    if len(raw) < 12:
        return None, None
    flags = struct.unpack("!H", raw[2:4])[0]
    if flags & 0x8000:
        return None, None
    q = DnsQuery()
    q.raw, q.txid, q.flags = raw, raw[:2], flags
    q.opcode, q.rd = (flags >> 11) & 0xF, bool(flags & 0x0100)
    q.qname = q.qtype = q.qclass = None
    q.question = b""
    if q.opcode != 0:
        return q, 4
    if struct.unpack("!H", raw[4:6])[0] != 1:
        return q, 1
    try:
        name, off = dns_parse_name(raw, 12, allow_pointers=False)
        if off + 4 > len(raw):
            raise ValueError("truncated question")
        qtype, qclass = struct.unpack("!HH", raw[off:off + 4])
    except (ValueError, struct.error):
        return q, 1
    q.qname, q.qtype, q.qclass, q.question = name, qtype, qclass, raw[12:off + 4]
    return q, None


def dns_response(q, rcode, *, ra=False, aa=False, tc=False, answers=b"", ancount=0):
    flags = 0x8000 | (q.opcode << 11) | (0x0400 if aa else 0) | (0x0200 if tc else 0) | (0x0100 if q.rd else 0) | (0x0080 if ra else 0) | rcode
    return q.txid + struct.pack("!HHHHH", flags, 1 if q.question else 0, ancount, 0, 0) + q.question + answers


def dns_local_answer(q, table, ttl, ra=False):
    """Authoritative answer for names in the lab table (CNAME chains followed), or None if the name is not ours."""
    if q.qname not in table:
        return None
    want_cname = q.qtype == _DNS_TYPES["CNAME"]
    chain, seen, name = [], set(), q.qname
    while len(chain) < 9:
        rec = table.get(name)
        if rec is None:
            break
        if name in seen:
            return dns_response(q, 2, ra=ra)  # CNAME loop -> SERVFAIL
        seen.add(name)
        chain.append((name, rec[0], rec[1]))
        if rec[0] != "CNAME" or want_cname:
            break
        name = rec[1]
    else:
        return dns_response(q, 2, ra=ra)      # chain too long -> SERVFAIL
    rrs = []
    for n, kind, value in chain:
        if kind == "CNAME":
            rtype, rdata = 5, dns_encode_name(value)
        elif q.qtype in (1, 255):
            rtype, rdata = 1, socket.inet_aton(value)
        else:
            continue                           # name exists, but not for this type: NOERROR/NODATA
        rrs.append(dns_encode_name(n) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata)
    resp = dns_response(q, 0, ra=ra, aa=True, answers=b"".join(rrs), ancount=len(rrs))
    return resp if len(resp) <= 512 else dns_response(q, 0, ra=ra, aa=True, tc=True)


def dns_parse_response(buf):
    """Decode a DNS response (A / AAAA / CNAME rdata understood; others are shown as hex)."""
    if len(buf) < 12:
        raise ValueError("short response")
    txid, flags, qd, an = struct.unpack("!HHHH", buf[:8])
    off = 12
    for _ in range(qd):
        _, off = dns_parse_name(buf, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = dns_parse_name(buf, off)
        if off + 10 > len(buf):
            raise ValueError("truncated record")
        rtype, _cls, ttl, rlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        if off + rlen > len(buf):
            raise ValueError("truncated rdata")
        rdata = buf[off:off + rlen]
        if rtype == 1 and rlen == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 28 and rlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            value, _ = dns_parse_name(buf, off)
        else:
            value = rdata.hex()
        answers.append({"name": name, "type": _DNS_TYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl, "value": value})
        off += rlen
    return {"txid": txid, "rcode": _DNS_RCODES.get(flags & 0xF, str(flags & 0xF)), "aa": bool(flags & 0x400),
            "tc": bool(flags & 0x200), "ra": bool(flags & 0x80), "answers": answers}


def _split_hostport(text, default_port):
    """Parse 'ip', 'ip:port', '[v6]:port' (IP literals only, so no surprise name resolution)."""
    t = str(text).strip()
    host, port = t, default_port
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        if rest.startswith(":"):
            port = rest[1:]
        elif rest:
            raise ValueError(f"bad address {text!r}")
    elif t.count(":") == 1:
        host, _, port = t.partition(":")
    try:
        ip = ipaddress.ip_address(host)
        port = int(port)
    except ValueError:
        raise ValueError(f"expected an IP address with optional port, got {text!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range in {text!r}")
    return str(ip), port


def dns_query_once(name, qtype, server, *, timeout=2.0):
    """Send one query (RD set) and return the decoded response plus round-trip time in ms."""
    host, port = server
    qname = dns_norm_name(name)
    txid = secrets.randbits(16)
    packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_encode_name(qname) + struct.pack("!HH", qtype, 1)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.sendto(packet, (host, port))
        deadline = time.monotonic() + timeout
        while True:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            data, addr = sock.recvfrom(4096)
            if addr[0] == host and addr[1] == port and data[:2] == packet[:2]:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out")
        rtt = (time.perf_counter() - t0) * 1000
    result = dns_parse_response(data)
    result["rtt_ms"] = round(rtt, 3)
    return result


class LabDnsServer:
    """UDP DNS for the lab: authoritative for the A/CNAME table, REFUSED for everything else (deny by default).
    Optional forwarding to one upstream resolver, limited to allow-listed client networks; per-client rate limit."""

    def __init__(self, host, port, records, *, ttl=30, forward=None, forward_clients=(), rate=50, workers=8):
        self.records, self.ttl, self.forward = records, ttl, forward
        self.forward_clients = list(forward_clients)
        self.rate = float(rate)
        self.family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self.address = self.sock.getsockname()[:2]
        self.queries = deque(maxlen=500)
        self._buckets = OrderedDict()          # least-recently-seen first; hard-capped at BUCKET_LIMIT
        self._bucket_lock = threading.Lock()
        self._pending = threading.BoundedSemaphore(256)
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ztna-dns")
        self._stop = threading.Event()

    BUCKET_LIMIT = 4096

    def _allow(self, ip):
        now = time.monotonic()
        with self._bucket_lock:
            tokens, last = self._buckets.get(ip, (self.rate, now))
            tokens = min(self.rate, tokens + (now - last) * self.rate)
            allowed = tokens >= 1
            self._buckets[ip] = (tokens - 1 if allowed else tokens, now)
            self._buckets.move_to_end(ip)
            while len(self._buckets) > self.BUCKET_LIMIT:
                self._buckets.popitem(last=False)   # evict the idlest source; memory stays bounded under spoofed-source floods
            return allowed

    def _may_forward(self, ip):
        if not self.forward:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in net for net in self.forward_clients)

    def _forward_query(self, q):
        host, port = self.forward
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.sendto(q.raw, (host, port))
            deadline = time.monotonic() + 2.0
            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    return None
                sock.settimeout(remain)
                try:
                    data, addr = sock.recvfrom(65535)
                except (socket.timeout, OSError):
                    return None
                # accept only the upstream's reply to *this* query (id + echoed question), never a stray datagram
                if addr[0] == host and addr[1] == port and len(data) >= 12 + len(q.question) and data[:2] == q.txid and data[2] & 0x80 and data[12:12 + len(q.question)] == q.question:
                    return data

    def _log(self, ip, q, rcode, how):
        qtype = _DNS_TYPE_NAMES.get(q.qtype, str(q.qtype)) if q and q.qtype is not None else "-"
        qname = q.qname if q and q.qname is not None else "-"
        self.queries.append({"ts": time.time(), "client": ip, "qname": qname, "qtype": qtype, "rcode": rcode, "via": how})
        logger.info("dns %s %a %s -> %s (%s)", ip, qname, qtype, rcode, how)

    def handle(self, data, addr):
        ip = addr[0]
        try:
            if not self._allow(ip):
                return
            q, err = dns_parse_query(data)
            if q is None:
                return
            ra = bool(self.forward)
            if err is not None:
                resp, how = dns_response(q, err, ra=ra), "error"
            elif q.qclass not in (1, 255):
                resp, how = dns_response(q, 5, ra=ra), "refused"
            else:
                resp = dns_local_answer(q, self.records.table(), self.ttl, ra)
                how = "local"
                if resp is None and self._may_forward(ip):
                    resp, how = self._forward_query(q), "forward"
                    if resp is None:
                        resp, how = dns_response(q, 2, ra=ra), "forward-failed"
                elif resp is None:
                    resp, how = dns_response(q, 5, ra=ra), "refused"
            self._log(ip, q, _DNS_RCODES.get(resp[3] & 0xF, str(resp[3] & 0xF)), how)
            self.sock.sendto(resp, addr)
        except OSError:
            pass
        except Exception:
            logger.exception("dns handler failed")
        finally:
            self._pending.release()

    def serve_forever(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            if not self._pending.acquire(blocking=False):
                continue  # overloaded: drop rather than queue without bound
            try:
                self._pool.submit(self.handle, data, addr)
            except RuntimeError:
                self._pending.release()
                break

    def shutdown(self):
        self._stop.set()

    def close(self):
        self._stop.set()
        self._pool.shutdown(wait=False, cancel_futures=True)
        try:
            self.sock.close()
        except OSError:
            pass


def _dns_records_path():
    return os.environ.get("ZTNA_DNS_RECORDS") or os.path.join(DATA_DIR, "dns_records.json")


def run_dns_server():
    host = os.environ.get("ZTNA_DNS_HOST", "127.0.0.1").strip() or "127.0.0.1"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit(f"ZTNA_DNS_HOST must be an IP address (got {host!r})") from None
    port = _env_int("ZTNA_DNS_PORT", 5353, 1, 65535)
    if not _is_loopback_bind(host) and os.environ.get("ZTNA_DNS_ALLOW_REMOTE") != "1":
        raise SystemExit("refusing to bind the lab DNS server to a non-loopback address; set ZTNA_DNS_ALLOW_REMOTE=1 to override")
    ttl = _env_int("ZTNA_DNS_TTL", 30, 0, 86400)
    rate = _env_int("ZTNA_DNS_RATE", 50, 1, 100000)
    forward = None
    raw_forward = os.environ.get("ZTNA_DNS_FORWARD", "").strip()
    if raw_forward:
        try:
            forward = _split_hostport(raw_forward, 53)
        except ValueError as exc:
            raise SystemExit(f"ZTNA_DNS_FORWARD: {exc}") from None
    clients = _parse_cidrs("ZTNA_DNS_FORWARD_CLIENTS", "127.0.0.0/8,::1/128")
    records = DnsRecords(_dns_records_path())
    try:
        records._read_file()
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    try:
        server = LabDnsServer(host, port, records, ttl=ttl, forward=forward, forward_clients=clients, rate=rate)
    except PermissionError:
        raise SystemExit(f"permission denied binding {host}:{port}: ports below 1024 need elevated rights (or CAP_NET_BIND_SERVICE)") from None
    except OSError as exc:
        raise SystemExit(f"cannot bind {host}:{port}: {exc}") from None
    logger.info("Lab DNS listening on %s:%s udp; records=%s; forwarding=%s", server.address[0], server.address[1], records.path,
                f"{forward[0]}:{forward[1]} for {[str(c) for c in clients]}" if forward else "off (unknown names -> REFUSED)")
    previous = {}

    def _stop(*_):
        server.shutdown()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass
    try:
        server.serve_forever()
    finally:
        server.close()
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
    return 0


def run_dns_cli(args):
    usage = ("usage: dns serve | dns list | dns add NAME IPV4 | dns cname NAME TARGET | dns remove NAME\n"
             "       dns query NAME [A|AAAA|CNAME|ANY] [IP[:PORT]]\n"
             "       dns probe NAME [IP[:PORT]] [count 1-1000] [interval_ms 0-60000]")
    if not args:
        raise SystemExit(usage)
    cmd, rest = args[0].lower(), args[1:]
    try:
        if cmd == "serve" and not rest:
            return run_dns_server()
        store = DnsRecords(_dns_records_path())
        if cmd == "list" and not rest:
            table = store._read_file()
            print(json.dumps({"records": [{"type": k, "name": n, "value": v} for n, (k, v) in sorted(table.items())]}, indent=2))
            return 0
        if cmd == "add" and len(rest) == 2:
            print(json.dumps(dict(zip(("type", "name", "value"), store.add("A", rest[0], rest[1])))))
            return 0
        if cmd == "cname" and len(rest) == 2:
            print(json.dumps(dict(zip(("type", "name", "value"), store.add("CNAME", rest[0], rest[1])))))
            return 0
        if cmd == "remove" and len(rest) == 1:
            existed = store.remove(rest[0])
            print(json.dumps({"removed": existed, "name": dns_norm_name(rest[0])}))
            return 0 if existed else 1
        default_server = ("127.0.0.1", _env_int("ZTNA_DNS_PORT", 5353, 1, 65535))
        if cmd == "query" and 1 <= len(rest) <= 3:
            qtype_name = (rest[1] if len(rest) > 1 else "A").upper()
            if qtype_name not in _DNS_TYPES:
                raise ValueError(f"query type must be one of {sorted(_DNS_TYPES)}")
            server = _split_hostport(rest[2], default_server[1]) if len(rest) > 2 else default_server
            result = dns_query_once(rest[0], _DNS_TYPES[qtype_name], server)
            result["server"] = f"{server[0]}:{server[1]}"
            print(json.dumps(result, indent=2))
            return 0 if result["rcode"] == "NOERROR" else 1
        if cmd == "probe" and 1 <= len(rest) <= 4:
            server = _split_hostport(rest[1], default_server[1]) if len(rest) > 1 else default_server
            count = int(rest[2]) if len(rest) > 2 else 20
            gap = int(rest[3]) if len(rest) > 3 else 200
            if not 1 <= count <= 1000 or not 0 <= gap <= 60000:
                raise ValueError("count must be 1-1000 and interval_ms 0-60000")
            samples, failures, rcodes = [], 0, Counter()
            for i in range(count):
                try:
                    r = dns_query_once(rest[0], 1, server)
                    samples.append(r["rtt_ms"])
                    rcodes[r["rcode"]] += 1
                except (OSError, ValueError):
                    failures += 1
                if gap and i < count - 1:
                    time.sleep(gap / 1000.0)
            out = probe_stats(samples, failures)
            out.update({"server": f"{server[0]}:{server[1]}", "name": dns_norm_name(rest[0]), "rcodes": dict(rcodes)})
            print(json.dumps(out, indent=2))
            return 0 if samples else 1
    except (ValueError, TimeoutError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    raise SystemExit(usage)

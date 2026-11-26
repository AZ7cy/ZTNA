"""Regression tests for the ZTNA lab (standard-library unittest; pytest also runs them).

Run from the project root:   python -m unittest discover -s tests -v

Every test uses an isolated temporary data directory in DEMO mode, so no real
state is touched. The legacy server is started as a subprocess on a free port,
exactly as a user would run it.
"""
import base64, hashlib, hmac, http.client, importlib.util, json, os, secrets, shutil, signal, socket, sqlite3, subprocess, sys, tempfile, threading, time, unittest
import urllib.error, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _find_script():
    # Works from project/tests/ (normal layout) or with the test next to the script.
    for d in (HERE.parent, HERE):
        if (d / "ztna.py").is_file():
            return str(d / "ztna.py")
    raise SystemExit(
        "ztna.py not found next to or above this test file.\n"
        "Extract the whole zip first (do not run the test from inside the zip preview), "
        "then run from the project folder:\n    python -m unittest discover -s tests -v"
    )


SCRIPT = _find_script()
ADMIN_KEY = "0123456789abcdef0123456789abcdef0123"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_env(data_dir, port=None, **extra):
    env = dict(os.environ, ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DEMO_FIXED_CREDENTIALS="1",
               ZTNA_DATA_DIR=str(data_dir), ZTNA_ADMIN_KEY=ADMIN_KEY)
    if port:
        env["ZTNA_PORT"] = str(port)
    env.update(extra)
    return env


def _kill_tree(proc):
    """Kill the child's whole process group (it is its own session leader), then reap it."""
    try:
        if os.name != "nt":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def run(args, env, timeout=60, input=None):
    """Run the CLI with a hard deadline. On timeout the process group is killed, reaped and its pipes
    closed, then the test fails with whatever output was captured (never hangs, never leaks)."""
    proc = subprocess.Popen([sys.executable, SCRIPT, *args], env=env,
                            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=(os.name != "nt"))
    try:
        out, err = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out = err = ""
        raise AssertionError(f"CLI timed out after {timeout}s: {args}\nstdout={out!r}\nstderr={err!r}") from None
    finally:
        for f in (proc.stdin, proc.stdout, proc.stderr):
            if f:
                try: f.close()
                except Exception: pass
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def spawn(args, env, errfile):
    """Long-running child: stderr goes to a file (no pipe to fill up or leak), stdin is closed."""
    return subprocess.Popen([sys.executable, SCRIPT, *args], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=errfile,
                            start_new_session=(os.name != "nt"))


def stop(proc, errfile=None):
    """Terminate, escalate to kill, always reap, always close the stderr file."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
    if errfile is not None:
        errfile.close()


def tail(path, n=1500):
    try:
        return Path(path).read_bytes()[-n:].decode(errors="replace")
    except OSError:
        return ""


class IsolatedLab(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ztna_test_")
        self.data = Path(self.tmp) / "data"
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class ServerCase(IsolatedLab):
    def setUp(self):
        super().setUp()
        port = free_port()
        self.env = make_env(self.data, port)
        self.url = f"http://127.0.0.1:{port}"
        self.errpath = Path(self.tmp) / "server.stderr"
        self.errfile = open(self.errpath, "wb")
        self.proc = spawn(["server"], self.env, self.errfile)
        self.addCleanup(self._stop)
        for _ in range(60):
            if self.proc.poll() is not None:
                self.fail(f"server exited early with code {self.proc.returncode}: " + tail(self.errpath))
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.2)
        self.fail("server did not start within 12 seconds")

    def _stop(self):
        stop(self.proc, self.errfile)


class TestBuiltin(IsolatedLab):
    def test_selftest(self):
        r = run(["selftest"], make_env(self.data))
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])
        self.assertIn(" 0 failed", r.stdout)

    def test_bad_config_fails_fast(self):
        for name, value in (("ZTNA_SESSION_MAX", "abc"), ("ZTNA_AUTH_BACKOFF_BASE", "nan")):
            with self.subTest(name=name):
                r = run(["iptables"], make_env(self.data, **{name: value}))
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(name, r.stdout + r.stderr)


class TestProbe(IsolatedLab):
    def test_probe_stats_math(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("ztna_under_test", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)          # module is import-safe
        st = mod.probe_stats([10, 20, 30, 40, 50], failures=1)
        self.assertEqual((st["sent"], st["ok"], st["failed"]), (6, 5, 1))
        self.assertEqual((st["min"], st["avg"], st["p50"], st["max"]), (10, 30, 30, 50))
        self.assertEqual(st["jitter"], 10)
        self.assertEqual(mod.probe_stats([], failures=3)["ok"], 0)

    def test_probe_rejects_bad_input(self):
        env = make_env(self.data)
        for args in ([], ["ftp://x"], ["http://127.0.0.1", "0"], ["http://127.0.0.1", "5", "999999"]):
            with self.subTest(args=args):
                self.assertNotEqual(run(["probe", *args], env).returncode, 0)


class TestServer(ServerCase):
    def test_probe_against_server(self):
        r = run(["probe", self.url + "/baseline", "5", "10"], self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        result = json.loads(r.stdout)
        self.assertEqual((result["ok"], result["failed"]), (5, 0))
        self.assertIn("p95", result)

    def test_inspector_requires_auth(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.url + "/inspect")
        self.assertEqual(cm.exception.code, 401)

    def test_red_team_suite(self):
        """All attack scenarios: forged JWT, stolen token, BYOD, off-hours,
        brute force, revoked session, posture forgery, TOTP replay..."""
        r = run(["attack", self.url], self.env)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        self.assertNotIn("FAIL", r.stdout)

    def test_admin_api_requires_key(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.url + "/api/logs")
        self.assertEqual(cm.exception.code, 401)

    def test_bad_host_header_rejected(self):
        req = urllib.request.Request(self.url + "/baseline", headers={"Host": "evil.example"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 421)

    def test_unauthenticated_access_denied(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.url + "/access/hr-db")
        self.assertEqual(cm.exception.code, 401)

    def test_audit_tamper_is_detected(self):
        """Rewrite one audit record on disk -> `verify` must exit non-zero."""
        for _ in range(3):
            try:
                urllib.request.urlopen(self.url + "/access/wiki")
            except urllib.error.HTTPError:
                pass
        time.sleep(0.5)
        audit = self.data / "audit.jsonl"
        self.assertTrue(audit.exists() and audit.stat().st_size > 0)
        self.assertEqual(run(["verify"], self.env).returncode, 0)

        lines = audit.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["decision"] = "ALLOW"          # attacker rewrites history
        lines[0] = json.dumps(rec, separators=(",", ":"))
        audit.write_text("\n".join(lines) + "\n")
        self.assertEqual(run(["verify"], self.env).returncode, 1)


# ---------------------------------------------------------------- lab toolkit

def load_module():
    spec = importlib.util.spec_from_file_location("ztna_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # module is import-safe
    return mod


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LabClient:
    """Minimal device-bound client: password + TOTP login, then per-request proof-of-possession headers."""

    def __init__(self, url, user="alice", device="laptop-alice", location=None):
        self.url = url
        for _ in range(8):
            try:
                code = json.load(urllib.request.urlopen(f"{url}/api/demo/totp?user={user}"))["code"]
                break
            except urllib.error.HTTPError:        # no OTP usable in this window yet
                time.sleep(1)
        else:
            raise RuntimeError("no demo OTP available")
        fields = {"username": user, "password": user + "123", "otp": code, "device_id": device}
        if location:
            fields["location"] = location
        body = json.dumps(fields).encode()
        reply = json.load(urllib.request.urlopen(urllib.request.Request(
            f"{url}/api/login", body, {"Content-Type": "application/json"})))
        self.token, self.device = reply["token"], device
        k = reply["device_key"]
        self.key = base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))

    def headers(self, method, path, extra=None, body=b"", sign_target=None, sign_body=None, digest=True, legacy=False):
        """Device-proof headers (v2). sign_target / sign_body let a test sign one request and send another."""
        ts, nonce = time.time(), secrets.token_urlsafe(18)
        signed_body = body if sign_body is None else sign_body
        dig = hashlib.sha256(signed_body).hexdigest()
        target = path if sign_target is None else sign_target
        if legacy:      # the old v1 format (method + path only)
            proof = hmac.new(self.key, f"{method} {path.split('?')[0]}|{ts:.3f}|{nonce}".encode(), hashlib.sha256).hexdigest()
        else:
            msg = "\n".join(("ztna-pop-v2", method, target, dig, f"{ts:.3f}", nonce)).encode()
            proof = hmac.new(self.key, msg, hashlib.sha256).hexdigest()
        h = {"Authorization": "Bearer " + self.token, "X-Device-Id": self.device,
             "X-Device-Timestamp": f"{ts:.3f}", "X-Device-Nonce": nonce, "X-Device-Proof": proof}
        if digest:
            h["X-Content-SHA256"] = dig
        return {**h, **(extra or {})}

    def request(self, method, path, data=None, extra=None, **sign):
        req = urllib.request.Request(self.url + path, data, self.headers(method, path, extra, data or b"", **sign), method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()


class TestDeviceProofCoversRequest(ServerCase):
    """The proof signs method, full target (query included), body digest, timestamp and nonce."""

    def test_valid_signed_requests_are_accepted(self):
        c = LabClient(self.url)
        self.assertEqual(c.request("GET", "/headers?a=1&b=2")[0], 200)       # query is part of the signed target
        self.assertEqual(c.request("PUT", "/upload", b"hello")[0], 200)      # body digest is part of it too

    def test_changed_query_is_rejected(self):
        c = LabClient(self.url)
        self.assertEqual(c.request("GET", "/headers?a=1", sign_target="/headers?a=1")[0], 200)       # control
        self.assertEqual(c.request("GET", "/headers?a=2", sign_target="/headers?a=1")[0], 401)
        self.assertEqual(c.request("GET", "/headers", sign_target="/headers?a=1")[0], 401)           # query dropped
        self.assertEqual(c.request("GET", "/headers?a=1&extra=x", sign_target="/headers?a=1")[0], 401)

    def test_changed_body_is_rejected(self):
        c = LabClient(self.url)
        # streamed endpoint: signed digest is checked against the bytes that actually arrived
        self.assertEqual(c.request("PUT", "/upload", b"HELLO", sign_body=b"hello")[0], 400)
        # JSON endpoint: body is verified before the action happens, and the session survives the rejected attempt
        self.assertEqual(c.request("POST", "/api/logout", b'{"x": 1}', sign_body=b"{}")[0], 401)
        self.assertEqual(c.request("GET", "/access/wiki")[0], 200)
        # a body smuggled onto a request that was signed as bodiless
        self.assertEqual(c.request("PUT", "/upload", b"x", sign_body=b"")[0], 400)

    def test_tampered_upload_is_never_audited_as_allowed(self):
        c = LabClient(self.url)
        self.assertEqual(c.request("PUT", "/upload", b"T" * 37, sign_body=b"U" * 37)[0], 400)
        self.assertEqual(c.request("PUT", "/upload", b"V" * 41)[0], 200)
        time.sleep(0.4)
        text = (self.data / "audit.jsonl").read_text()
        self.assertIn("upload body digest mismatch", text)           # recorded as a DENY
        self.assertNotIn("upload 37 bytes", text)                    # never as an ALLOW
        self.assertIn("upload 41 bytes verified", text)              # verified uploads are ALLOW after the check

    def test_first_seen_device_and_request_burst_raise_risk(self):
        c = LabClient(self.url)
        status, _, body = c.request("GET", "/access/wiki")
        first = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIn("device first seen for this account", first["signals"])
        again = json.loads(LabClient(self.url).request("GET", "/access/wiki")[2])      # second login, same device
        self.assertNotIn("device first seen for this account", again["signals"])
        last = None
        for _ in range(45):                                                             # > ZTNA_RISK_BURST_N (40) in 10 s
            last = json.loads(c.request("GET", "/access/wiki")[2])
        self.assertTrue(any(x.startswith("request burst") for x in last["signals"]), last["signals"])

    def test_network_acl_baseline_trusts_network_only(self):
        c = LabClient(self.url)
        self.assertEqual(c.request("GET", "/access/hr-db")[0], 403)     # ZTNA: engineer is not HR
        req = urllib.request.Request(self.url + "/netacl/hr-db")
        with urllib.request.urlopen(req) as r:                          # baseline: loopback is "trusted", no identity needed
            self.assertEqual(r.status, 200)

    def test_changed_method_is_rejected(self):
        c = LabClient(self.url)
        h = c.headers("PUT", "/upload", body=b"abc")
        req = urllib.request.Request(self.url + "/upload", b"abc", h, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=20)
        self.assertEqual(cm.exception.code, 401)

    def test_missing_digest_or_old_v1_format_is_rejected(self):
        c = LabClient(self.url)
        self.assertEqual(c.request("GET", "/headers", digest=False)[0], 401)
        self.assertEqual(c.request("GET", "/headers", legacy=True)[0], 401)

    def test_replayed_nonce_is_rejected(self):
        c = LabClient(self.url)
        h = c.headers("GET", "/headers")
        codes = []
        for _ in range(2):
            req = urllib.request.Request(self.url + "/headers", headers=h)
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    codes.append(r.status)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        self.assertEqual(codes, [200, 401])


class TestLabEndpoints(ServerCase):
    def test_health_is_open(self):
        with urllib.request.urlopen(self.url + "/health") as r:
            self.assertEqual((r.status, json.load(r)), (200, {"status": "ok"}))

    def test_lab_endpoints_require_auth(self):
        for method, path, data in (("GET", "/headers", None), ("GET", "/download/10", None),
                                   ("PUT", "/upload", b"x"), ("POST", "/upload", b"x")):
            with self.subTest(method=method, path=path):
                req = urllib.request.Request(self.url + path, data, method=method)
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req)
                self.assertEqual(cm.exception.code, 401)

    def test_headers_text_redacts_credentials(self):
        c = LabClient(self.url)
        status, hdrs, body = c.request("GET", "/headers", extra={"X-Probe": "gateway-was-here"})
        text = body.decode()
        self.assertEqual(status, 200)
        self.assertTrue(hdrs["Content-Type"].startswith("text/plain"))
        self.assertIn("client_ip: 127.0.0.1", text)
        self.assertIn("X-Probe: gateway-was-here", text)
        self.assertNotIn(c.token, text)
        self.assertIn("Authorization: [redacted]", text)
        self.assertIn("X-Device-Proof: [redacted]", text)

    def test_download_size_and_limits(self):
        c = LabClient(self.url)
        status, hdrs, body = c.request("GET", "/download/100000")
        self.assertEqual((status, len(body), hdrs["Content-Type"]), (200, 100000, "application/octet-stream"))
        self.assertEqual(c.request("GET", "/download/0")[:1], (200,))
        self.assertEqual(c.request("GET", "/download/12abc")[0], 400)
        self.assertEqual(c.request("GET", "/download/-5")[0], 400)
        self.assertEqual(c.request("GET", f"/download/{64 * 1024 * 1024}")[0], 413)   # default cap is 16 MiB

    def test_upload_discards_and_counts(self):
        c = LabClient(self.url)
        for method in ("POST", "PUT"):
            with self.subTest(method=method):
                status, _, body = c.request(method, "/upload", b"\0" * 70000)
                result = json.loads(body)
                self.assertEqual((status, result["received"]), (200, 70000))
                self.assertIn("mbps", result)
        self.assertEqual(c.request("PUT", "/upload", b"")[0], 200)

    def test_upload_limits_and_framing(self):
        c = LabClient(self.url)
        port = int(self.url.rsplit(":", 1)[1])

        def raw(extra_headers):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.putrequest("PUT", "/upload")
            for k, v in {**c.headers("PUT", "/upload"), **extra_headers}.items():
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
            code = resp.status
            conn.close()
            return code
        self.assertEqual(raw({"Content-Length": str(64 * 1024 * 1024)}), 413)   # refused before reading any body
        self.assertEqual(raw({"Transfer-Encoding": "chunked"}), 400)
        self.assertEqual(raw({}), 400)                                          # missing Content-Length
        self.assertEqual(c.request("DELETE", "/upload")[0], 501)                # unsupported methods stay unsupported

    def test_lab_endpoints_are_audited_and_chain_stays_valid(self):
        c = LabClient(self.url)
        c.request("GET", "/headers"); c.request("GET", "/download/10"); c.request("PUT", "/upload", b"abc")
        time.sleep(0.4)
        text = (self.data / "audit.jsonl").read_text()
        for resource in ("headers", "download", "upload"):
            self.assertIn(f'"resource":"{resource}"', text)
        self.assertEqual(run(["verify"], self.env).returncode, 0)

    def test_bad_host_rejected_on_lab_endpoints(self):
        for path in ("/health", "/headers", "/download/1"):
            req = urllib.request.Request(self.url + path, headers={"Host": "evil.example"})
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req)
            self.assertEqual(cm.exception.code, 421)


class TestLabConfig(IsolatedLab):
    def test_bad_transfer_limit_fails_fast(self):
        env = make_env(self.data, free_port(), ZTNA_LAB_MAX_TRANSFER="12")
        r = run(["server"], env, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ZTNA_LAB_MAX_TRANSFER", r.stdout + r.stderr)


class TestAdminCli(ServerCase):
    def cli(self, *args, **env):
        e = {**self.env, "ZTNA_ADMIN_URL": self.url, **env}
        return run(["cli", *args], e, timeout=60)

    def test_health_and_status(self):
        r = self.cli("health")
        self.assertEqual((r.returncode, json.loads(r.stdout)), (0, {"status": "ok"}))
        r = self.cli("status")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["users"], 20)

    def test_sessions_logs_verify_and_revoke(self):
        c = LabClient(self.url)
        sid = json.loads(base64.urlsafe_b64decode(c.token.split(".")[1] + "=="))["sid"]
        self.assertIn(sid, self.cli("sessions").stdout)
        c.request("GET", "/access/wiki")
        self.assertIn("wiki", self.cli("logs", "10").stdout)
        self.assertEqual(self.cli("verify").returncode, 0)
        self.assertEqual(self.cli("revoke", sid).returncode, 0)
        self.assertEqual(c.request("GET", "/access/wiki")[0], 401)       # revoked immediately

    def test_wrong_key_and_bad_usage(self):
        r = self.cli("status", ZTNA_ADMIN_KEY="f" * 40)
        self.assertEqual(r.returncode, 1)
        self.assertIn("unauthorized", r.stderr)
        self.assertEqual(self.cli("frobnicate").returncode, 2)
        self.assertEqual(self.cli("revoke", "../../etc").returncode, 2)  # SID is validated, never put in a path blindly
        self.assertEqual(self.cli("logs", "0").returncode, 2)

    def test_refuses_plaintext_admin_key_off_host(self):
        r = self.cli("status", ZTNA_ADMIN_URL="http://10.255.255.1:8443")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("plain http", r.stdout + r.stderr)

    def test_interactive_repl(self):
        r = run(["cli"], dict(self.env, ZTNA_ADMIN_URL=self.url), timeout=60, input="health\nbogus\nexit\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('{"status": "ok"}', r.stdout)
        self.assertIn("unknown command", r.stderr)


class TestDnsUnits(IsolatedLab):
    def setUp(self):
        super().setUp()
        self.mod = load_module()

    def test_name_validation(self):
        for bad in ("", "a..b", "-x.lab", "x-.lab", "a b.lab", "x" * 64 + ".lab", ("a" * 60 + ".") * 5 + "lab", "ex\u00e4mple.lab"):
            with self.subTest(name=bad[:30]):
                with self.assertRaises(ValueError):
                    self.mod.dns_norm_name(bad)
        self.assertEqual(self.mod.dns_norm_name("App.Lab."), "app.lab")

    def test_record_validation(self):
        v = self.mod.DnsRecords.validate
        self.assertEqual(v("a", "App.lab", "10.0.0.1"), ("A", "app.lab", "10.0.0.1"))
        for bad in (("A", "x.lab", "::1"), ("A", "x.lab", "999.1.1.1"), ("CNAME", "x.lab", "x.lab"), ("TXT", "x.lab", "hi")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    v(*bad)

    def _query(self, name, qtype=1, qclass=1):
        raw = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + self.mod.dns_encode_name(name)
               + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big"))
        q, err = self.mod.dns_parse_query(raw)
        self.assertIsNone(err)
        return q

    def test_answers_cname_chain_nodata_and_loop(self):
        t = {"www.lab": ("CNAME", "app.lab"), "app.lab": ("A", "10.0.0.42"), "a.lab": ("CNAME", "b.lab"), "b.lab": ("CNAME", "a.lab")}
        parsed = lambda q: self.mod.dns_parse_response(self.mod.dns_local_answer(q, t, 30))
        r = parsed(self._query("www.lab"))
        self.assertEqual([(x["type"], x["value"]) for x in r["answers"]], [("CNAME", "app.lab"), ("A", "10.0.0.42")])
        self.assertTrue(r["aa"])
        self.assertEqual(parsed(self._query("app.lab", 28))["answers"], [])                       # AAAA: NOERROR/NODATA
        self.assertEqual(parsed(self._query("www.lab", 5))["answers"][0]["value"], "app.lab")     # CNAME query: only the CNAME
        self.assertEqual(parsed(self._query("a.lab"))["rcode"], "SERVFAIL")                       # loop
        self.assertIsNone(self.mod.dns_local_answer(self._query("elsewhere.example"), t, 30))     # not ours

    def test_parser_rejects_hostile_packets(self):
        p = self.mod.dns_parse_query
        self.assertEqual(p(b"\x00\x01"), (None, None))                                            # runt
        self.assertEqual(p(b"\x00\x01\x81\x80" + b"\x00" * 8), (None, None))                      # a response: never answer
        self.assertEqual(p(b"\x00\x01\x01\x00\x00\x02" + b"\x00" * 6)[1], 1)                      # two questions -> FORMERR
        self.assertEqual(p(b"\x00\x01\x01\x00\x00\x01" + b"\x00" * 6 + b"\xc0\x0c\x00\x01\x00\x01")[1], 1)  # pointer in question
        self.assertEqual(p(b"\x00\x01\x01\x00\x00\x01" + b"\x00" * 6 + b"\x3fabc")[1], 1)          # label runs past the packet
        self.assertEqual(p(b"\x00\x01\x29\x00\x00\x01" + b"\x00" * 6 + b"\x01a\x00\x00\x01\x00\x01")[1], 4)  # opcode 5 -> NOTIMP
        with self.assertRaises(ValueError):                                                       # compression pointer loop
            self.mod.dns_parse_name(b"\xc0\x00", 0)


class TestDnsCli(IsolatedLab):
    def setUp(self):
        super().setUp()
        self.env = make_env(self.data, ZTNA_DNS_RECORDS=str(self.data / "records.json"))

    def test_add_list_remove_roundtrip(self):
        self.assertEqual(run(["dns", "add", "App.Lab", "10.0.0.42"], self.env).returncode, 0)
        self.assertEqual(run(["dns", "cname", "www.lab", "app.lab"], self.env).returncode, 0)
        recs = json.loads(run(["dns", "list"], self.env).stdout)["records"]
        self.assertEqual({(r["type"], r["name"], r["value"]) for r in recs},
                         {("A", "app.lab", "10.0.0.42"), ("CNAME", "www.lab", "app.lab")})
        self.assertEqual(run(["dns", "remove", "app.lab"], self.env).returncode, 0)
        self.assertEqual(run(["dns", "remove", "app.lab"], self.env).returncode, 1)   # already gone
        if os.name != "nt":
            self.assertEqual((self.data / "records.json").stat().st_mode & 0o077, 0)  # private file

    def test_invalid_input_rejected(self):
        for args in (["add", "x.lab", "not-an-ip"], ["add", "bad name", "10.0.0.1"], ["cname", "x.lab", "x.lab"],
                     ["query", "x.lab", "BOGUS"], ["probe", "x.lab", "127.0.0.1", "0"]):
            with self.subTest(args=args):
                self.assertNotEqual(run(["dns", *args], self.env).returncode, 0)

    def test_corrupt_records_file_fails_fast(self):
        self.data.mkdir(parents=True, exist_ok=True)
        (self.data / "records.json").write_text('{"records": [{"type": "A", "name": "x.lab", "value": "nope"}]}')
        r = run(["dns", "serve"], dict(self.env, ZTNA_DNS_PORT=str(free_udp_port())), timeout=30)
        self.assertNotEqual(r.returncode, 0)

    def test_remote_bind_needs_explicit_override(self):
        r = run(["dns", "serve"], dict(self.env, ZTNA_DNS_HOST="0.0.0.0", ZTNA_DNS_PORT=str(free_udp_port())), timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ZTNA_DNS_ALLOW_REMOTE", r.stdout + r.stderr)


class TestDnsServer(IsolatedLab):
    def setUp(self):
        super().setUp()
        self.port = free_udp_port()
        self.env = make_env(self.data, ZTNA_DNS_RECORDS=str(self.data / "records.json"), ZTNA_DNS_PORT=str(self.port))
        run(["dns", "add", "app.lab", "10.0.0.42"], self.env)
        run(["dns", "cname", "www.lab", "app.lab"], self.env)
        self.errpath = Path(self.tmp) / "dns.stderr"
        self.errfile = open(self.errpath, "wb")
        self.proc = spawn(["dns", "serve"], self.env, self.errfile)
        self.addCleanup(self._stop)
        for _ in range(60):
            if self.proc.poll() is not None:
                self.fail("dns server exited early: " + tail(self.errpath))
            if run(["dns", "query", "app.lab"], self.env).returncode == 0:
                return
            time.sleep(0.2)
        self.fail("dns server did not start")

    def _stop(self):
        stop(self.proc, self.errfile)

    def q(self, *args):
        r = run(["dns", "query", *args], self.env)
        return r.returncode, json.loads(r.stdout)

    def test_a_cname_nodata_refused(self):
        code, a = self.q("app.lab")
        self.assertEqual((code, a["answers"][0]["value"], a["aa"]), (0, "10.0.0.42", True))
        code, c = self.q("www.lab")
        self.assertEqual([x["type"] for x in c["answers"]], ["CNAME", "A"])
        self.assertEqual(self.q("app.lab", "AAAA")[1]["answers"], [])
        code, unknown = self.q("example.com")                      # deny by default: no forwarder configured
        self.assertEqual((code, unknown["rcode"]), (1, "REFUSED"))

    def test_edits_apply_without_restart(self):
        run(["dns", "add", "late.lab", "192.0.2.77"], self.env)
        for _ in range(20):
            code, r = self.q("late.lab")
            if code == 0:
                break
            time.sleep(0.25)
        self.assertEqual(r["answers"][0]["value"], "192.0.2.77")
        run(["dns", "remove", "late.lab"], self.env)
        time.sleep(1.5)
        self.assertEqual(self.q("late.lab")[1]["rcode"], "REFUSED")

    def test_probe_reports_latency_stats(self):
        r = run(["dns", "probe", "app.lab", "127.0.0.1", "5", "10"], self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual((out["ok"], out["failed"], out["rcodes"]), (5, 0, {"NOERROR": 5}))
        self.assertIn("p95", out)

    def test_survives_garbage_datagrams(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for blob in (b"", b"\x00", os.urandom(512), b"\xff" * 4096):
                s.sendto(blob, ("127.0.0.1", self.port))
        self.assertEqual(self.q("app.lab")[0], 0)
        self.assertIsNone(self.proc.poll())


class TestSystemdUnit(IsolatedLab):
    def test_unit_output(self):
        for kind in ("server", "dns"):
            with self.subTest(kind=kind):
                r = run(["systemd", kind], make_env(self.data))
                self.assertEqual(r.returncode, 0, r.stderr)
                for needle in ("NoNewPrivileges=yes", "ProtectSystem=strict", "User=ztna-lab", f"ztna.py {kind}", "EnvironmentFile=/etc/ztna-lab/config.env"):
                    self.assertIn(needle, r.stdout)
        self.assertIn("CAP_NET_BIND_SERVICE", run(["systemd", "dns"], make_env(self.data)).stdout)
        self.assertNotIn("CAP_NET_BIND_SERVICE", run(["systemd", "server"], make_env(self.data)).stdout)
        self.assertNotEqual(run(["systemd", "bogus"], make_env(self.data)).returncode, 0)


# ---------------------------------------------------------------- failure injection

class TestFailClosed(ServerCase):
    """Break the database or the audit log underneath a running server and check the server fails closed."""

    def admin(self, method, path, body=None):
        req = urllib.request.Request(self.url + path, json.dumps(body).encode() if body is not None else None,
                                     {"X-Admin-Key": ADMIN_KEY, "Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def sql(self, statement):
        con = sqlite3.connect(self.data / "ztna_lab.sqlite3", timeout=10)
        try:
            con.execute(statement)
            con.commit()
        finally:
            con.close()

    def raw_login(self):
        for _ in range(8):
            try:
                code = json.load(urllib.request.urlopen(f"{self.url}/api/demo/totp?user=alice"))["code"]
                break
            except urllib.error.HTTPError:
                time.sleep(1)
        body = json.dumps({"username": "alice", "password": "alice123", "otp": code, "device_id": "laptop-alice",
                           "location": "office"}).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{self.url}/api/login", body, {"Content-Type": "application/json"})) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def wiki_mfa_age(self):
        return self.admin("GET", "/api/state")[1]["resources"]["wiki"]["mfa_age"]

    def test_login_refused_when_session_store_fails(self):
        self.sql("DROP TABLE sessions")
        status, body = self.raw_login()
        self.assertEqual(status, 503)
        self.assertNotIn("token", body)
        self.assertEqual(self.admin("GET", "/api/state")[1]["sessions"], [])   # no half-created session left behind

    def test_revoke_reports_failure_but_session_is_dead(self):
        c = LabClient(self.url, location="office")
        self.assertEqual(c.request("GET", "/access/wiki")[0], 200)
        sid = json.loads(base64.urlsafe_b64decode(c.token.split(".")[1] + "=="))["sid"]
        self.sql("DROP TABLE sessions")
        status, body = self.admin("POST", f"/api/session/{sid}/revoke")
        self.assertEqual((status, body["revoked"]), (503, True))               # caller is told persistence failed
        self.assertEqual(c.request("GET", "/access/wiki")[0], 401)             # ...and access is still cut off

    def test_logout_fails_closed_when_store_fails(self):
        c = LabClient(self.url, location="office")
        self.sql("DROP TABLE sessions")
        self.assertEqual(c.request("POST", "/api/logout", b"{}")[0], 503)
        self.assertEqual(c.request("GET", "/access/wiki")[0], 401)

    def test_policy_rolled_back_when_history_write_fails(self):
        before = self.wiki_mfa_age()
        self.sql("DROP TABLE policy_changes")
        status, _ = self.admin("POST", "/api/policy/wiki", {"mfa_age": 1234})
        self.assertEqual(status, 503)
        self.assertEqual(self.wiki_mfa_age(), before)
        pol = self.data / "policy.json"
        if pol.exists():
            self.assertNotIn("1234", pol.read_text())

    def test_policy_rolled_back_when_audit_fails(self):
        LabClient(self.url, location="office")                                  # writes audit entries
        before = self.wiki_mfa_age()
        (self.data / "audit.jsonl").write_bytes(b"")                            # log shrinks under the running server
        status, _ = self.admin("POST", "/api/policy/wiki", {"mfa_age": 1234})
        self.assertEqual(status, 503)
        self.assertEqual(self.wiki_mfa_age(), before)
        pol = self.data / "policy.json"
        if pol.exists():
            self.assertNotIn("1234", pol.read_text())

    def test_policy_change_succeeds_when_everything_works(self):
        self.assertEqual(self.admin("POST", "/api/policy/wiki", {"mfa_age": 1234})[0], 200)
        self.assertEqual(self.wiki_mfa_age(), 1234)

    def test_telemetry_failure_stays_best_effort(self):
        c = LabClient(self.url, location="office")
        self.sql("DROP TABLE access_events")
        self.assertEqual(c.request("GET", "/access/wiki")[0], 200)              # dashboards degrade, access decisions do not


class TestWorkerSetting(IsolatedLab):
    def test_multi_worker_setting_is_rejected(self):
        r = run(["enterprise"], make_env(self.data, WEB_CONCURRENCY="4"), timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("WEB_CONCURRENCY", r.stdout + r.stderr)
        self.assertIn("not supported", r.stdout + r.stderr)


# ---------------------------------------------------------------- DNS hardening, locking

class TestDnsHardening(IsolatedLab):
    def setUp(self):
        super().setUp()
        self.mod = load_module()

    def test_rate_buckets_have_a_hard_cap(self):
        rec = self.mod.DnsRecords(str(self.data / "r.json"))
        srv = self.mod.LabDnsServer("127.0.0.1", 0, rec, rate=5)
        self.addCleanup(srv.close)
        srv.BUCKET_LIMIT = 8
        for i in range(500):                                                    # 500 distinct (e.g. spoofed) sources
            srv._allow(f"10.0.{i // 250}.{i % 250}")
        self.assertLessEqual(len(srv._buckets), 8)
        ip = "192.0.2.1"                                                        # limiting still works for a live source
        self.assertEqual([srv._allow(ip) for _ in range(7)], [True] * 5 + [False] * 2)

    def _fake_upstream(self, reply_from_other_port):
        """UDP 'upstream' that answers every query with a well-formed reply, optionally from a different source port."""
        main = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        main.bind(("127.0.0.1", 0))
        main.settimeout(5)
        other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        other.bind(("127.0.0.1", 0))
        for sk in (main, other):
            self.addCleanup(sk.close)

        def serve():
            try:
                data, addr = main.recvfrom(4096)
            except OSError:
                return
            q, _ = self.mod.dns_parse_query(data)
            (other if reply_from_other_port else main).sendto(self.mod.dns_response(q, 0), addr)
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self.addCleanup(t.join, 6)
        return main.getsockname()[1]

    def _forwarder(self, port):
        rec = self.mod.DnsRecords(str(self.data / "r.json"))
        srv = self.mod.LabDnsServer("127.0.0.1", 0, rec, forward=("127.0.0.1", port), forward_clients=[])
        self.addCleanup(srv.close)
        raw = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + self.mod.dns_encode_name("x.example") + b"\x00\x01\x00\x01"
        return srv, self.mod.dns_parse_query(raw)[0]

    def test_forwarder_accepts_reply_only_from_exact_upstream_endpoint(self):
        srv, q = self._forwarder(self._fake_upstream(reply_from_other_port=False))
        self.assertIsNotNone(srv._forward_query(q))                             # control: genuine upstream reply is accepted
        srv, q = self._forwarder(self._fake_upstream(reply_from_other_port=True))
        self.assertIsNone(srv._forward_query(q))                                # same IP, wrong port: rejected

    @unittest.skipIf(os.name == "nt", "flock semantics")
    def test_file_lock_timeout_is_bounded(self):
        import fcntl
        target = str(self.data / "x.json")
        self.data.mkdir(parents=True, exist_ok=True)
        fd = os.open(target + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)                                          # another process holds the lock
        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            with self.mod._file_lock(target, timeout=0.4):
                pass
        self.assertLess(time.monotonic() - t0, 5)

    def test_concurrent_cli_edits_do_not_lose_records(self):
        env = make_env(self.data, ZTNA_DNS_RECORDS=str(self.data / "records.json"))
        procs = [subprocess.Popen([sys.executable, SCRIPT, "dns", "add", f"host{i}.lab", f"10.0.0.{i + 1}"], env=env,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=(os.name != "nt")) for i in range(8)]
        codes = []
        try:
            for p in procs:
                try:
                    codes.append(p.wait(timeout=30))
                except subprocess.TimeoutExpired:
                    codes.append("timeout")
        finally:
            for p in procs:
                if p.poll() is None:
                    _kill_tree(p)
        self.assertEqual(codes, [0] * 8)
        names = {r["name"] for r in json.loads(run(["dns", "list"], env).stdout)["records"]}
        self.assertEqual(names, {f"host{i}.lab" for i in range(8)})


if __name__ == "__main__":
    unittest.main(verbosity=2)

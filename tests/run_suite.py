"""Deterministic test entry point: python tests/run_suite.py [--timeout SECONDS]
Enforces a whole-suite deadline (dumps all thread stacks, then hard-exits), runs every test, and prints
one summary line. Exit codes: 0 all passed, 1 failures, errors or suite deadline exceeded (stacks are dumped first)."""
import faulthandler, os, signal, sys, time, unittest
from pathlib import Path

limit = 300
if "--timeout" in sys.argv:
    limit = int(sys.argv[sys.argv.index("--timeout") + 1])
test_limit = int(os.environ.get("ZTNA_TEST_TIMEOUT", "90"))      # per-test deadline (POSIX main thread)
timings = []

class _Timed(unittest.TextTestResult):
    def startTest(self, test):
        self._t = time.monotonic()
        if hasattr(signal, "SIGALRM"):
            def _expired(*_): raise TimeoutError(f"test exceeded {test_limit}s: {test.id()}")
            signal.signal(signal.SIGALRM, _expired); signal.alarm(test_limit)
        super().startTest(test)
    def stopTest(self, test):
        if hasattr(signal, "SIGALRM"): signal.alarm(0)
        timings.append((time.monotonic() - self._t, test.id()))
        super().stopTest(test)
here = Path(__file__).resolve().parent
faulthandler.dump_traceback_later(limit, exit=True)      # prints stacks of every thread, then os._exit(1)
t0 = time.monotonic()
suite = unittest.defaultTestLoader.discover(str(here), pattern="test_*.py")
res = unittest.TextTestRunner(verbosity=1, resultclass=_Timed).run(suite)
for secs, tid in sorted(timings, reverse=True)[:5]: print(f"slow: {secs:6.1f}s {tid}")
faulthandler.cancel_dump_traceback_later()
status = "PASS" if res.wasSuccessful() else "FAIL"
print(f"SUMMARY {status} run={res.testsRun} failures={len(res.failures)} errors={len(res.errors)} "
      f"skipped={len(res.skipped)} seconds={time.monotonic() - t0:.1f}")
sys.exit(0 if res.wasSuccessful() else 1)

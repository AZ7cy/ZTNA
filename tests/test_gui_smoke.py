"""Native Tk desktop GUI smoke test. Run with xvfb-run on Linux CI."""
import os, sys, tempfile, unittest
from pathlib import Path

class NativeGuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get("DISPLAY") and os.name != "nt":
            raise unittest.SkipTest("Tk GUI smoke test requires a display (use xvfb-run)")
        os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-gui-smoke-"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import ztna_lab_v2 as z
        cls.z = z
        z.REQUESTED_MODE = "gui"
        z.init_runtime("gui")

    def test_employee_and_manager_portals_render(self):
        z = self.z
        app = z.App()
        try:
            app.update_idletasks(); app.update()
            emp = app.open_employee()
            app.update_idletasks(); app.update()
            self.assertIn("Employee sign-in", emp.title())
            self.assertTrue(hasattr(emp, "cb_user"))
            mgr = app.open_manager()
            app.update_idletasks(); app.update()
            mgr.v_mu.set("puja"); mgr.v_mp.set("puja123"); mgr._signin()
            app.update_idletasks(); app.update()
            self.assertIsNotNone(mgr.manager_user)
            self.assertTrue(hasattr(mgr, "req_tree"))
            self.assertTrue(hasattr(mgr, "ss_tree"))
            self.assertTrue(hasattr(mgr, "exc_tree"))
            self.assertTrue(hasattr(mgr, "_watch_gui_events"))
        finally:
            try: app.on_close()
            except Exception: pass

if __name__ == "__main__": unittest.main()

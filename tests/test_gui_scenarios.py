"""Runs tests/gui_scenarios.py (manager console, dashboard and employee portal driven headlessly against the real engine).

It runs in a separate process because tkinter must be replaced by the test stand-in before the engine is first imported.
"""
import os, subprocess, sys, unittest
from pathlib import Path


class GuiScenarioTests(unittest.TestCase):
    def test_manager_dashboard_and_employee_scenarios(self):
        script = Path(__file__).resolve().parent / "gui_scenarios.py"
        env = {k: v for k, v in os.environ.items() if not k.startswith("ZTNA_")}      # a clean engine configuration
        done = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=240, env=env)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + "\n" + done.stderr[-2500:])
        self.assertIn("ALL OK", done.stdout)


if __name__ == "__main__":
    unittest.main()

"""Gateway bypass-prevention rules (dry-run generator): default deny, only the ZTNA proxy may reach protected segments."""
import ast, textwrap, unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parent.parent / "ztna_lab_v2.py").read_text()
tree = ast.parse(SRC)
ns = {}
for node in tree.body:
    if (isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "SEG" for t in node.targets)) or \
       (isinstance(node, ast.FunctionDef) and node.name == "firewall_rules"):
        exec(compile(ast.Module([node], []), "x", "exec"), ns)


class TestGatewayRules(unittest.TestCase):
    def test_default_deny_and_proxy_only_access(self):
        rules = ns["firewall_rules"]("10.10.0.2")
        self.assertIn("iptables -P FORWARD DROP", rules)
        accepts = [r for r in rules if " -A FORWARD" in r and "-j ACCEPT" in r and "ctstate" not in r]
        self.assertEqual(len(accepts), len(ns["SEG"]))
        for r in accepts:
            self.assertIn("-s 10.10.0.2 ", r)                      # only the ZTNA proxy is a permitted source
        sources = {r.split("-s ")[1].split()[0] for r in accepts}
        self.assertEqual(sources, {"10.10.0.2"})                   # no segment-to-segment (lateral movement) rule

    def test_direct_client_to_segment_has_no_rule(self):
        text = "\n".join(ns["firewall_rules"]("10.10.0.2"))
        for ip in ns["SEG"].values():
            self.assertNotIn(f"-s {ip}", text)


if __name__ == "__main__":
    unittest.main()

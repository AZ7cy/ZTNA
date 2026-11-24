"""External audit-anchor location validation (pure function; runs without the enterprise dependencies)."""
import ast, os, tempfile, textwrap, unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parent.parent / "ztna_lab_v2.py").read_text()
_node = next(n for n in ast.parse(SRC).body if isinstance(n, ast.FunctionDef) and n.name == "_validate_external_anchor_location")
_ns = {"os": os, "Path": Path}
exec(textwrap.dedent(ast.get_source_segment(SRC, _node)), _ns)
validate = _ns["_validate_external_anchor_location"]


class TestAnchorLocation(unittest.TestCase):
    def test_rejects_anchor_inside_protected_dirs_and_via_symlink_or_dotdot(self):
        with tempfile.TemporaryDirectory() as td:
            data = Path(td, "data"); data.mkdir(); outside = Path(td, "anchor"); outside.mkdir(); outside.chmod(0o700)
            with self.assertRaises(RuntimeError): validate(data / "audit.monotonic", [str(data)])
            with self.assertRaises(RuntimeError): validate(data / "sub" / ".." / "a", [str(data)])
            (outside / "link").symlink_to(data)
            with self.assertRaises(RuntimeError): validate(outside / "link" / "a", [str(data)])
            validate(outside / "audit.monotonic", [str(data), None])   # genuinely external: accepted

    def test_rejects_world_writable_anchor_directory(self):
        with tempfile.TemporaryDirectory() as td:
            data = Path(td, "data"); data.mkdir(); d = Path(td, "anchor"); d.mkdir(); d.chmod(0o777)
            with self.assertRaises(RuntimeError): validate(d / "a", [str(data)])


if __name__ == "__main__":
    unittest.main()

"""Temporary application exceptions remain time-boxed and audited."""
import os, sys, tempfile, unittest
from pathlib import Path

class AccessExceptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(ZTNA_DEMO="1", ZTNA_DEMO_OTP="1", ZTNA_DATA_DIR=tempfile.mkdtemp(prefix="ztna-exceptions-"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import ztna as z
        cls.z = z
        z.REQUESTED_MODE = "gui"; z.init_runtime("gui")

    def test_approved_exception_is_resource_scoped_and_expires(self):
        z = self.z
        user, device, resource = "alice", "laptop-alice", "finance-ledger"
        self.assertFalse(z.rbac_allows(user, resource))
        rid = z.create_access_exception_request(user, device, resource, "Urgent month-end support")
        self.assertEqual(next(r for r in z.list_access_exception_requests() if r["id"] == rid)["status"], "pending")
        result = z.decide_access_exception_request(rid, True, "puja", 3600)
        self.assertIsNotNone(result)
        self.assertTrue(z.rbac_allows(user, resource))
        self.assertTrue(z.segment_allows(user, resource))
        self.assertFalse(z.rbac_allows(user, "admin-panel"))
        z.TEMP_RESOURCE_GRANTS[(user, resource)] = 1
        self.assertFalse(z.rbac_allows(user, resource))

    def test_repeated_pending_request_is_deduplicated(self):
        z = self.z
        rid1 = z.create_access_exception_request("alice", "laptop-alice", "finance-ledger", "work")
        rid2 = z.create_access_exception_request("alice", "laptop-alice", "finance-ledger", "work again")
        self.assertEqual(rid1, rid2)

if __name__ == "__main__": unittest.main()

import copy
import errno
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_btrfs_ugos import tool


class PolicyAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.native = {"profile": "acl-qgroup", "access": {
            "denied": {"read": {"allowed": False}, "write_open": {"allowed": False}},
            "readonly": {"read": {"allowed": True}, "write_open": {"allowed": False}}},
            "quota": {"host_probe": {"written": 8, "maximum": 12, "errno": errno.EDQUOT}}}
        self.guest = {"profile": "acl-qgroup", "production_volume_tested": False,
                      "readonly": {"file_hashes": {"fixture": True}, "access": copy.deepcopy(self.native["access"])},
                      "write_overlay": {"file_hashes": {"fixture": True}, "access": copy.deepcopy(self.native["access"]),
                                        "quota_probe": copy.deepcopy(self.native["quota"]["host_probe"])}}

    def test_denied_read_and_readonly_write_exposure_are_failures(self):
        self.guest["readonly"]["access"]["denied"]["read"]["allowed"] = True
        self.guest["write_overlay"]["access"]["readonly"]["write_open"]["allowed"] = True
        result = tool.assess_policy(self.native, self.guest)
        self.assertEqual(result["status"], "incompatible")
        self.assertEqual(len(result["differences"]), 2)

    def test_readonly_erofs_is_not_treated_as_acl_enforcement(self):
        self.guest["readonly"]["access"]["readonly"]["write_open"] = {"allowed": False, "errno": errno.EROFS}
        result = tool.assess_policy(self.native, self.guest)
        self.assertNotIn("readonly_write_open_policy", result["checks"])
        self.assertEqual(result["status"], "sample_checks_passed")
        self.assertFalse(result["production_conversion_supported"])

    def test_quota_bypass_or_wrong_limit_cannot_pass(self):
        for error, written in ((None, 12), (errno.ENOSPC, 8), (errno.EDQUOT, 4)):
            self.guest["write_overlay"]["quota_probe"].update(errno=error, written=written)
            result = tool.assess_policy(self.native, self.guest)
            self.assertEqual(result["checks"]["quota_policy"], "failed")

    def test_missing_evidence_cannot_pass(self):
        del self.guest["write_overlay"]
        self.assertEqual(tool.assess_policy(self.native, self.guest)["status"], "not_verified")

    def test_boolean_evidence_is_required(self):
        self.guest["readonly"]["file_hashes"]["fixture"] = "true"
        self.guest["write_overlay"]["access"]["denied"]["read"]["allowed"] = "false"
        self.assertEqual(tool.assess_policy(self.native, self.guest)["status"], "not_verified")

    def test_user_quota_fixture_does_not_certify_permissions(self):
        self.native["profile"] = self.guest["profile"] = "usrquota"
        self.guest["write_overlay"]["user_quota_probe"] = self.guest["write_overlay"].pop("quota_probe")
        result = tool.assess_policy(self.native, self.guest)
        self.assertFalse(any("_policy" in n and n != "quota_policy" for n in result["checks"]))
        self.assertEqual(result["status"], "sample_checks_passed")

    def test_profile_mismatch_and_production_report_rejected(self):
        for change in ({"profile": "usrquota"}, {"production_volume_tested": True}):
            with self.assertRaises(tool.ValidationError):
                tool.assess_policy(self.native, {**self.guest, **change})

    def test_cli_returns_failure_status_for_policy_bypass(self):
        self.guest["readonly"]["access"]["denied"]["read"]["allowed"] = True
        with tempfile.TemporaryDirectory() as directory:
            n, g = Path(directory)/"native.json", Path(directory)/"guest.json"
            n.write_text(json.dumps(self.native)); g.write_text(json.dumps(self.guest))
            with mock.patch("builtins.print"):
                self.assertEqual(tool.main(["assess-policy", str(n), str(g)]), 3)

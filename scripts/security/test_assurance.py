"""Synthetic fixtures only: these CVE-shaped IDs are not DNS Daddy advisories."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import assurance as a

NOW = datetime(2026, 10, 1, 9, tzinfo=timezone.utc)


def inputs():
    return ({"SchemaVersion": 2, "CreatedAt": NOW.isoformat(), "Results": [
        {"Target": "go.mod", "Type": "gomod", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2099-1234", "PkgName": "example", "InstalledVersion": "1", "Severity": "LOW"}]}]},
        {"catalogVersion": "fixture", "dateReleased": NOW.isoformat(), "count": 1,
         "vulnerabilities": [{"cveID": "CVE-2099-1234", "dateAdded": "2026-10-01", "requiredAction": "Synthetic test"}]})


class CorrelationTests(unittest.TestCase):
    def test_low_severity_unfixed_kev_is_not_hidden(self):
        result = a.correlate(*inputs(), NOW)
        self.assertEqual(result["kev_match_count"], 1)
        self.assertEqual(result["findings"][0]["fixed_version"], "")
        self.assertEqual(result["findings"][0]["severity"], "LOW")

    def test_exact_vendor_cve_alias(self):
        scan, kev = inputs()
        scan["Results"][0]["Vulnerabilities"][0].update(VulnerabilityID="GHSA-fixture", VendorIDs=["CVE-2099-1234"])
        self.assertEqual(a.correlate(scan, kev, NOW)["kev_match_count"], 1)

    def test_unmatched_is_not_listed_not_safe(self):
        scan, kev = inputs()
        scan["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "CVE-2099-12345"
        self.assertEqual(a.correlate(scan, kev, NOW)["findings"][0]["kev_status"], "not_listed")

    def test_no_cve_is_explicit(self):
        scan, kev = inputs()
        scan["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "GO-fixture"
        self.assertEqual(a.correlate(scan, kev, NOW)["findings"][0]["kev_status"], "no_cve_alias")

    def test_zero_findings_omitted_null_or_empty(self):
        for value in (None, []):
            scan, kev = inputs()
            scan["Results"][0]["Vulnerabilities"] = value
            self.assertEqual(a.correlate(scan, kev, NOW)["kev_match_count"], 0)
        del scan["Results"][0]["Vulnerabilities"]
        self.assertEqual(a.correlate(scan, kev, NOW)["findings"], [])

    def test_bad_catalogues_fail(self):
        for change in ({"count": 0}, {"vulnerabilities": []}, {"dateReleased": "2026-01-01T00:00:00Z"},
                       {"dateReleased": "2030-01-01T00:00:00Z"}, {"dateReleased": "2026-10-01"}, {"catalogVersion": None}):
            scan, kev = inputs()
            kev.update(change)
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                a.correlate(scan, kev, NOW)

    def test_duplicate_kev_ids_fail(self):
        scan, kev = inputs()
        kev["vulnerabilities"] *= 2
        kev["count"] = 2
        with self.assertRaises(ValueError):
            a.correlate(scan, kev, NOW)

    def test_bad_scans_fail(self):
        for change in ({"SchemaVersion": 1}, {"Results": []}, {"Results": None},
                       {"CreatedAt": "2025-01-01T00:00:00Z"}, {"Results": [{"Type": "npm", "Target": "package.json"}]}):
            scan, kev = inputs()
            scan.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                a.correlate(scan, kev, NOW)

    def test_bad_vulnerability_does_not_disappear(self):
        for value in ({}, None, "bad"):
            scan, kev = inputs()
            scan["Results"][0]["Vulnerabilities"].append(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                a.correlate(scan, kev, NOW)

    def test_strict_json(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'<html>failed</html>'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                a.decode(raw)
        with patch.object(a, "MAX_BYTES", 2), self.assertRaises(ValueError):
            a.decode(b'{"a":1}')

    def test_redirect_is_not_followed(self):
        with self.assertRaises(ValueError):
            a.NoRedirect().redirect_request(None, None, 302, None, None, "http://example.invalid")

    def test_cli_error_overwrites_old_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            output = path / "out.json"
            output.write_text('{"assessment":"completed"}')
            status = a.main(["correlate", "--scan", str(path / "absent"), "--kev", str(path / "absent"),
                             "--output", str(output), "--commit", "a" * 40])
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(output.read_text())["assessment"], "unavailable")

    def test_cli_kev_exit_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for name, value in zip(("scan", "kev"), inputs()):
                path.joinpath(name).write_text(json.dumps(value))
            with patch.object(a, "datetime") as clock:
                clock.now.return_value = NOW
                clock.fromisoformat = datetime.fromisoformat
                status = a.main(["correlate", "--scan", str(path / "scan"), "--kev", str(path / "kev"),
                                 "--output", str(path / "out"), "--commit", "a" * 40])
            result = json.loads(path.joinpath("out").read_text())
            self.assertEqual(status, 1)
            self.assertEqual(len(result["scan_sha256"]), 64)
            self.assertEqual(result["commit"], "a" * 40)


class RegisterTests(unittest.TestCase):
    def register(self):
        return {"schema_version": 1, "inventory_status": "not_assessed", "updated": "2026-10-01",
                "scope": "published advisories only", "vulnerabilities": []}

    def entry(self):
        return {"id": "TEST-1", "public": True, "summary": "fixture", "owner": "maintainer",
                "affected_versions": "under investigation", "mitigation": "fixture", "evidence": "fixture",
                "status": "investigating", "kev_status": "unknown", "next_review": "2026-10-02"}

    def test_unassessed_empty_is_valid_not_clean(self):
        a.validate_register(self.register())

    def test_reviewed_needs_evidence(self):
        data = self.register()
        data["inventory_status"] = "reviewed"
        with self.assertRaises(ValueError):
            a.validate_register(data)

    def test_public_entry(self):
        data = self.register()
        data["vulnerabilities"] = [self.entry()]
        a.validate_register(data)

    def test_reject_embargo_duplicate_and_unjustified_claims(self):
        for change in ({"public": False}, {"owner": ""}, {"status": "fixed"}, {"status": "not_affected"},
                       {"kev_status": "not_listed"}, {"next_review": "bad"}):
            data = self.register()
            entry = self.entry()
            entry.update(change)
            data["vulnerabilities"] = [entry]
            with self.subTest(change=change), self.assertRaises(ValueError):
                a.validate_register(data)
        data["vulnerabilities"] = [self.entry(), self.entry()]
        with self.assertRaises(ValueError):
            a.validate_register(data)


if __name__ == "__main__":
    unittest.main()

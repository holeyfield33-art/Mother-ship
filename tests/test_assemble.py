"""Tests for scripts/assemble.py (CWE-22 catalog export)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import assemble as a  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "assemble"
REPO_RECORDS = Path(__file__).resolve().parent.parent / "records" / "d004"


class AssembleFixtureTests(unittest.TestCase):
    def setUp(self):
        self.body = a.build(FIXTURES, cwe="CWE-22")
        self.payload = json.loads(self.body)

    def test_export_includes_only_cwe22_with_url_and_fix_commit(self):
        ids = [row["id"] for row in self.payload["records"]]
        self.assertEqual(ids, ["GO-2099-0001"])

    def test_fixed_version_alone_is_not_enough(self):
        ids = {row["id"] for row in self.payload["records"]}
        self.assertNotIn("GO-2099-0002", ids)

    def test_other_cwe_is_excluded(self):
        ids = {row["id"] for row in self.payload["records"]}
        self.assertNotIn("PYSEC-2099-1", ids)

    def test_missing_url_is_excluded(self):
        ids = {row["id"] for row in self.payload["records"]}
        self.assertNotIn("GO-2099-0003", ids)

    def test_withdrawn_is_counted_but_not_exported(self):
        counts = self.payload["catalog"]["counts"]
        self.assertEqual(counts["withdrawn_otherwise_eligible"], 1)
        self.assertEqual(counts["eligible_including_withdrawn"], 2)
        self.assertEqual(counts["exported"], 1)
        ids = {row["id"] for row in self.payload["records"]}
        self.assertNotIn("GO-2099-0004", ids)

    def test_counts_and_selection_metadata(self):
        catalog = self.payload["catalog"]
        self.assertEqual(catalog["schema"], "mothership-catalog/v1")
        self.assertEqual(catalog["slice"], "CWE-22")
        self.assertTrue(catalog["selection"]["require_public_url"])
        self.assertTrue(catalog["selection"]["require_fix_commit"])
        self.assertTrue(catalog["selection"]["exclude_withdrawn"])
        self.assertEqual(catalog["counts"]["cwe_records"], 4)
        self.assertEqual(catalog["counts"]["with_public_url"], 3)
        self.assertEqual(catalog["counts"]["with_fix_commit"], 3)

    def test_projected_record_keeps_fix_commit_and_cwe_join(self):
        row = self.payload["records"][0]
        self.assertEqual(row["url"], "https://pkg.go.dev/vuln/GO-2099-0001")
        self.assertEqual(
            row["fix"]["fix_commits"],
            ["https://github.com/ex/mod/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        )
        self.assertIn("CWE-22", row["cwe_all"])
        self.assertEqual(row["agreement"], "agree")
        self.assertNotIn("details", row)

    def test_determinism(self):
        self.assertEqual(a.build(FIXTURES), a.build(FIXTURES))

    def test_check_mode_ok_and_fails_on_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "mothership-catalog.json"
            self.assertEqual(a.main(["--records-dir", str(FIXTURES), "--output", str(out)]), 0)
            self.assertEqual(a.main(["--records-dir", str(FIXTURES), "--output", str(out), "--check"]), 0)
            out.write_text(out.read_text(encoding="utf-8") + " ", encoding="utf-8")
            self.assertEqual(a.main(["--records-dir", str(FIXTURES), "--output", str(out), "--check"]), 1)


@unittest.skipUnless(
    (REPO_RECORDS / "cwe_join.jsonl").is_file()
    and (REPO_RECORDS / "pypa.jsonl").is_file(),
    "repo records/d004 not present",
)
class AssembleRepoSliceTests(unittest.TestCase):
    def test_default_cwe22_slice_count(self):
        payload = json.loads(a.build(REPO_RECORDS, cwe="CWE-22"))
        counts = payload["catalog"]["counts"]
        self.assertEqual(counts["cwe_records"], 892)
        self.assertEqual(counts["withdrawn_otherwise_eligible"], 2)
        self.assertEqual(counts["exported"], 503)
        self.assertEqual(len(payload["records"]), 503)
        self.assertEqual(payload["records"], sorted(payload["records"], key=lambda row: row["id"]))
        self.assertTrue(all("CWE-22" in row["cwe_all"] for row in payload["records"]))
        self.assertTrue(all(row["fix"]["fix_commits"] for row in payload["records"]))
        self.assertTrue(all((row.get("url") or "").startswith("http") for row in payload["records"]))
        self.assertTrue(all(not row.get("withdrawn") for row in payload["records"]))


if __name__ == "__main__":
    unittest.main()

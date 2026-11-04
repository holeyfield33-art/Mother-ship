"""Tests for scripts/join_cwe.py and the zero-parse guard in scripts/extract_c002_cwe.py."""
import io
import json
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import extract_c002_cwe as x  # noqa: E402
import join_cwe as j  # noqa: E402

REC = {"id": "GO-2099-0001", "source": "go_vulndb", "kind": "vulnerability",
       "aliases": ["CVE-2099-1", "GHSA-aaaa"], "cwe": [], "cwe_source": None}
GHSA = {"GHSA-aaaa": {"ghsa": "GHSA-aaaa", "cves": ["CVE-2099-1"], "cwe": ["CWE-22"], "reviewed": True}}


def nvd(values, wtype="Primary"):
    return {"CVE-2099-1": {"cve": "CVE-2099-1",
                           "weaknesses": [{"source": "nvd@nist.gov", "type": wtype, "values": values}]}}


class JoinTests(unittest.TestCase):
    def test_agree_when_ghsa_and_nvd_share_a_cwe(self):
        r = j.join_record(REC, GHSA, nvd(["CWE-22", "CWE-73"]))
        self.assertEqual(r["agreement"], "agree")
        self.assertEqual(r["cwe_all"], ["CWE-22", "CWE-73"])
        origins = {(e["cwe"], e["origin"], e["via"]) for e in r["cwe_links"]}
        self.assertIn(("CWE-22", "ghsa", "GHSA-aaaa"), origins)
        self.assertIn(("CWE-22", "nvd", "CVE-2099-1"), origins)

    def test_conflict_when_no_cwe_shared(self):
        self.assertEqual(j.join_record(REC, GHSA, nvd(["CWE-79"]))["agreement"], "conflict")

    def test_placeholder_is_never_a_class(self):
        r = j.join_record(REC, {}, nvd(["NVD-CWE-noinfo"]))
        self.assertEqual(r["cwe_all"], [])
        self.assertEqual(r["agreement"], "none")
        self.assertEqual([p["cwe"] for p in r["nvd_placeholders"]], ["NVD-CWE-noinfo"])

    def test_only_direct_aliases_link(self):
        rec = dict(REC, aliases=["CVE-2099-1"])  # GHSA-aaaa shares the CVE but is not the record's alias
        r = j.join_record(rec, GHSA, {})
        self.assertEqual(r["cwe_all"], [])

    def test_source_record_cwe_is_kept_with_its_origin(self):
        rec = dict(REC, aliases=[], cwe=["CWE-79"], cwe_source="source:database_specific.cwe_ids")
        r = j.join_record(rec, {}, {})
        self.assertEqual(r["cwe_links"][0]["origin"], "source_record")
        self.assertEqual(r["agreement"], "single_origin")

    def test_unreviewed_ghsa_is_labelled(self):
        g = {"GHSA-aaaa": dict(GHSA["GHSA-aaaa"], reviewed=False)}
        r = j.join_record(REC, g, {})
        self.assertEqual(r["cwe_links"][0]["detail"], "unreviewed")


class ExtractGuardTests(unittest.TestCase):
    @staticmethod
    def tgz(files):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w:gz") as t:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        return b.getvalue()

    def test_snapshot_without_advisories_is_refused(self):
        with self.assertRaises(ValueError):
            x.ghsa_rows(self.tgz({"README.md": b"x"}), set(), set())

    def test_root_level_advisories_path_is_read(self):
        adv = json.dumps({"id": "GHSA-aaaa", "aliases": ["CVE-1"],
                          "database_specific": {"cwe_ids": ["CWE-22"]}}).encode()
        rows, parsed = x.ghsa_rows(self.tgz({"advisories/github-reviewed/2024/01/GHSA-aaaa/GHSA-aaaa.json": adv}),
                                   {"GHSA-aaaa"}, set())
        self.assertEqual(parsed, 1)
        self.assertEqual(rows["GHSA-aaaa"]["cwe"], ["CWE-22"])
        self.assertTrue(rows["GHSA-aaaa"]["reviewed"])


if __name__ == "__main__":
    unittest.main()

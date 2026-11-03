"""Tests for scripts/normalize_d004.py. Run: python -m unittest discover -s tests -v

Synthetic fixtures check each parser and each refusal. The full-package test runs only when
MSHIP_D004_ZIP points at the preserved D-004 package.
"""
import json
import os
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import normalize_d004 as n  # noqa: E402

PROV = {"cycle": "D-004", "package_id": "p", "package_sha256": "x", "source_artifact": "a",
        "source_artifact_sha256": "y", "source_revision": "r", "acquired_utc": "t", "authoritative_url": "u",
        "collected_by": "Manus", "spec_by": "DeepSeek (D-003)", "orchestrator": "ChatGPT"}

OSV = {
    "id": "GO-2099-0001", "aliases": ["GHSA-zzzz", "CVE-2099-1"], "summary": "Bug in pkg",
    "details": "Classic CWE-22 path traversal.", "published": "2099-01-01T00:00:00Z",
    "affected": [{"package": {"name": "example.com/pkg", "ecosystem": "Go"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]},
                             {"type": "GIT", "repo": "https://github.com/ex/pkg", "events": [{"introduced": "0"}, {"fixed": "abcdef1234567"}]}],
                  "versions": ["1.0.0", "1.1.0"],
                  "ecosystem_specific": {"imports": [{"path": "example.com/pkg", "symbols": ["Open", "Close"]}]}}],
    "references": [{"type": "FIX", "url": "https://github.com/ex/pkg/commit/0123456789abcdef"},
                   {"type": "WEB", "url": "https://example.com/blog"}],
}

RUSTSEC = '''```toml
[advisory]
id = "RUSTSEC-2099-0001"
package = "demo"
date = "2099-01-01"
url = "https://github.com/ex/demo/issues/1"
categories = ["memory-corruption"]
keywords = ["uaf"]
informational = "unsound"
aliases = ["CVE-2099-2"]

[versions]
patched = [">= 1.0.1"]

[affected.functions]
"demo::parse" = ["< 1.0.1"]
```

# Use after free in parse

Details here.
'''


class OsvTests(unittest.TestCase):
    def test_osv_record_fields(self):
        r = n.osv_record(OSV, "go_vulndb", "ID/GO-2099-0001.json", PROV)
        n.validate(r)
        self.assertEqual(r["url"], "https://pkg.go.dev/vuln/GO-2099-0001")
        self.assertEqual(r["aliases"], ["CVE-2099-1", "GHSA-zzzz"])
        self.assertEqual(r["fix"]["fixed_versions"], ["1.2.3"])
        self.assertEqual(r["fix"]["git_fixed"], [{"repo": "https://github.com/ex/pkg", "commit": "abcdef1234567"}])
        self.assertIn("https://github.com/ex/pkg/commit/0123456789abcdef", r["fix"]["fix_commits"])
        self.assertIn("https://github.com/ex/pkg/commit/abcdef1234567", r["fix"]["fix_commits"])
        self.assertEqual(r["affected"][0]["versions_listed"], 2)
        self.assertEqual(r["affected"][0]["symbols"], [{"path": "example.com/pkg", "symbols": ["Close", "Open"]}])
        self.assertEqual(r["evidence_tier"], "R1")
        self.assertEqual(r["provenance"]["source_path"], "ID/GO-2099-0001.json")

    def test_text_cwe_is_a_hint_not_a_class(self):
        r = n.osv_record(OSV, "go_vulndb", "p", PROV)
        self.assertEqual(r["cwe"], [])
        self.assertIsNone(r["cwe_source"])
        self.assertEqual(r["cwe_mentioned_in_text"], ["CWE-22"])

    def test_structured_cwe_is_recorded_with_source(self):
        raw = dict(OSV, database_specific={"cwe_ids": ["CWE-79"]})
        r = n.osv_record(raw, "pypa", "p", PROV)
        self.assertEqual(r["cwe"], ["CWE-79"])
        self.assertEqual(r["cwe_source"], "source:database_specific.cwe_ids")

    def test_no_fix_means_tier_r0(self):
        raw = dict(OSV, references=[], affected=[{"package": {"name": "x", "ecosystem": "Go"},
                                                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}])
        self.assertEqual(n.osv_record(raw, "go_vulndb", "p", PROV)["evidence_tier"], "R0")

    def test_missing_id_is_refused(self):
        with self.assertRaises(n.NormalizeError):
            n.osv_record(dict(OSV, id=None), "go_vulndb", "p", PROV)

    def test_yaml_versions_stay_strings(self):
        raw = yaml.load("id: PYSEC-2099-1\naffected:\n- package: {name: x, ecosystem: PyPI}\n  ranges:\n"
                        "  - type: ECOSYSTEM\n    events:\n    - introduced: \"0\"\n    - fixed: 1.10\n",
                        Loader=yaml.BaseLoader)
        r = n.osv_record(raw, "pypa", "p", PROV)
        self.assertEqual(r["fix"]["fixed_versions"], ["1.10"])


class RustsecTests(unittest.TestCase):
    def test_rustsec_record_fields(self):
        r = n.rustsec_record(RUSTSEC, "crates/demo/RUSTSEC-2099-0001.md", PROV)
        n.validate(r)
        self.assertEqual(r["kind"], "unsound")
        self.assertEqual(r["title"], "Use after free in parse")
        self.assertEqual(r["details"], "Details here.")
        self.assertEqual(r["fix"]["fixed_versions"], [">= 1.0.1"])
        self.assertEqual(r["source_categories"], ["memory-corruption", "uaf"])
        self.assertEqual(r["affected"][0]["symbols"], [{"path": "demo", "symbols": ["demo::parse"]}])
        self.assertEqual(r["url"], "https://rustsec.org/advisories/RUSTSEC-2099-0001.html")

    def test_plain_advisory_is_vulnerability(self):
        r = n.rustsec_record(RUSTSEC.replace('informational = "unsound"\n', ""), "p", PROV)
        self.assertEqual(r["kind"], "vulnerability")

    def test_missing_front_matter_is_refused(self):
        with self.assertRaises(n.NormalizeError):
            n.rustsec_record("# just markdown\n", "p", PROV)


class RuleTests(unittest.TestCase):
    def test_commit_url_patterns(self):
        yes = ["https://github.com/a/b/commit/0123456789abcdef", "https://gitlab.com/a/b/-/commit/0123456789abc",
               "https://go.googlesource.com/go/+/0123456789abcdef"]
        no = ["https://github.com/a/b/pull/12", "https://github.com/a/b/releases/tag/v1.2.3"]
        self.assertEqual(n.fix_commit_urls(yes + no), sorted(yes))

    def test_validate_refuses_incomplete_provenance(self):
        r = n.osv_record(OSV, "go_vulndb", "p", dict(PROV, orchestrator=""))
        with self.assertRaises(n.NormalizeError):
            n.validate(r)

    def test_validate_refuses_missing_url(self):
        r = n.osv_record(OSV, "go_vulndb", "p", PROV)
        r["url"] = ""
        with self.assertRaises(n.NormalizeError):
            n.validate(r)


@unittest.skipUnless(os.environ.get("MSHIP_D004_ZIP"), "set MSHIP_D004_ZIP to the preserved D-004 package")
class FullPackageTests(unittest.TestCase):
    def test_counts_and_determinism(self):
        a = n.build(os.environ["MSHIP_D004_ZIP"])
        b = n.build(os.environ["MSHIP_D004_ZIP"])
        self.assertEqual(a, b)
        s = json.loads(a["SUMMARY.json"])["sources"]
        self.assertEqual({k: v["records"] for k, v in s.items()},
                         {"go_vulndb": 4712, "pypa": 7901, "rustsec": 1375, "hackage": 33})

    def test_tampered_package_is_refused(self):
        bad = Path(os.environ.get("TMPDIR", "/tmp")) / "mship_tampered_d004.zip"
        bad.write_bytes(Path(os.environ["MSHIP_D004_ZIP"]).read_bytes() + b"x")
        try:
            with self.assertRaises(FileNotFoundError):
                n.build(bad)
        finally:
            bad.unlink()


if __name__ == "__main__":
    unittest.main()

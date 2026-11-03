#!/usr/bin/env python3
"""Extract CWE labels from the C-002 handoff for the IDs MOTHERSHIP records use.

Streams the C-002 tarball from stdin (it never needs the 3.66 GB file on disk), reads only the
GitHub Advisory Database snapshot and the NVD API pages, and keeps CWE data only for GHSA/CVE IDs
that appear in records/*/*.jsonl (as an id or alias). Every file read is hashed and checked
against C-002's own SHA256SUMS.txt.

  cat MOTHERSHIP_C002_HANDOFF.tar.gz.part00 MOTHERSHIP_C002_HANDOFF.tar.gz.part01 \
    | python scripts/extract_c002_cwe.py --out derived/c002_cwe

Exit codes: 0 OK, 1 checksum mismatch or missing input, 2 bad arguments.
"""
import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GHSA_MEMBER = "vuln_intel_cycle_02/raw/github-advisory-database-main.tar.gz"
NVD_PREFIX = "vuln_intel_cycle_02/raw/nvd_api_pages/"
SUMS_MEMBER = "vuln_intel_cycle_02/SHA256SUMS.txt"
REAL_CWE = re.compile(r"^CWE-\d+$")


def wanted_ids(records_root):
    ghsa, cve = set(), set()
    for f in sorted(Path(records_root).glob("*/*.jsonl")):
        for line in f.open(encoding="utf-8"):
            r = json.loads(line)
            for i in [r["id"], *r.get("aliases", [])]:
                if i.startswith("GHSA-"):
                    ghsa.add(i)
                elif i.startswith("CVE-"):
                    cve.add(i)
    return ghsa, cve


def ghsa_rows(data, ghsa_wanted, cve_wanted):
    rows = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t:
            if not (m.isfile() and m.name.endswith(".json") and "/advisories/" in m.name):
                continue
            a = json.loads(t.extractfile(m).read())
            gid = a.get("id", "")
            cves = sorted(x for x in a.get("aliases") or [] if x.startswith("CVE-"))
            if gid not in ghsa_wanted and not set(cves) & cve_wanted:
                continue
            ds = a.get("database_specific") or {}
            rows[gid] = {"ghsa": gid, "cves": cves, "cwe": sorted(set(ds.get("cwe_ids") or [])),
                         "reviewed": bool(ds.get("github_reviewed")), "withdrawn": a.get("withdrawn"),
                         "path": m.name.split("/", 1)[-1]}
    return rows


def nvd_rows(data, cve_wanted, rows):
    page = json.loads(data)
    for v in page.get("vulnerabilities") or []:
        c = v.get("cve") or {}
        cid = c.get("id")
        if cid not in cve_wanted:
            continue
        ws = []
        for w in c.get("weaknesses") or []:
            vals = sorted({d.get("value") for d in w.get("description") or [] if d.get("value")})
            ws.append({"source": w.get("source"), "type": w.get("type"), "values": vals})
        rows[cid] = {"cve": cid, "weaknesses": sorted(ws, key=lambda x: (x["type"] or "", x["source"] or "")),
                     "vuln_status": c.get("vulnStatus")}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "derived" / "c002_cwe"))
    ap.add_argument("--records", default=str(ROOT / "records"))
    a = ap.parse_args()
    ghsa_wanted, cve_wanted = wanted_ids(a.records)
    seen_hash, ghsa, nvd, sums = {}, {}, {}, None
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|gz") as t:
        for m in t:
            if not m.isfile():
                continue
            if m.name == SUMS_MEMBER:
                sums = t.extractfile(m).read().decode()
                continue
            if m.name != GHSA_MEMBER and not m.name.startswith(NVD_PREFIX):
                continue
            data = t.extractfile(m).read()
            seen_hash[m.name.split("vuln_intel_cycle_02/", 1)[1]] = hashlib.sha256(data).hexdigest()
            if m.name == GHSA_MEMBER:
                ghsa = ghsa_rows(data, ghsa_wanted, cve_wanted)
            else:
                nvd_rows(data, cve_wanted, nvd)
    if sums is None or GHSA_MEMBER.split("vuln_intel_cycle_02/", 1)[1] not in seen_hash:
        print("FAILED: SHA256SUMS or GitHub Advisory snapshot not found in stream")
        return 1
    expected = {}
    for line in sums.splitlines():
        if line.strip():
            h, p = line.split(None, 1)
            expected[p.strip().lstrip("*").removeprefix("./").removeprefix("vuln_intel_cycle_02/")] = h
    bad = [p for p, h in seen_hash.items() if expected.get(p) != h]
    if bad:
        print(f"FAILED: {len(bad)} files differ from C-002 SHA256SUMS, e.g. {bad[:3]}")
        return 1
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    dump = lambda rows: "".join(json.dumps(rows[k], sort_keys=True, separators=(",", ":")) + "\n" for k in sorted(rows))
    (out / "ghsa_cwe.jsonl").write_text(dump(ghsa), encoding="utf-8")
    (out / "nvd_cwe.jsonl").write_text(dump(nvd), encoding="utf-8")
    nvd_pages = sorted(p for p in seen_hash if p.startswith("raw/nvd_api_pages/"))
    summary = {
        "source_package": "c002-handoff", "source_sha256": "14738da2fc7d0dd0ea9cb36f9dd3b7b618344fbc3fe3103d8719c8d4c4dabf62",
        "files_read": len(seen_hash), "files_checked_against_c002_sha256sums": len(seen_hash),
        "ghsa_snapshot_sha256": seen_hash["raw/github-advisory-database-main.tar.gz"], "nvd_pages": len(nvd_pages),
        "wanted": {"ghsa_ids": len(ghsa_wanted), "cve_ids": len(cve_wanted)},
        "found": {"ghsa_rows": len(ghsa), "ghsa_with_cwe": sum(bool(r["cwe"]) for r in ghsa.values()),
                  "nvd_rows": len(nvd),
                  "nvd_with_real_cwe": sum(any(REAL_CWE.match(x) for w in r["weaknesses"] for x in w["values"]) for r in nvd.values())},
    }
    (out / "SUMMARY.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

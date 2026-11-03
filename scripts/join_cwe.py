#!/usr/bin/env python3
"""Join C-002 CWE labels onto MOTHERSHIP records through each record's own declared aliases.

Reads records/<cycle>/*.jsonl and derived/c002_cwe/{ghsa_cwe,nvd_cwe}.jsonl; writes
records/<cycle>/cwe_join.jsonl (one line per record) and CWE_SUMMARY.json. Phase 1 records are
not modified. Deterministic output.

  python scripts/join_cwe.py --cycle d004 [--check]

Rules (see docs/SCHEMA.md):
- Only direct links: the record's id or one of its aliases equals the GHSA or CVE id. No two-hop links.
- Every inherited CWE says where it came from: ghsa (reviewed or unreviewed) or nvd (Primary = NVD
  analyst, Secondary = the CNA that published the CVE).
- NVD placeholders (NVD-CWE-noinfo, NVD-CWE-Other) are kept as placeholders and never count as a class.
- agreement: none | single_origin | agree (GHSA and NVD share at least one CWE) | conflict (both
  have CWEs, none shared).
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REAL_CWE = re.compile(r"^CWE-\d+$")
NON_BUG_KINDS = {"unmaintained", "notice"}


def load_jsonl(path, key):
    return {r[key]: r for r in map(json.loads, Path(path).open(encoding="utf-8"))}


def join_record(rec, ghsa, nvd):
    links, placeholders = [], []
    for cwe in rec.get("cwe") or []:
        links.append({"cwe": cwe, "via": rec["id"], "origin": "source_record", "detail": rec.get("cwe_source")})
    for alias in [rec["id"], *rec.get("aliases", [])]:
        if alias in ghsa:
            g = ghsa[alias]
            for cwe in g["cwe"]:
                links.append({"cwe": cwe, "via": alias, "origin": "ghsa",
                              "detail": "reviewed" if g["reviewed"] else "unreviewed"})
        if alias in nvd:
            for w in nvd[alias]["weaknesses"]:
                for v in w["values"]:
                    entry = {"cwe": v, "via": alias, "origin": "nvd", "detail": f"{w['type']}:{w['source']}"}
                    (links if REAL_CWE.match(v) else placeholders).append(entry)
    key = lambda e: (e["cwe"], e["origin"], e["via"], e["detail"] or "")
    links = sorted({key(e): e for e in links}.values(), key=key)
    placeholders = sorted({key(e): e for e in placeholders}.values(), key=key)
    by_origin = {}
    for e in links:
        by_origin.setdefault(e["origin"], set()).add(e["cwe"])
    if not links:
        agreement = "none"
    elif "ghsa" in by_origin and "nvd" in by_origin:
        agreement = "agree" if by_origin["ghsa"] & by_origin["nvd"] else "conflict"
    else:
        agreement = "single_origin"
    return {"id": rec["id"], "source": rec["source"], "kind": rec["kind"],
            "cwe_all": sorted({e["cwe"] for e in links}), "cwe_links": links,
            "nvd_placeholders": placeholders, "agreement": agreement}


def build(cycle):
    rec_dir = ROOT / "records" / cycle
    ghsa = load_jsonl(ROOT / "derived" / "c002_cwe" / "ghsa_cwe.jsonl", "ghsa")
    nvd = load_jsonl(ROOT / "derived" / "c002_cwe" / "nvd_cwe.jsonl", "cve")
    rows = []
    for f in sorted(rec_dir.glob("*.jsonl")):
        if f.name == "cwe_join.jsonl":
            continue
        rows += [join_record(json.loads(line), ghsa, nvd) for line in f.open(encoding="utf-8")]
    rows.sort(key=lambda r: (r["source"], r["id"]))
    body = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in rows)
    per_source, top = {}, Counter()
    for r in rows:
        s = per_source.setdefault(r["source"], Counter())
        s["records"] += 1
        s["with_cwe"] += bool(r["cwe_all"])
        s[f"agreement_{r['agreement']}"] += 1
        for o in {e["origin"] for e in r["cwe_links"]}:
            s[f"cwe_from_{o}"] += 1
        s["with_reviewed_ghsa_cwe"] += any(e["origin"] == "ghsa" and e["detail"] == "reviewed" for e in r["cwe_links"])
        s["only_nvd_placeholder"] += bool(r["nvd_placeholders"] and not r["cwe_all"])
        if r["kind"] not in NON_BUG_KINDS:
            top.update(r["cwe_all"])
    summary = {"cycle": cycle, "records": len(rows),
               "per_source": {k: dict(sorted(v.items())) for k, v in sorted(per_source.items())},
               "top_cwe_excluding_unmaintained_and_notices": [[c, n] for c, n in
                                                              sorted(top.items(), key=lambda x: (-x[1], x[0]))[:40]]}
    return {"cwe_join.jsonl": body.encode(), "CWE_SUMMARY.json": (json.dumps(summary, indent=1) + "\n").encode()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cycle", default="d004")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    try:
        out = build(a.cycle)
    except FileNotFoundError as e:
        print(f"INPUT ERROR: {e}")
        return 2
    d = ROOT / "records" / a.cycle
    if a.check:
        bad = [n for n, b in out.items() if not (d / n).is_file() or (d / n).read_bytes() != b]
        print("CHECK " + ("FAILED: " + ", ".join(bad) if bad else "OK"))
        return 1 if bad else 0
    for n, b in out.items():
        (d / n).write_bytes(b)
    print(out["CWE_SUMMARY.json"].decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())

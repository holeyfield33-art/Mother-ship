#!/usr/bin/env python3
"""Assemble export/mothership-catalog.json from normalized records + CWE join.

Default slice (Class 1): CWE-22 records that have a public primary URL and at
least one fix-commit link. Withdrawn records are counted but excluded from the
export body. A fixed version alone is not enough; a fix-commit URL is required.

The catalog is generic. Consumers such as agent-security-index may use it only
as proposals; this script never publishes into ASI.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "mothership-catalog/v1"
DEFAULT_CWE = "CWE-22"
SOURCE_FILES = (
    "go_vulndb.jsonl",
    "pypa.jsonl",
    "rustsec.jsonl",
    "hackage.jsonl",
)

PUBLIC_PREFIXES = ("http://", "https://")


def public_url(value) -> bool:
    return isinstance(value, str) and value.strip().startswith(PUBLIC_PREFIXES)


def load_jsonl(path: Path):
    rows = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def fix_commit_urls(rec: dict) -> list[str]:
    commits = (rec.get("fix") or {}).get("fix_commits") or []
    return [u for u in commits if public_url(u)]


def matches_slice(rec: dict, join: dict, cwe: str) -> bool:
    if cwe not in (join.get("cwe_all") or []):
        return False
    if not public_url(rec.get("url") or ""):
        return False
    if not fix_commit_urls(rec):
        return False
    return True


def project_record(rec: dict, join: dict) -> dict:
    fix = rec.get("fix") or {}
    affected = []
    for pkg in rec.get("affected") or []:
        affected.append({
            "ecosystem": pkg.get("ecosystem"),
            "name": pkg.get("name"),
            "ranges": pkg.get("ranges") or [],
            "symbols": pkg.get("symbols") or [],
            "versions_listed": pkg.get("versions_listed"),
        })
    prov = rec.get("provenance") or {}
    return {
        "id": rec["id"],
        "source": rec["source"],
        "url": rec["url"],
        "kind": rec.get("kind"),
        "withdrawn": rec.get("withdrawn"),
        "aliases": rec.get("aliases") or [],
        "title": rec.get("title"),
        "published": rec.get("published"),
        "modified": rec.get("modified"),
        "affected": affected,
        "fix": {
            "fix_commits": fix_commit_urls(rec),
            "fixed_versions": fix.get("fixed_versions") or [],
            "git_fixed": fix.get("git_fixed") or [],
        },
        "references": rec.get("references") or [],
        "evidence_tier": rec.get("evidence_tier"),
        "cwe_all": join.get("cwe_all") or [],
        "cwe_links": join.get("cwe_links") or [],
        "agreement": join.get("agreement"),
        "provenance": {
            "cycle": prov.get("cycle"),
            "package_id": prov.get("package_id"),
            "package_sha256": prov.get("package_sha256"),
            "source_path": prov.get("source_path"),
        },
    }


def encode_catalog(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def build(records_dir: Path, cwe: str = DEFAULT_CWE) -> bytes:
    join_path = records_dir / "cwe_join.jsonl"
    if not join_path.is_file():
        raise FileNotFoundError(join_path)

    joins = {row["id"]: row for row in load_jsonl(join_path)}
    records = {}
    missing_source_files = []
    for name in SOURCE_FILES:
        path = records_dir / name
        if not path.is_file():
            missing_source_files.append(name)
            continue
        for rec in load_jsonl(path):
            records[rec["id"]] = rec

    if missing_source_files and not records:
        raise FileNotFoundError("missing record files: " + ", ".join(missing_source_files))

    cwe_ids = [rid for rid, join in joins.items() if cwe in (join.get("cwe_all") or [])]
    missing_records = [rid for rid in cwe_ids if rid not in records]

    n_cwe = 0
    n_url = 0
    n_fix = 0
    n_withdrawn = 0
    exported = []

    for rid in cwe_ids:
        rec = records.get(rid)
        if rec is None:
            continue
        n_cwe += 1
        join = joins[rid]
        has_url = public_url(rec.get("url") or "")
        has_fix = bool(fix_commit_urls(rec))
        if has_url:
            n_url += 1
        if has_fix:
            n_fix += 1
        if not matches_slice(rec, join, cwe):
            continue
        if rec.get("withdrawn"):
            n_withdrawn += 1
            continue
        exported.append(project_record(rec, join))

    exported.sort(key=lambda row: row["id"])

    payload = {
        "catalog": {
            "schema": SCHEMA,
            "slice": cwe,
            "selection": {
                "cwe": cwe,
                "require_public_url": True,
                "require_fix_commit": True,
                "exclude_withdrawn": True,
            },
            "counts": {
                "cwe_records": n_cwe,
                "cwe_records_missing_source": len(missing_records),
                "with_public_url": n_url,
                "with_fix_commit": n_fix,
                "eligible_including_withdrawn": len(exported) + n_withdrawn,
                "withdrawn_otherwise_eligible": n_withdrawn,
                "exported": len(exported),
            },
            "records_dir": str(Path("records") / records_dir.name) if records_dir.name else "records",
        },
        "records": exported,
    }
    return encode_catalog(payload)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cycle", default="d004")
    ap.add_argument("--cwe", default=DEFAULT_CWE)
    ap.add_argument("--records-dir", type=Path, default=None,
                    help="Override records/<cycle> (used by tests)")
    ap.add_argument("--output", type=Path, default=None,
                    help="Override export/mothership-catalog.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)

    records_dir = args.records_dir or (ROOT / "records" / args.cycle)
    output = args.output or (ROOT / "export" / "mothership-catalog.json")

    try:
        body = build(records_dir, cwe=args.cwe)
    except FileNotFoundError as exc:
        print(f"INPUT ERROR: {exc}")
        return 2

    if args.check:
        if not output.is_file() or output.read_bytes() != body:
            print(f"CHECK FAILED: {output}")
            return 1
        print("CHECK OK")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(body)
    catalog = json.loads(body)
    counts = catalog["catalog"]["counts"]
    print(json.dumps({"output": str(output), "slice": catalog["catalog"]["slice"], "counts": counts}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

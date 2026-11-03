#!/usr/bin/env python3
"""Normalize the D-004 ecosystem evidence package into mothership-record/v1 JSONL.

Usage:
  python scripts/normalize_d004.py PATH/TO/MOTHERSHIP_D004_ECOSYSTEM_EVIDENCE.zip [--out records/d004]
  python scripts/normalize_d004.py PACKAGE.zip --check     # rebuild in memory, compare with files on disk

Needs Python 3.11+ (tomllib) and PyYAML (see requirements.txt). Output is deterministic:
the same package always produces byte-identical files. See docs/SCHEMA.md.

Exit codes: 0 OK, 1 validation or --check mismatch, 2 input missing or package hash mismatch.
"""
import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "manifests" / "d004-ecosystem-evidence.json"
SCHEMA = "mothership-record/v1"

SOURCES = {
    # source key in D004 manifest -> (our source name, artifact path, output file)
    "go_vulndb": ("go_vulndb", "original/vulndb.zip", "go_vulndb.jsonl"),
    "pypa_advisory_database": ("pypa", "original/pypa-advisory-database-8084f16.tar.gz", "pypa.jsonl"),
    "rustsec_advisory_database": ("rustsec", "original/rustsec-advisory-db-2295466.tar.gz", "rustsec.jsonl"),
    "osv_hackage": ("hackage", "original/hackage-all.zip", "hackage.jsonl"),
}
URL = {
    "go_vulndb": "https://pkg.go.dev/vuln/{id}",
    "pypa": "https://osv.dev/vulnerability/{id}",
    "rustsec": "https://rustsec.org/advisories/{id}.html",
    "hackage": "https://osv.dev/vulnerability/{id}",
}
REQUIRED = ("schema", "id", "source", "url", "kind", "evidence_tier", "provenance")
PROV_REQUIRED = ("cycle", "package_id", "package_sha256", "source_artifact", "source_artifact_sha256",
                 "source_path", "source_revision", "acquired_utc", "collected_by", "spec_by", "orchestrator")
COMMIT_URL = re.compile(
    r"(/commit/[0-9a-f]{7,40}\b|/commits/[0-9a-f]{7,40}\b|/-/commit/[0-9a-f]{7,40}\b|googlesource\.com/.+/\+/[0-9a-f]{7,40}\b)",
    re.I)
CWE = re.compile(r"\bCWE-\d+\b")
FRONT_MATTER = re.compile(r"\A\s*```toml\n(.*?)\n```\s*\n?(.*)\Z", re.S)


class NormalizeError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sorted_unique(items):
    return sorted({i for i in items if i})


def fix_commit_urls(urls):
    return sorted_unique(u for u in urls if u and COMMIT_URL.search(u))


def git_commit_url(repo, commit):
    repo = (repo or "").rstrip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if re.match(r"https://(github\.com|gitlab\.com)/", repo) and re.fullmatch(r"[0-9a-f]{7,40}", commit or ""):
        return f"{repo}/commit/{commit}"
    return None


def text_cwes(*texts):
    return sorted_unique(m.group(0) for t in texts if isinstance(t, str) for m in CWE.finditer(t))


def tier(fix):
    return "R1" if (fix["fixed_versions"] or fix["fix_commits"] or fix["git_fixed"]) else "R0"


def osv_record(raw, source, source_path, prov_base):
    """Normalize one OSV-format record (Go, Hackage, PyPA)."""
    rid = raw.get("id")
    if not rid:
        raise NormalizeError(f"{source}:{source_path}: record has no id")
    affected, fixed_versions, git_fixed = [], [], []
    for a in raw.get("affected") or []:
        pkg = a.get("package") or {}
        ranges = []
        for rg in a.get("ranges") or []:
            r = {"type": rg.get("type"), "events": rg.get("events") or []}
            if rg.get("repo"):
                r["repo"] = rg["repo"]
            ranges.append(r)
            for ev in r["events"]:
                if "fixed" in ev:
                    if r["type"] == "GIT":
                        git_fixed.append({"repo": rg.get("repo"), "commit": ev["fixed"]})
                    else:
                        fixed_versions.append(ev["fixed"])
        eco = a.get("ecosystem_specific") or {}
        symbols = []
        for imp in eco.get("imports") or []:
            symbols.append({"path": imp.get("path"), "symbols": sorted(imp.get("symbols") or [])})
        api = eco.get("affected_api")
        if isinstance(api, list):
            symbols.append({"path": pkg.get("name"), "symbols": sorted(str(x) for x in api)})
        affected.append({"ecosystem": pkg.get("ecosystem"), "name": pkg.get("name"), "ranges": ranges,
                         "versions_listed": len(a.get("versions") or []), "symbols": symbols})
    refs = [{"type": r.get("type"), "url": r.get("url")} for r in raw.get("references") or []]
    git_fixed = sorted({(g["repo"] or "", g["commit"]) for g in git_fixed})
    fix = {
        "fixed_versions": sorted_unique(fixed_versions),
        "fix_commits": sorted_unique(fix_commit_urls(r["url"] for r in refs)
                                     + [git_commit_url(r, c) for r, c in git_fixed]),
        "git_fixed": [{"repo": r or None, "commit": c} for r, c in git_fixed],
    }
    ds = raw.get("database_specific") or {}
    cwe = sorted_unique(ds.get("cwe_ids") or [])
    return {
        "schema": SCHEMA, "id": rid, "source": source, "url": URL[source].format(id=rid),
        "kind": "vulnerability", "withdrawn": raw.get("withdrawn"),
        "aliases": sorted_unique(raw.get("aliases") or []), "related": sorted_unique(raw.get("related") or []),
        "title": raw.get("summary"), "details": raw.get("details"),
        "published": raw.get("published"), "modified": raw.get("modified"),
        "affected": affected, "fix": fix, "references": refs, "severity": raw.get("severity") or [],
        "cwe": cwe, "cwe_source": "source:database_specific.cwe_ids" if cwe else None,
        "cwe_mentioned_in_text": text_cwes(raw.get("summary"), raw.get("details")),
        "source_categories": [], "evidence_tier": tier(fix),
        "provenance": dict(prov_base, source_path=source_path),
    }


def rustsec_record(text, source_path, prov_base):
    m = FRONT_MATTER.match(text)
    if not m:
        raise NormalizeError(f"rustsec:{source_path}: no TOML front matter")
    meta = tomllib.loads(m.group(1))
    adv, versions, aff = meta.get("advisory") or {}, meta.get("versions") or {}, meta.get("affected") or {}
    rid = adv.get("id")
    if not rid:
        raise NormalizeError(f"rustsec:{source_path}: advisory has no id")
    body = m.group(2).strip("\n")
    title, details = None, body or None
    first, _, rest = body.partition("\n")
    if first.startswith("# "):
        title, details = first[2:].strip(), rest.strip("\n") or None
    refs = [{"type": "WEB", "url": u} for u in ([adv["url"]] if adv.get("url") else []) + list(adv.get("references") or [])]
    patched = list(versions.get("patched") or [])
    functions = aff.get("functions") or {}
    fix = {"fixed_versions": sorted_unique(patched), "fix_commits": fix_commit_urls(r["url"] for r in refs), "git_fixed": []}
    prov = dict(prov_base, source_path=source_path)
    prov["record_license"] = adv.get("license")
    return {
        "schema": SCHEMA, "id": rid, "source": "rustsec", "url": URL["rustsec"].format(id=rid),
        "kind": adv.get("informational") or "vulnerability", "withdrawn": adv.get("withdrawn"),
        "aliases": sorted_unique(adv.get("aliases") or []), "related": sorted_unique(adv.get("related") or []),
        "title": title, "details": details, "published": adv.get("date"), "modified": None,
        "affected": [{"ecosystem": "crates.io", "name": adv.get("package"), "ranges": [],
                      "rustsec_versions": {"patched": patched, "unaffected": list(versions.get("unaffected") or [])},
                      "versions_listed": 0,
                      "symbols": [{"path": adv.get("package"), "symbols": sorted(functions)}] if functions else []}],
        "fix": fix, "references": refs,
        "severity": [{"type": "CVSS", "score": adv["cvss"]}] if adv.get("cvss") else [],
        "cwe": [], "cwe_source": None, "cwe_mentioned_in_text": text_cwes(title, details),
        "source_categories": sorted_unique(list(adv.get("categories") or []) + list(adv.get("keywords") or [])),
        "evidence_tier": tier(fix), "provenance": prov,
    }


def iter_source(source, data):
    """Yield (source_path, record) for every advisory in one preserved artifact."""
    if source in ("go_vulndb", "hackage"):
        z = zipfile.ZipFile(io.BytesIO(data))
        for name in sorted(z.namelist()):
            if source == "go_vulndb" and not (name.startswith("ID/") and name.endswith(".json")):
                continue
            if name.endswith("/"):
                continue
            yield name, json.loads(z.read(name))
    elif source == "pypa":
        t = tarfile.open(fileobj=io.BytesIO(data))
        for m in sorted(t.getmembers(), key=lambda m: m.name):
            if m.isfile() and "/vulns/" in m.name and m.name.endswith(".yaml"):
                yield m.name, yaml.load(t.extractfile(m).read(), Loader=yaml.BaseLoader)
    elif source == "rustsec":
        t = tarfile.open(fileobj=io.BytesIO(data))
        for m in sorted(t.getmembers(), key=lambda m: m.name):
            if m.isfile() and "/crates/" in m.name and m.name.endswith(".md"):
                yield m.name, t.extractfile(m).read().decode("utf-8")


def validate(rec):
    missing = [k for k in REQUIRED if not rec.get(k)]
    missing += [f"provenance.{k}" for k in PROV_REQUIRED if not rec["provenance"].get(k)]
    if missing:
        raise NormalizeError(f"{rec.get('source')}:{rec.get('id')}: missing {missing}")
    if not rec["url"].startswith("https://"):
        raise NormalizeError(f"{rec['id']}: url is not https")


def build(package_path):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    pkg = Path(package_path).read_bytes()
    if sha256(pkg) != manifest["sha256"]:
        raise FileNotFoundError(f"package hash {sha256(pkg)} != manifest {manifest['sha256']}")
    z = zipfile.ZipFile(io.BytesIO(pkg))
    acq = {r["source_key"]: r for r in map(json.loads, z.read("D004_acquisition_manifest.jsonl").decode().splitlines()) if r}
    revisions = json.loads(z.read("D004_source_revisions.json"))["sources"]
    outputs, summary = {}, {"package_id": manifest["package_id"], "package_sha256": manifest["sha256"], "sources": {}}
    for key, (source, artifact, outfile) in SOURCES.items():
        data = z.read(artifact)
        a = acq[key]
        if sha256(data) != a["sha256"]:
            raise NormalizeError(f"{artifact}: sha256 differs from D004 acquisition manifest")
        rev = a.get("cloned_head_sha") or f"gcs-generation:{revisions[key].get('object_generation')}"
        prov = {"cycle": "D-004", "package_id": manifest["package_id"], "package_sha256": manifest["sha256"],
                "source_artifact": artifact, "source_artifact_sha256": a["sha256"], "source_revision": rev,
                "acquired_utc": a["retrieved_end_utc"], "authoritative_url": a["authoritative_url"],
                "collected_by": "Manus", "spec_by": "DeepSeek (D-003)", "orchestrator": "ChatGPT"}
        recs = []
        for path, raw in iter_source(source, data):
            rec = rustsec_record(raw, path, prov) if source == "rustsec" else osv_record(raw, source, path, prov)
            validate(rec)
            recs.append(rec)
        ids = [r["id"] for r in recs]
        if len(ids) != len(set(ids)):
            raise NormalizeError(f"{source}: duplicate ids")
        expected = a["record_counts"]["parsed_records"]
        if len(recs) != expected:
            raise NormalizeError(f"{source}: {len(recs)} records, D-004 manifest says {expected}")
        recs.sort(key=lambda r: r["id"])
        body = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n" for r in recs)
        outputs[outfile] = body.encode("utf-8")
        summary["sources"][source] = {
            "records": len(recs), "expected": expected, "file": outfile, "file_sha256": sha256(outputs[outfile]),
            "kind": count(r["kind"] for r in recs), "evidence_tier": count(r["evidence_tier"] for r in recs),
            "withdrawn": sum(bool(r["withdrawn"]) for r in recs),
            "with_fix_commit": sum(bool(r["fix"]["fix_commits"]) for r in recs),
            "with_fixed_version": sum(bool(r["fix"]["fixed_versions"]) for r in recs),
            "with_symbols": sum(any(a["symbols"] for a in r["affected"]) for r in recs),
            "with_cve_alias": sum(any(x.startswith("CVE-") for x in r["aliases"]) for r in recs),
            "with_structured_cwe": sum(bool(r["cwe"]) for r in recs),
            "with_cwe_text_mention": sum(bool(r["cwe_mentioned_in_text"]) for r in recs),
        }
    outputs["SUMMARY.json"] = (json.dumps(summary, indent=1, sort_keys=True) + "\n").encode("utf-8")
    return outputs


def count(values):
    out = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package")
    ap.add_argument("--out", default=str(ROOT / "records" / "d004"))
    ap.add_argument("--check", action="store_true", help="compare a fresh build with files on disk; write nothing")
    a = ap.parse_args()
    try:
        outputs = build(a.package)
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"INPUT ERROR: {e}")
        return 2
    except NormalizeError as e:
        print(f"VALIDATION FAILED: {e}")
        return 1
    out = Path(a.out)
    if a.check:
        bad = [n for n, b in outputs.items() if not (out / n).is_file() or (out / n).read_bytes() != b]
        print("CHECK " + ("FAILED: " + ", ".join(bad) if bad else f"OK: {len(outputs)} files identical"))
        return 1 if bad else 0
    out.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        (out / name).write_bytes(data)
    print(json.dumps(json.loads(outputs["SUMMARY.json"]), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

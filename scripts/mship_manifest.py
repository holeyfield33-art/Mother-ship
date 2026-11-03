#!/usr/bin/env python3
"""Build or verify a MOTHERSHIP package manifest. Python 3.9+, standard library only.

build:  python scripts/mship_manifest.py build PACKAGE --id ID --cycle C-003 --platform Manus \
            --tag c003 --asset NAME > manifests/ID.json
verify: python scripts/mship_manifest.py verify manifests/ID.json PATH [PATH ...]

verify exit codes: 0 PASS, 1 FAIL (bytes differ), 2 INCOMPLETE (file missing or unreadable).
For a split package, pass every part in order; parts and the rejoined whole are both checked.
"""
import argparse
import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path

SCHEMA = "mothership-package-manifest/v1"
CHUNK = 1 << 20


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def zip_entries(path):
    with zipfile.ZipFile(path) as z:
        bad = z.testzip()
        if bad is not None:
            raise ValueError(f"ZIP CRC failure at {bad}")
        return [{"path": i.filename, "bytes": i.file_size,
                 "sha256": hashlib.sha256(z.read(i.filename)).hexdigest()}
                for i in z.infolist() if not i.is_dir()]


def tar_entries(path):
    out = []
    with tarfile.open(path) as t:
        for m in t.getmembers():
            if m.isfile():
                data = t.extractfile(m).read()
                out.append({"path": m.name, "bytes": m.size, "sha256": hashlib.sha256(data).hexdigest()})
    return out


def entries_for(path):
    if zipfile.is_zipfile(path):
        return "zip", zip_entries(path)
    if tarfile.is_tarfile(path):
        return "tar", tar_entries(path)
    return "file", []


def build(a):
    p = Path(a.package)
    container, entries = entries_for(p)
    manifest = {
        "schema": SCHEMA,
        "package_id": a.id,
        "cycles": a.cycle,
        "producer": {"platform": a.platform, "orchestrator": "ChatGPT (Research Coordinator)",
                     "attribution": "self_reported, cross-checked against package bytes"},
        "original_filename": a.original or p.name,
        "asset_name": a.asset,
        "bytes": p.stat().st_size,
        "sha256": sha256_file(p),
        "container": container,
        "entry_count": len(entries),
        "entries": entries,
        "storage": {"repo": "holeyfield33-art/Mother-ship-archive", "release_tag": a.tag,
                    "status": "PENDING_UPLOAD"},
    }
    json.dump(manifest, sys.stdout, indent=1)
    sys.stdout.write("\n")


def verify(a):
    m = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    if m.get("schema") != SCHEMA:
        print(f"FAIL: unknown schema {m.get('schema')!r}")
        return 1
    paths = [Path(p) for p in a.paths]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        print(f"INCOMPLETE: missing {missing}")
        return 2
    parts = m.get("parts")
    if parts:
        if len(paths) != len(parts):
            print(f"INCOMPLETE: manifest lists {len(parts)} parts, got {len(paths)}")
            return 2
        whole = hashlib.sha256()
        total = 0
        for spec, p in zip(parts, paths):
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for block in iter(lambda: f.read(CHUNK), b""):
                    h.update(block)
                    whole.update(block)
                    total += len(block)
            if h.hexdigest() != spec["sha256"] or p.stat().st_size != spec["bytes"]:
                print(f"FAIL: part {p.name} does not match {spec['name']}")
                return 1
        ok = whole.hexdigest() == m["sha256"] and total == m["bytes"]
        print(("PASS" if ok else "FAIL") + f": rejoined {total} bytes, sha256 {whole.hexdigest()}")
        return 0 if ok else 1
    p = paths[0]
    if p.stat().st_size != m["bytes"] or sha256_file(p) != m["sha256"]:
        print(f"FAIL: {p.name} sha256/bytes differ from manifest {m['package_id']}")
        return 1
    if m.get("entries"):
        _, got = entries_for(p)
        want = {e["path"]: (e["bytes"], e["sha256"]) for e in m["entries"]}
        have = {e["path"]: (e["bytes"], e["sha256"]) for e in got}
        if want != have:
            diff = sorted(set(want.items()) ^ set(have.items()))[:5]
            print(f"FAIL: entry mismatch, first differences {diff}")
            return 1
    print(f"PASS: {m['package_id']} {m['bytes']} bytes, {m.get('entry_count', 0)} entries")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("package")
    b.add_argument("--id", required=True)
    b.add_argument("--cycle", required=True, action="append")
    b.add_argument("--platform", required=True)
    b.add_argument("--tag", required=True)
    b.add_argument("--asset", required=True)
    b.add_argument("--original")
    v = sub.add_parser("verify")
    v.add_argument("manifest")
    v.add_argument("paths", nargs="+")
    a = ap.parse_args()
    if a.cmd == "build":
        build(a)
        return 0
    try:
        return verify(a)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, KeyError, json.JSONDecodeError) as e:
        print(f"INCOMPLETE: could not verify ({type(e).__name__}: {e})")
        return 2


if __name__ == "__main__":
    sys.exit(main())

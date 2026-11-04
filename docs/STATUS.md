# MOTHERSHIP: current status

**This is the single living status page.** Dated notes in `checkpoints/` are history; where they disagree, this page wins.

**Updated:** 2026-11-03 · **Phase:** 0 complete · Phase 1 complete · **Phase 2 (CWE join) complete** · Class 1 (CWE-22) next · **Plan:** [PLAN.md](PLAN.md)

## Packages

Every package below was hashed in full and matches its manifest in `manifests/`. C-002 was checked on the owner's PC (original hash matched, split rejoin verified), against GitHub's computed digests for both release parts, and by streaming both parts back from GitHub: the rejoined bytes hash to `14738da2…`, 3,659,552,713 bytes.

| Package | Cycles | Producer | Bytes | SHA-256 (start) | Bytes stored |
|---|---|---|---:|---|---|
| `d004-ecosystem-evidence` | D-003 → D-004 | Manus (from DeepSeek's specs) | 22,742,076 | `8bf7a6311e32` | Archive repo `packages/` ✓ |
| `c002-handoff` | C-002 | Manus | 3,659,552,713 | `14738da2fc7d` | Archive release `c002` (2 parts) ✓ |
| `c003-results` | C-003 | Manus | 59,205 | `91a5c5683d75` | Archive repo `packages/` ✓ |
| `c003-verification` | C-003 | Manus | 1,321,581 | `2b6de56736ef` | Archive repo `packages/` ✓ |
| `grok-vuln-archive-x004` | D1, X-002, X-004 | Grok | 4,464,077 | `2f85e6a07784` | Archive repo `packages/` ✓ |
| `grok-vuln-archive-x002` | D1, X-002 | Grok | 4,449,135 | `bd4ac0281232` | Archive repo `packages/` ✓ (earlier snapshot, a subset of x004) |
| `p003-historical-evidence` | P-003 | Perplexity | 15,595 | `734c30752d03` | Archive repo `packages/` ✓ |
| `p004-historical-evidence` | P-004 | Manus | 298,434 | `220a48af59d6` | Archive repo `packages/` ✓ |

The D-004 inventory in `checkpoints/D004_EVIDENCE_INVENTORY.md` said "backup INCOMPLETE". The archive has since been found and matches that inventory byte for byte. Its backup status now follows the table above.

## Provenance

`provenance/cycles.json` records all five agents (Manus, Grok, Perplexity, DeepSeek, Gemini) and the ChatGPT coordinator. Each claim is marked `self_reported` or `confirmed` (matched against package bytes).

Three agent-to-agent hand-offs are linked by hash or by named input:
- P-003 → P-004
- C-002 → C-003
- DeepSeek's D-003 fetch specs → Manus's D-004

## Not yet located (deferred by owner)

- Perplexity cycle-1 ZIP
- Manus C-001 handoff
- Gemini chat text
- DeepSeek D-002/D-003 text blocks

## Storage

- **Bytes:** `holeyfield33-art/Mother-ship-archive` (**public**; it holds only public source data and agent collection reports). Packages are in `packages/<tag>/`; C-002 goes in release `c002` as two parts. Source terms are listed in the archive's `NOTICE.md`.
- **IP stays here** in this private repo: dossiers, templates, scorecards.
- Before going public, every committed package was scanned for credentials and personal details. Hits were vulnerability descriptions and published PoC snippets only. The C-002 tarball itself couldn't be scanned (too large), but its fetch checkpoints and logs (inside c003-verification) had no keys.

## Records (Phase 1)

`records/d004/*.jsonl`: 14,021 records in `mothership-record/v1` (see [SCHEMA.md](SCHEMA.md)), built by `scripts/normalize_d004.py` from the preserved D-004 package. The script refuses a package whose hash doesn't match its manifest. Counts per source and file hashes are in `records/d004/SUMMARY.json`.

| Source | Records | Tier R1 (fix located) | Fix commit URL | Named affected functions | Structured CWE |
|---|---:|---:|---:|---:|---:|
| Go | 4,712 | 4,203 | 2,690 | 1,022 | 0 |
| PyPA | 7,901 | 6,909 | 4,150 | 2 | 2 |
| RustSec | 1,375 (859 vuln · 228 unsound · 282 unmaintained · 6 notice) | 912 | 218 | 303 | 0 |
| Hackage | 33 | 33 | 16 | 1 | 0 |

Withdrawn records are kept and flagged (Go 18, PyPA 272, RustSec 25). **Bug class (CWE) is almost absent** (2 of 14,021), which is why Phase 2 exists.

Verified: counts match the D-004 acquisition manifest; two builds are byte-identical (`--check`); 16 tests pass, including refusals of a tampered package, a missing id, missing provenance and a YAML version coerced to a number; 3 records matched their live pages (GO-2022-0462, RUSTSEC-2020-0108, PYSEC-2012-1).

## CWE join (Phase 2)

`records/d004/cwe_join.jsonl` links records to CWEs from C-002 (GitHub Advisory snapshot, 397,466 advisories parsed; NVD, 209 pages). All 210 files read were checked against C-002's own checksums.

| Source | Records | With a CWE | GHSA & NVD agree | Conflict |
|---|---:|---:|---:|---:|
| Go | 4,712 | 4,532 | 3,771 | 76 |
| PyPA | 7,901 | 7,693 | 6,651 | 173 |
| RustSec | 1,375 | 712 | 449 | 27 |
| Hackage | 33 | 19 | 2 | 0 |
| **Total** | **14,021** | **12,956** | | |

Before the join, 2 records had a CWE. RustSec stays lower because 288 of its entries are unmaintained/notice and many crates have no CVE.

**First class ranking** (records with a fix-commit link = real vulnerable/fixed pairs):

| CWE | Records | Fix-commit pairs | Named functions | Agree |
|---|---:|---:|---:|---:|
| **CWE-22 path traversal** | 892 | **505** | 80 | 90% |
| CWE-20 input validation | 712 | 414 | 79 | 83% |
| CWE-79 XSS | 786 | 393 | 32 | 90% |
| CWE-400 resource consumption | 595 | 318 | 86 | 80% |
| CWE-200 information exposure | 566 | 272 | 23 | 86% |

**Bug caught and fixed during this phase:** the first extraction matched 0 GitHub advisories and still exited OK; the snapshot's paths start with `advisories/`, not `/advisories/`. The extractor now refuses a snapshot that yields zero advisory files (tested).

## Next 1-3 actions

1. **Class 1: CWE-22.** Write the selection rule and pick 10-20 study cases with fix commits across Go, PyPA and Rust.
2. Draft the case-sheet and dossier templates (PLAN section 10) on the first 3 cases, then hand case work to the agents.
3. Deferred, owner's choice: Perplexity cycle-1 ZIP, Manus C-001, Gemini and DeepSeek chat text.

## Verify a package

```bash
python scripts/mship_manifest.py verify manifests/d004-ecosystem-evidence.json MOTHERSHIP_D004_ECOSYSTEM_EVIDENCE.zip
```

Exit codes: 0 PASS, 1 FAIL (bytes differ), 2 INCOMPLETE (file missing). For split packages, pass every part in order.

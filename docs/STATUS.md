# MOTHERSHIP: current status

**This is the single living status page.** Dated notes in `checkpoints/` are history; where they disagree, this page wins.

**Updated:** 2026-11-03 · **Phase:** 0 (preservation) **complete**; Phase 1 next · **Plan:** [PLAN.md](PLAN.md)

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

## Next 1-3 actions

1. **Phase 1:** normalize D-004 into `records/*.jsonl`, one deterministic script per source. Done when counts equal 4,712 / 7,901 / 1,375 / 33 and reruns are byte-identical.
2. **Phase 2 prep:** decide where the C-002 extraction runs. GitHub Advisory (143 MB) and the NVD pages are needed for the CWE join; the parts can now be downloaded anywhere.
3. Deferred, owner's choice: Perplexity cycle-1 ZIP, Manus C-001, Gemini and DeepSeek chat text.

## Verify a package

```bash
python scripts/mship_manifest.py verify manifests/d004-ecosystem-evidence.json MOTHERSHIP_D004_ECOSYSTEM_EVIDENCE.zip
```

Exit codes: 0 PASS, 1 FAIL (bytes differ), 2 INCOMPLETE (file missing). For split packages, pass every part in order.

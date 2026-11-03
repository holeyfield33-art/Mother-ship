# MOTHERSHIP: current status

**This is the single living status page.** Dated notes in `checkpoints/` are history; where they disagree, this page wins.

**Updated:** 2026-11-02 · **Phase:** 0 (preservation) in progress · **Plan:** [PLAN.md](PLAN.md)

## Packages

Every package below was hashed in full on 2026-11-02 and matches its manifest in `manifests/`, except C-002, which is too large to transfer.

| Package | Cycles | Producer | Bytes | SHA-256 (start) | Bytes stored |
|---|---|---|---:|---|---|
| `d004-ecosystem-evidence` | D-003 → D-004 | Manus (from DeepSeek's specs) | 22,742,076 | `8bf7a6311e32` | Owner PC; release pending |
| `c002-handoff` | C-002 | Manus | 3,659,552,713 | `14738da2fc7d` | **Owner PC only**; split + release pending |
| `c003-results` | C-003 | Manus | 59,205 | `91a5c5683d75` | Owner PC; release pending |
| `c003-verification` | C-003 | Manus | 1,321,581 | `2b6de56736ef` | Owner PC; release pending |
| `grok-vuln-archive-x004` | D1, X-002, X-004 | Grok | 4,464,077 | `2f85e6a07784` | Upload; release pending |
| `grok-vuln-archive-x002` | D1, X-002 | Grok | 4,449,135 | `bd4ac0281232` | Owner PC; release pending (earlier snapshot, a subset of x004) |
| `p003-historical-evidence` | P-003 | Perplexity | 15,595 | `734c30752d03` | Upload; release pending |
| `p004-historical-evidence` | P-004 | Manus | 298,434 | `220a48af59d6` | Owner PC; release pending |

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

## Next 1-3 actions

1. **Owner:** create the private repo `holeyfield33-art/Mother-ship-archive`.
2. Upload the ~33 MB of packages as releases (tags in each manifest's `storage.release_tag`), then set `storage.status` to `UPLOADED`.
3. **Owner, on the PC:** split C-002 into two parts under 2 GiB each, fill `parts[]` in `manifests/c002-handoff.json`, verify the rejoin with `scripts/mship_manifest.py`, then upload.

## Verify a package

```bash
python scripts/mship_manifest.py verify manifests/d004-ecosystem-evidence.json MOTHERSHIP_D004_ECOSYSTEM_EVIDENCE.zip
```

Exit codes: 0 PASS, 1 FAIL (bytes differ), 2 INCOMPLETE (file missing). For split packages, pass every part in order.

# MOTHERSHIP

Global Vulnerability Intelligence Collection (MOTHERSHIP-001).

Purpose: build an evidence-backed intelligence foundation of software vulnerabilities, failure mechanisms, root causes, and verified fixes. Current phase: source acquisition and dataset integrity, not product deployment.

## Research boundaries

MOTHERSHIP is distinct from Software Research Studio. Do not import Studio checkpoints, datasets, or D-004 material solely because earlier archives used a MOTHERSHIP filename. Cross-project evidence requires an explicit ownership decision and provenance record.

## Data policy

Preserve original source bytes, SHA-256 checksums, retrieval metadata, source URLs, licensing notes, and evidence-to-claim relationships. Separate verified facts, hypotheses, and unreviewed claims. Do not assert an archive has been backed up unless the actual bytes and hashes are present and verified.

## Current backup status

All located research packages have been hashed and recorded in `manifests/`. Their bytes are being moved to the private `Mother-ship-archive` repo as releases. See [docs/STATUS.md](docs/STATUS.md) for current state, and `AGENTS.md` for how agents should work here.

## Consumers

Tools that use MOTHERSHIP's data live in their own repos and read its export; they are not merged in (see `AGENTS.md`). Current consumers include the bug-hunt agent, the ASI threat graph, scanner build/test (Sentinel, vibe-explainer, Code Atlas), and `diffsec` ([holeyfield33-art/diffsec](https://github.com/holeyfield33-art/diffsec)) -- a standalone differential-recon tool that uses the fix-commit pairs for scanner calibration. See [docs/PLAN.md](docs/PLAN.md) section 2.

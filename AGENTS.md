# MOTHERSHIP: agent entrypoint

**What this is:** a private vulnerability-intelligence research repo. It holds public advisory data collected by five agents (Manus, Grok, Perplexity, DeepSeek, Gemini), coordinated through ChatGPT. Its purpose is a class-by-class study of vulnerability classes, which in turn feeds security templates, scanner calibration and the threat graph.

## Read order

1. `README.md`: charter and data policy.
2. `docs/STATUS.md`: **the only current-state page.** Check its date.
3. `docs/PLAN.md`: phases and the class study program.
4. `docs/INTAKE.md`: record format.
5. On demand: `manifests/`, `provenance/cycles.json`, `checkpoints/` (history only).

## Rules

- **Never trust a claim you didn't check.** A self-report, an agent's summary or a doc statement is `self_reported` until it's matched against package bytes. Run `scripts/mship_manifest.py verify` before using any package.
- **Never invent a hash, count, URL, CVE or commit.** Write `UNKNOWN`. A fabricated hash has already happened in this project (Gemini G-002), and it is exactly what this repo exists to catch.
- **An ID link is not "same bug".** Crosswalk rows mean the identifiers are linked, not that root cause or scope are identical.
- **An inherited CWE must be marked inherited** (`cwe_source`).
- **Keep it separate.** No Software Research Studio material goes here, and no Sentinel code. Other tools consume MOTHERSHIP's export; they aren't merged into it.
- **Binaries don't go in git.** Bytes live as releases in `Mother-ship-archive`; this repo holds manifests that point to them.
- **Don't change a manifest's hash to make a check pass.** A mismatch is a finding. Stop and report it.

## Consumers

Other tools read MOTHERSHIP's export and live in their own repos (never merged in, per the rule above): the bug-hunt agent, the ASI threat graph, the Agent Security Index (`holeyfield33-art/agent-security-index`; proposal-only — MOTHERSHIP must not publish into the index, merge into it, or update the live catalog), scanner build/test (Sentinel, vibe-explainer, Code Atlas), and `diffsec` (standalone differential-recon / scanner-calibration tool; its own repo, `holeyfield33-art/diffsec`). `docs/PLAN.md` section 2 lists what each needs from a record.

## Handoff

When you finish, update `docs/STATUS.md` with what changed, what you ran and the result, and the next 1-3 actions. Don't create other status files.

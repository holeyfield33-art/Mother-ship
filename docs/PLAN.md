# MOTHERSHIP: organization plan

**Date:** 2026-11-02 (night)
**Repo:** `holeyfield33-art/Mother-ship` at `cc52072`, 4 doc files, private
**Status:** proposal. Nothing has been built, committed or moved. Every number below was measured tonight from the packages in your Downloads folder unless it's marked otherwise.

**Goal, in your words:** organize this repo like ASI, lay the threat graph over it, and use it to build, test and bug hunt. Use it for Blockwise once it's finished.

---

## 1. What exists today

### 1.1 The research packages

| Cycle | Package | What it holds | Integrity checked tonight |
|---|---|---|---|
| **D1** | `vuln_archive.zip` (Oct 29) | Source registry of every major vuln database, with URLs and licensing | ZIP valid |
| **X-002** | same ZIP | 30 deep technical findings (Project Zero, Trail of Bits): mechanism, root cause, patch, PoC status. 15 root-cause classes. CISA KEV snapshot. CWE v5 catalog | CWE hash matches its record |
| **C-002** | `vuln_intel_cycle_02_handoff.tar.gz` (3.66 GB, on your PC only) | Full raw baselines: NVD 416,844 / CVE List V5 416,267 / GitHub Advisory 397,466 / OSV 2,332,672 | Not transferable (too big). C-003 verified it |
| **C-003** | `MOTHERSHIP_C003_RESULTS.zip` + `_VERIFICATION.zip` | Re-verification of C-002: 217/217 raw files pass, tarball hash `14738da2…` matches. Verdict CONDITIONAL PASS | 6/6 sums present match |
| **D-004** | `MOTHERSHIP_D004_ECOSYSTEM_EVIDENCE.zip` (2 identical copies) | Go 4,712, PyPA 7,901, RustSec 1,375, Hackage 33 = 14,021 advisories. Crosswalk to C-002 | **Matches repo inventory `8bf7a631…`**; 18/18 sums |
| **P-003** | `9e132c85…zip` (sent earlier) | 24 historical advisories (1996-2001), metadata only | 10/10 |
| **P-004** | `Collect and catalog public vulnerability intelligence.zip` | The 21 original signed FreeBSD advisories P-003 couldn't get, plus patch references and signature inspection | 21/21 |

**Not yet located:** C-001, P-001, P-002, X-001, D-001 to D-003. They may be in your Codex folder (not checked yet) or only in chats.

### 1.2 The provenance chain (your core finding)

Two hand-offs from one agent to another are proven by hash:

- **P-003 → P-004.** P-004 names its input as P-003's ZIP, SHA-256 `734c3075…1925`. That's the hash I computed tonight from the file you sent. P-004 then fetched the 21 originals P-003 could only describe.
- **C-002 → C-003.** C-003 re-read the 3.66 GB handoff and matched its hash, then re-verified all 217 raw files.

And one link to the outside world:

- PyPA and RustSec pinned commits exist on GitHub, with exactly 7,901 and 1,375 advisory files.
- FreeBSD-SA-96:01 matches the live freebsd.org page.

**Still missing:** who did what. My inference: C-series and P-004 ran in `/home/ubuntu` sandboxes (Manus-style), X-002 in `/home/workdir` (a different platform), and P-003 uses Perplexity-style citations. ChatGPT was the orchestrator. The ChatGPT orchestrator thread would turn these guesses into facts.

### 1.3 Can records link to real reports?

This decides what the threat graph can do.

| Source | Records | Has a report link | Has a CVE alias | **Has a fix commit link** | Fixed version | **Has a bug class (CWE)** |
|---|---|---|---|---|---|---|
| Go | 4,712 | 4,708 | 4,272 | **2,579** | 3,901 | **1** |
| PyPA | 7,901 | all (ID → page) | 7,838 | **4,109** | 6,773 | **235** |
| RustSec | 1,375 | 1,264 | 571 | not measured | 866 | not measured |
| Hackage | 33 | 33 | 20 | 16 | 30 | 0 |
| X-002 | 30 | 30 | most | patch refs | n/a | root cause written out |
| P-003/P-004 | 24 | 24 | 2 | inline patches in 16 | n/a | n/a |

**Two conclusions:**

1. **Report links are already strong.** Every record has an ID that resolves to a real page, and most map to a CVE.
2. **Bug class is almost missing from the ecosystem sources.** CWE lives in GitHub Advisory and NVD, which are both inside C-002. D-004's crosswalk already maps 4,650 Go and 7,793 PyPA records to GitHub Advisory IDs. So the class layer comes from **C-002 + the crosswalk**. That makes the 3.66 GB tarball the most important file you have, not dead weight.

And **6,688 fix-commit links** (Go + PyPA) is the vulnerable/fixed code-pair set we said calibration needed. It already exists in the data.

---

## 2. Who uses MOTHERSHIP

Per your rule, the users are **agents**, not people. Each one needs a different question answered:

| Consumer | Question it asks | What it needs from a record |
|---|---|---|
| **Bug-hunt agent** | "What's known about package X at version Y? What bug classes hit this kind of code?" | Package, affected/fixed range, CWE, root cause, fix link |
| **Build/test (Sentinel, vibe-explainer, Code Atlas, diffsec)** | "Give me real vulnerable and fixed code to score my scanner on." | Fix commit URL, repo, CWE, file and line if known |
| **ASI threat graph** | "Which real-world bug classes back each attack class?" | CWE / root-cause class, report link, evidence tier |
| **Agent Security Index** (`holeyfield33-art/agent-security-index`) | "Which well-sourced advisories could become draft incidents?" | Public report URL, CWE, fix-commit link, evidence tier. **Proposal only:** MOTHERSHIP must not publish into the index or update its live catalog; candidates go through ASI's review branch and human approval. |
| **Blockwise (later)** | Not decided yet | Deferred; see 6.4 |

**Design rule:** an agent must be able to tell, from the record alone, how much to trust it. So every record carries its evidence tier and its provenance, the same way ASI does.

---

## 3. Organization: the ASI pattern applied

ASI works because it separates three things:

- **classes:** AAC-01 to AAC-40
- **evidence:** incidents, CVEs and sources attached to classes
- **trust labels:** evidence tiers T0-T3, and `validated: false` until reproduced

It ships as chunked JSON that scripts assemble and gate. MOTHERSHIP uses the same shape.

### 3.1 Three layers

| Layer | ASI equivalent | MOTHERSHIP content |
|---|---|---|
| **Classes** | AAC attack classes | CWE (from X-002's CWE v5 catalog), plus X-002's 15 root-cause classes as a finer layer |
| **Records** | Incidents and CVEs | One record per advisory ID (D-004, P-003/004, X-002), joined to C-002 for CWE |
| **Crosswalk** | Aliases | D-004's overlap rows: RUSTSEC/GO/PYSEC ↔ CVE ↔ GHSA ↔ NVD |

### 3.2 One record format

`docs/INTAKE.md` already defines 15 fields. Keep them and add three: `aliases`, `evidence_tier`, `provenance`.

```json
{
  "id": "PYSEC-2024-123",
  "source": "pypa",
  "url": "https://osv.dev/vulnerability/PYSEC-2024-123",
  "aliases": ["CVE-2024-…", "GHSA-…"],
  "package": {"ecosystem": "PyPI", "name": "…"},
  "affected": "…", "fixed": "1.2.3",
  "fix_refs": ["https://github.com/…/commit/…"],
  "cwe": ["CWE-79"], "cwe_source": "GHSA-… via crosswalk",
  "root_cause": null,
  "evidence_tier": "R1",
  "provenance": {"cycle": "D-004", "package_sha256": "8bf7a631…",
                 "agent": "UNKNOWN", "orchestrator": "ChatGPT"}
}
```

`cwe_source` says where the class came from. A class inherited through an alias is marked as inherited, never presented as the source's own claim.

### 3.3 Evidence tiers for records

These mirror ASI's T0-T3 tiers, adapted to vulnerability data:

| Tier | Meaning | Today's rough count |
|---|---|---|
| **R0 listed** | ID + resolvable report link | 14,075 |
| **R1 fix located** | Fixed version or fix commit link | at least 11,570 (fixed versions alone) |
| **R2 original preserved** | Original source bytes kept (e.g. P-004 `.asc` files) | 21 |
| **R3 root cause analysed** | Mechanism and root cause written up from primary research | 30 (X-002) |

Higher tiers are rarer and worth more. An agent can filter by tier.

### 3.4 Repo layout

The layout follows `docs/INTAKE.md` and ASI:

```text
Mother-ship/
├── README.md              charter (keep)
├── AGENTS.md              agent read order and trust rules (new, short)
├── docs/
│   ├── STATUS.md          single living state (new)
│   ├── INTAKE.md          record format (extend)
│   └── SCHEMA.md          record + tier definitions
├── provenance/
│   └── cycles.json        every cycle: agent, platform, prompt ref, inputs (by hash), outputs
├── manifests/             one manifest per package: file list, sha256, size, where the bytes live
├── records/               normalized JSONL, chunked per source (like ASI public/export)
├── classes/               CWE + root-cause classes
├── crosswalk/             alias table
├── export/
│   └── mothership-catalog.json   assembled; what the threat graph reads
├── scripts/
│   ├── normalize_*.py     one per source, deterministic
│   ├── assemble.py        builds export, checks counts
│   └── check_invariants.py  gate: every record has id+url+tier+provenance
└── checkpoints/           existing dated notes (keep)
```

### 3.5 Where the big files live

Git is wrong for large binaries, and GitHub caps release files at 2 GB each.

| Package | Size | Home |
|---|---|---|
| D-004, C-003, P-003, P-004, `vuln_archive` | ~30 MB total | **GitHub Release** on Mother-ship, one release per cycle; the manifest in git points to it |
| C-002 handoff | 3.66 GB | **Too big for a release.** Two copies off GitHub: your PC plus an external drive or cloud bucket. Only its manifest goes in git |

**Why not just commit them:** every clone would download them forever, and the repo would bloat. Records and manifests are small text. Raw bytes live next to them, linked by hash.

---

## 4. Laying the threat graph over it

`asi-threat-graph` already builds a graph from ASI's export JSON:

- ASI nodes and edges: MAPS_TO, MITIGATED_BY, …
- Code Atlas app graph nodes: CONTAINS, CALLS, ROUTES_TO
- cross-graph POTENTIALLY_MATCHES edges, always marked hypothetical

MOTHERSHIP becomes a **third input**, read the same way: from `export/mothership-catalog.json`, through a small adapter.

**New nodes:** CWE / root-cause class, advisory, package.

**New edges:**

| Edge | From → to | Evidence |
|---|---|---|
| `INSTANCE_OF` | advisory → CWE | direct or inherited (`cwe_source` says which) |
| `AFFECTS` | advisory → package@range | source record |
| `FIXED_BY` | advisory → fix commit URL | source record |
| `ALIAS_OF` | advisory ↔ CVE/GHSA | D-004 crosswalk |
| `GROUNDS` | CWE → ASI attack class | **hypothetical** unless a source states it |
| `POTENTIALLY_AFFECTED` | Code Atlas package node → advisory | **hypothetical**: dependency name+version match only |

The threat graph's own rule carries over unchanged: **hypothetical edges are never shown as verified vulnerabilities.**

**Keep it generic** (per your rule): MOTHERSHIP's export knows nothing about the threat graph, and the adapter knows nothing about any one target. The same export could feed Sentinel, vibe-explainer or something new.

**Scale note:** 14,000+ advisories is much bigger than the threat graph's current 112 nodes. The viewer should load the classes plus whatever a query touches, not everything. The API already has `/match` and `/search`, which is the right shape.

---

## 5. Using it

### 5.1 Bug hunting

The agent asks by package and version (from a target's lockfile, say) and gets back:

- prior advisories
- fix commits to diff
- the bug classes that keep recurring for that package

X-002's root-cause write-ups tell it what pattern to hunt. This is grounding, read-only, as `asi-threat-graph` already is for your bug-hunt agent.

**Gap you should know about:** your active targets lean Solidity and smart contracts (Paxos, SSV, audit contests). **None of the current data covers Solidity.** The sources that would are SWC Registry, the Solodit/audit-finding databases and DeFiHackLabs incidents. That's a future cycle, not this one.

### 5.2 Build and test

The 6,688 Go + PyPA fix-commit links give real vulnerable/fixed pairs for scoring a scanner:

1. Check out the parent commit (vulnerable) and the fix commit (fixed).
2. The tool should flag the first and not the second, in the changed files.
3. Matching CWE says whether it flagged the right class.

This is the calibration set we couldn't build earlier.

**Tooling:** `diffsec` (a standalone, generic differential-recon tool in its own repo, `holeyfield33-art/diffsec`; not merged here per the separation rule) mechanizes steps 1-2. Given a stable ref and a fixed ref it ranks the security-relevant commits, splits a bug pattern's call-site surface into patched sites vs. untouched **unpatched siblings**, and pulls the negative-control tests for each so a consumer does not re-chase intended behaviour. On MOTHERSHIP's fix-commit pairs it runs the parent-vs-fix differential above; pointed at a live target it hunts unpatched siblings of an already-fixed pattern. It reads the pairs and knows nothing about MOTHERSHIP's schema, so the export stays generic.

### 5.3 ASI grounding

CWE nodes linked to AAC classes give ASI field evidence it currently lacks. That has to go through ASI's own review gate; MOTHERSHIP doesn't publish into ASI directly.

The same no-auto-publish rule applies to the Agent Security Index itself (`holeyfield33-art/agent-security-index`). `scripts/assemble.py` builds `export/mothership-catalog.json` for a named CWE slice (Class 1: CWE-22 records with a public primary URL and a fix-commit link; withdrawn records are counted but not exported). The index may use those records only as *proposals*. Draft incidents belong on an ASI review branch; nothing is merged or deployed from this repo.

### 5.4 Blockwise (later)

Your Blockwise notes describe an ownership registry with dependency-based change routing and approval receipts. MOTHERSHIP could fit two ways:

- as a knowledge block an owner is responsible for
- as the source that triggers routing ("a new advisory hit a package this block owns")

**Not decided, not designed.** Revisit once Phases 1-4 are done, so it's built on working data rather than a guess.

---

## 6. Phases

Each phase ends with a check an agent can run.

| Phase | Work | Done when |
|---|---|---|
| **0. Preserve** | Upload the ~30 MB of packages as GitHub Releases. Second copy of C-002 off your PC. Write `manifests/` for every package. Get the ChatGPT orchestrator export and fill `provenance/cycles.json` | Every package hash in a manifest; every byte in two places; every cycle has an agent (or `UNKNOWN`) |
| **1. Normalize D-004** | One script per source turns originals into `records/*.jsonl` | Counts equal 4,712 / 7,901 / 1,375 / 33; reruns give identical output |
| **2. Join classes** | Extract GitHub Advisory (143 MB) and NVD pages from C-002 **on your PC**; join CWE through the crosswalk | Records with a CWE, by source, reported; every inherited CWE has `cwe_source` |
| **3. Add P/X sets + tiers** | Normalize P-003/P-004/X-002; assign R0-R3; build `check_invariants.py` | Gate fails on a record missing url/tier/provenance (tested with a broken record) |
| **4. Export + graph** | Assemble the export; add the threat-graph adapter | Graph builds; hypothetical-edge test still passes; one `/match` query returns real advisories |
| **5. First consumer** | Pick one: a 20-pair scanner calibration set, or a bug-hunt grounding query on a real target | Result recorded with its inputs |

**Phase 2 runs on your PC** because the tarball can't move. Through the computer link I can't hash or open a 3.66 GB file. You'd either run a script I write, or give Codex the job in its folder.

---

## 7. Next week

- **Tonight (Nov 2, research window):** this plan, plus reading your Codex folder for missing cycles if you want.
- **Nov 3-6:** Boundary beta is Friday. MOTHERSHIP waits, apart from Phase 0 if a short slot opens (uploads plus the ChatGPT export, about an hour).
- **After Nov 6:** Phases 1-3, one per session.
- **Following week:** Phases 4-5.

Nothing breaks if this slips. The data is now verified and located.

---

## 8. Failure modes

| Failure | Early sign | Guard |
|---|---|---|
| **Losing C-002** | Only copy is one PC drive | Phase 0 second copy, first |
| **Inherited CWE presented as fact** | Records show CWE with no source | `cwe_source` required; invariant gate |
| **Crosswalk overclaim** | Treating a shared ID as "same bug" | The overlap report's own rule: ID linkage only, not same root cause |
| **Scope creep** | New sources added before Phase 4 | One cycle at a time; Solidity is its own later cycle |
| **Over-fitting to one consumer** | Export fields named after the threat graph or Sentinel | Export is generic; adapters live in the consumers |
| **Mixing in Studio** | Studio files appearing in MOTHERSHIP | Charter rule: separate projects |
| **Attribution guessed** | `agent` filled from inference | `UNKNOWN` until the orchestrator thread confirms |
| **License surprises** | Redistributing records with unclear terms (RustSec CC-BY-SA mismatch, Go/Hackage unverified) | Repo stays private until licenses are checked |

---

## 9. Decisions (answered 2026-11-02)

1. **Storage: a separate linked repo for the bytes.** `Mother-ship-archive` is **public** (owner's choice, for free-tier tool access). It holds public source data only, with packages committed under `packages/` (this session can't create releases). GitHub caps each release file at 2 GB, so the 3.66 GB C-002 file is split into two parts. The manifest records each part's hash plus the whole file's hash (`14738da2…`), and the split is checked by rejoining the parts and re-hashing. Mother-ship's manifests point to the archive repo's releases.
2. **Attribution: agent self-reports, not a ChatGPT export.** A fixed directive goes to Perplexity, Manus, Grok, DeepSeek and Gemini (Appendix A). Every answer goes into `provenance/cycles.json` labelled `self_reported`. Self-reports are checked against the package evidence (sandbox paths, citation style, hashes) before anything is marked confirmed.
3. **Codex and ChatGPT folders: checked.** No missing MOTHERSHIP cycles. `Documents\Codex\2026-10-30\…\code-sentinel-review\calibration\cve_pairs.json` holds code-sentinel's CVE pairs. They're useful as cross-reference for the class study but stay a Sentinel asset. `Documents\ChatGPT` is Studio research and stays out.
4. **First consumer: the class-by-class study program.** See section 10.

---

## 10. The class study program (the IP)

This is where MOTHERSHIP's value comes from. The raw advisories are public. The **study of each class** is yours: what its failures have in common, plus the templates and calibration sets built from that.

### 10.1 One class at a time

For each bug class (a CWE, or one of X-002's root-cause classes):

| Step | Work | Output |
|---|---|---|
| **1. Select** | Pull every record in the class (needs the Phase 2 CWE join) | Class record set, with counts by ecosystem and tier |
| **2. Sample** | Pick cases that have a fix commit (R1+), spread across ecosystems and years, plus any X-002 deep write-ups (R3) | 10-20 study cases, chosen by a written rule, not by hand |
| **3. Study each case** | **Where:** file, function, layer, trust boundary crossed. **What:** the input, the missing check, the consequence. **Fix:** what the diff changed | One case sheet per case, each claim linked to the advisory and fix commit |
| **4. Find the common pattern** | Compare the case sheets: shared preconditions, source→sink shape, the check that's always missing, what fixes look like, common wrong fixes | **Class dossier**: the core document for that class |
| **5. Build templates** | Turn the dossier's "correct shape" into reusable secure-pattern blocks with Blockwise | Security templates, each traced to the dossier and its cases |
| **6. Build the calibration set** | From the same cases: vulnerable commit (must flag), fixed commit (must not flag), plus clean near-miss code (must not flag) | Per-class scoring set with a fixed scoring rule |
| **7. Calibrate the scanners** | Run Sentinel, vibe-explainer and others on the set. Record hits, misses and false alarms per class. Tune, then re-run | Per-class scanner scorecard, before and after tuning |
| **8. Graph it** | Add the dossier, templates and scorecard to the threat graph: class → cases → fixes → templates → scanner results | The graph shows what you know and how well your tools cover it |
| **9. Verify** | A fresh-context verifier (IVP) checks the dossier's claims against the case sheets before the class is marked done | Verification ledger entry |

A class is **done** when it has: a dossier, at least one template, a calibration set, a scorecard, and a passed verification.

### 10.2 Picking the class order

Rank by three things:
- **Data:** how many fix-commit cases the class has.
- **Relevance:** does it show up in your bug-hunt targets?
- **Scanner value:** does a tool you own claim to detect it?

The real counts come from Phase 2. Until then, a reasonable first class is **CWE-22 path traversal**: common in Go and PyPA, easy to define, and you've already found a real one (vibe-course). Treat it as provisional until the counts are in.

### 10.3 Pacing

**One class per one or two weeks**, matching your one-thing-at-a-time rule. The first class will be slower, because it sets the template for case sheets and dossiers. Later classes reuse that template.

### 10.4 Protecting the IP

- **Keep Mother-ship private.** Dossiers, templates and scorecards are the IP.
- **Keep source licenses in the record.** RustSec is CC0/CC-BY with an unresolved ShareAlike mismatch; PyPA is CC-BY 4.0; Go and Hackage are unverified. Your analysis is yours, but redistributing copied advisory text has to follow those terms.
- **Decide publishing later, class by class.** A dossier could become a public research piece like ASI-RESEARCH-001, which credits the sources and holds back the templates.

### 10.5 What this changes in the phases

Phases 0-2 must come first; a class can't be studied without the CWE join. Phases 3-4 can run alongside the first class. **Phase 5 becomes "class 1."**

---

## Appendix A: agent self-report directive

The paste-ready text was sent separately in chat. Every answer is stored as received, marked `self_reported`, and checked against the packages before anything is promoted to confirmed.

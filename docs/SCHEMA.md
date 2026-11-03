# MOTHERSHIP record format: `mothership-record/v1`

One JSON object per advisory, one per line, in `records/<cycle>/<source>.jsonl`. Records are sorted by `id`, keys are sorted, and the output is UTF-8 with `\n` line endings, so the same input always produces byte-identical files.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `mothership-record/v1` |
| `id` | string | The source's own ID (e.g. `GO-2022-0462`, `PYSEC-2024-1`, `RUSTSEC-2020-0108`, `HSEC-2023-0001`) |
| `source` | string | `go_vulndb`, `pypa`, `rustsec` or `hackage` |
| `url` | string | Public page for this ID. Required |
| `kind` | string | `vulnerability`, `unsound`, `unmaintained` or `notice`. Only RustSec uses the last three; everything else is `vulnerability` |
| `withdrawn` | string or null | Withdrawal timestamp/date if the source withdrew it. **Withdrawn records are kept, not deleted** |
| `aliases` | string[] | Other IDs (CVE, GHSA, …), sorted. ID linkage only, not proof of the same root cause |
| `related` | string[] | Source-declared related IDs |
| `title` | string or null | OSV `summary`, or the RustSec heading |
| `details` | string or null | Source description text, unchanged |
| `published`, `modified` | string or null | As given by the source |
| `affected` | object[] | Per package: `ecosystem`, `name`, `ranges` (type + events, plus `repo` for GIT ranges), `versions_listed` (count only; the list itself is dropped for size), `symbols` (affected functions where the source names them) |
| `fix` | object | `fixed_versions` (from range events or RustSec `patched`), `fix_commits` (URLs, see below), `git_fixed` (`{repo, commit}` from GIT ranges) |
| `references` | object[] | `{type, url}` as given (RustSec: `url` + `references` mapped to `WEB`) |
| `severity` | object[] | As given (e.g. CVSS vectors). Empty if none |
| `cwe` | string[] | CWEs from a **structured** source field only |
| `cwe_source` | string or null | Where `cwe` came from, e.g. `source:database_specific.cwe_ids`. Phase 2 adds inherited CWEs with their own source label |
| `cwe_mentioned_in_text` | string[] | CWE IDs appearing in the description text. **A hint, not a class assignment** |
| `source_categories` | string[] | Source-native class labels (RustSec `categories` + `keywords`) |
| `evidence_tier` | string | `R0` listed (ID + URL), `R1` fix located (fixed version or fix commit). R2/R3 come from other cycles |
| `provenance` | object | `cycle`, `package_id`, `package_sha256`, `source_artifact`, `source_artifact_sha256`, `source_path`, `source_revision`, `acquired_utc`, `collected_by`, `spec_by`, `orchestrator` |

## Rules

- **Fix commits:** a reference URL counts as a fix commit if it points at a specific commit (`/commit/<sha>`, `/commits/<sha>`, `/-/commit/<sha>`, or `googlesource …/+/<sha>`). A GIT range's `fixed` event is recorded under `git_fixed`, and also as a URL when the repo is on github.com or gitlab.com.
- **Parsing:** YAML is read with every value as a string, so `1.10` stays `"1.10"` and doesn't become the number `1.1`.
- **Nothing is invented.** A missing field is `null` or an empty list.
- **Every record must have** `id`, `source`, `url`, `kind`, `evidence_tier` and a complete `provenance`; the normalizer refuses to write output otherwise.

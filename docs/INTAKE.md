# Research intake

Track each item with: `record_id`, `source_url`, `source_type`, `retrieved_at`, `sha256`, `license`, `project_owner`, `vulnerability_id`, `affected_component`, `failure_mechanism`, `root_cause`, `fix_reference`, `evidence_path`, `verification_status`, and `notes`.

Suggested directories: `sources/raw/` for immutable original material, `manifests/` for inventories and hashes, `records/` for normalized entries, and `checkpoints/` for dated freeze reports.

Statuses: `unreviewed`, `source_verified`, `claim_verified`, `rejected`. Never treat a source checksum as proof of the vulnerability claim.

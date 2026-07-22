DROP TRIGGER managed_output_artifacts_no_delete;
DROP TRIGGER artifacts_no_delete;
DROP TRIGGER snapshots_no_delete;
DROP TRIGGER raw_documents_no_delete;
DROP TRIGGER raw_nodes_no_delete;
DROP TRIGGER canonical_nodes_no_delete;
DROP TRIGGER snapshot_occurrences_no_delete;
DROP TRIGGER fingerprints_no_delete;

CREATE INDEX jobs_retention
  ON jobs(source_id, created_at DESC, id DESC)
  WHERE status IN ('succeeded', 'failed', 'cancelled', 'dead');

CREATE INDEX managed_output_build_jobs_retention
  ON managed_output_build_jobs(output_id, created_at DESC, id DESC)
  WHERE status IN ('succeeded', 'failed', 'dead');

UPDATE application_metadata SET value = '11' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm4_retention_cleanup' WHERE key = 'schema_status';

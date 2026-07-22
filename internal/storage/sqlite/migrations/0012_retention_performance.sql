CREATE INDEX source_revisions_config_blob
  ON source_revisions(config_blob_id);

CREATE INDEX raw_documents_blob
  ON raw_documents(blob_id);

CREATE INDEX raw_nodes_raw_blob
  ON raw_nodes(raw_blob_id);

CREATE INDEX raw_nodes_original_name_blob
  ON raw_nodes(original_name_blob_id)
  WHERE original_name_blob_id IS NOT NULL;

CREATE INDEX canonical_nodes_canonical_blob
  ON canonical_nodes(canonical_blob_id);

CREATE INDEX artifacts_content_blob
  ON artifacts(content_blob_id);

CREATE INDEX managed_resources_config_blob
  ON managed_resources(config_blob_id);

CREATE INDEX managed_outputs_allocation_blob
  ON managed_outputs(allocation_blob_id)
  WHERE allocation_blob_id IS NOT NULL;

CREATE INDEX managed_output_artifacts_content_blob
  ON managed_output_artifacts(content_blob_id);

CREATE INDEX managed_output_artifacts_manifest_blob
  ON managed_output_artifacts(manifest_blob_id);

CREATE INDEX refresh_attempts_accepted_snapshot
  ON refresh_attempts(accepted_snapshot_id)
  WHERE accepted_snapshot_id IS NOT NULL;

CREATE INDEX artifacts_snapshot
  ON artifacts(snapshot_id);

CREATE INDEX health_records_snapshot
  ON health_records(snapshot_id);

CREATE INDEX node_health_states_latest_record
  ON node_health_states(latest_record_id)
  WHERE latest_record_id IS NOT NULL;

DROP TRIGGER refresh_attempts_snapshot_owner;

CREATE TRIGGER refresh_attempts_snapshot_owner
BEFORE UPDATE OF status, accepted_snapshot_id ON refresh_attempts
WHEN NEW.accepted_snapshot_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM snapshots s
    WHERE s.id = NEW.accepted_snapshot_id AND s.source_id = NEW.source_id
      AND (
        NEW.status = 'not_modified' OR
        s.refresh_attempt_id = NEW.id OR
        (NEW.status = 'succeeded' AND s.source_revision_id = NEW.source_revision_id)
      )
  ) THEN RAISE(ABORT, 'accepted snapshot does not belong to the refresh attempt') END;
END;

UPDATE application_metadata SET value = '12' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm4_retention_performance' WHERE key = 'schema_status';

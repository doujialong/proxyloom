CREATE TEMP TABLE managed_outputs_v9 AS SELECT * FROM managed_outputs;
CREATE TEMP TABLE managed_output_artifacts_v9 AS SELECT * FROM managed_output_artifacts;
CREATE TEMP TABLE managed_output_tokens_v9 AS SELECT * FROM managed_output_tokens;
CREATE TEMP TABLE managed_output_build_jobs_v9 AS SELECT * FROM managed_output_build_jobs;

DROP TRIGGER managed_output_build_jobs_terminal_immutable;
DROP TRIGGER managed_output_artifacts_no_update;
DROP TRIGGER managed_output_artifacts_no_delete;
DROP TRIGGER managed_outputs_resource_types_insert;

DROP TABLE managed_output_build_jobs;
DROP TABLE managed_output_tokens;
DROP TABLE managed_output_artifacts;
DROP TABLE managed_outputs;

CREATE TABLE managed_outputs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  collection_id TEXT NOT NULL REFERENCES managed_resources(id) ON DELETE RESTRICT,
  pipeline_id TEXT REFERENCES managed_resources(id) ON DELETE RESTRICT,
  template_id TEXT REFERENCES managed_resources(id) ON DELETE RESTRICT,
  target_profile TEXT NOT NULL CHECK (target_profile IN (
    'sing-box-1.12.25', 'momo-1.2.1-sing-box-1.12.25', 'sing-box-1.13.14'
  )),
  output_shape TEXT NOT NULL CHECK (output_shape IN ('outbounds_object', 'full_config')),
  health_filter_enabled INTEGER NOT NULL DEFAULT 0 CHECK (health_filter_enabled IN (0, 1)),
  minimum_nodes INTEGER NOT NULL DEFAULT 1 CHECK (minimum_nodes BETWEEN 1 AND 100000),
  maximum_drop_ratio REAL NOT NULL DEFAULT 0.5 CHECK (maximum_drop_ratio BETWEEN 0 AND 1),
  allocation_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  current_artifact_id TEXT,
  next_build_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_build_sequence > 0),
  lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active', 'archived')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  archived_at INTEGER,
  CHECK (updated_at >= created_at)
);

CREATE TABLE managed_output_artifacts (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES managed_outputs(id) ON DELETE RESTRICT,
  build_sequence INTEGER NOT NULL CHECK (build_sequence > 0),
  content_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  manifest_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  content_type TEXT NOT NULL CHECK (length(content_type) BETWEEN 1 AND 128),
  content_length INTEGER NOT NULL CHECK (content_length >= 0),
  public_sha256 TEXT NOT NULL CHECK (length(public_sha256) = 64),
  node_count INTEGER NOT NULL CHECK (node_count >= 0),
  excluded_count INTEGER NOT NULL DEFAULT 0 CHECK (excluded_count >= 0),
  warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
  target_profile TEXT NOT NULL,
  validator_version TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (output_id, build_sequence),
  UNIQUE (id, output_id)
);

CREATE TABLE managed_output_tokens (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES managed_outputs(id) ON DELETE RESTRICT,
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  token_hmac BLOB NOT NULL UNIQUE CHECK (length(token_hmac) = 32),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE TABLE managed_output_build_jobs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES managed_outputs(id) ON DELETE RESTRICT,
  trigger_kind TEXT NOT NULL CHECK (trigger_kind IN ('manual', 'source_refresh', 'health_boundary', 'collection_update')),
  trigger_source_id TEXT REFERENCES sources(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('queued', 'leased', 'running', 'succeeded', 'failed', 'dead')),
  priority INTEGER NOT NULL DEFAULT 0,
  dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 200),
  lease_owner TEXT CHECK (lease_owner IS NULL OR length(lease_owner) BETWEEN 1 AND 200),
  lease_expires_at INTEGER,
  attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
  error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
  error_detail TEXT CHECK (error_detail IS NULL OR length(error_detail) <= 4096),
  correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 200),
  due_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  CHECK ((status IN ('leased', 'running')) = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK ((status IN ('succeeded', 'failed', 'dead')) = (finished_at IS NOT NULL))
);

INSERT INTO managed_outputs SELECT * FROM managed_outputs_v9;
INSERT INTO managed_output_artifacts SELECT * FROM managed_output_artifacts_v9;
INSERT INTO managed_output_tokens SELECT * FROM managed_output_tokens_v9;
INSERT INTO managed_output_build_jobs SELECT * FROM managed_output_build_jobs_v9;

CREATE INDEX managed_output_tokens_active
  ON managed_output_tokens(output_id, created_at DESC) WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX managed_output_build_jobs_active
  ON managed_output_build_jobs(dedupe_key)
  WHERE status IN ('queued', 'leased', 'running');

CREATE INDEX managed_output_build_jobs_claim
  ON managed_output_build_jobs(status, due_at, priority DESC, created_at, id);

CREATE TRIGGER managed_outputs_resource_types_insert
BEFORE INSERT ON managed_outputs
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM managed_resources r
    WHERE r.id = NEW.collection_id AND r.resource_type = 'collection' AND r.lifecycle_state = 'active'
  ) THEN RAISE(ABORT, 'managed output collection is invalid') END;
  SELECT CASE WHEN NEW.pipeline_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM managed_resources r
    WHERE r.id = NEW.pipeline_id AND r.resource_type = 'pipeline' AND r.lifecycle_state = 'active'
  ) THEN RAISE(ABORT, 'managed output pipeline is invalid') END;
  SELECT CASE WHEN NEW.template_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM managed_resources r
    WHERE r.id = NEW.template_id AND r.resource_type = 'template' AND r.lifecycle_state = 'active'
  ) THEN RAISE(ABORT, 'managed output template is invalid') END;
  SELECT CASE WHEN NEW.output_shape = 'full_config' AND NEW.template_id IS NULL
    THEN RAISE(ABORT, 'full config output requires a template') END;
END;

CREATE TRIGGER managed_output_artifacts_no_update
BEFORE UPDATE ON managed_output_artifacts
BEGIN
  SELECT RAISE(ABORT, 'managed output artifacts are immutable');
END;

CREATE TRIGGER managed_output_artifacts_no_delete
BEFORE DELETE ON managed_output_artifacts
BEGIN
  SELECT RAISE(ABORT, 'managed output artifacts are immutable');
END;

CREATE TRIGGER managed_output_build_jobs_terminal_immutable
BEFORE UPDATE ON managed_output_build_jobs
WHEN OLD.status IN ('succeeded', 'failed', 'dead')
BEGIN
  SELECT RAISE(ABORT, 'terminal managed output build jobs are immutable');
END;

DROP TABLE managed_outputs_v9;
DROP TABLE managed_output_artifacts_v9;
DROP TABLE managed_output_tokens_v9;
DROP TABLE managed_output_build_jobs_v9;

UPDATE application_metadata SET value = '10' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm4_singbox_113_target' WHERE key = 'schema_status';

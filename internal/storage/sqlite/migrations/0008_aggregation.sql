CREATE TABLE managed_resources (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  resource_type TEXT NOT NULL CHECK (resource_type IN ('collection', 'pipeline', 'template')),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL DEFAULT 1 CHECK (revision_number > 0),
  lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active', 'archived')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  archived_at INTEGER,
  CHECK (updated_at >= created_at),
  CHECK ((lifecycle_state = 'active' AND archived_at IS NULL) OR
         (lifecycle_state = 'archived' AND archived_at IS NOT NULL))
);

CREATE INDEX managed_resources_type_time
  ON managed_resources(resource_type, lifecycle_state, updated_at DESC, id DESC);

CREATE TABLE managed_outputs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  collection_id TEXT NOT NULL REFERENCES managed_resources(id) ON DELETE RESTRICT,
  pipeline_id TEXT REFERENCES managed_resources(id) ON DELETE RESTRICT,
  template_id TEXT REFERENCES managed_resources(id) ON DELETE RESTRICT,
  target_profile TEXT NOT NULL CHECK (target_profile IN (
    'sing-box-1.12.25', 'momo-1.2.1-sing-box-1.12.25'
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

CREATE TABLE managed_output_tokens (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES managed_outputs(id) ON DELETE RESTRICT,
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  token_hmac BLOB NOT NULL UNIQUE CHECK (length(token_hmac) = 32),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX managed_output_tokens_active
  ON managed_output_tokens(output_id, created_at DESC) WHERE revoked_at IS NULL;

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

UPDATE application_metadata SET value = '8' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm4_aggregation' WHERE key = 'schema_status';

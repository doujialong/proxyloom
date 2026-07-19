-- ProxyLoom SQLite schema draft
-- M0 baseline, schema version 1, 2026-07-17
-- Timestamps are UTC Unix milliseconds. IDs are lowercase UUIDv7 strings.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

BEGIN IMMEDIATE;

CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL UNIQUE,
  checksum TEXT NOT NULL CHECK (length(checksum) = 64),
  applied_at INTEGER NOT NULL
);

CREATE TABLE application_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE master_key_slots (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  state TEXT NOT NULL CHECK (state IN ('prepared', 'active', 'retired')),
  format_version INTEGER NOT NULL DEFAULT 1 CHECK (format_version > 0),
  canary_nonce BLOB NOT NULL,
  canary_ciphertext BLOB NOT NULL,
  prepared_at INTEGER NOT NULL,
  activated_at INTEGER,
  retired_at INTEGER
);

CREATE UNIQUE INDEX master_key_slots_one_active
  ON master_key_slots(state) WHERE state = 'active';
CREATE UNIQUE INDEX master_key_slots_one_prepared
  ON master_key_slots(state) WHERE state = 'prepared';

CREATE TABLE instances (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  singleton INTEGER NOT NULL DEFAULT 1 UNIQUE CHECK (singleton = 1),
  created_at INTEGER NOT NULL,
  crypto_format_version INTEGER NOT NULL DEFAULT 1 CHECK (crypto_format_version > 0),
  active_master_key_id TEXT NOT NULL REFERENCES master_key_slots(id) ON DELETE RESTRICT
);

CREATE TABLE data_keys (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  purpose TEXT NOT NULL CHECK (purpose IN (
    'data', 'blob', 'fingerprint_hmac', 'health_hmac',
    'token_hmac', 'content_hmac'
  )),
  status TEXT NOT NULL CHECK (status IN ('active', 'decrypt_only', 'retired')),
  created_at INTEGER NOT NULL,
  retired_at INTEGER
);

CREATE UNIQUE INDEX data_keys_one_active_per_purpose
  ON data_keys(purpose) WHERE status = 'active';

CREATE TABLE master_key_wrappings (
  master_key_id TEXT NOT NULL REFERENCES master_key_slots(id) ON DELETE RESTRICT,
  data_key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  wrap_version INTEGER NOT NULL CHECK (wrap_version > 0),
  wrap_nonce BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  verified_at INTEGER,
  PRIMARY KEY (master_key_id, data_key_id)
);

CREATE INDEX master_key_wrappings_by_data_key ON master_key_wrappings(data_key_id, master_key_id);

CREATE TABLE encrypted_blobs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  kind TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  format_version INTEGER NOT NULL DEFAULT 1 CHECK (format_version > 0),
  aad_version INTEGER NOT NULL DEFAULT 1 CHECK (aad_version > 0),
  nonce BLOB NOT NULL,
  ciphertext_inline BLOB,
  relative_path TEXT,
  plaintext_size INTEGER NOT NULL CHECK (plaintext_size >= 0),
  ciphertext_size INTEGER NOT NULL CHECK (ciphertext_size >= 16),
  content_hmac BLOB NOT NULL CHECK (length(content_hmac) = 32),
  public_sha256 TEXT CHECK (public_sha256 IS NULL OR length(public_sha256) = 64),
  created_at INTEGER NOT NULL,
  delete_after INTEGER,
  CHECK (
    (ciphertext_inline IS NOT NULL AND relative_path IS NULL) OR
    (ciphertext_inline IS NULL AND relative_path IS NOT NULL)
  ),
  CHECK (relative_path IS NULL OR (
    relative_path NOT LIKE '/%' AND
    relative_path NOT LIKE '%..%' AND
    relative_path NOT LIKE '%\\%'
  ))
);

CREATE INDEX encrypted_blobs_gc ON encrypted_blobs(delete_after) WHERE delete_after IS NOT NULL;

CREATE TABLE administrators (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL,
  password_params TEXT NOT NULL,
  session_epoch INTEGER NOT NULL DEFAULT 1 CHECK (session_epoch > 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE setup_tokens (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  token_hmac BLOB NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  CHECK (expires_at > created_at)
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE CASCADE,
  token_hmac BLOB NOT NULL UNIQUE,
  csrf_hmac BLOB NOT NULL,
  session_epoch INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  recent_auth_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (expires_at > created_at)
);

CREATE INDEX sessions_active_by_admin ON sessions(administrator_id, expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE sources (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  lifecycle_state TEXT NOT NULL DEFAULT 'active'
    CHECK (lifecycle_state IN ('active', 'archived')),
  draft_revision_id TEXT,
  published_revision_id TEXT,
  current_snapshot_id TEXT,
  source_health TEXT NOT NULL DEFAULT 'unknown'
    CHECK (source_health IN ('unknown', 'healthy', 'degraded', 'unhealthy', 'disabled')),
  health_reason_code TEXT CHECK (health_reason_code IS NULL OR length(health_reason_code) <= 128),
  revision_counter INTEGER NOT NULL DEFAULT 0 CHECK (revision_counter >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  archived_at INTEGER,
  FOREIGN KEY (draft_revision_id) REFERENCES source_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (published_revision_id) REFERENCES source_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (current_snapshot_id) REFERENCES snapshots(id) ON DELETE RESTRICT,
  CHECK (updated_at >= created_at),
  CHECK (
    (lifecycle_state = 'active' AND archived_at IS NULL) OR
    (lifecycle_state = 'archived' AND archived_at IS NOT NULL)
  )
);

CREATE TABLE source_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'archived')),
  source_type TEXT NOT NULL CHECK (source_type IN ('remote', 'inline', 'upload')),
  input_format_hint TEXT CHECK (input_format_hint IS NULL OR length(input_format_hint) <= 128),
  import_purpose TEXT NOT NULL CHECK (import_purpose IN (
    'node_source', 'template', 'template_and_nodes', 'raw_passthrough'
  )),
  refresh_schedule TEXT CHECK (refresh_schedule IS NULL OR length(refresh_schedule) <= 256),
  schedule_timezone TEXT NOT NULL DEFAULT 'UTC' CHECK (length(schedule_timezone) BETWEEN 1 AND 64),
  private_network_authorized INTEGER NOT NULL DEFAULT 0 CHECK (private_network_authorized IN (0, 1)),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  config_schema_version INTEGER NOT NULL DEFAULT 1 CHECK (config_schema_version > 0),
  created_by TEXT REFERENCES administrators(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  UNIQUE (source_id, revision_number),
  UNIQUE (id, source_id),
  CHECK (
    (state = 'draft' AND published_at IS NULL) OR
    (state IN ('published', 'superseded') AND published_at IS NOT NULL) OR
    state = 'archived'
  ),
  CHECK (published_at IS NULL OR published_at >= created_at)
);

CREATE UNIQUE INDEX source_revisions_one_draft ON source_revisions(source_id) WHERE state = 'draft';
CREATE UNIQUE INDEX source_revisions_one_published ON source_revisions(source_id) WHERE state = 'published';
CREATE INDEX source_revisions_by_source ON source_revisions(source_id, revision_number DESC);

CREATE TABLE refresh_attempts (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  source_revision_id TEXT NOT NULL,
  job_id TEXT,
  trigger_kind TEXT NOT NULL CHECK (trigger_kind IN ('manual', 'schedule', 'retry', 'import')),
  status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'not_modified', 'rejected', 'failed')),
  http_status INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
  dns_ms INTEGER CHECK (dns_ms IS NULL OR dns_ms >= 0),
  connect_ms INTEGER CHECK (connect_ms IS NULL OR connect_ms >= 0),
  tls_ms INTEGER CHECK (tls_ms IS NULL OR tls_ms >= 0),
  total_ms INTEGER CHECK (total_ms IS NULL OR total_ms >= 0),
  response_bytes INTEGER CHECK (response_bytes IS NULL OR response_bytes >= 0),
  node_count INTEGER CHECK (node_count IS NULL OR node_count >= 0),
  warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
  error_code TEXT CHECK (error_code IS NULL OR length(error_code) <= 128),
  error_detail TEXT CHECK (error_detail IS NULL OR length(error_detail) <= 4096),
  accepted_snapshot_id TEXT,
  correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 200),
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE SET NULL,
  FOREIGN KEY (accepted_snapshot_id) REFERENCES snapshots(id) ON DELETE RESTRICT,
  UNIQUE (id, source_id),
  FOREIGN KEY (source_revision_id, source_id)
    REFERENCES source_revisions(id, source_id) ON DELETE RESTRICT,
  CHECK (finished_at IS NULL OR finished_at >= started_at),
  CHECK (status <> 'not_modified' OR http_status = 304),
  CHECK (
    (status = 'running' AND finished_at IS NULL AND accepted_snapshot_id IS NULL AND error_code IS NULL) OR
    (status IN ('succeeded', 'not_modified') AND finished_at IS NOT NULL AND accepted_snapshot_id IS NOT NULL AND error_code IS NULL) OR
    (status IN ('rejected', 'failed') AND finished_at IS NOT NULL AND accepted_snapshot_id IS NULL AND error_code IS NOT NULL)
  )
);

CREATE INDEX refresh_attempts_source_time ON refresh_attempts(source_id, started_at DESC, id DESC);
CREATE UNIQUE INDEX refresh_attempts_one_running_per_source ON refresh_attempts(source_id) WHERE status = 'running';

CREATE TABLE raw_documents (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  detected_format TEXT NOT NULL,
  format_adapter_version TEXT NOT NULL,
  content_hmac BLOB NOT NULL CHECK (length(content_hmac) = 32),
  media_type TEXT CHECK (media_type IS NULL OR length(media_type) <= 128),
  charset TEXT CHECK (charset IS NULL OR length(charset) <= 128),
  parse_limits_version INTEGER NOT NULL DEFAULT 1 CHECK (parse_limits_version > 0),
  created_at INTEGER NOT NULL,
  UNIQUE (id, source_id)
);

CREATE INDEX raw_documents_source_digest ON raw_documents(source_id, content_hmac);

CREATE TABLE snapshots (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  source_revision_id TEXT NOT NULL,
  raw_document_id TEXT NOT NULL,
  refresh_attempt_id TEXT NOT NULL UNIQUE,
  node_count INTEGER NOT NULL CHECK (node_count >= 0),
  logical_outbound_count INTEGER NOT NULL DEFAULT 0 CHECK (logical_outbound_count >= 0),
  warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
  content_hmac BLOB NOT NULL CHECK (length(content_hmac) = 32),
  occurrence_algorithm_version TEXT NOT NULL,
  accepted_at INTEGER NOT NULL,
  stale_after INTEGER NOT NULL,
  retain_until INTEGER NOT NULL,
  UNIQUE (id, source_id),
  FOREIGN KEY (source_revision_id, source_id)
    REFERENCES source_revisions(id, source_id) ON DELETE RESTRICT,
  FOREIGN KEY (raw_document_id, source_id)
    REFERENCES raw_documents(id, source_id) ON DELETE RESTRICT,
  FOREIGN KEY (refresh_attempt_id, source_id)
    REFERENCES refresh_attempts(id, source_id) ON DELETE RESTRICT,
  CHECK (stale_after > accepted_at),
  CHECK (retain_until >= stale_after)
);

CREATE INDEX snapshots_source_time ON snapshots(source_id, accepted_at DESC, id DESC);

CREATE TABLE fingerprints (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  protocol_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('semantic', 'opaque_structural')),
  algorithm TEXT NOT NULL DEFAULT 'hmac-sha256',
  projection_version TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  digest BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (key_id, projection_version, digest)
);

CREATE TABLE raw_nodes (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE RESTRICT,
  raw_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  original_name_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  original_name_hmac BLOB,
  source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
  extraction_path TEXT NOT NULL,
  raw_kind TEXT NOT NULL CHECK (raw_kind IN ('json_object', 'uri', 'text')),
  format_id TEXT NOT NULL,
  format_adapter_version TEXT NOT NULL,
  protocol_id TEXT NOT NULL,
  fingerprint_id TEXT REFERENCES fingerprints(id) ON DELETE RESTRICT,
  parse_status TEXT NOT NULL CHECK (parse_status IN ('complete', 'partial', 'opaque', 'invalid')),
  warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
  created_at INTEGER NOT NULL,
  UNIQUE (snapshot_id, source_ordinal)
);

CREATE INDEX raw_nodes_snapshot_protocol ON raw_nodes(snapshot_id, protocol_id, source_ordinal);
CREATE INDEX raw_nodes_fingerprint ON raw_nodes(fingerprint_id) WHERE fingerprint_id IS NOT NULL;

CREATE TABLE canonical_nodes (
  raw_node_id TEXT PRIMARY KEY REFERENCES raw_nodes(id) ON DELETE RESTRICT,
  protocol_adapter_version TEXT NOT NULL,
  completeness TEXT NOT NULL CHECK (completeness IN ('complete', 'partial', 'opaque')),
  canonical_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  feature_flags TEXT NOT NULL DEFAULT '[]',
  generated_at INTEGER NOT NULL
);

CREATE TABLE node_occurrences (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  current_fingerprint_id TEXT REFERENCES fingerprints(id) ON DELETE RESTRICT,
  lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('present', 'absent', 'retired')),
  duplicate_slot INTEGER NOT NULL DEFAULT 1 CHECK (duplicate_slot > 0),
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  absent_since INTEGER,
  retain_until INTEGER,
  association_version TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX node_occurrences_source_state ON node_occurrences(source_id, lifecycle_state, last_seen_at DESC);
CREATE INDEX node_occurrences_fingerprint ON node_occurrences(source_id, current_fingerprint_id);

CREATE TABLE snapshot_occurrences (
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE RESTRICT,
  raw_node_id TEXT NOT NULL UNIQUE REFERENCES raw_nodes(id) ON DELETE RESTRICT,
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  occurrence_ordinal INTEGER NOT NULL CHECK (occurrence_ordinal >= 0),
  match_method TEXT NOT NULL CHECK (match_method IN (
    'fingerprint_unique', 'path', 'duplicate_slot',
    'auxiliary_unique', 'new', 'ambiguous_new'
  )),
  association_version TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (snapshot_id, node_occurrence_id)
);

CREATE INDEX snapshot_occurrences_occurrence ON snapshot_occurrences(node_occurrence_id, snapshot_id);

CREATE TABLE collections (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active', 'archived')),
  draft_revision_id TEXT,
  published_revision_id TEXT,
  revision_counter INTEGER NOT NULL DEFAULT 0 CHECK (revision_counter >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (draft_revision_id) REFERENCES collection_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (published_revision_id) REFERENCES collection_revisions(id) ON DELETE RESTRICT
);

CREATE TABLE collection_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'archived')),
  created_by TEXT REFERENCES administrators(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  UNIQUE (collection_id, revision_number)
);

CREATE TABLE collection_members (
  collection_revision_id TEXT NOT NULL REFERENCES collection_revisions(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  source_id TEXT REFERENCES sources(id) ON DELETE RESTRICT,
  node_occurrence_id TEXT REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  PRIMARY KEY (collection_revision_id, ordinal),
  CHECK ((source_id IS NOT NULL) <> (node_occurrence_id IS NOT NULL))
);

CREATE TABLE pipelines (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active', 'archived')),
  draft_revision_id TEXT,
  published_revision_id TEXT,
  revision_counter INTEGER NOT NULL DEFAULT 0 CHECK (revision_counter >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (draft_revision_id) REFERENCES pipeline_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (published_revision_id) REFERENCES pipeline_revisions(id) ON DELETE RESTRICT
);

CREATE TABLE pipeline_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'archived')),
  created_by TEXT REFERENCES administrators(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  UNIQUE (pipeline_id, revision_number)
);

CREATE TABLE pipeline_operations (
  pipeline_revision_id TEXT NOT NULL REFERENCES pipeline_revisions(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  operation_type TEXT NOT NULL,
  operation_schema_version INTEGER NOT NULL CHECK (operation_schema_version > 0),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  PRIMARY KEY (pipeline_revision_id, ordinal)
);

CREATE TABLE templates (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active', 'archived')),
  draft_revision_id TEXT,
  published_revision_id TEXT,
  revision_counter INTEGER NOT NULL DEFAULT 0 CHECK (revision_counter >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (draft_revision_id) REFERENCES template_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (published_revision_id) REFERENCES template_revisions(id) ON DELETE RESTRICT
);

CREATE TABLE template_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  template_id TEXT NOT NULL REFERENCES templates(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'archived')),
  source_type TEXT NOT NULL CHECK (source_type IN ('inline', 'upload', 'remote', 'source_snapshot')),
  target_format TEXT NOT NULL,
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  private_network_authorized INTEGER NOT NULL DEFAULT 0 CHECK (private_network_authorized IN (0, 1)),
  created_by TEXT REFERENCES administrators(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  UNIQUE (template_id, revision_number)
);

CREATE TABLE template_snapshots (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  template_revision_id TEXT NOT NULL REFERENCES template_revisions(id) ON DELETE RESTRICT,
  blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  content_hmac BLOB NOT NULL,
  validation_status TEXT NOT NULL CHECK (validation_status IN ('valid', 'invalid')),
  accepted_at INTEGER NOT NULL,
  retain_until INTEGER NOT NULL
);

CREATE TABLE target_profiles (
  id TEXT NOT NULL,
  profile_version INTEGER NOT NULL CHECK (profile_version > 0),
  client_id TEXT NOT NULL,
  client_version TEXT NOT NULL,
  core_id TEXT NOT NULL,
  core_version TEXT NOT NULL,
  format_family TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  validator_version TEXT NOT NULL,
  registry_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('p0_baseline', 'compatibility_target', 'research_baseline', 'retired')),
  definition_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (id, profile_version)
);

CREATE TABLE health_policies (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL,
  draft_revision_id TEXT,
  published_revision_id TEXT,
  revision_counter INTEGER NOT NULL DEFAULT 0 CHECK (revision_counter >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (draft_revision_id) REFERENCES health_policy_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (published_revision_id) REFERENCES health_policy_revisions(id) ON DELETE RESTRICT
);

CREATE TABLE health_policy_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  health_policy_id TEXT NOT NULL REFERENCES health_policies(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'archived')),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  UNIQUE (health_policy_id, revision_number)
);

CREATE TABLE probe_profiles (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL,
  draft_revision_id TEXT,
  published_revision_id TEXT,
  revision_counter INTEGER NOT NULL DEFAULT 0 CHECK (revision_counter >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (draft_revision_id) REFERENCES probe_profile_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (published_revision_id) REFERENCES probe_profile_revisions(id) ON DELETE RESTRICT
);

CREATE TABLE probe_profile_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  probe_profile_id TEXT NOT NULL REFERENCES probe_profiles(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'archived')),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  UNIQUE (probe_profile_id, revision_number)
);

CREATE TABLE network_context_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  revision_number INTEGER NOT NULL UNIQUE CHECK (revision_number > 0),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL
);

CREATE TABLE outputs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  display_name TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active', 'archived')),
  draft_revision_id TEXT,
  published_revision_id TEXT,
  revision_counter INTEGER NOT NULL DEFAULT 0 CHECK (revision_counter >= 0),
  allocation_version INTEGER NOT NULL DEFAULT 0 CHECK (allocation_version >= 0),
  next_build_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_build_sequence > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (draft_revision_id) REFERENCES output_revisions(id) ON DELETE RESTRICT,
  FOREIGN KEY (published_revision_id) REFERENCES output_revisions(id) ON DELETE RESTRICT
);

CREATE TABLE output_revisions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  state TEXT NOT NULL CHECK (state IN ('draft', 'published', 'superseded', 'archived')),
  collection_revision_id TEXT NOT NULL REFERENCES collection_revisions(id) ON DELETE RESTRICT,
  pipeline_revision_id TEXT NOT NULL REFERENCES pipeline_revisions(id) ON DELETE RESTRICT,
  template_revision_id TEXT REFERENCES template_revisions(id) ON DELETE RESTRICT,
  target_profile_id TEXT NOT NULL,
  target_profile_version INTEGER NOT NULL CHECK (target_profile_version > 0),
  health_policy_revision_id TEXT NOT NULL REFERENCES health_policy_revisions(id) ON DELETE RESTRICT,
  probe_profile_revision_id TEXT NOT NULL REFERENCES probe_profile_revisions(id) ON DELETE RESTRICT,
  output_shape TEXT NOT NULL CHECK (output_shape IN ('outbounds_array', 'outbounds_object', 'full_config')),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  created_by TEXT REFERENCES administrators(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  UNIQUE (output_id, revision_number),
  UNIQUE (id, output_id),
  FOREIGN KEY (target_profile_id, target_profile_version)
    REFERENCES target_profiles(id, profile_version) ON DELETE RESTRICT
);

CREATE TABLE publication_tokens (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  token_hmac BLOB NOT NULL UNIQUE,
  token_hint TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX publication_tokens_output_active ON publication_tokens(output_id) WHERE status = 'active';

CREATE TABLE name_allocations (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  allocation_version INTEGER NOT NULL CHECK (allocation_version > 0),
  base_name_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  final_name_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  final_name_hmac BLOB NOT NULL,
  suffix_number INTEGER NOT NULL CHECK (suffix_number > 0),
  locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  last_seen_at INTEGER NOT NULL,
  reserved_until INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (output_id, node_occurrence_id),
  UNIQUE (id, output_id)
);

CREATE UNIQUE INDEX name_allocations_unique_active_name
  ON name_allocations(output_id, final_name_hmac) WHERE active = 1;
CREATE INDEX name_allocations_reservation ON name_allocations(output_id, reserved_until);

CREATE TABLE name_allocation_snapshots (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  output_revision_id TEXT NOT NULL,
  allocation_version INTEGER NOT NULL CHECK (allocation_version >= 0),
  algorithm_version TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (id, output_id),
  FOREIGN KEY (output_revision_id, output_id)
    REFERENCES output_revisions(id, output_id) ON DELETE RESTRICT
);

CREATE TABLE name_allocation_snapshot_items (
  snapshot_id TEXT NOT NULL,
  output_id TEXT NOT NULL,
  allocation_id TEXT NOT NULL,
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  final_name_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  final_name_hmac BLOB NOT NULL,
  suffix_number INTEGER NOT NULL CHECK (suffix_number > 0),
  allocation_version INTEGER NOT NULL CHECK (allocation_version > 0),
  candidate_ordinal INTEGER NOT NULL CHECK (candidate_ordinal >= 0),
  included_ordinal INTEGER CHECK (included_ordinal IS NULL OR included_ordinal >= 0),
  PRIMARY KEY (snapshot_id, node_occurrence_id),
  UNIQUE (snapshot_id, final_name_hmac),
  UNIQUE (snapshot_id, candidate_ordinal),
  UNIQUE (snapshot_id, included_ordinal),
  FOREIGN KEY (snapshot_id, output_id)
    REFERENCES name_allocation_snapshots(id, output_id) ON DELETE RESTRICT,
  FOREIGN KEY (allocation_id, output_id)
    REFERENCES name_allocations(id, output_id) ON DELETE RESTRICT
);

CREATE TABLE health_keys (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  algorithm TEXT NOT NULL DEFAULT 'hmac-sha256',
  projection_version TEXT NOT NULL,
  digest BLOB NOT NULL,
  protocol_id TEXT NOT NULL,
  executor_id TEXT NOT NULL,
  executor_version TEXT NOT NULL,
  probe_profile_revision_id TEXT NOT NULL REFERENCES probe_profile_revisions(id) ON DELETE RESTRICT,
  network_context_revision_id TEXT NOT NULL REFERENCES network_context_revisions(id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL,
  UNIQUE (key_id, projection_version, digest)
);

CREATE TABLE probe_batches (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  health_policy_revision_id TEXT NOT NULL REFERENCES health_policy_revisions(id) ON DELETE RESTRICT,
  probe_profile_revision_id TEXT NOT NULL REFERENCES probe_profile_revisions(id) ON DELETE RESTRICT,
  executor_id TEXT NOT NULL,
  executor_version TEXT NOT NULL,
  network_context_revision_id TEXT NOT NULL REFERENCES network_context_revisions(id) ON DELETE RESTRICT,
  window_start INTEGER NOT NULL,
  window_end INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
  conclusion TEXT CHECK (conclusion IS NULL OR conclusion IN (
    'normal', 'mass_failure_suppressed', 'control_failure_suppressed', 'insufficient_sample'
  )),
  control_total INTEGER NOT NULL DEFAULT 0 CHECK (control_total >= 0),
  control_failed INTEGER NOT NULL DEFAULT 0 CHECK (control_failed >= 0),
  completed_unique INTEGER NOT NULL DEFAULT 0 CHECK (completed_unique >= 0),
  eligible_unique INTEGER NOT NULL DEFAULT 0 CHECK (eligible_unique >= 0),
  node_failure_unique INTEGER NOT NULL DEFAULT 0 CHECK (node_failure_unique >= 0),
  created_at INTEGER NOT NULL,
  closed_at INTEGER,
  CHECK (window_end > window_start),
  CHECK (control_failed <= control_total),
  CHECK (node_failure_unique <= eligible_unique),
  CHECK (eligible_unique <= completed_unique),
  UNIQUE (
    output_id, health_policy_revision_id, probe_profile_revision_id,
    executor_id, executor_version, network_context_revision_id, window_start
  ),
  UNIQUE (id, output_id)
);

CREATE TABLE health_records (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  health_key_id TEXT NOT NULL REFERENCES health_keys(id) ON DELETE RESTRICT,
  probe_level TEXT NOT NULL CHECK (probe_level IN ('endpoint', 'proxy_http', 'capability')),
  target_id TEXT,
  target_url_redacted TEXT,
  result_class TEXT NOT NULL CHECK (result_class IN (
    'success', 'dns_failure', 'connect_timeout', 'connect_refused',
    'auth_failure', 'tls_failure', 'protocol_failure', 'unexpected_status',
    'target_failure', 'executor_unsupported', 'executor_crash',
    'resource_limited', 'cancelled'
  )),
  success INTEGER NOT NULL CHECK (success IN (0, 1)),
  node_attributable INTEGER NOT NULL CHECK (node_attributable IN (0, 1)),
  http_status INTEGER,
  queue_ms INTEGER CHECK (queue_ms IS NULL OR queue_ms >= 0),
  dns_ms INTEGER CHECK (dns_ms IS NULL OR dns_ms >= 0),
  connect_ms INTEGER CHECK (connect_ms IS NULL OR connect_ms >= 0),
  tls_ms INTEGER CHECK (tls_ms IS NULL OR tls_ms >= 0),
  first_byte_ms INTEGER CHECK (first_byte_ms IS NULL OR first_byte_ms >= 0),
  total_ms INTEGER NOT NULL CHECK (total_ms >= 0),
  executor_id TEXT NOT NULL,
  executor_version TEXT NOT NULL,
  policy_revision_id TEXT NOT NULL REFERENCES health_policy_revisions(id) ON DELETE RESTRICT,
  diagnostic_code TEXT,
  diagnostic_detail TEXT,
  observed_at INTEGER NOT NULL,
  stale_after INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (id, health_key_id)
);

CREATE INDEX health_records_key_time ON health_records(health_key_id, observed_at DESC, id DESC);
CREATE INDEX health_records_retention ON health_records(created_at);

CREATE TABLE probe_queue_items (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  health_key_id TEXT NOT NULL UNIQUE REFERENCES health_keys(id) ON DELETE RESTRICT,
  priority_class TEXT NOT NULL CHECK (priority_class IN (
    'manual', 'unhealthy_recovery', 'initial', 'failure_recheck', 'periodic'
  )),
  priority INTEGER NOT NULL,
  manual_waiter_count INTEGER NOT NULL DEFAULT 0 CHECK (manual_waiter_count >= 0),
  status TEXT NOT NULL CHECK (status IN ('dormant', 'queued', 'leased', 'running')),
  due_at INTEGER,
  lease_owner TEXT,
  lease_expires_at INTEGER,
  latest_record_id TEXT REFERENCES health_records(id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (status = 'dormant' OR due_at IS NOT NULL),
  UNIQUE (id, health_key_id)
);

CREATE INDEX probe_queue_claim
  ON probe_queue_items(status, priority DESC, due_at, health_key_id)
  WHERE status IN ('queued', 'leased', 'running');

CREATE TABLE control_probe_records (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  probe_profile_revision_id TEXT NOT NULL REFERENCES probe_profile_revisions(id) ON DELETE RESTRICT,
  network_context_revision_id TEXT NOT NULL REFERENCES network_context_revisions(id) ON DELETE RESTRICT,
  target_id TEXT NOT NULL,
  target_url_redacted TEXT NOT NULL,
  result_class TEXT NOT NULL CHECK (result_class IN (
    'success', 'dns_failure', 'connect_timeout', 'connect_refused',
    'tls_failure', 'unexpected_status', 'target_failure',
    'resource_limited', 'cancelled'
  )),
  success INTEGER NOT NULL CHECK (success IN (0, 1)),
  http_status INTEGER,
  total_ms INTEGER NOT NULL CHECK (total_ms >= 0),
  executor_id TEXT NOT NULL,
  executor_version TEXT NOT NULL,
  diagnostic_code TEXT,
  observed_at INTEGER NOT NULL,
  valid_until INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX control_probe_records_context_time
  ON control_probe_records(probe_profile_revision_id, network_context_revision_id, observed_at DESC);

CREATE TABLE probe_batch_controls (
  batch_id TEXT NOT NULL REFERENCES probe_batches(id) ON DELETE RESTRICT,
  control_record_id TEXT NOT NULL REFERENCES control_probe_records(id) ON DELETE RESTRICT,
  PRIMARY KEY (batch_id, control_record_id)
);

CREATE TABLE probe_batch_items (
  batch_id TEXT NOT NULL REFERENCES probe_batches(id) ON DELETE RESTRICT,
  health_key_id TEXT NOT NULL REFERENCES health_keys(id) ON DELETE RESTRICT,
  queue_item_id TEXT NOT NULL,
  health_record_id TEXT,
  priority INTEGER NOT NULL,
  due_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'deferred', 'cancelled')),
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  PRIMARY KEY (batch_id, health_key_id),
  UNIQUE (batch_id, queue_item_id),
  FOREIGN KEY (queue_item_id, health_key_id)
    REFERENCES probe_queue_items(id, health_key_id) ON DELETE RESTRICT,
  FOREIGN KEY (health_record_id, health_key_id)
    REFERENCES health_records(id, health_key_id) ON DELETE RESTRICT
);

CREATE INDEX probe_batch_items_queue ON probe_batch_items(status, priority DESC, due_at, health_key_id);

CREATE TABLE node_health_links (
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  health_record_id TEXT NOT NULL REFERENCES health_records(id) ON DELETE RESTRICT,
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  prior_state TEXT NOT NULL,
  resulting_state TEXT NOT NULL,
  transition_reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (node_occurrence_id, health_record_id, output_id)
);

CREATE INDEX node_health_links_occurrence_time ON node_health_links(node_occurrence_id, created_at DESC);

CREATE TABLE node_health_states (
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  health_key_id TEXT REFERENCES health_keys(id) ON DELETE RESTRICT,
  latest_record_id TEXT,
  state TEXT NOT NULL CHECK (state IN (
    'unchecked', 'checking', 'healthy', 'degraded',
    'unhealthy', 'unsupported', 'disabled'
  )),
  stale INTEGER NOT NULL DEFAULT 0 CHECK (stale IN (0, 1)),
  consecutive_successes INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_successes >= 0),
  consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
  recovery_step INTEGER NOT NULL DEFAULT 0 CHECK (recovery_step >= 0),
  next_check_at INTEGER,
  policy_revision_id TEXT NOT NULL REFERENCES health_policy_revisions(id) ON DELETE RESTRICT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (output_id, node_occurrence_id),
  FOREIGN KEY (latest_record_id, health_key_id)
    REFERENCES health_records(id, health_key_id) ON DELETE RESTRICT
);

CREATE INDEX node_health_states_due ON node_health_states(next_check_at) WHERE next_check_at IS NOT NULL;
CREATE INDEX node_health_states_filter ON node_health_states(output_id, state, stale);

CREATE TABLE artifacts (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE RESTRICT,
  output_revision_id TEXT NOT NULL,
  build_sequence INTEGER NOT NULL CHECK (build_sequence > 0),
  status TEXT NOT NULL CHECK (status IN ('building', 'validated', 'rejected', 'publishable')),
  reason TEXT NOT NULL,
  content_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  content_type TEXT,
  content_length INTEGER CHECK (content_length IS NULL OR content_length >= 0),
  public_sha256 TEXT CHECK (public_sha256 IS NULL OR length(public_sha256) = 64),
  node_count INTEGER CHECK (node_count IS NULL OR node_count >= 0),
  warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
  input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
  service_version TEXT NOT NULL,
  platform TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  UNIQUE (output_id, build_sequence),
  UNIQUE (id, output_id),
  FOREIGN KEY (output_revision_id, output_id)
    REFERENCES output_revisions(id, output_id) ON DELETE RESTRICT
);

CREATE INDEX artifacts_output_time ON artifacts(output_id, created_at DESC, id DESC);

CREATE TABLE build_manifests (
  artifact_id TEXT PRIMARY KEY,
  output_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version > 0),
  manifest_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  canonical_sha256 TEXT NOT NULL CHECK (length(canonical_sha256) = 64),
  name_allocation_snapshot_id TEXT NOT NULL REFERENCES name_allocation_snapshots(id) ON DELETE RESTRICT,
  occurrence_algorithm_version TEXT NOT NULL,
  protocol_registry_version TEXT NOT NULL,
  format_registry_version TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (artifact_id, output_id)
    REFERENCES artifacts(id, output_id) ON DELETE RESTRICT,
  FOREIGN KEY (name_allocation_snapshot_id, output_id)
    REFERENCES name_allocation_snapshots(id, output_id) ON DELETE RESTRICT
);

CREATE TABLE artifact_source_snapshots (
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  snapshot_id TEXT NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK (member_ordinal >= 0),
  content_hmac BLOB NOT NULL,
  PRIMARY KEY (artifact_id, source_id),
  UNIQUE (artifact_id, member_ordinal),
  FOREIGN KEY (snapshot_id, source_id)
    REFERENCES snapshots(id, source_id) ON DELETE RESTRICT
);

CREATE TABLE artifact_health_records (
  artifact_id TEXT NOT NULL,
  output_id TEXT NOT NULL,
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  health_record_id TEXT REFERENCES health_records(id) ON DELETE RESTRICT,
  probe_batch_id TEXT,
  adopted_state TEXT NOT NULL,
  stale INTEGER NOT NULL CHECK (stale IN (0, 1)),
  batch_suppressed INTEGER NOT NULL DEFAULT 0 CHECK (batch_suppressed IN (0, 1)),
  PRIMARY KEY (artifact_id, node_occurrence_id),
  FOREIGN KEY (artifact_id, output_id)
    REFERENCES artifacts(id, output_id) ON DELETE RESTRICT,
  FOREIGN KEY (probe_batch_id, output_id)
    REFERENCES probe_batches(id, output_id) ON DELETE RESTRICT
);

CREATE TABLE artifact_probe_batches (
  artifact_id TEXT NOT NULL,
  output_id TEXT NOT NULL,
  probe_batch_id TEXT NOT NULL,
  conclusion TEXT NOT NULL CHECK (conclusion IN (
    'normal', 'mass_failure_suppressed', 'control_failure_suppressed', 'insufficient_sample'
  )),
  eligible_unique INTEGER NOT NULL CHECK (eligible_unique >= 0),
  node_failure_unique INTEGER NOT NULL CHECK (node_failure_unique >= 0),
  PRIMARY KEY (artifact_id, probe_batch_id),
  CHECK (node_failure_unique <= eligible_unique),
  FOREIGN KEY (artifact_id, output_id)
    REFERENCES artifacts(id, output_id) ON DELETE RESTRICT,
  FOREIGN KEY (probe_batch_id, output_id)
    REFERENCES probe_batches(id, output_id) ON DELETE RESTRICT
);

CREATE TABLE artifact_control_probe_records (
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
  probe_batch_id TEXT NOT NULL REFERENCES probe_batches(id) ON DELETE RESTRICT,
  control_record_id TEXT NOT NULL REFERENCES control_probe_records(id) ON DELETE RESTRICT,
  PRIMARY KEY (artifact_id, probe_batch_id, control_record_id),
  FOREIGN KEY (artifact_id, probe_batch_id)
    REFERENCES artifact_probe_batches(artifact_id, probe_batch_id) ON DELETE RESTRICT
);

CREATE TABLE artifact_nodes (
  artifact_id TEXT NOT NULL,
  output_id TEXT NOT NULL,
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  raw_node_id TEXT NOT NULL REFERENCES raw_nodes(id) ON DELETE RESTRICT,
  allocation_snapshot_id TEXT NOT NULL,
  output_ordinal INTEGER,
  included INTEGER NOT NULL CHECK (included IN (0, 1)),
  exclusion_code TEXT,
  patch_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  effective_node_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  PRIMARY KEY (artifact_id, node_occurrence_id),
  UNIQUE (artifact_id, output_ordinal),
  CHECK ((included = 1 AND output_ordinal IS NOT NULL) OR included = 0),
  FOREIGN KEY (artifact_id, output_id)
    REFERENCES artifacts(id, output_id) ON DELETE RESTRICT,
  FOREIGN KEY (allocation_snapshot_id, output_id)
    REFERENCES name_allocation_snapshots(id, output_id) ON DELETE RESTRICT
);

CREATE TABLE validation_results (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
  strength TEXT NOT NULL CHECK (strength IN ('structural', 'semantic_internal', 'target_binary')),
  validator_id TEXT NOT NULL,
  validator_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'skipped')),
  diagnostic_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER NOT NULL
);

CREATE INDEX validation_results_artifact ON validation_results(artifact_id, strength);

CREATE TABLE output_publications (
  output_id TEXT PRIMARY KEY REFERENCES outputs(id) ON DELETE RESTRICT,
  current_artifact_id TEXT REFERENCES artifacts(id) ON DELETE RESTRICT,
  mode TEXT NOT NULL DEFAULT 'automatic' CHECK (mode IN ('automatic', 'manual_lock')),
  automatic_sequence INTEGER NOT NULL DEFAULT 0 CHECK (automatic_sequence >= 0),
  published_at INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE TABLE jobs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  job_type TEXT NOT NULL CHECK (job_type IN (
    'source_refresh', 'node_probe', 'output_build', 'cleanup',
    'template_refresh', 'backup', 'restore', 'key_rotation',
    'config_export', 'name_compaction', 'import'
  )),
  resource_type TEXT,
  resource_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('queued', 'leased', 'running', 'succeeded', 'failed', 'cancelled', 'dead')),
  priority INTEGER NOT NULL DEFAULT 0,
  dedupe_key TEXT,
  input_digest TEXT NOT NULL,
  payload_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  lease_owner TEXT,
  lease_expires_at INTEGER,
  attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
  progress_current INTEGER NOT NULL DEFAULT 0 CHECK (progress_current >= 0),
  progress_total INTEGER CHECK (progress_total IS NULL OR progress_total >= 0),
  error_code TEXT,
  error_detail TEXT,
  correlation_id TEXT NOT NULL,
  due_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER
);

CREATE UNIQUE INDEX jobs_unique_active_dedupe ON jobs(job_type, dedupe_key)
  WHERE dedupe_key IS NOT NULL AND status IN ('queued', 'leased', 'running');
CREATE INDEX jobs_claim ON jobs(status, priority DESC, due_at, created_at, id);

CREATE TABLE idempotency_records (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  actor_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  key_hmac BLOB NOT NULL,
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  response_status INTEGER NOT NULL,
  response_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  job_id TEXT REFERENCES jobs(id) ON DELETE RESTRICT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE (actor_id, scope, key_hmac),
  CHECK (expires_at > created_at)
);

CREATE INDEX idempotency_records_expiry ON idempotency_records(expires_at);

CREATE TABLE configuration_exports (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('building', 'ready', 'failed', 'expired')),
  include_secrets INTEGER NOT NULL CHECK (include_secrets IN (0, 1)),
  document_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  schema_version INTEGER NOT NULL CHECK (schema_version > 0),
  public_sha256 TEXT CHECK (public_sha256 IS NULL OR length(public_sha256) = 64),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  downloaded_at INTEGER,
  CHECK (expires_at > created_at)
);

CREATE INDEX configuration_exports_expiry ON configuration_exports(expires_at);

CREATE TABLE operation_previews (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  kind TEXT NOT NULL CHECK (kind IN ('configuration_import', 'restore', 'name_compaction')),
  actor_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
  source_digest TEXT NOT NULL CHECK (length(source_digest) = 64),
  staging_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  summary_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('ready', 'consumed', 'expired')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  CHECK (expires_at > created_at)
);

CREATE INDEX operation_previews_expiry ON operation_previews(status, expires_at);

CREATE TABLE backups (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('building', 'verified', 'failed', 'restored')),
  encryption_mode TEXT NOT NULL CHECK (encryption_mode IN ('passphrase', 'recipient_public_key', 'redacted')),
  manifest_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  archive_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  schema_version INTEGER NOT NULL CHECK (schema_version > 0),
  public_sha256 TEXT CHECK (public_sha256 IS NULL OR length(public_sha256) = 64),
  created_at INTEGER NOT NULL,
  verified_at INTEGER,
  restored_at INTEGER
);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  occurred_at INTEGER NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('administrator', 'token', 'system', 'cli')),
  actor_id TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
  correlation_id TEXT NOT NULL,
  remote_address TEXT,
  diff_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  detail_code TEXT,
  retain_until INTEGER NOT NULL
);

CREATE INDEX audit_events_time ON audit_events(occurred_at DESC, id DESC);
CREATE INDEX audit_events_resource ON audit_events(resource_type, resource_id, occurred_at DESC);

-- Deferred cross-table pointers. SQLite permits these references to tables created above.
CREATE TRIGGER instances_active_master_key_insert
BEFORE INSERT ON instances
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM master_key_slots m
    WHERE m.id = NEW.active_master_key_id AND m.state = 'active'
  ) THEN RAISE(ABORT, 'instance master key is not active') END;
END;

CREATE TRIGGER instances_active_master_key_update
BEFORE UPDATE OF active_master_key_id ON instances
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM master_key_slots m
    WHERE m.id = NEW.active_master_key_id AND m.state = 'active'
  ) THEN RAISE(ABORT, 'instance master key is not active') END;
END;

CREATE TRIGGER sources_snapshot_same_source_insert
BEFORE UPDATE OF current_snapshot_id ON sources
WHEN NEW.current_snapshot_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM snapshots s
    JOIN refresh_attempts a ON a.id = s.refresh_attempt_id
    WHERE s.id = NEW.current_snapshot_id AND s.source_id = NEW.id
      AND a.status = 'succeeded' AND a.accepted_snapshot_id = s.id
      AND (
        OLD.current_snapshot_id IS NULL OR
        s.accepted_at >= (
          SELECT current.accepted_at FROM snapshots current
          WHERE current.id = OLD.current_snapshot_id
        )
      )
  ) THEN RAISE(ABORT, 'current snapshot belongs to another source') END;
END;

CREATE TRIGGER sources_revision_pointer_owner
BEFORE UPDATE OF draft_revision_id, published_revision_id ON sources
BEGIN
  SELECT CASE WHEN NEW.draft_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM source_revisions r
    WHERE r.id = NEW.draft_revision_id AND r.source_id = NEW.id AND r.state = 'draft'
  ) THEN RAISE(ABORT, 'source draft revision mismatch') END;
  SELECT CASE WHEN NEW.published_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM source_revisions r
    WHERE r.id = NEW.published_revision_id AND r.source_id = NEW.id AND r.state = 'published'
  ) THEN RAISE(ABORT, 'source published revision mismatch') END;
END;

CREATE TRIGGER collections_revision_pointer_owner
BEFORE UPDATE OF draft_revision_id, published_revision_id ON collections
BEGIN
  SELECT CASE WHEN NEW.draft_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM collection_revisions r
    WHERE r.id = NEW.draft_revision_id AND r.collection_id = NEW.id AND r.state = 'draft'
  ) THEN RAISE(ABORT, 'collection draft revision mismatch') END;
  SELECT CASE WHEN NEW.published_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM collection_revisions r
    WHERE r.id = NEW.published_revision_id AND r.collection_id = NEW.id AND r.state = 'published'
  ) THEN RAISE(ABORT, 'collection published revision mismatch') END;
END;

CREATE TRIGGER pipelines_revision_pointer_owner
BEFORE UPDATE OF draft_revision_id, published_revision_id ON pipelines
BEGIN
  SELECT CASE WHEN NEW.draft_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pipeline_revisions r
    WHERE r.id = NEW.draft_revision_id AND r.pipeline_id = NEW.id AND r.state = 'draft'
  ) THEN RAISE(ABORT, 'pipeline draft revision mismatch') END;
  SELECT CASE WHEN NEW.published_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM pipeline_revisions r
    WHERE r.id = NEW.published_revision_id AND r.pipeline_id = NEW.id AND r.state = 'published'
  ) THEN RAISE(ABORT, 'pipeline published revision mismatch') END;
END;

CREATE TRIGGER templates_revision_pointer_owner
BEFORE UPDATE OF draft_revision_id, published_revision_id ON templates
BEGIN
  SELECT CASE WHEN NEW.draft_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM template_revisions r
    WHERE r.id = NEW.draft_revision_id AND r.template_id = NEW.id AND r.state = 'draft'
  ) THEN RAISE(ABORT, 'template draft revision mismatch') END;
  SELECT CASE WHEN NEW.published_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM template_revisions r
    WHERE r.id = NEW.published_revision_id AND r.template_id = NEW.id AND r.state = 'published'
  ) THEN RAISE(ABORT, 'template published revision mismatch') END;
END;

CREATE TRIGGER health_policies_revision_pointer_owner
BEFORE UPDATE OF draft_revision_id, published_revision_id ON health_policies
BEGIN
  SELECT CASE WHEN NEW.draft_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM health_policy_revisions r
    WHERE r.id = NEW.draft_revision_id AND r.health_policy_id = NEW.id AND r.state = 'draft'
  ) THEN RAISE(ABORT, 'health policy draft revision mismatch') END;
  SELECT CASE WHEN NEW.published_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM health_policy_revisions r
    WHERE r.id = NEW.published_revision_id AND r.health_policy_id = NEW.id AND r.state = 'published'
  ) THEN RAISE(ABORT, 'health policy published revision mismatch') END;
END;

CREATE TRIGGER probe_profiles_revision_pointer_owner
BEFORE UPDATE OF draft_revision_id, published_revision_id ON probe_profiles
BEGIN
  SELECT CASE WHEN NEW.draft_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM probe_profile_revisions r
    WHERE r.id = NEW.draft_revision_id AND r.probe_profile_id = NEW.id AND r.state = 'draft'
  ) THEN RAISE(ABORT, 'probe profile draft revision mismatch') END;
  SELECT CASE WHEN NEW.published_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM probe_profile_revisions r
    WHERE r.id = NEW.published_revision_id AND r.probe_profile_id = NEW.id AND r.state = 'published'
  ) THEN RAISE(ABORT, 'probe profile published revision mismatch') END;
END;

CREATE TRIGGER outputs_revision_pointer_owner
BEFORE UPDATE OF draft_revision_id, published_revision_id ON outputs
BEGIN
  SELECT CASE WHEN NEW.draft_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM output_revisions r
    WHERE r.id = NEW.draft_revision_id AND r.output_id = NEW.id AND r.state = 'draft'
  ) THEN RAISE(ABORT, 'output draft revision mismatch') END;
  SELECT CASE WHEN NEW.published_revision_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM output_revisions r
    WHERE r.id = NEW.published_revision_id AND r.output_id = NEW.id AND r.state = 'published'
  ) THEN RAISE(ABORT, 'output published revision mismatch') END;
END;

CREATE TRIGGER probe_queue_limit_insert
BEFORE INSERT ON probe_queue_items
WHEN NEW.status IN ('queued', 'leased', 'running')
BEGIN
  SELECT CASE WHEN (
    SELECT count(*) FROM probe_queue_items
    WHERE status IN ('queued', 'leased', 'running')
  ) >= 100000 THEN RAISE(ABORT, 'probe queue hard limit reached') END;
END;

CREATE TRIGGER probe_queue_limit_activate
BEFORE UPDATE OF status ON probe_queue_items
WHEN OLD.status = 'dormant' AND NEW.status IN ('queued', 'leased', 'running')
BEGIN
  SELECT CASE WHEN (
    SELECT count(*) FROM probe_queue_items
    WHERE status IN ('queued', 'leased', 'running')
  ) >= 100000 THEN RAISE(ABORT, 'probe queue hard limit reached') END;
END;

CREATE TRIGGER artifacts_status_transition
BEFORE UPDATE OF status ON artifacts
WHEN NOT (
  (OLD.status = 'building' AND NEW.status IN ('validated', 'rejected')) OR
  (OLD.status = 'validated' AND NEW.status IN ('publishable', 'rejected')) OR
  OLD.status = NEW.status
)
BEGIN
  SELECT RAISE(ABORT, 'invalid artifact status transition');
END;

CREATE TRIGGER publication_artifact_same_output_insert
BEFORE INSERT ON output_publications
WHEN NEW.current_artifact_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM artifacts a
    WHERE a.id = NEW.current_artifact_id
      AND a.output_id = NEW.output_id
      AND a.status = 'publishable'
  ) THEN RAISE(ABORT, 'publication artifact is not publishable for output') END;
END;

CREATE TRIGGER publication_artifact_same_output_update
BEFORE UPDATE OF current_artifact_id ON output_publications
WHEN NEW.current_artifact_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM artifacts a
    WHERE a.id = NEW.current_artifact_id
      AND a.output_id = NEW.output_id
      AND a.status = 'publishable'
  ) THEN RAISE(ABORT, 'publication artifact is not publishable for output') END;
END;

INSERT INTO application_metadata(key, value) VALUES ('schema_version', '1');
INSERT INTO application_metadata(key, value) VALUES ('document_status', 'm0_draft');

-- The migration runner records a SHA-256 checksum in schema_migrations after
-- applying a release migration. This design draft deliberately carries no fake checksum.

COMMIT;

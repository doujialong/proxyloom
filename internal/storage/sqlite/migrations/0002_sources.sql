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
  private_network_authorized INTEGER NOT NULL DEFAULT 0
    CHECK (private_network_authorized IN (0, 1)),
  config_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  config_schema_version INTEGER NOT NULL DEFAULT 1 CHECK (config_schema_version > 0),
  created_by TEXT CHECK (created_by IS NULL OR length(created_by) = 36),
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

CREATE UNIQUE INDEX source_revisions_one_draft
  ON source_revisions(source_id) WHERE state = 'draft';

CREATE UNIQUE INDEX source_revisions_one_published
  ON source_revisions(source_id) WHERE state = 'published';

CREATE INDEX source_revisions_by_source
  ON source_revisions(source_id, revision_number DESC);

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
  accepted_snapshot_id TEXT REFERENCES snapshots(id) ON DELETE RESTRICT,
  correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 200),
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
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

CREATE INDEX refresh_attempts_source_time
  ON refresh_attempts(source_id, started_at DESC, id DESC);

CREATE UNIQUE INDEX refresh_attempts_one_running_per_source
  ON refresh_attempts(source_id) WHERE status = 'running';

CREATE TABLE raw_documents (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  detected_format TEXT NOT NULL CHECK (length(detected_format) BETWEEN 1 AND 128),
  format_adapter_version TEXT NOT NULL CHECK (length(format_adapter_version) BETWEEN 1 AND 128),
  content_hmac BLOB NOT NULL CHECK (length(content_hmac) = 32),
  media_type TEXT CHECK (media_type IS NULL OR length(media_type) <= 128),
  charset TEXT CHECK (charset IS NULL OR length(charset) <= 128),
  parse_limits_version INTEGER NOT NULL DEFAULT 1 CHECK (parse_limits_version > 0),
  created_at INTEGER NOT NULL,
  UNIQUE (id, source_id)
);

CREATE INDEX raw_documents_source_digest
  ON raw_documents(source_id, content_hmac);

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
  occurrence_algorithm_version TEXT NOT NULL
    CHECK (length(occurrence_algorithm_version) BETWEEN 1 AND 128),
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

CREATE INDEX snapshots_source_time
  ON snapshots(source_id, accepted_at DESC, id DESC);

CREATE TRIGGER source_revisions_immutable_fields
BEFORE UPDATE ON source_revisions
WHEN
  NEW.id IS NOT OLD.id OR
  NEW.source_id IS NOT OLD.source_id OR
  NEW.revision_number IS NOT OLD.revision_number OR
  NEW.source_type IS NOT OLD.source_type OR
  NEW.input_format_hint IS NOT OLD.input_format_hint OR
  NEW.import_purpose IS NOT OLD.import_purpose OR
  NEW.refresh_schedule IS NOT OLD.refresh_schedule OR
  NEW.schedule_timezone IS NOT OLD.schedule_timezone OR
  NEW.private_network_authorized IS NOT OLD.private_network_authorized OR
  NEW.config_blob_id IS NOT OLD.config_blob_id OR
  NEW.config_schema_version IS NOT OLD.config_schema_version OR
  NEW.created_by IS NOT OLD.created_by OR
  NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'source revision fields are immutable');
END;

CREATE TRIGGER source_revisions_state_transition
BEFORE UPDATE OF state, published_at ON source_revisions
WHEN NOT (
  (OLD.state = 'draft' AND NEW.state = 'published' AND OLD.published_at IS NULL AND NEW.published_at IS NOT NULL) OR
  (OLD.state = 'draft' AND NEW.state = 'archived' AND NEW.published_at IS NULL) OR
  (OLD.state = 'published' AND NEW.state = 'superseded' AND NEW.published_at = OLD.published_at) OR
  (OLD.state = 'superseded' AND NEW.state = 'archived' AND NEW.published_at = OLD.published_at)
)
BEGIN
  SELECT RAISE(ABORT, 'invalid source revision state transition');
END;

CREATE TRIGGER source_revisions_state_pointer_guard
BEFORE UPDATE OF state ON source_revisions
WHEN EXISTS (
  SELECT 1 FROM sources s
  WHERE (s.draft_revision_id = OLD.id AND NEW.state <> 'draft')
     OR (s.published_revision_id = OLD.id AND NEW.state <> 'published')
)
BEGIN
  SELECT RAISE(ABORT, 'source revision state is still referenced by a source pointer');
END;

CREATE TRIGGER source_revisions_no_delete
BEFORE DELETE ON source_revisions
BEGIN
  SELECT RAISE(ABORT, 'source revisions are immutable');
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

CREATE TRIGGER sources_revision_pointer_owner_insert
BEFORE INSERT ON sources
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

CREATE TRIGGER refresh_attempts_published_revision
BEFORE INSERT ON refresh_attempts
BEGIN
  SELECT CASE WHEN NEW.status <> 'running' OR NOT EXISTS (
    SELECT 1 FROM sources s
    JOIN source_revisions r ON r.id = NEW.source_revision_id AND r.source_id = s.id
    WHERE s.id = NEW.source_id
      AND s.lifecycle_state = 'active'
      AND s.published_revision_id = r.id
      AND r.state = 'published'
  ) THEN RAISE(ABORT, 'refresh attempt must use the current published revision') END;
END;

CREATE TRIGGER refresh_attempts_running_identity_immutable
BEFORE UPDATE ON refresh_attempts
WHEN OLD.status = 'running' AND (
  NEW.id IS NOT OLD.id OR
  NEW.source_id IS NOT OLD.source_id OR
  NEW.source_revision_id IS NOT OLD.source_revision_id OR
  NEW.job_id IS NOT OLD.job_id OR
  NEW.trigger_kind IS NOT OLD.trigger_kind OR
  NEW.correlation_id IS NOT OLD.correlation_id OR
  NEW.started_at IS NOT OLD.started_at
)
BEGIN
  SELECT RAISE(ABORT, 'refresh attempt identity is immutable');
END;

CREATE TRIGGER refresh_attempts_terminal_immutable
BEFORE UPDATE ON refresh_attempts
WHEN OLD.status <> 'running'
BEGIN
  SELECT RAISE(ABORT, 'terminal refresh attempt is immutable');
END;

CREATE TRIGGER snapshots_accept_running_attempt
BEFORE INSERT ON snapshots
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM refresh_attempts a
    WHERE a.id = NEW.refresh_attempt_id
      AND a.source_id = NEW.source_id
      AND a.source_revision_id = NEW.source_revision_id
      AND a.status = 'running'
      AND NEW.accepted_at >= a.started_at
  ) THEN RAISE(ABORT, 'snapshot must accept a running attempt') END;
END;

CREATE TRIGGER refresh_attempts_snapshot_owner
BEFORE UPDATE OF status, accepted_snapshot_id ON refresh_attempts
WHEN NEW.accepted_snapshot_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM snapshots s
    WHERE s.id = NEW.accepted_snapshot_id AND s.source_id = NEW.source_id
      AND (NEW.status = 'not_modified' OR s.refresh_attempt_id = NEW.id)
  ) THEN RAISE(ABORT, 'accepted snapshot does not belong to the refresh attempt') END;
END;

CREATE TRIGGER sources_snapshot_same_source
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

CREATE TRIGGER sources_snapshot_same_source_insert
BEFORE INSERT ON sources
WHEN NEW.current_snapshot_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM snapshots s
    JOIN refresh_attempts a ON a.id = s.refresh_attempt_id
    WHERE s.id = NEW.current_snapshot_id AND s.source_id = NEW.id
      AND a.status = 'succeeded' AND a.accepted_snapshot_id = s.id
  ) THEN RAISE(ABORT, 'current snapshot belongs to another source') END;
END;

CREATE TRIGGER raw_documents_no_update
BEFORE UPDATE ON raw_documents
BEGIN
  SELECT RAISE(ABORT, 'raw documents are immutable');
END;

CREATE TRIGGER raw_documents_no_delete
BEFORE DELETE ON raw_documents
BEGIN
  SELECT RAISE(ABORT, 'raw documents are immutable');
END;

CREATE TRIGGER snapshots_no_update
BEFORE UPDATE ON snapshots
BEGIN
  SELECT RAISE(ABORT, 'snapshots are immutable');
END;

CREATE TRIGGER snapshots_no_delete
BEFORE DELETE ON snapshots
BEGIN
  SELECT RAISE(ABORT, 'snapshots are immutable');
END;

UPDATE application_metadata SET value = '2' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm2_sources' WHERE key = 'schema_status';

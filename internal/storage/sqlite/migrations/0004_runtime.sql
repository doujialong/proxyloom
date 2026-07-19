CREATE TABLE jobs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  job_type TEXT NOT NULL CHECK (job_type = 'source_refresh'),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  source_revision_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'queued', 'leased', 'running', 'succeeded', 'failed', 'cancelled', 'dead'
  )),
  priority INTEGER NOT NULL DEFAULT 0,
  dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 200),
  lease_owner TEXT CHECK (lease_owner IS NULL OR length(lease_owner) BETWEEN 1 AND 200),
  lease_expires_at INTEGER,
  attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
  error_code TEXT CHECK (error_code IS NULL OR length(error_code) <= 128),
  error_detail TEXT CHECK (error_detail IS NULL OR length(error_detail) <= 4096),
  correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 200),
  due_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  FOREIGN KEY (source_revision_id, source_id)
    REFERENCES source_revisions(id, source_id) ON DELETE RESTRICT,
  CHECK (started_at IS NULL OR started_at >= created_at),
  CHECK (finished_at IS NULL OR finished_at >= created_at),
  CHECK (
    (status = 'queued' AND lease_owner IS NULL AND lease_expires_at IS NULL AND finished_at IS NULL) OR
    (status IN ('leased', 'running') AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND finished_at IS NULL) OR
    (status IN ('succeeded', 'failed', 'cancelled', 'dead') AND lease_owner IS NULL AND lease_expires_at IS NULL AND finished_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX jobs_one_active_refresh
  ON jobs(job_type, dedupe_key)
  WHERE status IN ('queued', 'leased', 'running');

CREATE INDEX jobs_claim
  ON jobs(status, priority DESC, due_at, created_at, id);

CREATE TRIGGER jobs_terminal_immutable
BEFORE UPDATE ON jobs
WHEN OLD.status IN ('succeeded', 'failed', 'cancelled', 'dead')
BEGIN
  SELECT RAISE(ABORT, 'terminal jobs are immutable');
END;

CREATE TRIGGER jobs_identity_immutable
BEFORE UPDATE ON jobs
WHEN
  NEW.id IS NOT OLD.id OR
  NEW.job_type IS NOT OLD.job_type OR
  NEW.source_id IS NOT OLD.source_id OR
  NEW.source_revision_id IS NOT OLD.source_revision_id OR
  NEW.dedupe_key IS NOT OLD.dedupe_key OR
  NEW.max_attempts IS NOT OLD.max_attempts OR
  NEW.correlation_id IS NOT OLD.correlation_id OR
  NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'job identity is immutable');
END;

CREATE TABLE artifacts (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  snapshot_id TEXT NOT NULL,
  build_sequence INTEGER NOT NULL CHECK (build_sequence > 0),
  content_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  content_type TEXT NOT NULL CHECK (length(content_type) BETWEEN 1 AND 128),
  content_length INTEGER NOT NULL CHECK (content_length >= 0),
  public_sha256 TEXT NOT NULL CHECK (length(public_sha256) = 64),
  node_count INTEGER NOT NULL CHECK (node_count >= 0),
  warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
  output_format TEXT NOT NULL CHECK (length(output_format) BETWEEN 1 AND 128),
  builder_version TEXT NOT NULL CHECK (length(builder_version) BETWEEN 1 AND 128),
  created_at INTEGER NOT NULL,
  UNIQUE (source_id, build_sequence),
  UNIQUE (id, source_id),
  FOREIGN KEY (snapshot_id, source_id)
    REFERENCES snapshots(id, source_id) ON DELETE RESTRICT
);

CREATE INDEX artifacts_source_sequence
  ON artifacts(source_id, build_sequence DESC);

CREATE TRIGGER artifacts_no_update
BEFORE UPDATE ON artifacts
BEGIN
  SELECT RAISE(ABORT, 'artifacts are immutable');
END;

CREATE TRIGGER artifacts_no_delete
BEFORE DELETE ON artifacts
BEGIN
  SELECT RAISE(ABORT, 'artifacts are immutable');
END;

CREATE TABLE source_publications (
  source_id TEXT PRIMARY KEY REFERENCES sources(id) ON DELETE RESTRICT,
  current_artifact_id TEXT NOT NULL,
  published_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (current_artifact_id, source_id)
    REFERENCES artifacts(id, source_id) ON DELETE RESTRICT,
  CHECK (updated_at >= published_at)
);

CREATE TRIGGER source_publications_current_snapshot
BEFORE INSERT ON source_publications
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM sources s
    JOIN artifacts a ON a.id = NEW.current_artifact_id AND a.source_id = s.id
    WHERE s.id = NEW.source_id AND s.current_snapshot_id = a.snapshot_id
  ) THEN RAISE(ABORT, 'publication artifact is not built from the current snapshot') END;
END;

CREATE TRIGGER source_publications_current_snapshot_update
BEFORE UPDATE OF current_artifact_id ON source_publications
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM sources s
    JOIN artifacts a ON a.id = NEW.current_artifact_id AND a.source_id = s.id
    WHERE s.id = NEW.source_id AND s.current_snapshot_id = a.snapshot_id
  ) THEN RAISE(ABORT, 'publication artifact is not built from the current snapshot') END;
END;

CREATE TABLE publication_tokens (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  token_hmac BLOB NOT NULL CHECK (length(token_hmac) = 32),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  UNIQUE (source_id, token_hmac),
  CHECK (last_used_at IS NULL OR last_used_at >= created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX publication_tokens_source_active
  ON publication_tokens(source_id, created_at DESC)
  WHERE revoked_at IS NULL;

CREATE TRIGGER publication_tokens_identity_immutable
BEFORE UPDATE ON publication_tokens
WHEN
  NEW.id IS NOT OLD.id OR
  NEW.source_id IS NOT OLD.source_id OR
  NEW.token_hmac IS NOT OLD.token_hmac OR
  NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'publication token identity is immutable');
END;

UPDATE application_metadata SET value = '4' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm2_runtime' WHERE key = 'schema_status';

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

CREATE UNIQUE INDEX managed_output_build_jobs_active
  ON managed_output_build_jobs(dedupe_key)
  WHERE status IN ('queued', 'leased', 'running');

CREATE INDEX managed_output_build_jobs_claim
  ON managed_output_build_jobs(status, due_at, priority DESC, created_at, id);

CREATE TRIGGER managed_output_build_jobs_terminal_immutable
BEFORE UPDATE ON managed_output_build_jobs
WHEN OLD.status IN ('succeeded', 'failed', 'dead')
BEGIN
  SELECT RAISE(ABORT, 'terminal managed output build jobs are immutable');
END;

UPDATE application_metadata SET value = '9' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm4_output_jobs' WHERE key = 'schema_status';

CREATE TABLE health_records (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE RESTRICT,
  protocol_id TEXT NOT NULL CHECK (length(protocol_id) BETWEEN 1 AND 128),
  probe_level TEXT NOT NULL CHECK (probe_level IN ('proxy_http', 'capability')),
  target_id TEXT,
  result_class TEXT NOT NULL CHECK (result_class IN (
    'success', 'dns_failure', 'connect_timeout', 'connect_refused',
    'auth_failure', 'tls_failure', 'protocol_failure', 'unexpected_status',
    'target_failure', 'executor_unsupported', 'executor_crash',
    'resource_limited', 'cancelled'
  )),
  success INTEGER NOT NULL CHECK (success IN (0, 1)),
  node_attributable INTEGER NOT NULL CHECK (node_attributable IN (0, 1)),
  http_status INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
  total_ms INTEGER NOT NULL CHECK (total_ms >= 0),
  executor_id TEXT NOT NULL CHECK (length(executor_id) BETWEEN 1 AND 128),
  executor_version TEXT NOT NULL CHECK (length(executor_version) BETWEEN 1 AND 128),
  diagnostic_code TEXT CHECK (diagnostic_code IS NULL OR length(diagnostic_code) <= 128),
  observed_at INTEGER NOT NULL,
  stale_after INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK (stale_after > observed_at)
);

CREATE INDEX health_records_occurrence_time
  ON health_records(node_occurrence_id, observed_at DESC, id DESC);
CREATE INDEX health_records_window
  ON health_records(observed_at, node_attributable, success);

CREATE TABLE node_health_states (
  node_occurrence_id TEXT PRIMARY KEY REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  latest_record_id TEXT REFERENCES health_records(id) ON DELETE RESTRICT,
  state TEXT NOT NULL CHECK (state IN (
    'unchecked', 'checking', 'healthy', 'degraded',
    'unhealthy', 'unsupported', 'disabled'
  )),
  stale INTEGER NOT NULL DEFAULT 0 CHECK (stale IN (0, 1)),
  consecutive_successes INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_successes >= 0),
  consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
  recovery_step INTEGER NOT NULL DEFAULT 0 CHECK (recovery_step >= 0),
  next_check_at INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE INDEX node_health_states_due
  ON node_health_states(next_check_at) WHERE next_check_at IS NOT NULL;
CREATE INDEX node_health_states_filter
  ON node_health_states(state, stale);

CREATE TABLE probe_queue_items (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  node_occurrence_id TEXT NOT NULL UNIQUE REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  priority_class TEXT NOT NULL CHECK (priority_class IN (
    'manual', 'unhealthy_recovery', 'initial', 'failure_recheck', 'periodic'
  )),
  priority INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('dormant', 'queued', 'leased', 'running')),
  due_at INTEGER,
  lease_owner TEXT,
  lease_expires_at INTEGER,
  attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (status = 'dormant' OR due_at IS NOT NULL),
  CHECK (
    (status IN ('dormant', 'queued') AND lease_owner IS NULL AND lease_expires_at IS NULL) OR
    (status IN ('leased', 'running') AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
);

CREATE INDEX probe_queue_claim
  ON probe_queue_items(status, priority DESC, due_at, created_at, id);

CREATE TABLE control_probe_records (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
  success INTEGER NOT NULL CHECK (success IN (0, 1)),
  http_status INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
  result_class TEXT NOT NULL,
  total_ms INTEGER NOT NULL CHECK (total_ms >= 0),
  observed_at INTEGER NOT NULL,
  valid_until INTEGER NOT NULL,
  CHECK (valid_until > observed_at)
);

CREATE INDEX control_probe_records_time
  ON control_probe_records(observed_at DESC, target_id);

CREATE TABLE health_guard_windows (
  window_start INTEGER PRIMARY KEY,
  window_end INTEGER NOT NULL,
  conclusion TEXT NOT NULL CHECK (conclusion IN (
    'normal', 'mass_failure_suppressed', 'control_failure_suppressed', 'insufficient_sample'
  )),
  control_total INTEGER NOT NULL CHECK (control_total >= 0),
  control_failed INTEGER NOT NULL CHECK (control_failed >= 0),
  eligible_unique INTEGER NOT NULL CHECK (eligible_unique >= 0),
  node_failure_unique INTEGER NOT NULL CHECK (node_failure_unique >= 0),
  created_at INTEGER NOT NULL,
  CHECK (window_end > window_start),
  CHECK (control_failed <= control_total),
  CHECK (node_failure_unique <= eligible_unique)
);

UPDATE application_metadata SET value = '7' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm3_node_health' WHERE key = 'schema_status';

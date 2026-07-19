CREATE TABLE administrators (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  username TEXT NOT NULL COLLATE NOCASE UNIQUE
    CHECK (length(username) BETWEEN 3 AND 64),
  password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 32 AND 1024),
  password_params TEXT NOT NULL CHECK (length(password_params) BETWEEN 2 AND 512),
  session_epoch INTEGER NOT NULL DEFAULT 1 CHECK (session_epoch > 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  timezone TEXT NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 64),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER,
  CHECK (updated_at >= created_at),
  CHECK (last_login_at IS NULL OR last_login_at >= created_at)
);

CREATE TABLE setup_tokens (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  token_hmac BLOB NOT NULL UNIQUE CHECK (length(token_hmac) = 32),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  CHECK (expires_at > created_at),
  CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE INDEX setup_tokens_expiry ON setup_tokens(expires_at) WHERE used_at IS NULL;

CREATE TABLE sessions (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  token_hmac BLOB NOT NULL UNIQUE CHECK (length(token_hmac) = 32),
  csrf_hmac BLOB NOT NULL CHECK (length(csrf_hmac) = 32),
  session_epoch INTEGER NOT NULL CHECK (session_epoch > 0),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  recent_auth_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (expires_at > created_at),
  CHECK (last_seen_at >= created_at),
  CHECK (recent_auth_at >= created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX sessions_active_by_admin
  ON sessions(administrator_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  occurred_at INTEGER NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('administrator', 'system', 'setup')),
  actor_id TEXT,
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
  resource_type TEXT CHECK (resource_type IS NULL OR length(resource_type) <= 128),
  resource_id TEXT,
  result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
  correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 200),
  client_address TEXT CHECK (client_address IS NULL OR length(client_address) <= 128),
  detail_json TEXT NOT NULL DEFAULT '{}'
    CHECK (length(detail_json) <= 16384 AND json_valid(detail_json))
);

CREATE INDEX audit_events_time ON audit_events(occurred_at DESC, id DESC);
CREATE INDEX audit_events_action_time ON audit_events(action, occurred_at DESC);

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit events are immutable');
END;

UPDATE application_metadata SET value = '6' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm2_administrator_sessions' WHERE key = 'schema_status';

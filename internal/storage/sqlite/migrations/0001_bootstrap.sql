CREATE TABLE application_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE master_key_slots (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  state TEXT NOT NULL CHECK (state IN ('prepared', 'active', 'retired')),
  format_version INTEGER NOT NULL DEFAULT 1 CHECK (format_version > 0),
  canary_nonce BLOB NOT NULL CHECK (length(canary_nonce) = 12),
  canary_ciphertext BLOB NOT NULL CHECK (length(canary_ciphertext) >= 16),
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
  wrap_nonce BLOB NOT NULL CHECK (length(wrap_nonce) = 12),
  wrapped_key BLOB NOT NULL CHECK (length(wrapped_key) >= 48),
  created_at INTEGER NOT NULL,
  verified_at INTEGER,
  PRIMARY KEY (master_key_id, data_key_id)
);

CREATE INDEX master_key_wrappings_by_data_key
  ON master_key_wrappings(data_key_id, master_key_id);

CREATE TABLE encrypted_blobs (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  kind TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  format_version INTEGER NOT NULL DEFAULT 1 CHECK (format_version > 0),
  aad_version INTEGER NOT NULL DEFAULT 1 CHECK (aad_version > 0),
  nonce BLOB NOT NULL CHECK (length(nonce) = 12),
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
    relative_path NOT LIKE '%\%'
  ))
);

CREATE INDEX encrypted_blobs_gc
  ON encrypted_blobs(delete_after) WHERE delete_after IS NOT NULL;

INSERT INTO application_metadata(key, value) VALUES ('schema_version', '1');
INSERT INTO application_metadata(key, value) VALUES ('schema_status', 'm2_bootstrap');

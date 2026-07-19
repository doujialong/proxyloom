CREATE TABLE fingerprints (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  protocol_id TEXT NOT NULL CHECK (length(protocol_id) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK (kind IN ('semantic', 'opaque_structural')),
  algorithm TEXT NOT NULL CHECK (algorithm = 'hmac-sha256'),
  projection_version TEXT NOT NULL CHECK (length(projection_version) BETWEEN 1 AND 128),
  key_id TEXT NOT NULL REFERENCES data_keys(id) ON DELETE RESTRICT,
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  created_at INTEGER NOT NULL,
  UNIQUE (key_id, projection_version, digest)
);

CREATE TABLE raw_nodes (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE RESTRICT,
  raw_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  original_name_blob_id TEXT REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  original_name_hmac BLOB CHECK (original_name_hmac IS NULL OR length(original_name_hmac) = 32),
  source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
  extraction_path TEXT NOT NULL CHECK (length(extraction_path) <= 1024),
  raw_kind TEXT NOT NULL CHECK (raw_kind IN ('json_object', 'uri', 'text')),
  format_id TEXT NOT NULL CHECK (length(format_id) BETWEEN 1 AND 128),
  format_adapter_version TEXT NOT NULL CHECK (length(format_adapter_version) BETWEEN 1 AND 128),
  protocol_id TEXT NOT NULL CHECK (length(protocol_id) BETWEEN 1 AND 128),
  fingerprint_id TEXT NOT NULL REFERENCES fingerprints(id) ON DELETE RESTRICT,
  parse_status TEXT NOT NULL CHECK (parse_status IN ('complete', 'partial', 'opaque', 'invalid')),
  warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
  created_at INTEGER NOT NULL,
  UNIQUE (snapshot_id, source_ordinal),
  UNIQUE (id, snapshot_id)
);

CREATE INDEX raw_nodes_snapshot_protocol
  ON raw_nodes(snapshot_id, protocol_id, source_ordinal);

CREATE INDEX raw_nodes_fingerprint
  ON raw_nodes(fingerprint_id);

CREATE TABLE canonical_nodes (
  raw_node_id TEXT PRIMARY KEY REFERENCES raw_nodes(id) ON DELETE RESTRICT,
  protocol_adapter_version TEXT NOT NULL CHECK (length(protocol_adapter_version) BETWEEN 1 AND 128),
  completeness TEXT NOT NULL CHECK (completeness IN ('complete', 'partial', 'opaque')),
  canonical_blob_id TEXT NOT NULL REFERENCES encrypted_blobs(id) ON DELETE RESTRICT,
  feature_flags TEXT NOT NULL DEFAULT '[]',
  generated_at INTEGER NOT NULL
);

CREATE TABLE node_occurrences (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
  current_fingerprint_id TEXT NOT NULL REFERENCES fingerprints(id) ON DELETE RESTRICT,
  lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('present', 'absent', 'retired')),
  duplicate_slot INTEGER NOT NULL DEFAULT 1 CHECK (duplicate_slot > 0),
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  absent_since INTEGER,
  retain_until INTEGER,
  association_version TEXT NOT NULL CHECK (length(association_version) BETWEEN 1 AND 128),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (id, source_id),
  CHECK (last_seen_at >= first_seen_at),
  CHECK (updated_at >= created_at),
  CHECK (
    (lifecycle_state = 'present' AND absent_since IS NULL AND retain_until IS NULL) OR
    (lifecycle_state = 'absent' AND absent_since IS NOT NULL AND retain_until IS NOT NULL AND retain_until > absent_since) OR
    lifecycle_state = 'retired'
  )
);

CREATE INDEX node_occurrences_source_state
  ON node_occurrences(source_id, lifecycle_state, last_seen_at DESC);

CREATE INDEX node_occurrences_fingerprint
  ON node_occurrences(source_id, current_fingerprint_id);

CREATE TABLE snapshot_occurrences (
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE RESTRICT,
  raw_node_id TEXT NOT NULL,
  node_occurrence_id TEXT NOT NULL REFERENCES node_occurrences(id) ON DELETE RESTRICT,
  occurrence_ordinal INTEGER NOT NULL CHECK (occurrence_ordinal >= 0),
  match_method TEXT NOT NULL CHECK (match_method IN (
    'fingerprint_unique', 'path', 'duplicate_slot',
    'auxiliary_unique', 'new', 'ambiguous_new'
  )),
  association_version TEXT NOT NULL CHECK (length(association_version) BETWEEN 1 AND 128),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (snapshot_id, node_occurrence_id),
  UNIQUE (raw_node_id),
  UNIQUE (snapshot_id, occurrence_ordinal),
  FOREIGN KEY (raw_node_id, snapshot_id)
    REFERENCES raw_nodes(id, snapshot_id) ON DELETE RESTRICT
);

CREATE INDEX snapshot_occurrences_occurrence
  ON snapshot_occurrences(node_occurrence_id, snapshot_id);

CREATE TRIGGER snapshot_occurrences_same_source
BEFORE INSERT ON snapshot_occurrences
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM snapshots s
    JOIN node_occurrences o ON o.id = NEW.node_occurrence_id
    WHERE s.id = NEW.snapshot_id AND s.source_id = o.source_id
  ) THEN RAISE(ABORT, 'snapshot occurrence belongs to another source') END;
END;

CREATE TRIGGER raw_nodes_fingerprint_protocol
BEFORE INSERT ON raw_nodes
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM fingerprints f
    WHERE f.id = NEW.fingerprint_id AND f.protocol_id = NEW.protocol_id
  ) THEN RAISE(ABORT, 'raw node fingerprint protocol mismatch') END;
END;

CREATE TRIGGER node_occurrences_immutable_identity
BEFORE UPDATE ON node_occurrences
WHEN
  NEW.id IS NOT OLD.id OR
  NEW.source_id IS NOT OLD.source_id OR
  NEW.first_seen_at IS NOT OLD.first_seen_at OR
  NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'node occurrence identity is immutable');
END;

CREATE TRIGGER fingerprints_no_update
BEFORE UPDATE ON fingerprints
BEGIN
  SELECT RAISE(ABORT, 'fingerprints are immutable');
END;

CREATE TRIGGER fingerprints_no_delete
BEFORE DELETE ON fingerprints
BEGIN
  SELECT RAISE(ABORT, 'fingerprints are immutable');
END;

CREATE TRIGGER raw_nodes_no_update
BEFORE UPDATE ON raw_nodes
BEGIN
  SELECT RAISE(ABORT, 'raw nodes are immutable');
END;

CREATE TRIGGER raw_nodes_no_delete
BEFORE DELETE ON raw_nodes
BEGIN
  SELECT RAISE(ABORT, 'raw nodes are immutable');
END;

CREATE TRIGGER canonical_nodes_no_update
BEFORE UPDATE ON canonical_nodes
BEGIN
  SELECT RAISE(ABORT, 'canonical nodes are immutable');
END;

CREATE TRIGGER canonical_nodes_no_delete
BEFORE DELETE ON canonical_nodes
BEGIN
  SELECT RAISE(ABORT, 'canonical nodes are immutable');
END;

CREATE TRIGGER snapshot_occurrences_no_update
BEFORE UPDATE ON snapshot_occurrences
BEGIN
  SELECT RAISE(ABORT, 'snapshot occurrences are immutable');
END;

CREATE TRIGGER snapshot_occurrences_no_delete
BEFORE DELETE ON snapshot_occurrences
BEGIN
  SELECT RAISE(ABORT, 'snapshot occurrences are immutable');
END;

UPDATE application_metadata SET value = '3' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm2_nodes' WHERE key = 'schema_status';

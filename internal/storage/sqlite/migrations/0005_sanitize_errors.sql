DROP TRIGGER refresh_attempts_terminal_immutable;
DROP TRIGGER jobs_terminal_immutable;

UPDATE refresh_attempts
SET error_detail = CASE error_code
  WHEN 'fetch_failed' THEN 'remote source request failed; sensitive diagnostics removed'
  WHEN 'parse_failed' THEN 'source content could not be parsed; sensitive diagnostics removed'
  WHEN 'content_gate_rejected' THEN 'source content gate rejected the candidate snapshot'
  ELSE 'operation failed; sensitive diagnostics removed'
END
WHERE error_detail IS NOT NULL;

UPDATE jobs
SET error_detail = CASE error_code
  WHEN 'fetch_failed' THEN 'remote source request failed; sensitive diagnostics removed'
  WHEN 'parse_failed' THEN 'source content could not be parsed; sensitive diagnostics removed'
  WHEN 'content_gate_rejected' THEN 'source content gate rejected the candidate snapshot'
  WHEN 'lease_expired' THEN 'worker lease expired'
  ELSE 'operation failed; sensitive diagnostics removed'
END
WHERE error_detail IS NOT NULL;

CREATE TRIGGER refresh_attempts_terminal_immutable
BEFORE UPDATE ON refresh_attempts
WHEN OLD.status <> 'running'
BEGIN
  SELECT RAISE(ABORT, 'terminal refresh attempt is immutable');
END;

CREATE TRIGGER jobs_terminal_immutable
BEFORE UPDATE ON jobs
WHEN OLD.status IN ('succeeded', 'failed', 'cancelled', 'dead')
BEGIN
  SELECT RAISE(ABORT, 'terminal jobs are immutable');
END;

UPDATE application_metadata SET value = '5' WHERE key = 'schema_version';
UPDATE application_metadata SET value = 'm2_sanitized_errors' WHERE key = 'schema_status';

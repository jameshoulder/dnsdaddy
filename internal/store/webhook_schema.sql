CREATE TABLE IF NOT EXISTS webhook_config (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  enabled INTEGER NOT NULL DEFAULT 0,
  url TEXT NOT NULL DEFAULT '',
  event_types TEXT NOT NULL DEFAULT '["finding.created"]',
  allow_private INTEGER NOT NULL DEFAULT 0,
  timeout_ms INTEGER NOT NULL DEFAULT 5000,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  max_queue INTEGER NOT NULL DEFAULT 500,
  ciphertext BLOB,
  key_id TEXT NOT NULL DEFAULT '',
  hint TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO webhook_config (id) VALUES (1);

CREATE TABLE IF NOT EXISTS webhook_stats (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  queued INTEGER NOT NULL DEFAULT 0,
  attempted INTEGER NOT NULL DEFAULT 0,
  delivered INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0,
  dropped INTEGER NOT NULL DEFAULT 0,
  retried INTEGER NOT NULL DEFAULT 0,
  last_success_at INTEGER NOT NULL DEFAULT 0,
  last_failure_at INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  last_http_status INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO webhook_stats (id) VALUES (1);

CREATE TABLE IF NOT EXISTS webhook_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL CHECK(length(payload) <= 32768),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt INTEGER NOT NULL DEFAULT 0,
  config_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS webhook_outbox_due ON webhook_outbox(next_attempt, id);

-- Capture is in the same transaction as the original append. No network or
-- unbounded work occurs on this path; capacity overflow is counted and dropped.
-- Disabled installations queue nothing, including events from before opt-in.
CREATE TRIGGER IF NOT EXISTS webhook_finding_created AFTER INSERT ON findings
WHEN EXISTS (SELECT 1 FROM webhook_config c, json_each(c.event_types) e WHERE c.id = 1 AND c.enabled = 1 AND e.value = 'finding.created')
BEGIN
  UPDATE webhook_stats SET dropped = dropped + CASE WHEN (SELECT COUNT(*) FROM webhook_outbox) >= (SELECT max_queue FROM webhook_config WHERE id = 1) THEN 1 ELSE 0 END WHERE id = 1;
  INSERT OR IGNORE INTO webhook_outbox (event_id,event_type,payload,config_version,created_at)
  SELECT 'finding.created:' || NEW.id, 'finding.created',
    json_object('id','finding.created:' || NEW.id,'type','finding.created','occurredAt',strftime('%Y-%m-%dT%H:%M:%fZ',NEW.ts / 1000.0,'unixepoch'),
      'data',json_object('findingId',NEW.id,'eventType',substr(NEW.event_type,1,128),'severity',substr(NEW.severity,1,32),'confidence',NEW.confidence,'score',NEW.score,'domain',substr(NEW.domain,1,253),'clientIp',substr(NEW.client_ip,1,64),'networkId',substr(NEW.network_id,1,128),'detector',substr(NEW.detector,1,128),'title',substr(NEW.title,1,512),'summary',substr(NEW.summary,1,2048))),
    version, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) FROM webhook_config
  WHERE id = 1 AND (SELECT COUNT(*) FROM webhook_outbox) < max_queue;
  UPDATE webhook_stats SET queued = queued + changes() WHERE id = 1;
END;

CREATE TRIGGER IF NOT EXISTS webhook_finding_reviewed AFTER INSERT ON finding_review_history
WHEN EXISTS (SELECT 1 FROM webhook_config c, json_each(c.event_types) e WHERE c.id = 1 AND c.enabled = 1 AND e.value = 'finding.reviewed')
BEGIN
  UPDATE webhook_stats SET dropped = dropped + CASE WHEN (SELECT COUNT(*) FROM webhook_outbox) >= (SELECT max_queue FROM webhook_config WHERE id = 1) THEN 1 ELSE 0 END WHERE id = 1;
  INSERT OR IGNORE INTO webhook_outbox (event_id,event_type,payload,config_version,created_at)
  SELECT 'finding.reviewed:' || NEW.finding_id || ':' || NEW.version, 'finding.reviewed',
    json_object('id','finding.reviewed:' || NEW.finding_id || ':' || NEW.version,'type','finding.reviewed','occurredAt',strftime('%Y-%m-%dT%H:%M:%fZ',NEW.at / 1000.0,'unixepoch'),
      'data',json_object('findingId',NEW.finding_id,'version',NEW.version,'fromState',NEW.from_state,'toState',NEW.to_state,'note',substr(NEW.note,1,4096),'actor',substr(NEW.actor,1,256))),
    version, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) FROM webhook_config
  WHERE id = 1 AND (SELECT COUNT(*) FROM webhook_outbox) < max_queue;
  UPDATE webhook_stats SET queued = queued + changes() WHERE id = 1;
END;

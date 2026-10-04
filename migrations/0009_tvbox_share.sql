ALTER TABLE resources ADD COLUMN auto_sync INTEGER NOT NULL DEFAULT 1;
ALTER TABLE resources ADD COLUMN sync_interval_minutes INTEGER NOT NULL DEFAULT 360;
ALTER TABLE resources ADD COLUMN content_hash TEXT NOT NULL DEFAULT '';

CREATE TABLE resource_sync_log (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  started_at TEXT NOT NULL,
  ok INTEGER NOT NULL CHECK (ok IN (0, 1)),
  error TEXT NOT NULL DEFAULT '',
  url_count INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX resource_sync_log_resource_time ON resource_sync_log(resource_id, started_at DESC);
CREATE INDEX resource_sync_log_time ON resource_sync_log(started_at);

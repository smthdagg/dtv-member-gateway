CREATE TABLE resource_snapshots (
  resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
  content_json TEXT NOT NULL,
  source_content_type TEXT NOT NULL DEFAULT 'application/json',
  url_count INTEGER NOT NULL DEFAULT 0,
  blocked_url_count INTEGER NOT NULL DEFAULT 0,
  top_level_keys TEXT NOT NULL DEFAULT '[]',
  synced_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS site_probe_state (
  api_hash TEXT PRIMARY KEY,
  api TEXT NOT NULL,
  last_ok INTEGER NOT NULL DEFAULT 0,
  fail_streak INTEGER NOT NULL DEFAULT 0,
  last_checked_at TEXT,
  last_status TEXT NOT NULL DEFAULT ''
);
CREATE INDEX site_probe_state_streak ON site_probe_state(fail_streak, last_checked_at);

PRAGMA foreign_keys = ON;

ALTER TABLE resources ADD COLUMN last_sync_attempt_at TEXT;
ALTER TABLE resources ADD COLUMN last_sync_error TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN geo_location TEXT NOT NULL DEFAULT '';

CREATE TABLE device_limit_requests (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  additional_devices INTEGER NOT NULL CHECK (additional_devices BETWEEN 1 AND 5),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewed_by TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX device_limit_requests_one_pending_member
  ON device_limit_requests(member_id) WHERE status = 'pending';
CREATE INDEX device_limit_requests_pending_time
  ON device_limit_requests(status, created_at);

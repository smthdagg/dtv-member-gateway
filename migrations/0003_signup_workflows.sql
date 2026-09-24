PRAGMA foreign_keys = ON;

ALTER TABLE members ADD COLUMN wechat_id TEXT NOT NULL DEFAULT '';
ALTER TABLE members ADD COLUMN member_number TEXT NOT NULL DEFAULT '';

CREATE TABLE signup_requests (
  id TEXT PRIMARY KEY,
  telegram_user_id TEXT NOT NULL,
  telegram_username TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL DEFAULT '',
  wechat_id TEXT NOT NULL DEFAULT '',
  member_number TEXT NOT NULL DEFAULT '',
  plan_id TEXT NOT NULL REFERENCES plans(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  member_id TEXT REFERENCES members(id) ON DELETE SET NULL,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewed_by TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX signup_requests_one_pending_user
  ON signup_requests(telegram_user_id) WHERE status = 'pending';
CREATE INDEX signup_requests_pending_time
  ON signup_requests(status, created_at);

CREATE TABLE signup_drafts (
  telegram_user_id TEXT PRIMARY KEY,
  telegram_username TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL DEFAULT '',
  step TEXT NOT NULL CHECK (step IN ('wechat_id', 'member_number', 'plan')),
  wechat_id TEXT NOT NULL DEFAULT '',
  member_number TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX renewal_requests_one_pending_member
  ON renewal_requests(member_id) WHERE status = 'pending';

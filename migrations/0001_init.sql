PRAGMA foreign_keys = ON;

CREATE TABLE plans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  duration_days INTEGER NOT NULL CHECK (duration_days > 0),
  default_max_devices INTEGER NOT NULL DEFAULT 1 CHECK (default_max_devices > 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE TABLE resources (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('url', 'tv', 'json', 'repository', 'stremio')),
  upstream_url TEXT NOT NULL,
  allowed_hosts TEXT NOT NULL DEFAULT '[]',
  delivery_mode TEXT NOT NULL DEFAULT 'proxy' CHECK (delivery_mode IN ('proxy', 'redirect')),
  rewrite_fields TEXT NOT NULL DEFAULT '[]',
  max_response_bytes INTEGER NOT NULL DEFAULT 2097152,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE plan_resources (
  plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  PRIMARY KEY (plan_id, resource_id)
);

CREATE TABLE members (
  id TEXT PRIMARY KEY,
  telegram_user_id TEXT NOT NULL UNIQUE,
  telegram_username TEXT,
  display_name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'paused', 'expired', 'revoked')),
  plan_id TEXT REFERENCES plans(id) ON DELETE SET NULL,
  expires_at TEXT,
  max_devices INTEGER NOT NULL DEFAULT 1 CHECK (max_devices > 0),
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE tokens (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  token_ciphertext TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  version INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX tokens_one_active_per_member ON tokens(member_id) WHERE revoked_at IS NULL;

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  signature_hash TEXT NOT NULL,
  trust_level TEXT NOT NULL DEFAULT 'weak' CHECK (trust_level IN ('trusted', 'limited', 'weak')),
  user_agent_hint TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  revoked_at TEXT,
  UNIQUE (member_id, signature_hash)
);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  change_summary TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_events_time ON audit_events(timestamp DESC);

CREATE TABLE usage_hourly (
  hour TEXT NOT NULL,
  member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  allowed_count INTEGER NOT NULL DEFAULT 0,
  denied_count INTEGER NOT NULL DEFAULT 0,
  last_seen TEXT NOT NULL,
  PRIMARY KEY (hour, member_id, resource_id)
);
CREATE INDEX usage_hourly_member_time ON usage_hourly(member_id, hour DESC);
CREATE INDEX usage_hourly_time ON usage_hourly(hour);

CREATE TABLE telegram_updates (
  update_id INTEGER PRIMARY KEY,
  received_at TEXT NOT NULL
);

CREATE TABLE telegram_confirmations (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  telegram_user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE renewal_requests (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  reviewed_at TEXT
);

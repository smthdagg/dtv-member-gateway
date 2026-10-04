CREATE TABLE catalog_repositories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'single' CHECK (kind IN ('single', 'multi', 'live')),
  source TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  last_checked_at TEXT,
  last_ok INTEGER NOT NULL DEFAULT 0 CHECK (last_ok IN (0, 1)),
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX catalog_repositories_kind_time ON catalog_repositories(kind, created_at DESC);

CREATE TABLE generated_artifacts (
  key TEXT PRIMARY KEY,
  content TEXT NOT NULL,
  generated_at TEXT NOT NULL
);
ALTER TABLE catalog_repositories ADD COLUMN last_expand_at TEXT;

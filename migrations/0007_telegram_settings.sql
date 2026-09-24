CREATE TABLE app_settings (
  setting_key TEXT PRIMARY KEY,
  plain_value TEXT,
  encrypted_value TEXT,
  updated_at TEXT NOT NULL,
  CHECK ((plain_value IS NOT NULL) != (encrypted_value IS NOT NULL))
);

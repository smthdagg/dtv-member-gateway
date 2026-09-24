-- Example catalog for two JSON feeds. Replace these example URLs in the admin UI
-- before syncing; no production source addresses are included in this repository.

INSERT INTO resources (
  id, slug, name, type, upstream_url, allowed_hosts, delivery_mode,
  rewrite_fields, max_response_bytes, enabled, created_at, updated_at
) VALUES (
  '44cc3f2c-31cc-4a72-8245-a274a2c46210',
  'lines',
  '多多线路',
  'json',
  'https://example.com/lines.json',
  '["example.com"]',
  'proxy',
  '["url","sourceUrl"]',
  2097152,
  1,
  datetime('now'),
  datetime('now')
)
ON CONFLICT(slug) DO UPDATE SET
  name = excluded.name,
  type = excluded.type,
  upstream_url = excluded.upstream_url,
  allowed_hosts = excluded.allowed_hosts,
  delivery_mode = excluded.delivery_mode,
  rewrite_fields = excluded.rewrite_fields,
  max_response_bytes = excluded.max_response_bytes,
  enabled = excluded.enabled,
  updated_at = datetime('now');

INSERT INTO resources (
  id, slug, name, type, upstream_url, allowed_hosts, delivery_mode,
  rewrite_fields, max_response_bytes, enabled, created_at, updated_at
) VALUES (
  '75e014c9-61f5-4566-8c35-e392b2ca64c9',
  'room',
  '多多资源仓',
  'json',
  'https://example.com/room.json',
  '["example.com"]',
  'proxy',
  '["url","sourceUrl"]',
  2097152,
  1,
  datetime('now'),
  datetime('now')
)
ON CONFLICT(slug) DO UPDATE SET
  name = excluded.name,
  type = excluded.type,
  upstream_url = excluded.upstream_url,
  allowed_hosts = excluded.allowed_hosts,
  delivery_mode = excluded.delivery_mode,
  rewrite_fields = excluded.rewrite_fields,
  max_response_bytes = excluded.max_response_bytes,
  enabled = excluded.enabled,
  updated_at = datetime('now');

INSERT INTO plans (id, name, duration_days, default_max_devices, enabled, created_at)
VALUES ('12d923af-7725-4cd5-a78f-440f8764e618', '标准会员（30天）', 30, 1, 1, datetime('now'))
ON CONFLICT(id) DO UPDATE SET
  name = excluded.name,
  duration_days = excluded.duration_days,
  default_max_devices = excluded.default_max_devices,
  enabled = excluded.enabled;

INSERT OR IGNORE INTO plan_resources (plan_id, resource_id)
SELECT '12d923af-7725-4cd5-a78f-440f8764e618', id FROM resources WHERE slug IN ('lines', 'room');

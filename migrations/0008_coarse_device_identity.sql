ALTER TABLE devices ADD COLUMN network_bucket TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN geo_region_key TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN browser_key TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN last_seen_day TEXT NOT NULL DEFAULT '';

CREATE INDEX devices_member_network_bucket
  ON devices(member_id, network_bucket, revoked_at);

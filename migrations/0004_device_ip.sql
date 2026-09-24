ALTER TABLE devices ADD COLUMN ip_address TEXT NOT NULL DEFAULT '';
ALTER TABLE telegram_confirmations ADD COLUMN target_id TEXT NOT NULL DEFAULT '';

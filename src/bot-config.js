import { b64url, decryptOpaque, encryptOpaque, nowIso } from "./security.js";

const CACHE_TTL_MS = 5_000;
const TOKEN_PATTERN = /^\d{6,16}:[A-Za-z0-9_-]{25,}$/u;
const WEBHOOK_SECRET_PATTERN = /^[A-Za-z0-9_-]{1,256}$/u;
const configCache = new WeakMap();

function parseAdminIds(value) {
  return [...new Set(String(value || "").split(/[\s,;]+/u).map((item) => item.trim()).filter((item) => /^\d{5,20}$/u.test(item)))];
}

async function readStoredSettings(env) {
  const result = await env.DB.prepare("SELECT setting_key, plain_value, encrypted_value FROM app_settings WHERE setting_key IN ('telegram_bot_token', 'telegram_admin_ids', 'telegram_webhook_secret', 'telegram_bot_username')").all();
  return new Map((result.results || []).map((row) => [row.setting_key, row]));
}

export async function getTelegramConfig(env, { force = false } = {}) {
  const db = env.DB;
  const cached = db && configCache.get(db);
  if (!force && cached && cached.expiresAt > Date.now()) return { ...cached.value, adminIds: [...cached.value.adminIds] };

  const stored = db ? await readStoredSettings(env) : new Map();
  const tokenRow = stored.get("telegram_bot_token");
  const idsRow = stored.get("telegram_admin_ids");
  const secretRow = stored.get("telegram_webhook_secret");
  const usernameRow = stored.get("telegram_bot_username");
  const botToken = tokenRow?.encrypted_value
    ? await decryptOpaque(tokenRow.encrypted_value, env.TOKEN_ENCRYPTION_KEY)
    : String(env.TELEGRAM_BOT_TOKEN || "");
  const webhookSecret = secretRow?.encrypted_value
    ? await decryptOpaque(secretRow.encrypted_value, env.TOKEN_ENCRYPTION_KEY)
    : String(env.TELEGRAM_WEBHOOK_SECRET || "");
  const adminIds = parseAdminIds(idsRow ? idsRow.plain_value : env.ADMIN_TELEGRAM_IDS);
  const value = {
    botToken,
    botConfigured: Boolean(botToken),
    botSource: tokenRow?.encrypted_value ? "database" : (botToken ? "cloudflare" : "missing"),
    adminIds,
    webhookSecret,
    webhookConfigured: Boolean(webhookSecret),
    botUsername: String(usernameRow?.plain_value || ""),
  };
  if (db) configCache.set(db, { value, expiresAt: Date.now() + CACHE_TTL_MS });
  return { ...value, adminIds: [...value.adminIds] };
}

function secretStatement(db, key, encryptedValue, timestamp) {
  return db.prepare("INSERT INTO app_settings (setting_key, plain_value, encrypted_value, updated_at) VALUES (?, NULL, ?, ?) ON CONFLICT(setting_key) DO UPDATE SET plain_value = NULL, encrypted_value = excluded.encrypted_value, updated_at = excluded.updated_at")
    .bind(key, encryptedValue, timestamp);
}

function plainStatement(db, key, plainValue, timestamp) {
  return db.prepare("INSERT INTO app_settings (setting_key, plain_value, encrypted_value, updated_at) VALUES (?, ?, NULL, ?) ON CONFLICT(setting_key) DO UPDATE SET plain_value = excluded.plain_value, encrypted_value = NULL, updated_at = excluded.updated_at")
    .bind(key, plainValue, timestamp);
}

async function verifyBotToken(token) {
  if (!TOKEN_PATTERN.test(token)) return { error: "BOT_TOKEN_INVALID" };
  try {
    const response = await fetch("https://api.telegram.org/bot" + token + "/getMe", { signal: AbortSignal.timeout(10_000) });
    const payload = await response.json().catch(() => null);
    if (!response.ok || payload?.ok !== true || !payload.result?.is_bot) return { error: "BOT_TOKEN_REJECTED" };
    return { user: payload.result };
  } catch {
    return { error: "BOT_TOKEN_VERIFY_FAILED" };
  }
}

export async function saveTelegramConfig(env, { botToken = "", adminIds = [] } = {}) {
  const current = await getTelegramConfig(env, { force: true });
  const candidate = String(botToken || "").trim();
  let resolvedToken = current.botToken;
  let botUsername = current.botUsername;
  let tokenUpdated = false;

  if (candidate) {
    const verified = await verifyBotToken(candidate);
    if (verified.error) return { error: verified.error };
    resolvedToken = candidate;
    botUsername = String(verified.user.username || "").slice(0, 64);
    tokenUpdated = candidate !== current.botToken;
  }
  if (!Array.isArray(adminIds) || !adminIds.length || adminIds.length > 30 || adminIds.some((id) => !/^\d{5,20}$/u.test(String(id)))) {
    return { error: "ADMIN_TELEGRAM_IDS_INVALID" };
  }

  let webhookSecret = current.webhookSecret;
  if (!webhookSecret) webhookSecret = b64url(crypto.getRandomValues(new Uint8Array(32)));
  if (!WEBHOOK_SECRET_PATTERN.test(webhookSecret)) return { error: "WEBHOOK_SECRET_INVALID" };

  const timestamp = nowIso();
  const statements = [plainStatement(env.DB, "telegram_admin_ids", [...new Set(adminIds.map(String))].join(","), timestamp)];
  try {
    if (resolvedToken) statements.push(secretStatement(env.DB, "telegram_bot_token", await encryptOpaque(resolvedToken, env.TOKEN_ENCRYPTION_KEY), timestamp));
    statements.push(secretStatement(env.DB, "telegram_webhook_secret", await encryptOpaque(webhookSecret, env.TOKEN_ENCRYPTION_KEY), timestamp));
  } catch {
    return { error: "BOT_ENCRYPTION_UNAVAILABLE" };
  }
  if (botUsername) statements.push(plainStatement(env.DB, "telegram_bot_username", botUsername, timestamp));

  try {
    await env.DB.batch(statements);
  } catch {
    return { error: "BOT_SETTINGS_SAVE_FAILED" };
  }
  configCache.delete(env.DB);
  return { ok: true, tokenUpdated, botUsername, tokenConfigured: Boolean(resolvedToken) };
}

export async function configureTelegramWebhook(env) {
  const config = await getTelegramConfig(env, { force: true });
  if (!config.botToken || !config.webhookSecret) return { error: "BOT_CONFIG_MISSING" };
  if (!WEBHOOK_SECRET_PATTERN.test(config.webhookSecret)) return { error: "WEBHOOK_SECRET_INVALID" };
  const baseUrl = String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "");
  const webhook = baseUrl + "/telegram/webhook";
  try {
    const result = await fetch("https://api.telegram.org/bot" + config.botToken + "/setWebhook", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: webhook, secret_token: config.webhookSecret, allowed_updates: ["message", "callback_query"] }),
      signal: AbortSignal.timeout(12_000),
    });
    const payload = await result.json().catch(() => null);
    if (!result.ok || payload?.ok !== true) return { error: "BOT_WEBHOOK_SETUP_FAILED" };
    return { ok: true, webhook, botUsername: config.botUsername };
  } catch {
    return { error: "BOT_WEBHOOK_SETUP_FAILED" };
  }
}

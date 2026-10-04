import {
  apiError, audit, clearSessionCookie, hasAdminSession, isSameOrigin, issueToken,
  json, makeSessionCookie, newId, nowIso, parseJsonList, parseJsonWithComments, readJson, safeEqual,
  setSessionCookie, sessionTtlSeconds,
} from "./security.js";
import { boundedText, syncJsonResource } from "./sync.js";
import { notifyDeviceLimitDecision, notifyMemberProvisioned, reviewRenewal, reviewSignup } from "./telegram.js";
import { configureTelegramWebhook, getTelegramConfig, saveTelegramConfig } from "./bot-config.js";

const MEMBER_STATUSES = new Set(["pending", "active", "paused", "expired", "revoked"]);
const RESOURCE_TYPES = new Set(["url", "tv", "json", "repository", "stremio"]);
const LOG_RETENTION_OPTIONS = new Set([30, 60, 90]);
const RESERVED_SLUGS = new Set(["tvbox", "all", "catalog", "admin", "telegram", "healthz", "status", "app.js", "style.css", "logo.png", "favicon.ico"]);
const CATALOG_KINDS = new Set(["single", "multi", "live"]);

async function logRetentionDays(db, env) {
  const row = await db.prepare("SELECT plain_value FROM app_settings WHERE setting_key = 'log_retention_days'").first();
  const configured = Number(row?.plain_value || env.USAGE_RETENTION_DAYS || 90);
  return LOG_RETENTION_OPTIONS.has(configured) ? configured : 90;
}

async function logCounts(db) {
  const [access, auditRows, telegramUpdates] = await Promise.all([
    db.prepare("SELECT COUNT(*) AS count FROM usage_hourly").first(),
    db.prepare("SELECT COUNT(*) AS count FROM audit_events").first(),
    db.prepare("SELECT COUNT(*) AS count FROM telegram_updates").first(),
  ]);
  return { access_rows: Number(access?.count || 0), audit_rows: Number(auditRows?.count || 0), telegram_update_rows: Number(telegramUpdates?.count || 0) };
}

function validId(value) {
  return typeof value === "string" && /^[0-9a-f-]{20,40}$/iu.test(value);
}

function safeHostname(host) {
  const value = String(host || "").trim().toLowerCase().replace(/\.$/u, "");
  if (!value || value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local")) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value) || value.includes(":")) return false;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(value);
}

function resourceInput(body) {
  const slug = String(body.slug || "").trim().toLowerCase();
  const type = String(body.type || "");
  const upstreamUrl = String(body.upstream_url || "").trim();
  const allowedHosts = [...new Set((Array.isArray(body.allowed_hosts) ? body.allowed_hosts : String(body.allowed_hosts || "").split(","))
    .map((host) => String(host).trim().toLowerCase().replace(/\.$/u, "")).filter(Boolean))];
  const rewriteFields = [...new Set((Array.isArray(body.rewrite_fields) ? body.rewrite_fields : String(body.rewrite_fields || "").split(","))
    .map((field) => String(field).trim()).filter((field) => /^[A-Za-z][A-Za-z0-9_-]{0,39}$/u.test(field)))];
  let upstream;
  try { upstream = new URL(upstreamUrl); } catch { return { error: "UPSTREAM_NOT_APPROVED" }; }
  if (!/^[a-z0-9][a-z0-9._-]{1,39}$/u.test(slug) || slug.includes("..")) return { error: "SLUG_INVALID" };
  if (RESERVED_SLUGS.has(slug)) return { error: "SLUG_RESERVED" };
  if (!RESOURCE_TYPES.has(type)) return { error: "RESOURCE_TYPE_INVALID" };
  if (upstream.protocol !== "https:" || upstream.username || upstream.password || !safeHostname(upstream.hostname) || !allowedHosts.includes(upstream.hostname.toLowerCase()) || !allowedHosts.every(safeHostname)) {
    return { error: "UPSTREAM_NOT_APPROVED" };
  }
  const requestedBytes = Number(body.max_response_bytes || 2_097_152);
  if (!Number.isFinite(requestedBytes)) return { error: "RESPONSE_SIZE_INVALID" };
  return {
    slug, type, upstreamUrl, allowedHosts, rewriteFields,
    mode: type === "json" ? "proxy" : (body.delivery_mode === "redirect" ? "redirect" : "proxy"),
    maxBytes: Math.min(10_485_760, Math.max(1_024, requestedBytes)),
    enabled: body.enabled === false || body.enabled === 0 ? 0 : 1,
    name: String(body.name || slug).trim().slice(0, 80),
    autoSync: body.auto_sync === undefined ? null : (body.auto_sync ? 1 : 0),
    syncIntervalMinutes: Math.max(15, Math.min(10_080, Number(body.sync_interval_minutes || 360) || 360)),
  };
}

function expiryFromInput(value) {
  if (value === null || value === "") return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

async function createMember(db, env, body) {
  const telegramId = String(body.telegram_user_id || "").trim();
  if (!/^\d{5,20}$/u.test(telegramId)) return apiError("TELEGRAM_ID_INVALID", 400);
  const plan = await db.prepare("SELECT id, duration_days, default_max_devices, enabled FROM plans WHERE id = ?").bind(String(body.plan_id || "")).first();
  if (!plan || !plan.enabled) return apiError("PLAN_NOT_FOUND", 400);
  const id = newId();
  const tokenId = newId();
  const issued = await issueToken(env);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + plan.duration_days * 86400000).toISOString();
  const status = MEMBER_STATUSES.has(body.status) ? body.status : "active";
  const maxDevices = Math.max(1, Math.min(50, Number(body.max_devices || plan.default_max_devices)));
  try {
    await db.batch([
      db.prepare("INSERT INTO members (id, telegram_user_id, telegram_username, display_name, wechat_id, member_number, status, plan_id, expires_at, max_devices, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id, telegramId, String(body.telegram_username || "").slice(0, 64), String(body.display_name || "").slice(0, 120), String(body.wechat_id || "").slice(0, 100), String(body.member_number || "").slice(0, 100), status, plan.id, expiresAt, maxDevices, String(body.notes || "").slice(0, 500), now.toISOString(), now.toISOString()),
      db.prepare("INSERT INTO tokens (id, member_id, token_hash, token_ciphertext, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(tokenId, id, issued.tokenHash, issued.tokenCiphertext, now.toISOString()),
    ]);
  } catch {
    return apiError("MEMBER_CREATE_FAILED", 409, "Member could not be created");
  }
  await audit(db, "admin", "member.create", "member", id, "plan=" + plan.id + "; status=" + status);
  const botNotified = status === "active" ? await notifyMemberProvisioned(env, db, telegramId, "管理员已为你开通会员") : false;
  return json({ member: { id, telegram_user_id: telegramId, status, plan_id: plan.id, expires_at: expiresAt, max_devices: maxDevices }, token: issued.raw, bot_notified: botNotified }, 201, { "cache-control": "no-store" });
}

async function rotateToken(db, env, memberId) {
  const member = await db.prepare("SELECT id, telegram_user_id, status, expires_at FROM members WHERE id = ?").bind(memberId).first();
  if (!member) return apiError("MEMBER_NOT_FOUND", 404);
  const issued = await issueToken(env);
  const now = nowIso();
  await db.batch([
    db.prepare("UPDATE tokens SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL").bind(now, memberId),
    db.prepare("INSERT INTO tokens (id, member_id, token_hash, token_ciphertext, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(newId(), memberId, issued.tokenHash, issued.tokenCiphertext, now),
  ]);
  await audit(db, "admin", "token.rotate", "member", memberId, "active token rotated; previous links invalidated");
  const botNotified = member.status === "active" && Date.parse(member.expires_at || "") > Date.now()
    ? await notifyMemberProvisioned(env, db, member.telegram_user_id, "管理员已重置你的订阅地址")
    : false;
  return json({ token: issued.raw, bot_notified: botNotified, warning: "Previous subscription addresses are now invalid." }, 200, { "cache-control": "no-store" });
}

async function reviewDeviceLimitRequest(db, env, requestId, status, actorId, note = "") {
  if (!["approved", "rejected"].includes(status)) return { error: "DEVICE_LIMIT_STATUS_INVALID" };
  const request = await db.prepare("SELECT r.id, r.member_id, r.additional_devices, m.telegram_user_id, m.display_name, m.max_devices FROM device_limit_requests r JOIN members m ON m.id = r.member_id WHERE r.id = ? AND r.status = 'pending'")
    .bind(requestId).first();
  if (!request) return { error: "DEVICE_LIMIT_NOT_PENDING" };
  const reviewedAt = nowIso();
  if (status === "approved") {
    const results = await db.batch([
      db.prepare("UPDATE device_limit_requests SET status = 'approved', note = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending' AND EXISTS (SELECT 1 FROM members m WHERE m.id = device_limit_requests.member_id AND m.max_devices + device_limit_requests.additional_devices <= 50)")
        .bind(String(note).slice(0, 300), reviewedAt, actorId, requestId),
      db.prepare("UPDATE members SET max_devices = max_devices + (SELECT additional_devices FROM device_limit_requests WHERE id = ? AND status = 'approved' AND reviewed_at = ?), updated_at = ? WHERE id = (SELECT member_id FROM device_limit_requests WHERE id = ? AND status = 'approved' AND reviewed_at = ?) AND max_devices + (SELECT additional_devices FROM device_limit_requests WHERE id = ? AND status = 'approved' AND reviewed_at = ?) <= 50")
        .bind(requestId, reviewedAt, reviewedAt, requestId, reviewedAt, requestId, reviewedAt),
    ]);
    if (Number(results?.[0]?.meta?.changes || 0) !== 1) {
      const current = await db.prepare("SELECT r.status, m.max_devices FROM device_limit_requests r JOIN members m ON m.id = r.member_id WHERE r.id = ?").bind(requestId).first();
      return current?.status === "pending" && Number(current.max_devices) + Number(request.additional_devices) > 50
        ? { error: "DEVICE_LIMIT_CAP_REACHED" }
        : { error: "DEVICE_LIMIT_NOT_PENDING" };
    }
  } else {
    const result = await db.prepare("UPDATE device_limit_requests SET status = 'rejected', note = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending'")
      .bind(String(note).slice(0, 300), reviewedAt, actorId, requestId).run();
    if (Number(result?.meta?.changes || 0) !== 1) return { error: "DEVICE_LIMIT_NOT_PENDING" };
  }
  const member = await db.prepare("SELECT max_devices FROM members WHERE id = ?").bind(request.member_id).first();
  await audit(db, actorId, "device_limit." + status, "member", request.member_id, "request=" + requestId + "; additional=" + request.additional_devices);
  await notifyDeviceLimitDecision(env, request.telegram_user_id, status, Number(member?.max_devices || request.max_devices), Number(request.additional_devices));
  return { id: requestId, status, max_devices: Number(member?.max_devices || request.max_devices) };
}

async function savePlan(db, body, planId = null) {
  const name = String(body.name || "").trim().slice(0, 80);
  const days = Math.max(1, Math.min(3650, Number(body.duration_days || 0)));
  const devices = Math.max(1, Math.min(50, Number(body.default_max_devices || 1)));
  const resources = Array.isArray(body.resource_ids) ? [...new Set(body.resource_ids.map(String))] : [];
  if (!name || !Number.isFinite(days)) return apiError("PLAN_INVALID", 400);
  const id = planId || newId();
  const statements = [];
  if (planId) {
    statements.push(db.prepare("UPDATE plans SET name = ?, duration_days = ?, default_max_devices = ?, enabled = ? WHERE id = ?")
      .bind(name, days, devices, body.enabled === false ? 0 : 1, id));
    statements.push(db.prepare("DELETE FROM plan_resources WHERE plan_id = ?").bind(id));
  } else {
    statements.push(db.prepare("INSERT INTO plans (id, name, duration_days, default_max_devices, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(id, name, days, devices, body.enabled === false ? 0 : 1, nowIso()));
  }
  for (const resourceId of resources) statements.push(db.prepare("INSERT INTO plan_resources (plan_id, resource_id) VALUES (?, ?)").bind(id, resourceId));
  try { await db.batch(statements); } catch { return apiError("PLAN_SAVE_FAILED", 400); }
  await audit(db, "admin", planId ? "plan.update" : "plan.create", "plan", id, "resources=" + resources.length);
  return json({ id, name, duration_days: days, default_max_devices: devices, resource_ids: resources }, planId ? 200 : 201);
}

async function saveResource(db, body, resourceId = null) {
  const value = resourceInput(body);
  if (value.error) return apiError(value.error, 400);
  const previous = resourceId
    ? await db.prepare("SELECT * FROM resources WHERE id = ?").bind(resourceId).first()
    : null;
  const resetSyncStatus = Boolean(previous && (
    previous.upstream_url !== value.upstreamUrl ||
    previous.allowed_hosts !== JSON.stringify(value.allowedHosts) ||
    previous.type !== value.type ||
    Number(previous.max_response_bytes) !== value.maxBytes
  ));
  const autoSync = value.autoSync === null
    ? (Number(previous?.auto_sync ?? 1) ? 1 : 0)
    : value.autoSync;
  const syncInterval = value.syncIntervalMinutes;
  const id = resourceId || newId();
  const now = nowIso();
  const args = [value.slug, value.name, value.type, value.upstreamUrl, JSON.stringify(value.allowedHosts), value.mode,
    JSON.stringify(value.rewriteFields), value.maxBytes, value.enabled, autoSync, syncInterval, now];
  try {
    if (resourceId) {
      const result = await db.prepare("UPDATE resources SET slug = ?, name = ?, type = ?, upstream_url = ?, allowed_hosts = ?, delivery_mode = ?, rewrite_fields = ?, max_response_bytes = ?, enabled = ?, auto_sync = ?, sync_interval_minutes = ?, updated_at = ?, last_sync_attempt_at = CASE WHEN ? = 1 THEN NULL ELSE last_sync_attempt_at END, last_sync_error = CASE WHEN ? = 1 THEN '' ELSE last_sync_error END WHERE id = ?")
        .bind(...args, resetSyncStatus ? 1 : 0, resetSyncStatus ? 1 : 0, id).run();
      if (!result.meta.changes) return apiError("RESOURCE_NOT_FOUND", 404);
    } else {
      await db.prepare("INSERT INTO resources (id, slug, name, type, upstream_url, allowed_hosts, delivery_mode, rewrite_fields, max_response_bytes, enabled, auto_sync, sync_interval_minutes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id, value.slug, value.name, value.type, value.upstreamUrl, JSON.stringify(value.allowedHosts), value.mode, JSON.stringify(value.rewriteFields), value.maxBytes, value.enabled, autoSync, syncInterval, now, now).run();
    }
  } catch {
    return apiError("RESOURCE_SAVE_FAILED", 409);
  }
  if (resetSyncStatus) {
    await db.prepare("DELETE FROM resource_snapshots WHERE resource_id = ?").bind(id).run();
  }
  await audit(db, "admin", resourceId ? "resource.update" : "resource.create", "resource", id, "slug=" + value.slug + "; enabled=" + value.enabled + "; auto_sync=" + autoSync);
  return json({ id, slug: value.slug, name: value.name }, resourceId ? 200 : 201);
}

export async function adminApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/u, "") || "/";
  const method = request.method;

  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && !isSameOrigin(request)) return apiError("ORIGIN_REQUIRED", 403);

  if (path === "/admin/api/login" && method === "POST") {
    const body = await readJson(request, 4096);
    if (!body || typeof body.password !== "string") return apiError("INVALID_REQUEST", 400);
    if (!env.ADMIN_PASSWORD || !safeEqual(body.password, env.ADMIN_PASSWORD)) return apiError("LOGIN_FAILED", 401);
    return json({ ok: true }, 200, { "set-cookie": setSessionCookie(await makeSessionCookie(env), sessionTtlSeconds(env)), "cache-control": "no-store" });
  }
  if (path === "/admin/api/logout" && method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": clearSessionCookie(), "cache-control": "no-store" });
  }
  if (path === "/admin/api/me" && method === "GET") {
    return json({ authenticated: await hasAdminSession(request, env) }, 200, { "cache-control": "no-store" });
  }

  if (!await hasAdminSession(request, env)) return apiError("ADMIN_AUTH_REQUIRED", 401, "管理员登录已失效，请重新登录");

  if (path === "/admin/api/settings/telegram" && method === "GET") {
    const config = await getTelegramConfig(env, { force: true });
    return json({
      bot_token_configured: config.botConfigured,
      bot_token_source: config.botSource,
      bot_username: config.botUsername,
      admin_telegram_ids: config.adminIds.join("\n"),
      webhook_secret_configured: config.webhookConfigured,
    }, 200, { "cache-control": "no-store" });
  }
  if (path === "/admin/api/settings/telegram" && method === "PUT") {
    const body = await readJson(request, 8192);
    if (!body || typeof body.admin_telegram_ids !== "string" || typeof body.bot_token !== "string") return apiError("BOT_SETTINGS_INVALID", 400);
    const adminIds = [...new Set(body.admin_telegram_ids.split(/[\s,;]+/u).map((value) => value.trim()).filter(Boolean))];
    const result = await saveTelegramConfig(env, { botToken: body.bot_token.trim(), adminIds });
    if (result.error) {
      const status = result.error === "BOT_TOKEN_VERIFY_FAILED" ? 502
        : result.error === "BOT_ENCRYPTION_UNAVAILABLE" || result.error === "BOT_SETTINGS_SAVE_FAILED" ? 500 : 400;
      return apiError(result.error, status);
    }
    const webhook = result.tokenConfigured ? await configureTelegramWebhook(env) : { error: "BOT_CONFIG_MISSING" };
    await audit(env.DB, "admin", "telegram.settings.update", "bot", "telegram", "admin_count=" + adminIds.length + "; token_updated=" + (result.tokenUpdated ? "yes" : "no"));
    return json({
      ok: true,
      bot_token_configured: result.tokenConfigured,
      bot_username: result.botUsername,
      webhook_configured: webhook.ok === true,
      webhook_error: webhook.error || "",
    });
  }
  if (path === "/admin/api/settings/logs" && method === "GET") {
    const [retentionDays, counts] = await Promise.all([logRetentionDays(env.DB, env), logCounts(env.DB)]);
    return json({ retention_days: retentionDays, ...counts }, 200, { "cache-control": "no-store" });
  }
  if (path === "/admin/api/settings/logs" && method === "PUT") {
    const body = await readJson(request, 4096);
    const retentionDays = Number(body?.retention_days);
    if (!LOG_RETENTION_OPTIONS.has(retentionDays)) return apiError("LOG_RETENTION_INVALID", 400);
    await env.DB.prepare("INSERT INTO app_settings (setting_key, plain_value, encrypted_value, updated_at) VALUES ('log_retention_days', ?, NULL, ?) ON CONFLICT(setting_key) DO UPDATE SET plain_value = excluded.plain_value, encrypted_value = NULL, updated_at = excluded.updated_at")
      .bind(String(retentionDays), nowIso()).run();
    return json({ ok: true, retention_days: retentionDays });
  }
  if (path === "/admin/api/logs/cleanup" && method === "POST") {
    const retentionDays = await logRetentionDays(env.DB, env);
    const cutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
    const results = await env.DB.batch([
      env.DB.prepare("DELETE FROM usage_hourly WHERE hour < ?").bind(cutoff.slice(0, 13)),
      env.DB.prepare("DELETE FROM audit_events WHERE timestamp < ?").bind(cutoff),
      env.DB.prepare("DELETE FROM telegram_updates WHERE received_at < ?").bind(cutoff),
    ]);
    return json({ ok: true, retention_days: retentionDays, deleted_access_rows: Number(results[0]?.meta?.changes || 0), deleted_audit_rows: Number(results[1]?.meta?.changes || 0), deleted_telegram_update_rows: Number(results[2]?.meta?.changes || 0), ...(await logCounts(env.DB)) });
  }
  if (path === "/admin/api/logs" && method === "DELETE") {
    const results = await env.DB.batch([
      env.DB.prepare("DELETE FROM usage_hourly"),
      env.DB.prepare("DELETE FROM audit_events"),
      env.DB.prepare("DELETE FROM telegram_updates"),
    ]);
    return json({ ok: true, deleted_access_rows: Number(results[0]?.meta?.changes || 0), deleted_audit_rows: Number(results[1]?.meta?.changes || 0), deleted_telegram_update_rows: Number(results[2]?.meta?.changes || 0), ...(await logCounts(env.DB)) });
  }

  if (path === "/admin/api/overview" && method === "GET") {
    const [usage, totals, applications, deviceRequests] = await Promise.all([
      env.DB.prepare("SELECT COALESCE(SUM(allowed_count), 0) AS allowed, COALESCE(SUM(denied_count), 0) AS denied FROM usage_hourly WHERE hour >= strftime('%Y-%m-%dT%H', 'now', '-24 hours')").first(),
      env.DB.prepare("SELECT SUM(CASE WHEN status = 'active' AND expires_at > ? THEN 1 ELSE 0 END) AS active, SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending, SUM(CASE WHEN status = 'paused' THEN 1 ELSE 0 END) AS paused, SUM(CASE WHEN status = 'expired' OR (status = 'active' AND (expires_at IS NULL OR expires_at <= ?)) THEN 1 ELSE 0 END) AS expired FROM members")
        .bind(nowIso(), nowIso()).first(),
      env.DB.prepare("SELECT COUNT(*) AS pending FROM signup_requests WHERE status = 'pending'").first(),
      env.DB.prepare("SELECT COUNT(*) AS pending FROM device_limit_requests WHERE status = 'pending'").first(),
    ]);
    return json({ members: totals || {}, applications: applications || { pending: 0 }, device_limit_requests: deviceRequests || { pending: 0 }, requests: usage || { allowed: 0, denied: 0 } });
  }
  if (path === "/admin/api/bot/configure" && method === "POST") {
    const result = await configureTelegramWebhook(env);
    if (result.error) return apiError(result.error, result.error === "BOT_CONFIG_MISSING" ? 409 : 502);
    await audit(env.DB, "admin", "telegram.webhook.configure", "bot", "telegram", "webhook configured");
    return json({ ok: true, webhook: result.webhook });
  }

  if (path === "/admin/api/plans" && method === "GET") {
    const result = await env.DB.prepare("SELECT p.*, COALESCE(json_group_array(pr.resource_id) FILTER (WHERE pr.resource_id IS NOT NULL), '[]') AS resource_ids FROM plans p LEFT JOIN plan_resources pr ON pr.plan_id = p.id GROUP BY p.id ORDER BY p.created_at DESC").all();
    return json((result.results || []).map((row) => ({ ...row, resource_ids: parseJsonList(row.resource_ids) })));
  }
  if (path === "/admin/api/plans" && method === "POST") {
    const body = await readJson(request);
    return body ? savePlan(env.DB, body) : apiError("INVALID_REQUEST", 400);
  }
  const planPath = path.split("/");
  if (planPath.length === 5 && planPath[1] === "admin" && planPath[2] === "api" && planPath[3] === "plans" && method === "PUT") {
    const body = await readJson(request);
    return body ? savePlan(env.DB, body, planPath[4]) : apiError("INVALID_REQUEST", 400);
  }

  if (path === "/admin/api/resources/batch" && method === "POST") {
    const body = await readJson(request, 131_072);
    const lines = String(body?.text || "").split(/\r?\n/u).map((line) => line.trim()).filter(Boolean).slice(0, 30);
    if (!lines.length) return apiError("INVALID_REQUEST", 400, "每行一条上游地址，支持 名称|地址 格式");
    const resourceType = body?.type === "tv" ? "tv" : "json";
    const results = [];
    for (const line of lines) {
      let name = "";
      let urlText = line;
      const separator = line.indexOf("|");
      if (separator >= 0) { name = line.slice(0, separator).trim(); urlText = line.slice(separator + 1).trim(); }
      let upstream;
      try { upstream = new URL(urlText); } catch { results.push({ url: urlText, ok: false, error: "URL_INVALID" }); continue; }
      if (upstream.protocol !== "https:") { results.push({ url: urlText, ok: false, error: "HTTPS_REQUIRED" }); continue; }
      const hostBase = (upstream.hostname.split(".").filter(Boolean)[0] || "src").replace(/[^a-z0-9-]/giu, "").toLowerCase().slice(0, 24) || "src";
      let slug = "";
      for (let attempt = 0; attempt < 5 && !slug; attempt++) {
        const candidate = hostBase + "-" + Math.random().toString(36).slice(2, 6);
        const exists = await env.DB.prepare("SELECT 1 AS present FROM resources WHERE slug = ?").bind(candidate).first();
        if (!exists) slug = candidate;
      }
      if (!slug) { results.push({ url: urlText, ok: false, error: "SLUG_EXHAUSTED" }); continue; }
      const response = await saveResource(env.DB, {
        slug,
        name: name || upstream.hostname,
        type: resourceType,
        upstream_url: upstream.href,
        allowed_hosts: [upstream.hostname],
        max_response_bytes: 3_145_728,
        auto_sync: body?.auto_sync === 0 ? 0 : 1,
        sync_interval_minutes: Number(body?.sync_interval_minutes || 360),
      });
      const saved = await response.json();
      if (!response.ok) { results.push({ url: urlText, ok: false, error: saved?.error?.code || "SAVE_FAILED" }); continue; }
      let sync = null;
      if (resourceType === "json") {
        sync = await syncJsonResource(env.DB, env, {
          id: saved.id, slug: saved.slug, name: saved.name, type: "json",
          upstream_url: upstream.href, allowed_hosts: JSON.stringify([upstream.hostname]),
          rewrite_fields: "[]", max_response_bytes: 3_145_728,
        });
      }
      results.push({ url: urlText, slug: saved.slug, ok: true, sync_ok: sync ? sync.ok : null, sync_error: sync && !sync.ok ? (sync.error_detail || sync.error || "") : "" });
    }
    return json({ created: results.filter((row) => row.ok).length, failed: results.filter((row) => !row.ok).length, results });
  }
  if (path === "/admin/api/sync/log" && method === "GET") {
    const result = await env.DB.prepare("SELECT l.id, l.resource_id, r.slug, r.name AS resource_name, l.started_at, l.ok, l.error, l.url_count, l.duration_ms FROM resource_sync_log l LEFT JOIN resources r ON r.id = l.resource_id ORDER BY l.started_at DESC LIMIT 100").all();
    return json(result.results || []);
  }

  if (path === "/admin/api/catalog" && method === "GET") {
    const result = await env.DB.prepare("SELECT id, name, url, kind, source, enabled, last_checked_at, last_ok, last_error, created_at FROM catalog_repositories ORDER BY created_at DESC LIMIT 500").all();
    return json(result.results || []);
  }
  if (path === "/admin/api/catalog/import" && method === "POST") {
    const body = await readJson(request, 131_072);
    const kind = CATALOG_KINDS.has(body?.kind) ? body.kind : "single";
    const source = String(body?.source || "manual").slice(0, 60);
    const lines = String(body?.text || "").split(/\r?\n/u).map((line) => line.trim()).filter(Boolean).slice(0, 300);
    if (!lines.length) return apiError("INVALID_REQUEST", 400, "每行一条地址，支持 名称|地址 格式");
    let inserted = 0; let duplicate = 0; let invalid = 0;
    const now = nowIso();
    for (const line of lines) {
      const separator = line.indexOf("|");
      const name = separator > 0 ? line.slice(0, separator).trim().slice(0, 80) : "";
      const urlText = (separator >= 0 ? line.slice(separator + 1) : line).trim();
      let upstream;
      try { upstream = new URL(urlText); } catch { invalid++; continue; }
      if (upstream.protocol !== "https:" && upstream.protocol !== "http:") { invalid++; continue; }
      if (!safeHostname(upstream.hostname)) { invalid++; continue; }
      const result = await env.DB.prepare("INSERT INTO catalog_repositories (id, name, url, kind, source, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?) ON CONFLICT(url) DO NOTHING")
        .bind(newId(), name, upstream.href, kind, source, now).run();
      if (Number(result.meta.changes || 0) > 0) inserted++;
      else duplicate++;
    }
    await audit(env.DB, "admin", "catalog.import", "catalog", source, "inserted=" + inserted + "; duplicate=" + duplicate + "; invalid=" + invalid);
    return json({ inserted, duplicate, invalid });
  }
  if (path === "/admin/api/catalog/validate" && method === "POST") {
    const rows = await env.DB.prepare("SELECT id, url, kind FROM catalog_repositories WHERE enabled = 1 AND (last_checked_at IS NULL OR last_checked_at < datetime('now', '-60 minutes')) ORDER BY last_checked_at ASC LIMIT 40").all();
    const statements = [];
    for (const row of rows.results || []) {
      let ok = 0;
      let detail = "";
      try {
        const response = await fetch(row.url, { method: "GET", redirect: "follow", headers: { "user-agent": "DTV-Member-Gateway/1.0" }, signal: AbortSignal.timeout(12_000) });
        if (response.ok) {
          const text = await boundedText(response, 262_144);
          if (text === null) detail = "响应过大";
          else if (row.kind === "live") {
            if (/#EXTM3U/u.test(text)) ok = 1;
            else detail = "不是有效的 M3U";
          } else {
            try { parseJsonWithComments(text); ok = 1; } catch { detail = "不是有效 JSON"; }
          }
        } else detail = "HTTP " + response.status;
        try { await response.body?.cancel(); } catch {}
      } catch (err) {
        detail = String(err?.name || "FETCH_FAILED");
      }
      statements.push(env.DB.prepare("UPDATE catalog_repositories SET last_checked_at = ?, last_ok = ?, last_error = ? WHERE id = ?").bind(nowIso(), ok, detail.slice(0, 200), row.id));
    }
    if (statements.length) await env.DB.batch(statements);
    return json({ checked: statements.length });
  }
  const catalogItemMatch = path.match(/^\/admin\/api\/catalog\/([0-9a-f-]{20,40})$/iu);
  if (catalogItemMatch && method === "POST") {
    const body = await readJson(request, 4096);
    const result = await env.DB.prepare("UPDATE catalog_repositories SET enabled = ? WHERE id = ?").bind(body?.enabled ? 1 : 0, catalogItemMatch[1]).run();
    if (!result.meta.changes) return apiError("CATALOG_NOT_FOUND", 404);
    return json({ id: catalogItemMatch[1], enabled: body?.enabled ? 1 : 0 });
  }
  if (catalogItemMatch && method === "DELETE") {
    const result = await env.DB.prepare("DELETE FROM catalog_repositories WHERE id = ?").bind(catalogItemMatch[1]).run();
    if (!result.meta.changes) return apiError("CATALOG_NOT_FOUND", 404);
    return json({ removed: true });
  }
  if (path === "/admin/api/resources/sync" && method === "POST") {
    const result = await env.DB.prepare("SELECT id, slug, name, type, upstream_url, allowed_hosts, rewrite_fields, max_response_bytes, content_hash FROM resources WHERE type = 'json' AND enabled = 1 ORDER BY name LIMIT 10").all();
    const resources = result.results || [];
    const rows = await Promise.all(resources.map((resource) => syncJsonResource(env.DB, env, resource)));
    return json({ synced: rows.filter((row) => row.ok).length, failed: rows.filter((row) => !row.ok).length, results: rows });
  }
  const resourceSyncMatch = path.match(/^\/admin\/api\/resources\/([0-9a-f-]{20,40})\/sync$/iu);
  if (resourceSyncMatch && method === "POST") {
    const resource = await env.DB.prepare("SELECT id, slug, name, type, upstream_url, allowed_hosts, rewrite_fields, max_response_bytes, content_hash FROM resources WHERE id = ?")
      .bind(resourceSyncMatch[1]).first();
    if (!resource) return apiError("RESOURCE_NOT_FOUND", 404);
    const result = await syncJsonResource(env.DB, env, resource);
    return result.ok ? json(result) : json({ error: { code: result.error, message: result.error_detail || result.error } }, 502, { "cache-control": "no-store" });
  }
  if (path === "/admin/api/resources" && method === "GET") {
    const result = await env.DB.prepare("SELECT r.*, COALESCE(json_group_array(pr.plan_id) FILTER (WHERE pr.plan_id IS NOT NULL), '[]') AS plan_ids, s.synced_at AS snapshot_synced_at, s.url_count AS snapshot_url_count, s.blocked_url_count AS snapshot_blocked_url_count, s.top_level_keys AS snapshot_top_level_keys FROM resources r LEFT JOIN plan_resources pr ON pr.resource_id = r.id LEFT JOIN resource_snapshots s ON s.resource_id = r.id GROUP BY r.id ORDER BY r.created_at DESC").all();
    return json((result.results || []).map((row) => ({ ...row, allowed_hosts: parseJsonList(row.allowed_hosts), rewrite_fields: parseJsonList(row.rewrite_fields), plan_ids: parseJsonList(row.plan_ids), snapshot_top_level_keys: parseJsonList(row.snapshot_top_level_keys) })));
  }
  if (path === "/admin/api/resources" && method === "POST") {
    const body = await readJson(request);
    return body ? saveResource(env.DB, body) : apiError("INVALID_REQUEST", 400);
  }
  if (planPath.length === 5 && planPath[1] === "admin" && planPath[2] === "api" && planPath[3] === "resources" && method === "PUT") {
    const body = await readJson(request);
    return body ? saveResource(env.DB, body, planPath[4]) : apiError("INVALID_REQUEST", 400);
  }

  if (path === "/admin/api/applications" && method === "GET") {
    const result = await env.DB.prepare("SELECT s.id, s.telegram_user_id, s.telegram_username, s.display_name, s.wechat_id, s.member_number, s.plan_id, p.name AS plan_name, p.duration_days, s.created_at FROM signup_requests s JOIN plans p ON p.id = s.plan_id WHERE s.status = 'pending' ORDER BY s.created_at ASC LIMIT 200").all();
    return json(result.results || []);
  }
  if (path === "/admin/api/applications/batch" && method === "POST") {
    const body = await readJson(request, 32_768);
    const ids = Array.isArray(body?.ids) ? [...new Set(body.ids.map(String))] : [];
    const status = String(body?.status || "");
    if (!ids.length || ids.length > 50 || !["approved", "rejected"].includes(status) || ids.some((id) => !validId(id))) return apiError("APPLICATION_BATCH_INVALID", 400);
    const results = [];
    for (const id of ids) {
      const result = await reviewSignup(env.DB, env, id, status, "admin", String(body.note || "").slice(0, 300));
      results.push({ id, ok: !result.error, error: result.error || "" });
    }
    return json({ processed: results.filter((row) => row.ok).length, failed: results.filter((row) => !row.ok).length, results });
  }
  const applicationMatch = path.match(/^\/admin\/api\/applications\/([0-9a-f-]{20,40})$/iu);
  if (applicationMatch && method === "POST") {
    const body = await readJson(request);
    if (!body || !["approved", "rejected"].includes(body.status)) return apiError("SIGNUP_STATUS_INVALID", 400);
    const result = await reviewSignup(env.DB, env, applicationMatch[1], body.status, "admin", String(body.note || "").slice(0, 300));
    if (result.error) return apiError(result.error, result.error === "SIGNUP_NOT_PENDING" ? 404 : 409);
    return json(result);
  }

  if (path === "/admin/api/members" && method === "GET") {
    const q = (url.searchParams.get("q") || "").trim().slice(0, 80);
    const like = "%" + q.replace(/[\\%_]/gu, "\\$&") + "%";
    const result = await env.DB.prepare("SELECT m.id, m.telegram_user_id, m.telegram_username, m.display_name, m.wechat_id, m.member_number, m.status, m.plan_id, p.name AS plan_name, m.expires_at, m.max_devices, (SELECT COUNT(*) FROM devices d WHERE d.member_id = m.id AND d.revoked_at IS NULL) AS active_devices, m.notes, m.created_at, substr(t.token_hash, -8) AS token_suffix FROM members m LEFT JOIN plans p ON p.id = m.plan_id LEFT JOIN tokens t ON t.member_id = m.id AND t.revoked_at IS NULL WHERE (? = '%%' OR m.telegram_user_id LIKE ? ESCAPE '\\' OR m.display_name LIKE ? ESCAPE '\\' OR m.telegram_username LIKE ? ESCAPE '\\' OR m.wechat_id LIKE ? ESCAPE '\\' OR m.member_number LIKE ? ESCAPE '\\' OR substr(t.token_hash, -8) LIKE ?) ORDER BY m.created_at DESC LIMIT 200")
      .bind(like, like, like, like, like, like, like).all();
    return json(result.results || []);
  }
  if (path === "/admin/api/members" && method === "POST") {
    const body = await readJson(request);
    return body ? createMember(env.DB, env, body) : apiError("INVALID_REQUEST", 400);
  }
  if (path === "/admin/api/members/import" && method === "POST") {
    const body = await readJson(request, 256_000);
    if (!Array.isArray(body?.members) || body.members.length < 1 || body.members.length > 200) return apiError("IMPORT_INVALID", 400, "Import up to 200 members at a time");
    const results = [];
    for (let index = 0; index < body.members.length; index++) {
      const item = body.members[index] || {};
      let planId = item.plan_id;
      if (!planId && item.plan_name) {
        const plan = await env.DB.prepare("SELECT id FROM plans WHERE name = ? AND enabled = 1 LIMIT 1").bind(String(item.plan_name)).first();
        planId = plan?.id;
      }
      const response = await createMember(env.DB, env, { ...item, plan_id: planId, status: item.status || "active" });
      const value = await response.json();
      results.push(response.ok
        ? { row: index + 2, telegram_user_id: value.member.telegram_user_id, status: "created" }
        : { row: index + 2, telegram_user_id: String(item.telegram_user_id || ""), status: "failed", error: value?.error?.code || "IMPORT_FAILED" });
    }
    return json({ created: results.filter((row) => row.status === "created").length, failed: results.filter((row) => row.status === "failed").length, results });
  }
  const parts = path.split("/");
  if (parts[1] === "admin" && parts[2] === "api" && parts[3] === "members" && parts.length === 5 && method === "PATCH") {
    const memberId = parts[4];
    const body = await readJson(request);
    if (!body || !validId(memberId)) return apiError("INVALID_REQUEST", 400);
    const member = await env.DB.prepare("SELECT * FROM members WHERE id = ?").bind(memberId).first();
    if (!member) return apiError("MEMBER_NOT_FOUND", 404);
    const status = body.status === undefined ? member.status : String(body.status);
    if (!MEMBER_STATUSES.has(status)) return apiError("MEMBER_STATUS_INVALID", 400);
    const expiry = body.expires_at === undefined ? member.expires_at : expiryFromInput(body.expires_at);
    if (expiry === undefined) return apiError("EXPIRY_INVALID", 400);
    const planId = body.plan_id === undefined ? member.plan_id : (body.plan_id || null);
    if (planId && !await env.DB.prepare("SELECT id FROM plans WHERE id = ?").bind(planId).first()) return apiError("PLAN_NOT_FOUND", 400);
    const maxDevices = Math.max(1, Math.min(50, Number(body.max_devices === undefined ? member.max_devices : body.max_devices)));
    await env.DB.prepare("UPDATE members SET status = ?, plan_id = ?, expires_at = ?, max_devices = ?, notes = ?, display_name = ?, telegram_username = ?, wechat_id = ?, member_number = ?, updated_at = ? WHERE id = ?")
      .bind(status, planId, expiry, maxDevices, body.notes === undefined ? member.notes : String(body.notes).slice(0, 500),
        body.display_name === undefined ? member.display_name : String(body.display_name).slice(0, 120),
        body.telegram_username === undefined ? member.telegram_username : String(body.telegram_username).slice(0, 64),
        body.wechat_id === undefined ? member.wechat_id : String(body.wechat_id).slice(0, 100),
        body.member_number === undefined ? member.member_number : String(body.member_number).slice(0, 100), nowIso(), memberId).run();
    await audit(env.DB, "admin", "member.update", "member", memberId, "status=" + status + "; plan=" + (planId || "none"));
    const becameUsable = status === "active" && expiry && Date.parse(expiry) > Date.now() &&
      (member.status !== "active" || member.expires_at !== expiry || member.plan_id !== planId);
    const botNotified = becameUsable ? await notifyMemberProvisioned(env, env.DB, member.telegram_user_id, "管理员已更新你的会员资料") : false;
    return json({ id: memberId, status, plan_id: planId, expires_at: expiry, max_devices: maxDevices, bot_notified: botNotified });
  }
  if (parts[1] === "admin" && parts[2] === "api" && parts[3] === "members" && parts[5] === "renew" && method === "POST") {
    const memberId = parts[4];
    const body = await readJson(request);
    if (!validId(memberId) || !body || !["from_expiry", "from_now"].includes(body.mode)) return apiError("RENEWAL_INVALID", 400);
    const member = await env.DB.prepare("SELECT id, expires_at FROM members WHERE id = ?").bind(memberId).first();
    const planId = String(body.plan_id || "");
    const plan = await env.DB.prepare("SELECT id, duration_days FROM plans WHERE id = ? AND enabled = 1").bind(planId).first();
    if (!member) return apiError("MEMBER_NOT_FOUND", 404);
    if (!plan) return apiError("PLAN_NOT_FOUND", 400);
    const priorExpiry = Date.parse(member.expires_at || "");
    const base = body.mode === "from_expiry" && Number.isFinite(priorExpiry) && priorExpiry > Date.now() ? priorExpiry : Date.now();
    const expiry = new Date(base + plan.duration_days * 86400000).toISOString();
    await env.DB.prepare("UPDATE members SET plan_id = ?, status = 'active', expires_at = ?, updated_at = ? WHERE id = ?")
      .bind(plan.id, expiry, nowIso(), memberId).run();
    await audit(env.DB, "admin", "member.renew", "member", memberId, "plan=" + plan.id + "; mode=" + body.mode + "; expires_at=" + expiry);
    const linked = await env.DB.prepare("SELECT telegram_user_id FROM members WHERE id = ?").bind(memberId).first();
    const botNotified = linked?.telegram_user_id ? await notifyMemberProvisioned(env, env.DB, linked.telegram_user_id, "会员已续期") : false;
    return json({ id: memberId, plan_id: plan.id, expires_at: expiry, bot_notified: botNotified });
  }
  if (parts[1] === "admin" && parts[2] === "api" && parts[3] === "members" && parts.length === 5 && method === "GET") {
    const memberId = parts[4];
    const [member, devices, usage, events] = await Promise.all([
      env.DB.prepare("SELECT m.*, p.name AS plan_name, substr(t.token_hash, -8) AS token_suffix FROM members m LEFT JOIN plans p ON p.id = m.plan_id LEFT JOIN tokens t ON t.member_id = m.id AND t.revoked_at IS NULL WHERE m.id = ?").bind(memberId).first(),
      env.DB.prepare("SELECT id, trust_level, user_agent_hint, ip_address, geo_location, first_seen, last_seen, revoked_at, network_bucket, geo_region_key, browser_key, last_seen_day FROM devices WHERE member_id = ? ORDER BY last_seen DESC LIMIT 50").bind(memberId).all(),
      env.DB.prepare("SELECT u.hour, r.slug, r.name AS resource_name, u.allowed_count, u.denied_count, u.last_seen FROM usage_hourly u JOIN resources r ON r.id = u.resource_id WHERE u.member_id = ? ORDER BY u.hour DESC LIMIT 60").bind(memberId).all(),
      env.DB.prepare("SELECT actor_id, action, timestamp, change_summary FROM audit_events WHERE target_type = 'member' AND target_id = ? ORDER BY timestamp DESC LIMIT 40").bind(memberId).all(),
    ]);
    return member ? json({ member, devices: devices.results || [], usage: usage.results || [], events: events.results || [] }) : apiError("MEMBER_NOT_FOUND", 404);
  }
  if (parts[1] === "admin" && parts[2] === "api" && parts[3] === "members" && parts[5] === "devices" && parts.length === 6 && method === "DELETE") {
    const memberId = parts[4];
    if (!validId(memberId)) return apiError("MEMBER_NOT_FOUND", 404);
    const result = await env.DB.prepare("DELETE FROM devices WHERE member_id = ?").bind(memberId).run();
    await audit(env.DB, "admin", "devices.clear", "member", memberId, "weak device records removed=" + result.meta.changes);
    return json({ removed: result.meta.changes });
  }
  if (parts[1] === "admin" && parts[2] === "api" && parts[3] === "members" && parts[5] === "devices" && parts.length === 7 && method === "DELETE") {
    const memberId = parts[4];
    const deviceId = parts[6];
    if (!validId(memberId) || !validId(deviceId)) return apiError("DEVICE_NOT_FOUND", 404);
    const result = await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND member_id = ? AND revoked_at IS NULL")
      .bind(nowIso(), deviceId, memberId).run();
    if (!result.meta.changes) return apiError("DEVICE_NOT_FOUND", 404);
    await audit(env.DB, "admin", "device.remove", "member", memberId, "device=" + deviceId);
    return json({ removed: true });
  }
  if (parts[1] === "admin" && parts[2] === "api" && parts[3] === "members" && parts[5] === "reset-token" && method === "POST") {
    return rotateToken(env.DB, env, parts[4]);
  }

  if (path === "/admin/api/audit" && method === "GET") {
    const result = await env.DB.prepare("SELECT actor_id, action, target_type, target_id, timestamp, change_summary FROM audit_events ORDER BY timestamp DESC LIMIT 200").all();
    return json(result.results || []);
  }
  if (path === "/admin/api/renewals" && method === "GET") {
    const result = await env.DB.prepare("SELECT r.id, r.member_id, r.status, r.note, r.created_at, m.telegram_user_id, m.display_name FROM renewal_requests r JOIN members m ON m.id = r.member_id WHERE r.status = 'pending' ORDER BY r.created_at").all();
    return json(result.results || []);
  }
  if (path === "/admin/api/device-limit-requests" && method === "GET") {
    const result = await env.DB.prepare("SELECT r.id, r.member_id, r.additional_devices, r.note, r.created_at, m.telegram_user_id, m.telegram_username, m.display_name, m.wechat_id, m.member_number, m.max_devices, (SELECT COUNT(*) FROM devices d WHERE d.member_id = m.id AND d.revoked_at IS NULL) AS active_devices FROM device_limit_requests r JOIN members m ON m.id = r.member_id WHERE r.status = 'pending' ORDER BY r.created_at ASC LIMIT 200").all();
    return json(result.results || []);
  }
  if (path === "/admin/api/device-limit-requests/batch" && method === "POST") {
    const body = await readJson(request, 32_768);
    const ids = Array.isArray(body?.ids) ? [...new Set(body.ids.map(String))] : [];
    const status = String(body?.status || "");
    if (!ids.length || ids.length > 50 || !["approved", "rejected"].includes(status) || ids.some((id) => !validId(id))) return apiError("DEVICE_LIMIT_BATCH_INVALID", 400);
    const results = [];
    for (const id of ids) {
      const result = await reviewDeviceLimitRequest(env.DB, env, id, status, "admin", String(body.note || "").slice(0, 300));
      results.push({ id, ok: !result.error, error: result.error || "" });
    }
    return json({ processed: results.filter((row) => row.ok).length, failed: results.filter((row) => !row.ok).length, results });
  }
  const deviceLimitMatch = path.match(/^\/admin\/api\/device-limit-requests\/([0-9a-f-]{20,40})$/iu);
  if (deviceLimitMatch && method === "POST") {
    const body = await readJson(request);
    if (!body || !["approved", "rejected"].includes(body.status)) return apiError("DEVICE_LIMIT_STATUS_INVALID", 400);
    const result = await reviewDeviceLimitRequest(env.DB, env, deviceLimitMatch[1], body.status, "admin", String(body.note || "").slice(0, 300));
    if (result.error) {
      const status = result.error === "DEVICE_LIMIT_NOT_PENDING" ? 409 : result.error === "DEVICE_LIMIT_CAP_REACHED" ? 400 : 400;
      return apiError(result.error, status);
    }
    return json(result);
  }
  if (parts[1] === "admin" && parts[2] === "api" && parts[3] === "renewals" && parts.length === 5 && method === "POST") {
    const body = await readJson(request);
    const status = body && body.status;
    if (!["approved", "rejected"].includes(status)) return apiError("RENEWAL_STATUS_INVALID", 400);
    const result = await reviewRenewal(env.DB, env, parts[4], status, "admin", String(body.note || "").slice(0, 300));
    if (result.error) return apiError(result.error, result.error === "RENEWAL_NOT_FOUND" ? 404 : 409);
    return json(result);
  }
  return apiError("NOT_FOUND", 404);
}

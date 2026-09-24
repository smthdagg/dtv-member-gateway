import {
  apiError, audit, clearSessionCookie, hasAdminSession, isSameOrigin, issueToken,
  json, makeSessionCookie, newId, nowIso, parseJsonList, parseJsonWithComments, readJson, safeEqual,
  setSessionCookie,
} from "./security.js";
import { notifyDeviceLimitDecision, notifyMemberProvisioned, reviewRenewal, reviewSignup } from "./telegram.js";

const MEMBER_STATUSES = new Set(["pending", "active", "paused", "expired", "revoked"]);
const RESOURCE_TYPES = new Set(["url", "tv", "json", "repository", "stremio"]);

function validId(value) {
  return typeof value === "string" && /^[0-9a-f-]{20,40}$/iu.test(value);
}

function safeHostname(host) {
  const value = String(host || "").trim().toLowerCase().replace(/\.$/u, "");
  if (!value || value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local")) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value) || value.includes(":")) return false;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(value);
}

function approvedHost(hostname, allowedHosts) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/u, "");
  return safeHostname(host) && allowedHosts.includes(host);
}

function safePublicHostname(hostname) {
  const value = String(hostname || "").trim().toLowerCase().replace(/\.$/u, "");
  if (!value || value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local") || value.endsWith(".internal") || value.endsWith(".lan")) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value) || value.includes(":")) return false;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(value);
}

function isAddressCandidate(value, key, rewriteFields) {
  const text = value.trim();
  if (/^(?:https?:\/\/|\/\/[^/])/iu.test(text)) return true;
  return rewriteFields.has(key) && /^(?:\/(?!\/)|\.{1,2}\/|\?.+)/u.test(text);
}

async function boundedText(response, limit) {
  const announced = Number(response.headers.get("content-length") || 0);
  if (announced > limit) return null;
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); return null; }
      chunks.push(value);
    }
  } catch { return null; }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(bytes);
}

function summarizeJson(value, baseUrl, rewriteFields) {
  const summary = { urlCount: 0, blockedUrlCount: 0, arrayItemCount: 0 };
  function visit(node, key = "") {
    if (Array.isArray(node)) {
      summary.arrayItemCount += node.length;
      for (const item of node) visit(item, key);
      return;
    }
    if (node && typeof node === "object") {
      for (const [childKey, childValue] of Object.entries(node)) visit(childValue, childKey);
      return;
    }
    if (typeof node !== "string") return;
    const valueText = node.trim();
    const candidate = isAddressCandidate(valueText, key, rewriteFields);
    if (!candidate || !valueText) return;
    summary.urlCount++;
    try {
      const target = new URL(valueText, baseUrl);
      if (!(target.protocol === "http:" || target.protocol === "https:") || target.username || target.password || target.href.length > 2048 || !safePublicHostname(target.hostname)) summary.blockedUrlCount++;
    } catch { summary.blockedUrlCount++; }
  }
  visit(value);
  return summary;
}

async function fetchJsonSnapshot(resource, env) {
  const allowedHosts = parseJsonList(resource.allowed_hosts).map((host) => String(host).toLowerCase());
  let target;
  try { target = new URL(resource.upstream_url); } catch { return { error: "UPSTREAM_NOT_APPROVED" }; }
  const limit = Math.min(Number(resource.max_response_bytes || 2_097_152), Number(env.MAX_UPSTREAM_BYTES || 2_097_152));
  for (let hop = 0; hop <= 3; hop++) {
    if (target.protocol !== "https:" || target.username || target.password || !approvedHost(target.hostname, allowedHosts)) return { error: "UPSTREAM_REDIRECT_BLOCKED" };
    let response;
    try {
      response = await fetch(target.href, {
        method: "GET",
        redirect: "manual",
        headers: { accept: "application/json, text/*;q=0.9", "user-agent": "DTV-Member-Gateway/1.0" },
        signal: AbortSignal.timeout(12_000),
      });
    } catch { return { error: "UPSTREAM_FETCH_FAILED" }; }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      try { await response.body?.cancel(); } catch {}
      if (!location || hop === 3) return { error: "UPSTREAM_REDIRECT_BLOCKED" };
      try { target = new URL(location, target); } catch { return { error: "UPSTREAM_REDIRECT_BLOCKED", detail: "上游重定向地址无效。" }; }
      if (target.protocol !== "https:" || target.username || target.password || !approvedHost(target.hostname, allowedHosts)) {
        return { error: "UPSTREAM_REDIRECT_BLOCKED", detail: "上游重定向到未加入允许列表的域名：" + target.hostname };
      }
      continue;
    }
    if (!response.ok) { try { await response.body?.cancel(); } catch {} return { error: "UPSTREAM_HTTP_ERROR", detail: "上游返回 HTTP " + response.status + "。" }; }
    const contentType = (response.headers.get("content-type") || "application/octet-stream").split(";")[0].trim().toLowerCase();
    const text = await boundedText(response, limit);
    if (text === null) return { error: "UPSTREAM_RESPONSE_TOO_LARGE" };
    let value;
    try { value = parseJsonWithComments(text); } catch { return { error: "UPSTREAM_JSON_INVALID", detail: "上游返回内容不是有效 JSON（响应类型：" + contentType + "）。" }; }
    if (!value || typeof value !== "object") return { error: "UPSTREAM_JSON_INVALID" };
    const summary = summarizeJson(value, target, new Set(parseJsonList(resource.rewrite_fields)));
    return {
      contentJson: text,
      contentType,
      urlCount: summary.urlCount,
      blockedUrlCount: summary.blockedUrlCount,
      arrayItemCount: summary.arrayItemCount,
      topLevelKeys: Array.isArray(value) ? [] : Object.keys(value).slice(0, 30),
      errorDetail: "",
    };
  }
  return { error: "UPSTREAM_REDIRECT_BLOCKED", detail: "上游重定向次数过多。" };
}

async function syncJsonResource(db, env, resource) {
  if (resource.type !== "json") return { id: resource.id, slug: resource.slug, ok: false, error: "RESOURCE_TYPE_NOT_JSON" };
  const fetched = await fetchJsonSnapshot(resource, env);
  if (fetched.error) {
    const attemptedAt = nowIso();
    const detail = fetched.detail || ({
      UPSTREAM_FETCH_FAILED: "无法连接上游；请检查 DNS、TLS、网络或站点访问策略。",
      UPSTREAM_JSON_INVALID: "上游返回内容不是有效 JSON。",
      UPSTREAM_RESPONSE_TOO_LARGE: "上游响应超过资源大小限制。",
      UPSTREAM_NOT_APPROVED: "上游域名未加入允许列表。",
    }[fetched.error] || fetched.error);
    await db.prepare("UPDATE resources SET last_sync_attempt_at = ?, last_sync_error = ? WHERE id = ?")
      .bind(attemptedAt, detail.slice(0, 400), resource.id).run();
    return { id: resource.id, slug: resource.slug, ok: false, error: fetched.error, error_detail: detail };
  }
  const syncedAt = nowIso();
  await db.batch([
    db.prepare("INSERT INTO resource_snapshots (resource_id, content_json, source_content_type, url_count, blocked_url_count, top_level_keys, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(resource_id) DO UPDATE SET content_json = excluded.content_json, source_content_type = excluded.source_content_type, url_count = excluded.url_count, blocked_url_count = excluded.blocked_url_count, top_level_keys = excluded.top_level_keys, synced_at = excluded.synced_at")
      .bind(resource.id, fetched.contentJson, fetched.contentType, fetched.urlCount, fetched.blockedUrlCount, JSON.stringify(fetched.topLevelKeys), syncedAt),
    db.prepare("UPDATE resources SET last_sync_attempt_at = ?, last_sync_error = '' WHERE id = ?").bind(syncedAt, resource.id),
  ]);
  await audit(db, "admin", "resource.sync", "resource", resource.id, "JSON snapshot refreshed; urls=" + fetched.urlCount + "; blocked=" + fetched.blockedUrlCount);
  return {
    id: resource.id,
    slug: resource.slug,
    ok: true,
    synced_at: syncedAt,
    url_count: fetched.urlCount,
    blocked_url_count: fetched.blockedUrlCount,
    array_item_count: fetched.arrayItemCount,
    unusable_url_count: fetched.blockedUrlCount,
    top_level_keys: fetched.topLevelKeys,
  };
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
    ? await db.prepare("SELECT upstream_url, allowed_hosts, type, max_response_bytes FROM resources WHERE id = ?").bind(resourceId).first()
    : null;
  const resetSyncStatus = Boolean(previous && (
    previous.upstream_url !== value.upstreamUrl ||
    previous.allowed_hosts !== JSON.stringify(value.allowedHosts) ||
    previous.type !== value.type ||
    Number(previous.max_response_bytes) !== value.maxBytes
  ));
  const id = resourceId || newId();
  const now = nowIso();
  const args = [value.slug, value.name, value.type, value.upstreamUrl, JSON.stringify(value.allowedHosts), value.mode,
    JSON.stringify(value.rewriteFields), value.maxBytes, value.enabled, now];
  try {
    if (resourceId) {
      const result = await db.prepare("UPDATE resources SET slug = ?, name = ?, type = ?, upstream_url = ?, allowed_hosts = ?, delivery_mode = ?, rewrite_fields = ?, max_response_bytes = ?, enabled = ?, updated_at = ?, last_sync_attempt_at = CASE WHEN ? = 1 THEN NULL ELSE last_sync_attempt_at END, last_sync_error = CASE WHEN ? = 1 THEN '' ELSE last_sync_error END WHERE id = ?")
        .bind(...args, resetSyncStatus ? 1 : 0, resetSyncStatus ? 1 : 0, id).run();
      if (!result.meta.changes) return apiError("RESOURCE_NOT_FOUND", 404);
    } else {
      await db.prepare("INSERT INTO resources (id, slug, name, type, upstream_url, allowed_hosts, delivery_mode, rewrite_fields, max_response_bytes, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id, value.slug, value.name, value.type, value.upstreamUrl, JSON.stringify(value.allowedHosts), value.mode, JSON.stringify(value.rewriteFields), value.maxBytes, value.enabled, now, now).run();
    }
  } catch {
    return apiError("RESOURCE_SAVE_FAILED", 409);
  }
  if (resetSyncStatus) {
    await db.prepare("DELETE FROM resource_snapshots WHERE resource_id = ?").bind(id).run();
  }
  await audit(db, "admin", resourceId ? "resource.update" : "resource.create", "resource", id, "slug=" + value.slug + "; enabled=" + value.enabled);
  return json({ id, slug: value.slug, name: value.name }, resourceId ? 200 : 201);
}

export async function adminApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/$/u, "") || "/";
  const method = request.method;

  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && !isSameOrigin(request)) return apiError("ORIGIN_REQUIRED", 403);

  if (path === "/admin/api/login" && method === "POST") {
    const limited = await env.ADMIN_LOGIN_LIMITER.limit({ key: request.headers.get("cf-connecting-ip") || "unknown" });
    if (!limited.success) return apiError("LOGIN_RATE_LIMITED", 429);
    const body = await readJson(request, 4096);
    if (!body || typeof body.password !== "string") return apiError("INVALID_REQUEST", 400);
    if (!env.ADMIN_PASSWORD || !safeEqual(body.password, env.ADMIN_PASSWORD)) return apiError("LOGIN_FAILED", 401);
    return json({ ok: true }, 200, { "set-cookie": setSessionCookie(await makeSessionCookie(env)), "cache-control": "no-store" });
  }
  if (path === "/admin/api/logout" && method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": clearSessionCookie(), "cache-control": "no-store" });
  }
  if (path === "/admin/api/me" && method === "GET") {
    return json({ authenticated: await hasAdminSession(request, env) }, 200, { "cache-control": "no-store" });
  }

  if (!await hasAdminSession(request, env)) return apiError("ADMIN_AUTH_REQUIRED", 401);

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
    if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_WEBHOOK_SECRET) return apiError("BOT_CONFIG_MISSING", 409, "Bot token and webhook secret must be configured in Cloudflare first");
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(env.TELEGRAM_WEBHOOK_SECRET)) return apiError("WEBHOOK_SECRET_INVALID", 500);
    const endpoint = "https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/setWebhook";
    const result = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "") + "/telegram/webhook", secret_token: env.TELEGRAM_WEBHOOK_SECRET, allowed_updates: ["message", "callback_query"] }),
    });
    const payload = await result.json().catch(() => null);
    if (!result.ok || payload?.ok !== true) return apiError("BOT_WEBHOOK_SETUP_FAILED", 502, "Telegram did not accept the webhook configuration");
    await audit(env.DB, "admin", "telegram.webhook.configure", "bot", "telegram", "webhook configured");
    return json({ ok: true, webhook: String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "") + "/telegram/webhook" });
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

  if (path === "/admin/api/resources/sync" && method === "POST") {
    const result = await env.DB.prepare("SELECT id, slug, type, upstream_url, allowed_hosts, rewrite_fields, max_response_bytes FROM resources WHERE type = 'json' AND enabled = 1 ORDER BY name LIMIT 10").all();
    const resources = result.results || [];
    const rows = await Promise.all(resources.map((resource) => syncJsonResource(env.DB, env, resource)));
    return json({ synced: rows.filter((row) => row.ok).length, failed: rows.filter((row) => !row.ok).length, results: rows });
  }
  const resourceSyncMatch = path.match(/^\/admin\/api\/resources\/([0-9a-f-]{20,40})\/sync$/iu);
  if (resourceSyncMatch && method === "POST") {
    const resource = await env.DB.prepare("SELECT id, slug, type, upstream_url, allowed_hosts, rewrite_fields, max_response_bytes FROM resources WHERE id = ?")
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
      env.DB.prepare("SELECT id, trust_level, user_agent_hint, ip_address, geo_location, first_seen, last_seen, revoked_at FROM devices WHERE member_id = ? ORDER BY last_seen DESC LIMIT 50").bind(memberId).all(),
      env.DB.prepare("SELECT u.hour, r.slug, u.allowed_count, u.denied_count, u.last_seen FROM usage_hourly u JOIN resources r ON r.id = u.resource_id WHERE u.member_id = ? ORDER BY u.hour DESC LIMIT 60").bind(memberId).all(),
      env.DB.prepare("SELECT action, timestamp, change_summary FROM audit_events WHERE target_type = 'member' AND target_id = ? ORDER BY timestamp DESC LIMIT 40").bind(memberId).all(),
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

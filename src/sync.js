import { audit, newId, nowIso, parseJsonList, parseJsonWithComments, sha256Hex } from "./security.js";
import { getTelegramConfig } from "./bot-config.js";

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

export async function boundedText(response, limit) {
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

function isAddressCandidate(value, key, rewriteFields) {
  const text = value.trim();
  if (/^(?:https?:\/\/|\/\/[^/])/iu.test(text)) return true;
  return rewriteFields.has(key) && /^(?:\/(?!\/)|\.{1,2}\/|\?.+)/u.test(text);
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
      if (!(target.protocol === "http:" || target.protocol === "https:") || target.username || target.password || target.href.length > 2048 || !safeHostname(target.hostname)) summary.blockedUrlCount++;
    } catch { summary.blockedUrlCount++; }
  }
  visit(value);
  return summary;
}

export async function fetchJsonSnapshot(resource, env) {
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

const SYNC_ERROR_DETAILS = {
  UPSTREAM_FETCH_FAILED: "无法连接上游；请检查 DNS、TLS、网络或站点访问策略。",
  UPSTREAM_JSON_INVALID: "上游返回内容不是有效 JSON。",
  UPSTREAM_RESPONSE_TOO_LARGE: "上游响应超过资源大小限制。",
  UPSTREAM_NOT_APPROVED: "上游域名未加入允许列表。",
};

export async function syncJsonResource(db, env, resource, { actor = "admin" } = {}) {
  if (resource.type !== "json") return { id: resource.id, slug: resource.slug, ok: false, error: "RESOURCE_TYPE_NOT_JSON" };
  const startedAt = Date.now();
  const fetched = await fetchJsonSnapshot(resource, env);
  const attemptedAt = nowIso();
  if (fetched.error) {
    const detail = fetched.detail || SYNC_ERROR_DETAILS[fetched.error] || fetched.error;
    await db.batch([
      db.prepare("UPDATE resources SET last_sync_attempt_at = ?, last_sync_error = ? WHERE id = ?")
        .bind(attemptedAt, detail.slice(0, 400), resource.id),
      db.prepare("INSERT INTO resource_sync_log (id, resource_id, started_at, ok, error, url_count, duration_ms) VALUES (?, ?, ?, 0, ?, 0, ?)")
        .bind(newId(), resource.id, attemptedAt, fetched.error.slice(0, 120), Date.now() - startedAt),
    ]);
    await audit(db, actor, "resource.sync_failed", "resource", resource.id, fetched.error);
    return { id: resource.id, slug: resource.slug, ok: false, error: fetched.error, error_detail: detail };
  }
  const contentHash = await sha256Hex(fetched.contentJson);
  const syncedAt = attemptedAt;
  const unchanged = resource.content_hash && resource.content_hash === contentHash;
  if (unchanged) {
    await db.batch([
      db.prepare("UPDATE resources SET last_sync_attempt_at = ?, last_sync_error = '', content_hash = ? WHERE id = ?")
        .bind(syncedAt, contentHash, resource.id),
      db.prepare("INSERT INTO resource_sync_log (id, resource_id, started_at, ok, error, url_count, duration_ms) VALUES (?, ?, ?, 1, '', ?, ?)")
        .bind(newId(), resource.id, syncedAt, fetched.urlCount, Date.now() - startedAt),
    ]);
    return {
      id: resource.id, slug: resource.slug, ok: true, unchanged: true, synced_at: syncedAt,
      url_count: fetched.urlCount, blocked_url_count: fetched.blockedUrlCount,
      array_item_count: fetched.arrayItemCount, top_level_keys: fetched.topLevelKeys,
    };
  }
  await db.batch([
    db.prepare("INSERT INTO resource_snapshots (resource_id, content_json, source_content_type, url_count, blocked_url_count, top_level_keys, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(resource_id) DO UPDATE SET content_json = excluded.content_json, source_content_type = excluded.source_content_type, url_count = excluded.url_count, blocked_url_count = excluded.blocked_url_count, top_level_keys = excluded.top_level_keys, synced_at = excluded.synced_at")
      .bind(resource.id, fetched.contentJson, fetched.contentType, fetched.urlCount, fetched.blockedUrlCount, JSON.stringify(fetched.topLevelKeys), syncedAt),
    db.prepare("UPDATE resources SET last_sync_attempt_at = ?, last_sync_error = '', content_hash = ? WHERE id = ?").bind(syncedAt, contentHash, resource.id),
    db.prepare("INSERT INTO resource_sync_log (id, resource_id, started_at, ok, error, url_count, duration_ms) VALUES (?, ?, ?, 1, '', ?, ?)")
      .bind(newId(), resource.id, syncedAt, fetched.urlCount, Date.now() - startedAt),
  ]);
  await audit(db, actor, "resource.sync", "resource", resource.id, "JSON snapshot refreshed; urls=" + fetched.urlCount + "; blocked=" + fetched.blockedUrlCount);
  return {
    id: resource.id,
    slug: resource.slug,
    ok: true,
    unchanged: false,
    synced_at: syncedAt,
    url_count: fetched.urlCount,
    blocked_url_count: fetched.blockedUrlCount,
    array_item_count: fetched.arrayItemCount,
    unusable_url_count: fetched.blockedUrlCount,
    top_level_keys: fetched.topLevelKeys,
  };
}

export async function notifyAdmins(env, text) {
  try {
    const config = await getTelegramConfig(env, { force: true });
    if (!config.botConfigured || !config.adminIds?.length) return false;
    const results = await Promise.allSettled(config.adminIds.map((chatId) =>
      fetch("https://api.telegram.org/bot" + config.botToken + "/sendMessage", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
        signal: AbortSignal.timeout(10_000),
      }).then((response) => response.ok)));
    return results.some((item) => item.status === "fulfilled" && item.value === true);
  } catch {
    return false;
  }
}

const SYNC_RESOURCE_COLUMNS = "id, slug, name, type, upstream_url, allowed_hosts, rewrite_fields, max_response_bytes, content_hash";

export async function runDueSync(env, { limit = 8, notify = true } = {}) {
  const result = await env.DB.prepare(
    "SELECT " + SYNC_RESOURCE_COLUMNS + " FROM resources WHERE type = 'json' AND enabled = 1 AND auto_sync = 1 AND (last_sync_attempt_at IS NULL OR last_sync_attempt_at < datetime('now', '-' || MAX(15, sync_interval_minutes) || ' minutes')) ORDER BY COALESCE(last_sync_attempt_at, '1970-01-01') ASC LIMIT ?"
  ).bind(limit).all();
  const resources = result.results || [];
  if (!resources.length) return { attempted: 0, synced: 0, failed: 0 };
  const rows = [];
  for (const resource of resources) {
    try {
      rows.push(await syncJsonResource(env.DB, env, resource, { actor: "cron" }));
    } catch (error) {
      rows.push({ id: resource.id, slug: resource.slug, ok: false, error: "SYNC_EXCEPTION", error_detail: String(error && error.message || error).slice(0, 200) });
    }
  }
  const failed = rows.filter((row) => !row.ok);
  if (notify && failed.length) {
    const repeated = await Promise.all(failed.map((row) =>
      env.DB.prepare("SELECT COUNT(*) AS count FROM resource_sync_log WHERE resource_id = ? AND ok = 0 AND started_at > datetime('now', '-12 hours')").bind(row.id).first()));
    const recurring = failed.filter((row, index) => Number(repeated[index]?.count || 0) >= 3);
    if (recurring.length) {
      await notifyAdmins(env, "DTV 多仓平台：以下资源连续同步失败（近 12 小时 ≥3 次）：\n" +
        recurring.map((row) => "· " + row.slug + " — " + (row.error_detail || row.error || "")).join("\n") +
        "\n会员仍可读取最近一次成功快照。");
    }
  }
  return { attempted: rows.length, synced: rows.filter((row) => row.ok).length, failed: failed.length, results: rows };
}

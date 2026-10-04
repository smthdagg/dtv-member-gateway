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

// 节点探活：http 直连型 api 实测可达性，连续失败计入 fail_streak
export async function probeHttpApis(env, sites, { limit = 250, concurrency = 25 } = {}) {
  const candidates = [];
  const seen = new Set();
  for (const site of sites) {
    const api = String(site?.api || "").trim();
    if (/^https?:\/\//iu.test(api) && !seen.has(api)) {
      seen.add(api);
      candidates.push(api);
    }
  }
  // 跳过 12 小时内已检测过的 api，让每轮探活覆盖新的节点
  const hashes = [];
  for (const api of candidates) hashes.push((await sha256Hex(api)).slice(0, 32));
  const recentChecked = new Set();
  for (let start = 0; start < hashes.length; start += 100) {
    const chunk = hashes.slice(start, start + 100);
    const placeholders = chunk.map(() => "?").join(",");
    const rows = await env.DB.prepare(`SELECT api_hash FROM site_probe_state WHERE api_hash IN (${placeholders}) AND last_checked_at > datetime('now', '-12 hours')`).bind(...chunk).all();
    for (const row of rows.results || []) recentChecked.add(row.api_hash);
  }
  const apis = candidates.filter((_, index) => !recentChecked.has(hashes[index])).slice(0, limit);
  let alive = 0;
  let dead = 0;
  const upserts = [];
  let index = 0;
  const worker = async () => {
    while (index < apis.length) {
      const api = apis[index++];
      let ok = 0;
      let status = "";
      try {
        const response = await fetch(api, { method: "GET", redirect: "follow", headers: { "user-agent": "Mozilla/5.0", accept: "*/*" }, signal: AbortSignal.timeout(6_000) });
        try { await response.body?.cancel(); } catch {}
        // 网络可达性判定：服务器有任何响应（含 4xx/5xx）即视为可达
        ok = 1;
        status = "HTTP " + response.status;
      } catch (error) {
        ok = 0;
        status = String(error?.name || error?.message || "ERR").slice(0, 20);
      }
      if (ok) alive++; else dead++;
      const hash = (await sha256Hex(api)).slice(0, 32);
      upserts.push({ api, hash, ok, status });
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, apis.length) }, worker));
  if (upserts.length) {
    const statements = upserts.map((row) =>
      env.DB.prepare("INSERT INTO site_probe_state (api_hash, api, last_ok, fail_streak, last_checked_at, last_status) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(api_hash) DO UPDATE SET last_ok = excluded.last_ok, fail_streak = CASE WHEN excluded.last_ok = 1 THEN 0 ELSE site_probe_state.fail_streak + 1 END, last_checked_at = excluded.last_checked_at, last_status = excluded.last_status")
        .bind(row.hash, row.api, row.ok, row.ok ? 0 : 1, nowIso(), row.status));
    for (let start = 0; start < statements.length; start += 50) {
      await env.DB.batch(statements.slice(start, start + 50));
    }
  }
  return { checked: upserts.length, alive, dead };
}

export async function loadBlockedApis(env) {
  const rows = await env.DB.prepare(
    "SELECT api FROM site_probe_state WHERE fail_streak >= 1 AND last_checked_at > datetime('now', '-24 hours')"
  ).all();
  return new Set((rows.results || []).map((row) => row.api));
}

export async function regenerateArtifacts(env, { probe = false, probeLimit = 250 } = {}) {
  // 仓级准入：只有最近一次同步成功（上游当前可达）的仓才进入地址库
  const rows = await env.DB.prepare(
    "SELECT r.slug, r.name, s.content_json FROM resources r JOIN resource_snapshots s ON s.resource_id = r.id WHERE r.enabled = 1 AND r.type = 'json' AND r.last_sync_error = '' ORDER BY r.created_at ASC, r.slug ASC"
  ).all();
  const excludedWarehouses = await env.DB.prepare(
    "SELECT slug, name, last_sync_error FROM resources WHERE enabled = 1 AND type = 'json' AND last_sync_error != '' LIMIT 50"
  ).all();
  const resources = rows.results || [];
  const origin = String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "");
  const entries = resources.map((row) => ({
    sourceName: (row.name || row.slug) + " · 本站",
    sourceUrl: origin + "/catalog/" + row.slug + ".json",
  }));
  const backupBase = String(env.PUBLIC_BACKUP_URL || "").replace(/\/+$/u, "");
  if (backupBase && backupBase !== origin) {
    entries.push({ sourceName: "AITV 备用线路 · 一键切换到 dtv.us.ci", sourceUrl: backupBase + "/catalog/tvbox.json" });
  }
  const multi = JSON.stringify({
    storeHouse: entries,
    urls: entries.map((entry) => ({ name: entry.sourceName, url: entry.sourceUrl })),
  }, null, 2);

  const merged = { sites: [], lives: [], parses: [] };
  const usedSiteNames = new Set();
  const usedParseNames = new Set();
  const seenSiteKeys = new Set();
  const seenSiteSignatures = new Set();
  for (const resource of resources) {
    let value;
    try { value = parseJsonWithComments(resource.content_json); } catch { continue; }
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    if (!merged.spider && typeof value.spider === "string" && value.spider) merged.spider = value.spider;
    if (!merged.wallpaper && typeof value.wallpaper === "string" && value.wallpaper) merged.wallpaper = value.wallpaper;
    const siteList = Array.isArray(value.sites) ? value.sites : [];
    for (let index = 0; index < siteList.length; index++) {
      const site = siteList[index];
      if (!site || typeof site !== "object") continue;
      const siteKey = `${resource.slug}:${String(site.key || index)}`;
      if (seenSiteKeys.has(siteKey)) continue;
      const signature = [String(site.api || "").trim(), String(site.name || "").trim()].join("|");
      if (signature !== "|" && seenSiteSignatures.has(signature)) continue;
      seenSiteKeys.add(siteKey);
      if (signature !== "|") seenSiteSignatures.add(signature);
      const originalName = String(site.name || "").trim();
      let name = originalName;
      if (name && usedSiteNames.has(name)) name = `${name} · ${resource.name || resource.slug}`;
      if (name) usedSiteNames.add(name);
      merged.sites.push({
        ...site,
        key: `${resource.slug}:${String(site.key || index)}`,
        name: name || `${resource.name || resource.slug} ${index + 1}`,
      });
    }
    const lifeList = Array.isArray(value.lives) ? value.lives : [];
    merged.lives.push(...lifeList.filter((item) => item && typeof item === "object"));
    const parseList = Array.isArray(value.parses) ? value.parses : [];
    for (const parse of parseList) {
      if (!parse || typeof parse !== "object") continue;
      let name = String(parse.name || "").trim();
      if (name && usedParseNames.has(name)) name = `${name} · ${resource.name || resource.slug}`;
      if (name) usedParseNames.add(name);
      merged.parses.push({ ...parse, name: name || `解析 ${merged.parses.length + 1}` });
    }
  }
  // 节点级准入：http 直连型 api 实测探活（可选），连续 2 次失败的剔除出单仓
  let probeStats = { checked: 0, alive: 0, dead: 0, blocked: 0, skipped: 0 };
  if (probe) probeStats = { ...probeStats, ...(await probeHttpApis(env, merged.sites, { limit: probeLimit })) };
  const blocked = await loadBlockedApis(env);
  if (blocked.size) {
    const before = merged.sites.length;
    merged.sites = merged.sites.filter((site) => {
      const api = String(site?.api || "").trim();
      return !(/^https?:\/\//iu.test(api) && blocked.has(api));
    });
    probeStats.blocked = before - merged.sites.length;
  }
  probeStats.skipped = merged.sites.length;
  const single = JSON.stringify(merged);
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO generated_artifacts (key, content, generated_at) VALUES ('catalog:multi', ?, ?) ON CONFLICT(key) DO UPDATE SET content = excluded.content, generated_at = excluded.generated_at").bind(multi, now),
    env.DB.prepare("INSERT INTO generated_artifacts (key, content, generated_at) VALUES ('catalog:merged', ?, ?) ON CONFLICT(key) DO UPDATE SET content = excluded.content, generated_at = excluded.generated_at").bind(single, now),
  ]);
  return {
    resources: resources.length,
    warehousesExcluded: (excludedWarehouses.results || []).map((row) => ({ slug: row.slug, name: row.name, error: row.last_sync_error.slice(0, 80) })),
    sites: merged.sites.length,
    lives: merged.lives.length,
    parses: merged.parses.length,
    probe: probeStats,
    generated_at: now,
  };
}

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
  // 连续 3 次同步失败的仓自动下线：不可达的仓不进入多仓/单仓地址库
  const autoOffline = [];
  const failing = await env.DB.prepare(
    "SELECT id, slug, name, last_sync_error FROM resources WHERE enabled = 1 AND type = 'json' AND auto_sync = 1 AND last_sync_error != '' AND last_sync_attempt_at IS NOT NULL"
  ).all();
  for (const resource of failing.results || []) {
    const logs = await env.DB.prepare("SELECT ok FROM resource_sync_log WHERE resource_id = ? ORDER BY started_at DESC LIMIT 3").bind(resource.id).all();
    const entries = logs.results || [];
    if (entries.length >= 3 && entries.every((entry) => !entry.ok)) {
      await env.DB.prepare("UPDATE resources SET enabled = 0, updated_at = ? WHERE id = ?").bind(nowIso(), resource.id).run();
      await audit(env.DB, "cron", "resource.auto_offline", "resource", resource.id, "连续 3 次同步失败，自动下线");
      autoOffline.push(resource.slug + "（" + resource.name + "）");
    }
  }
  if (notify && (failed.length || autoOffline.length)) {
    const repeated = await Promise.all(failed.map((row) =>
      env.DB.prepare("SELECT COUNT(*) AS count FROM resource_sync_log WHERE resource_id = ? AND ok = 0 AND started_at > datetime('now', '-12 hours')").bind(row.id).first()));
    const recurring = failed.filter((row, index) => Number(repeated[index]?.count || 0) >= 3);
    const sections = [];
    if (recurring.length) sections.push("连续同步失败（近 12 小时 ≥3 次）：\n" + recurring.map((row) => "· " + row.slug + " — " + (row.error_detail || row.error || "")).join("\n"));
    if (autoOffline.length) sections.push("已自动下线（连续 3 次失败，地址库中移除）：\n" + autoOffline.map((row) => "· " + row).join("\n"));
    if (sections.length) await notifyAdmins(env, "AITV 多仓平台\n\n" + sections.join("\n\n"));
  }
  return { attempted: rows.length, synced: rows.filter((row) => row.ok).length, failed: failed.length, autoOffline, results: rows };
}

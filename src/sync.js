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
  // 入库即规范化：快照统一存纯 JSON（剥离注释、消除格式差异），下游全部直接可用
  let normalizedJson;
  try {
    normalizedJson = JSON.stringify(parseJsonWithComments(fetched.contentJson));
  } catch {
    const detail = "上游配置包含无法标准化的语法（注释或尾逗号），已拒绝入库。";
    await db.batch([
      db.prepare("UPDATE resources SET last_sync_attempt_at = ?, last_sync_error = ? WHERE id = ?")
        .bind(attemptedAt, detail.slice(0, 400), resource.id),
      db.prepare("INSERT INTO resource_sync_log (id, resource_id, started_at, ok, error, url_count, duration_ms) VALUES (?, ?, ?, 0, ?, 0, ?)")
        .bind(newId(), resource.id, attemptedAt, "UPSTREAM_JSON_INVALID", Date.now() - startedAt),
    ]);
    return { id: resource.id, slug: resource.slug, ok: false, error: "UPSTREAM_JSON_INVALID", error_detail: detail };
  }
  fetched.contentJson = normalizedJson;
  const contentHash = await sha256Hex(normalizedJson);
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
      let latency = null;
      const startedAt = Date.now();
      try {
        const response = await fetch(api, { method: "GET", redirect: "follow", headers: { "user-agent": "Mozilla/5.0", accept: "*/*" }, signal: AbortSignal.timeout(6_000) });
        try { await response.body?.cancel(); } catch {}
        // 网络可达性判定：服务器有任何响应（含 4xx/5xx）即视为可达，记录耗时用于测速排名
        ok = 1;
        latency = Date.now() - startedAt;
        status = "HTTP " + response.status + " " + latency + "ms";
      } catch (error) {
        ok = 0;
        status = String(error?.name || error?.message || "ERR").slice(0, 20);
      }
      if (ok) alive++; else dead++;
      const hash = (await sha256Hex(api)).slice(0, 32);
      upserts.push({ api, hash, ok, status, latency });
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, apis.length) }, worker));
  if (upserts.length) {
    const statements = upserts.map((row) =>
      env.DB.prepare("INSERT INTO site_probe_state (api_hash, api, last_ok, fail_streak, last_checked_at, last_status, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(api_hash) DO UPDATE SET last_ok = excluded.last_ok, fail_streak = CASE WHEN excluded.last_ok = 1 THEN 0 ELSE site_probe_state.fail_streak + 1 END, last_checked_at = excluded.last_checked_at, last_status = excluded.last_status, latency_ms = excluded.latency_ms")
        .bind(row.hash, row.api, row.ok, row.ok ? 0 : 1, nowIso(), row.status, row.latency));
    for (let start = 0; start < statements.length; start += 50) {
      await env.DB.batch(statements.slice(start, start + 50));
    }
  }
  return { checked: upserts.length, alive, dead };
}

const externalMultiCache = { entries: [], expiresAt: 0 };

export async function getExternalMultiEntries(env) {
  const url = String(env.EXTERNAL_MULTI_URL || "").trim();
  if (!url) return [];
  if (externalMultiCache.entries && Date.now() < externalMultiCache.expiresAt) return externalMultiCache.entries;
  try {
    const response = await fetch(url, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(5_000) });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const parsed = JSON.parse(await response.text());
    const list = Array.isArray(parsed?.urls) ? parsed.urls.filter((e) => e && e.url && e.name).map((e) => ({ name: String(e.name), url: String(e.url) })) : [];
    externalMultiCache.entries = list;
    externalMultiCache.expiresAt = Date.now() + 1_800_000;
  } catch {
    externalMultiCache.expiresAt = Date.now() + 300_000;
  }
  return externalMultiCache.entries;
}

let epochMemo = { value: "init", expiresAt: 0 };

// 缓存世代：地址库每次重建自动换代，网关缓存随之整体失效（= 缓存有效到下次更新）
export async function getCacheEpoch(env) {
  if (Date.now() < epochMemo.expiresAt) return epochMemo.value;
  try {
    const row = await env.DB.prepare("SELECT generated_at FROM generated_artifacts WHERE key = 'catalog:merged'").first();
    epochMemo = { value: String(row?.generated_at || "init").replace(/[^0-9]/gu, "").slice(0, 14), expiresAt: Date.now() + 10_000 };
  } catch {
    epochMemo = { value: "init", expiresAt: Date.now() + 10_000 };
  }
  return epochMemo.value;
}

const de5MultiCache = { value: null, expiresAt: 0 };
const DE5_MAIN_HOST = "0.12yue.de5.net";

// ── AiTV 多仓：只收集 0.12yue.de5.net 主站与备份站 ──
// 结构（对齐 room.json / dc2）：多仓 = 4 个仓（主站+3 备份站），每仓 → 该域全量线路列表（list.txt 87 条），线路 → 节点
async function loadDe5Manifest() {
  if (de5MultiCache.value && Date.now() < de5MultiCache.expiresAt) return de5MultiCache.value;
  const result = { warehouses: [], linesByKey: {} };
  try {
    const [cfgText, listText] = await Promise.all([
      fetch("https://0.12yue.de5.net/config.json", { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(10_000) }).then((r) => r.text()),
      fetch("https://0.12yue.de5.net/list.txt", { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(10_000) }).then((r) => r.text()),
    ]);
    const cfg = JSON.parse(cfgText);
    const names = [];
    for (const line of listText.split(/\r?\n/u)) {
      const name = line.split("|")[0].trim();
      if (/^[^|]+\.json$/iu.test(name)) names.push(name.replace(/\.json$/iu, ""));
    }
    const unique = [...new Set(names)];
    const domains = (cfg.apiDomains || [])
      .map((d) => ({ base: String(d.base || "").replace(/\/+$/u, ""), tag: String(d.tag || "备份") }))
      .filter((d) => /^https?:\/\//iu.test(d.base))
      .sort((a, b) => (b.base.includes(DE5_MAIN_HOST) ? 1 : 0) - (a.base.includes(DE5_MAIN_HOST) ? 1 : 0));
    if (!domains.length || !unique.length) throw new Error("de5 清单为空");
    domains.forEach((domain, index) => {
      const label = domain.base.includes(DE5_MAIN_HOST) ? "主站" : domain.tag;
      const key = index === 0 ? "main" : "b" + index;
      const lines = unique.map((name) => ({ name, url: domain.base + "/" + encodeURIComponent(name + ".json") }));
      if (index === 0 && cfg.liveAggregate?.url) lines.push({ name: "海量直播聚合", url: String(cfg.liveAggregate.url) });
      result.warehouses.push({ sourceName: "AiTV" + label + " · 全量接口（" + lines.length + "）", sourceUrl: "", key });
      result.linesByKey[key] = { urls: lines };
    });
    de5MultiCache.value = result;
    de5MultiCache.expiresAt = Date.now() + 30 * 60_000;
  } catch {
    if (!de5MultiCache.value) { de5MultiCache.value = result; de5MultiCache.expiresAt = Date.now() + 300_000; }
  }
  return de5MultiCache.value;
}

// 多仓（room.json 的 storeHouse 格式）：4 个仓，各指向本站的该域线路列表端点
export async function buildDe5Multi(baseUrl) {
  const manifest = await loadDe5Manifest();
  const base = String(baseUrl || "https://tvbox.aisoft.live").replace(/\/+$/u, "");
  const storeHouse = manifest.warehouses.map((w) => ({ sourceName: w.sourceName, sourceUrl: base + "/lines/" + w.key + ".json" }));
  return { storeHouse };
}

// 某个域的线路列表（dc2 的 urls 格式）
export async function buildDe5Lines(key) {
  const manifest = await loadDe5Manifest();
  return manifest.linesByKey[key] || { urls: [] };
}

export async function loadProbeMap(env) {
  const rows = await env.DB.prepare(
    "SELECT api, last_ok, fail_streak, latency_ms FROM site_probe_state WHERE last_checked_at > datetime('now', '-24 hours')"
  ).all();
  const map = new Map();
  for (const row of rows.results || []) {
    map.set(String(row.api), {
      dead: row.fail_streak >= 1,
      latency: row.last_ok ? Number(row.latency_ms || 999_999) : Infinity,
    });
  }
  return map;
}

export async function regenerateArtifacts(env, { probe = false, probeLimit = 250 } = {}) {
  const isInternalUrl = (value) => /(?:^|[^\w.])(?:localhost|127\.0\.0\.1|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|::1)/iu.test(String(value || ""));
  // 仓级准入：只有最近一次同步成功（上游当前可达）的仓才进入地址库
  const rows = await env.DB.prepare(
    "SELECT r.slug, r.name, s.content_json FROM resources r JOIN resource_snapshots s ON s.resource_id = r.id WHERE r.enabled = 1 AND r.type = 'json' AND r.last_sync_error = '' ORDER BY r.created_at ASC, r.slug ASC"
  ).all();
  const excludedWarehouses = await env.DB.prepare(
    "SELECT slug, name, last_sync_error FROM resources WHERE enabled = 1 AND type = 'json' AND last_sync_error != '' LIMIT 50"
  ).all();
  const resources = rows.results || [];
  const origin = String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "");
  const backupBase = String(env.PUBLIC_BACKUP_URL || "").replace(/\/+$/u, "");
  // 分享源头 = 验证可用的外部多仓（dc2），原样作为我们的多仓内容
  const de5 = await buildDe5Multi(origin);
  const multi = JSON.stringify(de5, null, 2);

  // ===== 归类与测速择优 =====
  // 节点身份 = 类型|api|ext；同身份/同归一化名称的多个实例，只保留实测最快的一个
  const groups = new Map(); // identity -> { site, slug, nameNorm }
  const lives = [];
  const parses = [];
  const spiderCandidates = new Map(); // slug -> spider
  const siteCountBySlug = new Map();
  let wallpaper = "";
  let totalRaw = 0;
  const nameNorm = (value) => String(value || "").toLowerCase().replace(/[\s\u3000·•・┃｜│|_\-–——()（）\[\]【】「」『』:：!！?？,，.。'"'"'~～*★☆🔥🎬📺]/gu, "");
  for (const resource of resources) {
    let value;
    try { value = parseJsonWithComments(resource.content_json); } catch { continue; }
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    if (typeof value.spider === "string" && /^https?:\/\//iu.test(value.spider.trim()) && !isInternalUrl(value.spider)) spiderCandidates.set(resource.slug, value.spider.trim());
    if (!wallpaper && typeof value.wallpaper === "string" && /^https?:\/\//iu.test(value.wallpaper) && !isInternalUrl(value.wallpaper)) wallpaper = value.wallpaper;
    const siteList = Array.isArray(value.sites) ? value.sites : [];
    for (let index = 0; index < siteList.length; index++) {
      const site = siteList[index];
      if (!site || typeof site !== "object") continue;
      totalRaw++;
      const siteApi = String(site.api || "").trim();
      let extKey = "";
      if (site.ext !== undefined && site.ext !== null && site.ext !== "") {
        extKey = typeof site.ext === "object" ? JSON.stringify(site.ext) : String(site.ext).trim();
      }
      if (!siteApi) continue;
      const isExecutable = /^https?:\/\//iu.test(siteApi) || /^csp_/iu.test(siteApi);
      if (!isExecutable) continue;
      const identity = [String(site.type ?? ""), siteApi, extKey].join("|");
      const displayName = String(site.name || "").trim() || `${resource.name || resource.slug} ${index + 1}`;
      const existing = groups.get(identity);
      if (existing) {
        existing.copies.push({ slug: resource.slug, name: displayName });
        continue;
      }
      groups.set(identity, { site, slug: resource.slug, name: displayName, identity, copies: [{ slug: resource.slug, name: displayName }] });
      siteCountBySlug.set(resource.slug, (siteCountBySlug.get(resource.slug) || 0) + 1);
    }
    const lifeList = Array.isArray(value.lives) ? value.lives : [];
    for (const life of lifeList) {
      if (!life || typeof life !== "object" || !String(life.name || "").trim()) continue;
      // 形态一：type 0 + 直播源 url（m3u/txt/php），必须全部为公网 http(s)
      if (Array.isArray(life.groups)) {
        const cleanGroups = [];
        for (const group of life.groups) {
          if (!group || typeof group !== "object" || !String(group.name || "").trim()) continue;
          const urls = Array.isArray(group.urls) ? group.urls.filter((u) => typeof u === "string" && /^https?:\/\//iu.test(u) && !isInternalUrl(u)) : [];
          if (!urls.length) continue;
          cleanGroups.push({ name: String(group.name).trim(), urls });
        }
        if (cleanGroups.length && lives.length < 20) lives.push({ name: String(life.name).trim(), groups: cleanGroups });
        continue;
      }
      if (typeof life.url === "string" && life.url.trim()) {
        const urls = life.url.split("#").filter((u) => /^https?:\/\//iu.test(u) && !isInternalUrl(u));
        if (urls.length && lives.length < 20) lives.push({ name: String(life.name).trim(), type: 0, url: urls.join("#") });
      }
    }
    const parseList = Array.isArray(value.parses) ? value.parses : [];
    for (const parse of parseList) {
      if (!parse || typeof parse !== "object") continue;
      const name = String(parse.name || "").trim();
      const url = String(parse.url || "").trim();
      if (!name || !/^https?:\/\//iu.test(url) || isInternalUrl(url)) continue;
      if (parses.some((item) => String(item.name || "").toLowerCase() === name.toLowerCase())) continue;
      if (parses.length >= 12) continue;
      parses.push({ name, type: Number(parse.type) === 1 ? 1 : 0, url });
    }
  }

  // 探活（可选）+ 载入耗时与可达状态
  let probeStats = { checked: 0, alive: 0, dead: 0, blocked: 0, skipped: 0 };
  const probeInput = [];
  for (const group of groups.values()) {
    const api = String(group.site.api || "").trim();
    if (/^https?:\/\//iu.test(api)) probeInput.push({ api });
  }
  if (probe) probeStats = { ...probeStats, ...(await probeHttpApis(env, probeInput, { limit: probeLimit })) };
  const probeMap = await loadProbeMap(env);

  // spider（jar 包）实测择优：按"贡献合并节点数最多"的仓优先，逐一实测必须是有效 ZIP（PK 魔数），否则不携带
  async function validateJar(candidate) {
    const url = String(candidate || "").split(";")[0].trim();
    if (!/^https?:\/\//iu.test(url)) return false;
    try {
      const response = await fetch(url, { redirect: "follow", headers: { "user-agent": "Mozilla/5.0", accept: "application/java-archive, application/zip, application/octet-stream, */*" }, signal: AbortSignal.timeout(12_000) });
      if (!response.ok) return false;
      const head = new Uint8Array(await (await response.arrayBuffer()).slice(0, 2));
      const isZip = head[0] === 0x50 && head[1] === 0x4b;
      const ctype = (response.headers.get("content-type") || "").toLowerCase();
      if (isZip || ctype.includes("zip") || ctype.includes("java-archive") || ctype.includes("octet-stream")) return true;
      return false;
    } catch { return false; }
  }
  const spiderRanking = [...spiderCandidates.entries()]
    .map(([slug, spider]) => ({ slug, spider, sites: siteCountBySlug.get(slug) || 0 }))
    .sort((a, b) => b.sites - a.sites)
    .slice(0, 6);
  let mergedSpider = "";
  const spiderReport = [];
  for (const candidate of spiderRanking) {
    let valid = await validateJar(candidate.spider);
    if (!valid) valid = await validateJar(candidate.spider); // 抖动重试一次
    spiderReport.push({ slug: candidate.slug, sites: candidate.sites, valid });
    if (valid && !mergedSpider) mergedSpider = candidate.spider;
  }
  if (mergedSpider) {
    await env.DB.prepare("INSERT INTO app_settings (setting_key, plain_value, encrypted_value, updated_at) VALUES ('last_good_spider', ?, NULL, ?) ON CONFLICT(setting_key) DO UPDATE SET plain_value = excluded.plain_value, updated_at = excluded.updated_at")
      .bind(mergedSpider, nowIso()).run();
  } else {
    const lastGood = await env.DB.prepare("SELECT plain_value FROM app_settings WHERE setting_key = 'last_good_spider'").first();
    if (lastGood?.plain_value) { mergedSpider = lastGood.plain_value; spiderReport.push({ slug: "last-good", sites: 0, valid: true }); }
  }

  // 同名组内测速择优：http 型按实测耗时取最快；未测的排后；不可达的剔除；csp 型保留首个
  const mergedSites = [];
  const usedDisplayNames = new Set();
  let mergedDead = 0;
  for (const group of groups.values()) {
    const api = String(group.site.api || "").trim();
    const isHttp = /^https?:\/\//iu.test(api);
    if (isHttp) {
      const state = probeMap.get(api);
      if (state && state.dead) { mergedDead++; continue; }
      group.latency = state ? state.latency : 999_999;
    }
    mergedSites.push(group);
  }
  mergedSites.sort((a, b) => a.latency - b.latency);
  // 精华上限：http 按实测耗时取 75%，csp 保留 25%（保证爬虫节点配额）
  const maxMerged = Math.min(600, Math.max(100, Number(env.MERGED_MAX_SITES || 600)));
  if (mergedSites.length > maxMerged) {
    const httpAlive = mergedSites.filter((g) => g.latency < 999_999);
    const others = mergedSites.filter((g) => !(g.latency < 999_999));
    const httpQuota = Math.min(httpAlive.length, Math.round(maxMerged * 0.75));
    const kept = [...httpAlive.slice(0, httpQuota), ...others.slice(0, maxMerged - httpQuota)];
    mergedSites.length = 0;
    mergedSites.push(...kept);
  }
  const merged = { sites: [], lives, parses };
  if (mergedSpider) merged.spider = mergedSpider;
  if (wallpaper) merged.wallpaper = wallpaper;
  let siteIndex = 0;
  for (const group of mergedSites) {
    siteIndex++;
    const site = group.site;
    const siteApi = String(site.api || "").trim();
    // 严格消毒：api 不能是内网/本地地址
    if (isInternalUrl(siteApi)) continue;
    const displayName = (() => {
      let name = group.name;
      if (name && usedDisplayNames.has(name)) name = `${name} · ${group.copies[0].slug}`;
      if (name) usedDisplayNames.add(name);
      return name || `节点 ${siteIndex}`;
    })();
    // 稳定 key：由节点身份派生（重建间不变，收藏/历史不丢）
    const clean = {
      ...site,
      key: "aitv_" + (await sha256Hex(group.identity)).slice(0, 16),
      name: displayName,
      searchable: site.searchable ?? 1,
      quickSearch: site.quickSearch ?? 1,
      filterable: site.filterable ?? 1,
      changeable: site.changeable ?? 0,
    };
    // 相对路径 api 解析为绝对地址（合并后脱离原仓域名，相对路径会失效）
    if (siteApi && !/^https?:\/\//iu.test(siteApi) && !/^csp_/iu.test(siteApi)) {
      try { clean.api = new URL(siteApi, resource.upstream_url).href; } catch {}
    }
    // csp 节点绑定其来源仓的 jar：每个节点用自己仓库的爬虫包，类名必然存在
    if (/^csp_/iu.test(String(clean.api || "")) && !clean.jar) {
      const warehouseSpider = spiderCandidates.get(group.slug);
      if (warehouseSpider) clean.jar = warehouseSpider;
    }
    if (clean.jar && isInternalUrl(String(clean.jar))) delete clean.jar;
    merged.sites.push(clean);
  }
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
    spider: { picked: mergedSpider, report: spiderReport },
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

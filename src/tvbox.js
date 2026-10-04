import { parseJsonList, parseJsonWithComments, sha256Hex } from "./security.js";
import { responseHeaders, error } from "./http.js";
import { noteWeakDevice } from "./devices.js";
import { rewriteJsonText, gatewayOrigin } from "./rewrite.js";
import { MEMBER_JS } from "./ui.js";

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{42,48}$/u;
const AGGREGATE_MAX_BYTES = 6_291_456;

const MEMBER_STATUSES_ZH = {
  active: "生效中",
  pending: "待审核",
  paused: "已暂停",
  expired: "已过期",
  revoked: "已撤销",
};

async function lookupSubscriptionToken(db, tokenHash) {
  return db.prepare(
    "SELECT t.id AS token_id, t.member_id, t.revoked_at, m.telegram_user_id, m.display_name, m.status AS member_status, m.expires_at, m.max_devices, m.plan_id, p.name AS plan_name, p.enabled AS plan_enabled FROM tokens t JOIN members m ON m.id = t.member_id LEFT JOIN plans p ON p.id = m.plan_id WHERE t.token_hash = ? ORDER BY t.created_at DESC LIMIT 1"
  ).bind(tokenHash).first();
}

function memberUsable(lookup) {
  return Boolean(lookup?.token_id) && !lookup.revoked_at &&
    lookup.member_status === "active" && lookup.plan_enabled &&
    lookup.expires_at && Date.parse(lookup.expires_at) > Date.now();
}

async function loadPlanJsonResources(db, planId) {
  const result = await db.prepare(
    "SELECT r.id, r.slug, r.name, r.upstream_url, r.allowed_hosts, r.rewrite_fields, r.content_hash, s.content_json, s.synced_at, s.url_count FROM resources r JOIN plan_resources pr ON pr.resource_id = r.id AND pr.plan_id = ? LEFT JOIN resource_snapshots s ON s.resource_id = r.id WHERE r.enabled = 1 AND r.type = 'json' ORDER BY r.created_at ASC, r.slug ASC"
  ).bind(planId).all();
  return (result.results || []).filter((row) => typeof row.content_json === "string" && row.content_json.length > 0);
}

async function jsonSubscriptionResponse(request, bodyText) {
  const etag = '"' + (await sha256Hex(bodyText)).slice(0, 32) + '"';
  if (request.headers.get("if-none-match") === etag) {
    return new Response(null, { status: 304, headers: responseHeaders({ etag }) });
  }
  return new Response(bodyText, {
    status: 200,
    headers: responseHeaders({
      "content-type": "application/json; charset=utf-8",
      "content-length": String(new TextEncoder().encode(bodyText).byteLength),
      etag,
    }),
  });
}

function buildMultiWarehouse(resources, origin, token) {
  const entries = resources.map((resource) => ({
    sourceName: resource.name || resource.slug,
    sourceUrl: `${origin}/${token}/${resource.slug}.json`,
  }));
  return JSON.stringify({
    storeHouse: entries,
    urls: entries.map((entry) => ({ name: entry.sourceName, url: entry.sourceUrl })),
  }, null, 2);
}

async function buildMergedWarehouse(request, env, resources, origin, token) {
  const merged = { sites: [], lives: [], parses: [] };
  const usedSiteNames = new Set();
  const usedParseNames = new Set();
  let usedBytes = 0;
  for (const resource of resources) {
    const fields = new Set(parseJsonList(resource.rewrite_fields));
    const allowedHosts = parseJsonList(resource.allowed_hosts).map((host) => String(host).toLowerCase());
    const prefix = `${origin}/${token}/${resource.slug}`;
    let text;
    try {
      text = await rewriteJsonText(resource.content_json, fields, new URL(resource.upstream_url), prefix, allowedHosts, env);
    } catch {
      continue;
    }
    let value;
    try { value = parseJsonWithComments(text); } catch { continue; }
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    if (!merged.spider && typeof value.spider === "string" && value.spider) merged.spider = value.spider;
    if (!merged.wallpaper && typeof value.wallpaper === "string" && value.wallpaper) merged.wallpaper = value.wallpaper;
    const siteList = Array.isArray(value.sites) ? value.sites : [];
    for (let index = 0; index < siteList.length; index++) {
      const site = siteList[index];
      if (!site || typeof site !== "object") continue;
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
    usedBytes += resource.content_json.length;
    if (usedBytes > AGGREGATE_MAX_BYTES) break;
  }
  if (!merged.sites.length && !merged.lives.length) return { error: "AGGREGATE_EMPTY" };
  const bodyText = JSON.stringify(merged, null, 2);
  if (bodyText.length > AGGREGATE_MAX_BYTES) return { error: "AGGREGATE_TOO_LARGE" };
  return { bodyText };
}

export async function serveAggregate(request, env, token, variant) {
  if (!TOKEN_PATTERN.test(token)) return error("TOKEN_INVALID", 401);
  if (request.method !== "GET" && request.method !== "HEAD") return error("METHOD_NOT_ALLOWED", 405);
  const tokenHash = await sha256Hex(token);
  const lookup = await lookupSubscriptionToken(env.DB, tokenHash);
  const limited = await env.MEMBER_LIMITER.limit({ key: tokenHash });
  if (!limited.success) return error("RATE_LIMITED", 429);
  if (!lookup?.token_id || lookup.revoked_at) return error("TOKEN_INVALID", 401);
  if (!memberUsable(lookup)) {
    if (!lookup?.token_id || lookup.revoked_at) return error("TOKEN_INVALID", 401);
    if (lookup.member_status !== "active" || !lookup.expires_at || Date.parse(lookup.expires_at) <= Date.now()) return error("MEMBER_EXPIRED", 403);
    if (!lookup.plan_enabled) return error("PLAN_DISABLED", 403);
    return error("MEMBER_NOT_ACTIVE", 403);
  }
  const device = await noteWeakDevice(env.DB, lookup.member_id, request);
  if (device.blocked) return error(device.reason || "DEVICE_REMOVED", 403);
  const resources = await loadPlanJsonResources(env.DB, lookup.plan_id);
  if (!resources.length) return error("AGGREGATE_EMPTY", 404);
  const origin = gatewayOrigin(request, env);
  let bodyText;
  if (variant === "tvbox") {
    bodyText = buildMultiWarehouse(resources, origin, token);
  } else {
    const merged = await buildMergedWarehouse(request, env, resources, origin, token);
    if (merged.error) return error(merged.error, merged.error === "AGGREGATE_EMPTY" ? 404 : 413);
    bodyText = merged.bodyText;
  }
  if (request.method === "HEAD") return new Response(null, { status: 200, headers: responseHeaders({ "content-type": "application/json; charset=utf-8" }) });
  return jsonSubscriptionResponse(request, bodyText);
}

export async function serveCatalog(request, env, variant) {
  if (request.method !== "GET" && request.method !== "HEAD") return error("METHOD_NOT_ALLOWED", 405);
  if (variant === "status") {
    const [repos, resources] = await Promise.all([
      env.DB.prepare("SELECT kind, name, url, enabled, last_checked_at, last_ok, last_error FROM catalog_repositories ORDER BY kind, created_at ASC LIMIT 500").all(),
      env.DB.prepare("SELECT slug, name, upstream_url, enabled, last_sync_attempt_at, last_sync_error, (SELECT synced_at FROM resource_snapshots s WHERE s.resource_id = r.id) AS synced_at, (SELECT url_count FROM resource_snapshots s WHERE s.resource_id = r.id) AS url_count FROM resources r WHERE type = 'json' ORDER BY created_at ASC LIMIT 500").all(),
    ]);
    return jsonSubscriptionResponse(request, JSON.stringify({ generated_at: new Date().toISOString(), repositories: repos.results || [], resources: resources.results || [] }, null, 2));
  }
  const [repos, resources] = await Promise.all([
    env.DB.prepare("SELECT name, url FROM catalog_repositories WHERE enabled = 1 AND last_ok = 1 AND kind IN ('multi', 'single') ORDER BY kind ASC, created_at ASC LIMIT 300").all(),
    env.DB.prepare("SELECT name, upstream_url FROM resources WHERE enabled = 1 AND type = 'json' AND content_hash != '' ORDER BY created_at ASC LIMIT 300").all(),
  ]);
  const entries = [
    ...(repos.results || []).map((row) => ({ sourceName: row.name || "外部仓库", sourceUrl: row.url })),
    ...(resources.results || []).map((row) => ({ sourceName: (row.name || row.slug) + " · 本站", sourceUrl: row.upstream_url })),
  ];
  if (!entries.length) return error("AGGREGATE_EMPTY", 404);
  return jsonSubscriptionResponse(request, JSON.stringify({
    storeHouse: entries,
    urls: entries.map((entry) => ({ name: entry.sourceName, url: entry.sourceUrl })),
  }, null, 2));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/gu, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

export async function serveMemberPage(request, env, token) {
  if (request.method !== "GET" && request.method !== "HEAD") return error("METHOD_NOT_ALLOWED", 405);
  if (!TOKEN_PATTERN.test(token)) return memberNoticePage("地址无效", "该分发地址格式不正确，请向管理员重新获取。", 404);
  const tokenHash = await sha256Hex(token);
  const lookup = await lookupSubscriptionToken(env.DB, tokenHash);
  if (!lookup?.token_id || lookup.revoked_at) return memberNoticePage("地址无效", "该分发地址不存在或已被重置，请向管理员重新获取。", 404);
  const deviceRow = await env.DB.prepare("SELECT COUNT(*) AS count FROM devices WHERE member_id = ? AND revoked_at IS NULL").bind(lookup.member_id).first();
  const activeDevices = Number(deviceRow?.count || 0);
  const usable = memberUsable(lookup);
  let resources = [];
  let origin = gatewayOrigin(request, env);
  if (usable) {
    const rows = await env.DB.prepare(
      "SELECT r.slug, r.name, s.synced_at, s.url_count FROM resources r JOIN plan_resources pr ON pr.resource_id = r.id AND pr.plan_id = ? LEFT JOIN resource_snapshots s ON s.resource_id = r.id WHERE r.enabled = 1 AND r.type = 'json' ORDER BY r.created_at ASC, r.slug ASC"
    ).bind(lookup.plan_id).all();
    resources = (rows.results || []).filter((row) => row.synced_at);
  }
  const data = {
    display_name: lookup.display_name || lookup.telegram_user_id,
    status: lookup.member_status,
    status_label: MEMBER_STATUSES_ZH[lookup.member_status] || lookup.member_status,
    expires_at: lookup.expires_at || "",
    plan_name: lookup.plan_name || "",
    active_devices: activeDevices,
    max_devices: Number(lookup.max_devices || 1),
    origin,
    token,
    usable,
    resources,
  };
  const html = memberPageHtml(data);
  return new Response(request.method === "HEAD" ? null : html, {
    status: 200,
    headers: responseHeaders({ "content-type": "text/html; charset=utf-8" }),
  });
}

function memberNoticePage(title, message, status) {
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><style>${MEMBER_PAGE_CSS}</style></head><body><div class="notice"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></div></body></html>`;
  return new Response(html, { status, headers: responseHeaders({ "content-type": "text/html; charset=utf-8" }) });
}

const MEMBER_PAGE_CSS = `
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #0b0f17; color: #e6ebf5; font-family: -apple-system, "PingFang SC", "Microsoft YaHei", system-ui, sans-serif; }
.notice { max-width: 480px; margin: 18vh auto; text-align: center; padding: 0 24px; }
.notice h1 { font-size: 22px; }
.notice p { color: #8b95a8; }
.wrap { max-width: 720px; margin: 0 auto; padding: 32px 20px 64px; }
header.top { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
.brand { font-size: 20px; font-weight: 700; letter-spacing: .5px; }
.badge { font-size: 12px; padding: 4px 10px; border-radius: 999px; border: 1px solid #2a3548; color: #9fb0c9; }
.badge.ok { color: #67e08b; border-color: #275c39; }
.meta { color: #8b95a8; font-size: 13px; margin-bottom: 24px; }
.meta b { color: #c6d2e4; font-weight: 600; }
.card { background: #121927; border: 1px solid #223049; border-radius: 14px; padding: 18px; margin-bottom: 16px; }
.card h2 { margin: 0 0 4px; font-size: 16px; }
.card .desc { color: #8b95a8; font-size: 12.5px; margin-bottom: 12px; }
.urlrow { display: flex; gap: 8px; align-items: stretch; }
.urlrow code { flex: 1; background: #0b1220; border: 1px solid #223049; border-radius: 8px; padding: 10px 12px; font-size: 12.5px; word-break: break-all; color: #9fd0ff; user-select: all; }
button { background: #2f6fed; border: none; color: #fff; border-radius: 8px; padding: 10px 14px; font-size: 13px; cursor: pointer; }
button.ghost { background: #1b2536; color: #9fb0c9; }
button:active { transform: translateY(1px); }
.actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.reslist { list-style: none; margin: 0; padding: 0; }
.reslist li { display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 10px 0; border-top: 1px solid #1c2739; }
.reslist li:first-child { border-top: none; }
.resname { font-size: 14px; }
.ressub { color: #8b95a8; font-size: 12px; margin-top: 2px; }
.qr { background: #fff; padding: 10px; border-radius: 10px; display: none; width: fit-content; margin-top: 12px; }
.qr.show { display: block; }
.qr svg, .qr img { display: block; }
ol.steps { color: #a7b3c7; font-size: 13px; line-height: 1.9; padding-left: 18px; margin: 8px 0 0; }
footer { color: #5f6b80; font-size: 12px; margin-top: 28px; text-align: center; }
.toast { position: fixed; left: 50%; bottom: 36px; transform: translateX(-50%); background: #1f2b40; color: #dfe8f6; padding: 10px 18px; border-radius: 999px; font-size: 13px; opacity: 0; transition: opacity .2s; pointer-events: none; }
.toast.show { opacity: 1; }
`;

function memberPageHtml(data) {
  const body = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>DTV 影视订阅</title><style>${MEMBER_PAGE_CSS}</style></head><body><div class="wrap"><header class="top"><div class="brand">DTV 影视订阅</div><div class="badge${data.usable ? " ok" : ""}">${escapeHtml(data.status_label)}</div></header><div class="meta">会员 <b>${escapeHtml(data.display_name)}</b>${data.plan_name ? " · 套餐 <b>" + escapeHtml(data.plan_name) + "</b>" : ""}${data.expires_at ? " · 有效期至 <b>" + escapeHtml(data.expires_at.slice(0, 10)) + "</b>" : ""} · 设备 <b>${data.active_devices}/${data.max_devices}</b></div><div id="app"></div><div class="card"><h2>使用说明</h2><ol class="steps"><li>在电视/手机上打开 TVBox（影视仓等兼容应用）。</li><li>进入「设置 → 配置地址」，选择扫码或粘贴多仓订阅地址。</li><li>保存后在仓库列表中选择任意一个仓库即可观看。</li><li>地址仅限本人使用，请勿转发；泄露后可在 Bot 中一键重置。</li></ol></div><footer>生成于 ${escapeHtml(new Date().toISOString().slice(0, 16).replace("T", " "))} · DTV 多仓分享平台</footer></div><div class="toast" id="toast"></div><script>window.__DTV__=${JSON.stringify(data)};</script><script>${MEMBER_JS}</script></body></html>`;
  return body;
}

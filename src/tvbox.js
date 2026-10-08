import { sha256Hex } from "./security.js";
import { responseHeaders, error } from "./http.js";
import { noteWeakDevice } from "./devices.js";
import { rewriteJsonText, gatewayOrigin } from "./rewrite.js";
import { buildDe5Lines, buildDe5Multi } from "./sync.js";
import { MEMBER_JS } from "./ui.js";

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{42,48}$/u;

const MEMBER_STATUSES_ZH = {
  active: "生效中",
  pending: "待审核",
  paused: "已暂停",
  expired: "已过期",
  revoked: "已撤销",
};

async function lookupSubscriptionToken(db, tokenHash) {
  return db.prepare(
    "SELECT t.id AS token_id, t.member_id, t.revoked_at, m.telegram_user_id, m.display_name, m.status AS member_status, m.expires_at, m.max_devices, m.plan_id, p.name AS plan_name, p.enabled AS plan_enabled, COALESCE(p.include_all, 0) AS include_all FROM tokens t JOIN members m ON m.id = t.member_id LEFT JOIN plans p ON p.id = m.plan_id WHERE t.token_hash = ? ORDER BY t.created_at DESC LIMIT 1"
  ).bind(tokenHash).first();
}

function memberUsable(lookup) {
  return Boolean(lookup?.token_id) && !lookup.revoked_at &&
    lookup.member_status === "active" && lookup.plan_enabled &&
    lookup.expires_at && Date.parse(lookup.expires_at) > Date.now();
}

// 会员可见的仓清单：启用 + 类型 json + 最近同步成功（上游当前可达）+ 有快照
async function loadPlanWarehouseMeta(db, planId, includeAll = 0) {
  const base = "SELECT r.slug, r.name FROM resources r JOIN resource_snapshots s ON s.resource_id = r.id WHERE r.enabled = 1 AND r.type = 'json' AND r.last_sync_error = ''";
  const tail = " ORDER BY r.created_at ASC, r.slug ASC";
  const result = includeAll
    ? await db.prepare(base + tail).all()
    : await db.prepare(base + " AND EXISTS (SELECT 1 FROM plan_resources pr WHERE pr.plan_id = ? AND pr.resource_id = r.id)" + tail).bind(planId).all();
  return result.results || [];
}

function isPermanentExpiry(value) {
  const parsed = Date.parse(value || "");
  return Number.isFinite(parsed) && parsed > Date.now() + 80 * 365.5 * 86_400_000;
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

async function buildMultiWarehouse(env, origin) {
  // 会员多仓 = AiTV 多仓（4 仓：de5 主站 + 3 备份站，与公开分享同源）
  let de5 = await buildDe5Multi(origin);
  if (!de5) de5 = await buildDe5Multi(origin); // 瞬时失败重试一次
  if (de5) return JSON.stringify(de5, null, 2);
  // 仍失败：回退到存库的最近一次产物
  const row = await env.DB.prepare("SELECT content FROM generated_artifacts WHERE key = 'catalog:multi'").first();
  return row?.content || JSON.stringify({ storeHouse: [] }, null, 2);
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
  const warehouses = await loadPlanWarehouseMeta(env.DB, lookup.plan_id, lookup.include_all);
  if (!warehouses.length) return error("AGGREGATE_EMPTY", 404);
  const origin = gatewayOrigin(request, env);
  let bodyText;
  if (variant === "aitv-main" || variant === "aitv-backup") {
    const base = variant === "aitv-backup" ? (String(env.PUBLIC_BACKUP_URL || "").replace(/\/+$/u, "") || origin) : origin;
    bodyText = JSON.stringify({ urls: [{ name: "AiTV聚合精华线路", url: `${base}/${token}/all.json` }] }, null, 2);
  } else if (variant === "tvbox") {
    const primary = String(env.PUBLIC_BASE_URL || "").replace(/\/+$/u, "");
    const backupBase = String(env.PUBLIC_BACKUP_URL || "").replace(/\/+$/u, "");
    const altOrigin = origin === backupBase ? primary : backupBase;
    bodyText = await buildMultiWarehouse(env, gatewayOrigin(request, env));
  } else {
    // 单仓 = 读取已准入（去重+探活）的合并产物，整体改写为该会员的网关地址
    const artifact = await env.DB.prepare("SELECT content FROM generated_artifacts WHERE key = 'catalog:merged'").first();
    if (!artifact?.content) return error("AGGREGATE_EMPTY", 404, "单仓地址库尚未生成，请联系管理员执行「一键抓取更新」。");
    const anchorSlug = warehouses[0].slug;
    const prefix = `${origin}/${token}/${anchorSlug}`;
    try {
      bodyText = await rewriteJsonText(artifact.content, new Set(), new URL(origin + "/"), prefix, [], env);
    } catch {
      return error("AGGREGATE_FAILED", 502);
    }
  }
  if (request.method === "HEAD") return new Response(null, { status: 200, headers: responseHeaders({ "content-type": "application/json; charset=utf-8" }) });
  return jsonSubscriptionResponse(request, bodyText);
}

async function cachedText(request, build, extra = {}) {
  // 不使用 Cache API：低频端点每次现生成，避免任何陈旧缓存；边缘缓存由 s-maxage 控制
  const bodyText = await build();
  const etag = '"' + (await sha256Hex(bodyText)).slice(0, 32) + '"';
  if (request.headers.get("if-none-match") === etag) {
    const notModified = new Response(null, { status: 304, headers: responseHeaders({ etag, "cache-control": "public, max-age=300, s-maxage=1800" }) });
    return notModified;
  }
  const response = new Response(bodyText, {
    status: 200,
    headers: responseHeaders({
      "content-type": "application/json; charset=utf-8",
      etag,
      "cache-control": "public, max-age=300, s-maxage=1800",
    }),
  });
  try { await cache.put(request, response.clone()); } catch {}
  return response;
}

export async function serveCatalog(request, env, variant) {
  if (request.method !== "GET" && request.method !== "HEAD") return error("METHOD_NOT_ALLOWED", 405);
  if (variant.startsWith("lines:")) {
    const lines = await buildDe5Lines(variant.slice(6));
    return cachedText(request, async () => JSON.stringify(lines, null, 2));
  }
  if (variant === "tvbox" || variant === "all" || variant === "nodes" || variant === "aitv-main" || variant === "aitv-backup") {
    const key = variant === "tvbox" ? "catalog:multi" : variant === "aitv-main" ? "catalog:aitv-main" : variant === "aitv-backup" ? "catalog:aitv-backup" : "catalog:merged";
    const row = await env.DB.prepare("SELECT content FROM generated_artifacts WHERE key = ?").bind(key).first();
    if (!row?.content) return error("AGGREGATE_EMPTY", 404, "地址库尚未生成，请在后台执行一次「一键抓取更新」。");
    return cachedText(request, async () => row.content);
  }
  if (variant === "status") {
    const [repos, resources, artifacts] = await Promise.all([
      env.DB.prepare("SELECT kind, name, url, enabled, last_checked_at, last_ok, last_error FROM catalog_repositories ORDER BY kind, created_at ASC LIMIT 500").all(),
      env.DB.prepare("SELECT slug, name, upstream_url, enabled, last_sync_attempt_at, last_sync_error, (SELECT synced_at FROM resource_snapshots s WHERE s.resource_id = r.id) AS synced_at, (SELECT url_count FROM resource_snapshots s WHERE s.resource_id = r.id) AS url_count FROM resources r WHERE type = 'json' ORDER BY created_at ASC LIMIT 500").all(),
      env.DB.prepare("SELECT key, generated_at, LENGTH(content) AS bytes FROM generated_artifacts").all(),
    ]);
    return jsonSubscriptionResponse(request, JSON.stringify({
      generated_at: new Date().toISOString(),
      artifacts: artifacts.results || [],
      repositories: repos.results || [],
      resources: resources.results || [],
    }, null, 2));
  }
  return error("NOT_FOUND", 404);
}

export async function serveCatalogSource(request, env, slug) {
  if (request.method !== "GET" && request.method !== "HEAD") return error("METHOD_NOT_ALLOWED", 405);
  if (!/^[a-z0-9][a-z0-9._-]{1,39}$/iu.test(slug)) return error("PATH_INVALID", 400);
  const row = await env.DB.prepare(
    "SELECT s.content_json, s.source_content_type FROM resources r JOIN resource_snapshots s ON s.resource_id = r.id WHERE r.slug = ? AND r.enabled = 1 AND r.type = 'json'"
  ).bind(slug).first();
  if (!row?.content_json) return error("AGGREGATE_EMPTY", 404);
  let normFail = "";
  return cachedText(request, async () => {
    try {
      return JSON.stringify(parseJsonWithComments(row.content_json));
    } catch (err) {
      normFail = String(err?.message || err).slice(0, 100);
      return row.content_json;
    }
  }, { "x-norm-fail": normFail });
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
  const origin = gatewayOrigin(request, env);
  const primaryBase = String(env.PUBLIC_BASE_URL || "").replace(/\/+$/u, "");
  const backupBase = String(env.PUBLIC_BACKUP_URL || "").replace(/\/+$/u, "");
  const data = {
    backup_origin: origin === backupBase ? primaryBase : backupBase,
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
.logo { width: 46px; height: 46px; border-radius: 13px; flex: none; }
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
  const body = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AITV 共享社区</title>
<meta name="theme-color" content="#0D1526"><link rel="icon" type="image/png" href="/logo.png?v=aitv1"><style>${MEMBER_PAGE_CSS}</style></head><body><div class="wrap"><header class="top"><img class="logo" src="/logo.png?v=aitv1" alt="AITV"><div class="brand">AITV 共享社区</div><div class="badge${data.usable ? " ok" : ""}">${escapeHtml(data.status_label)}</div></header><div class="meta">会员 <b>${escapeHtml(data.display_name)}</b>${data.plan_name ? " · 套餐 <b>" + escapeHtml(data.plan_name) + "</b>" : ""}${data.expires_at ? (isPermanentExpiry(data.expires_at) ? " · <b>永久有效</b>" : " · 有效期至 <b>" + escapeHtml(data.expires_at.slice(0, 10)) + "</b>") : ""} · 设备 <b>${data.active_devices}/${data.max_devices}</b></div><div id="app"></div><div class="card"><h2>使用说明</h2><ol class="steps"><li>在电视/手机上打开 TVBox（影视仓等兼容应用）。</li><li>进入「设置 → 配置地址」，选择扫码或粘贴多仓订阅地址。</li><li>保存后在仓库列表中选择任意一个仓库即可观看。</li><li>地址仅限本人使用，请勿转发；泄露后可在 Bot 中一键重置。</li></ol></div><footer>生成于 ${escapeHtml(new Date().toISOString().slice(0, 16).replace("T", " "))} · AITV 共享社区 · AI 多仓聚合分享</footer></div><div class="toast" id="toast"></div><script>window.__DTV__=${JSON.stringify(data)};</script><script>${MEMBER_JS}</script></body></html>`;
  return body;
}

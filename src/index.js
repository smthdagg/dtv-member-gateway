import { adminApi } from "./admin.js";
import { telegramWebhook } from "./telegram.js";
import { apiError, decryptToken, encryptOpaque, json, parseJsonList, parseJsonWithComments, sha256Hex, stripJsonComments } from "./security.js";
import { ADMIN_HTML, APP_JS, LOGO_PNG_BASE64, STYLE_CSS } from "./ui.js";

const encoder = new TextEncoder();
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{42,48}$/u;

function responseHeaders(extra = {}) {
  return {
    "cache-control": "no-store, private",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    ...extra,
  };
}

function error(code, status, message = code) {
  const messages = {
    DEVICE_LIMIT_EXCEEDED: "设备数量已达到上限。请在 Bot 的设备管理中移除旧设备，或申请增加设备数。",
    DEVICE_REMOVED: "此设备记录已被移除，当前设备标识不能继续访问。",
    UPSTREAM_FETCH_FAILED: "上游接口连接失败，请稍后重试或联系管理员检查资源同步。",
    UPSTREAM_HTTP_ERROR: "上游接口返回错误，请管理员检查资源地址和访问权限。",
    UPSTREAM_JSON_INVALID: "上游内容不是有效 JSON，请管理员检查接口格式。",
    UPSTREAM_REDIRECT_BLOCKED: "上游接口跳转到了不受支持的地址，请管理员检查资源配置。",
    UPSTREAM_RESPONSE_TOO_LARGE: "上游接口返回内容超过允许大小。",
    RESOURCE_STREAM_UNSUPPORTED: "此资源返回了不支持的音视频流。",
    TARGET_INVALID: "此分发地址的转发凭证无效，请从 Bot 重新获取当前地址。",
  };
  if (message === code && messages[code]) message = messages[code];
  return json({ error: { code, message } }, status, responseHeaders());
}

function subscriptionResponse(response) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET, HEAD, OPTIONS");
  headers.set("access-control-allow-headers", "Accept, Authorization, Content-Type, Range");
  headers.set("access-control-expose-headers", "Accept-Ranges, Content-Length, Content-Range, Content-Type");
  headers.set("access-control-max-age", "86400");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function isApprovedHost(hostname, allowedHosts) {
  const host = hostname.toLowerCase().replace(/\.$/u, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host) || host.includes(":")) return false;
  return allowedHosts.includes(host);
}

function isPublicHostname(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/u, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".lan")) return false;
  if (/^(?:\d{1,3}\.){4}$/u.test(host) || /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host) || host.includes(":" ) || host.startsWith("[")) return false;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(host);
}

async function writeUsage(db, memberId, resourceId, allowed) {
  const now = new Date();
  await db.prepare("INSERT INTO usage_hourly (hour, member_id, resource_id, allowed_count, denied_count, last_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(hour, member_id, resource_id) DO UPDATE SET allowed_count = allowed_count + excluded.allowed_count, denied_count = denied_count + excluded.denied_count, last_seen = excluded.last_seen")
    .bind(now.toISOString().slice(0, 13), memberId, resourceId, allowed ? 1 : 0, allowed ? 0 : 1, now.toISOString()).run();
}

function deviceGeography(request) {
  const cf = request.cf || {};
  const country = String(cf.country || request.headers.get("cf-ipcountry") || "").trim().toUpperCase();
  const region = String(cf.regionCode || cf.region || "").trim().toLowerCase();
  const city = String(cf.city || "").trim().toLowerCase();
  const latitude = Number(cf.latitude);
  const longitude = Number(cf.longitude);
  const coordinates = Number.isFinite(latitude) && Number.isFinite(longitude)
    ? (Math.round(latitude * 100) / 100) + "," + (Math.round(longitude * 100) / 100)
    : "";
  const key = [country, region, city, coordinates].filter(Boolean).join("|") || "unknown";
  const label = [cf.city, cf.region || cf.regionCode, cf.country].filter(Boolean).map(String).join(", ") || (country || "位置未知");
  return { key, label };
}

async function noteWeakDevice(db, memberId, request) {
  const ip = request.headers.get("cf-connecting-ip") || "";
  const agent = String(request.headers.get("user-agent") || "unknown").replace(/[\r\n\t]/gu, " ").slice(0, 300);
  const geography = deviceGeography(request);
  const signatureHash = await sha256Hex("ua-geo:" + agent.toLowerCase().replace(/\s+/gu, " ").trim() + ":" + geography.key);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const existing = await db.prepare("SELECT id, revoked_at, last_seen FROM devices WHERE member_id = ? AND signature_hash = ?")
    .bind(memberId, signatureHash).first();
  if (existing?.revoked_at) return { blocked: true, id: existing.id };
  if (existing) {
    const lastSeen = Date.parse(existing.last_seen || "");
    if (!Number.isFinite(lastSeen) || lastSeen < Date.now() - 10 * 60_000) {
      await db.prepare("UPDATE devices SET last_seen = ?, ip_address = ?, user_agent_hint = ?, geo_location = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(now, ip.slice(0, 100), agent.slice(0, 120), geography.label.slice(0, 120), existing.id).run();
    }
    return { blocked: false, id: existing.id };
  }
  const legacy = await db.prepare("SELECT id, signature_hash, revoked_at FROM devices WHERE member_id = ? AND ip_address = ? AND user_agent_hint = ? AND geo_location = '' ORDER BY last_seen DESC LIMIT 1")
    .bind(memberId, ip.slice(0, 100), agent.slice(0, 120)).first();
  if (legacy?.revoked_at) return { blocked: true, reason: "DEVICE_REMOVED", id: legacy.id };
  if (legacy) {
    try {
      const rebound = await db.prepare("UPDATE devices SET signature_hash = ?, geo_location = ? WHERE id = ? AND revoked_at IS NULL AND signature_hash = ?")
        .bind(signatureHash, geography.label.slice(0, 120), legacy.id, legacy.signature_hash).run();
      if (Number(rebound?.meta?.changes || 0) === 1) return { blocked: false, id: legacy.id };
    } catch {}
    const racedLegacy = await db.prepare("SELECT id, revoked_at FROM devices WHERE member_id = ? AND signature_hash = ?")
      .bind(memberId, signatureHash).first();
    if (racedLegacy && !racedLegacy.revoked_at) return { blocked: false, id: racedLegacy.id };
  }
  const inserted = await db.prepare("INSERT INTO devices (id, member_id, signature_hash, trust_level, user_agent_hint, ip_address, geo_location, first_seen, last_seen) SELECT ?, ?, ?, 'weak', ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM devices WHERE member_id = ? AND revoked_at IS NULL) < (SELECT max_devices FROM members WHERE id = ?) AND true ON CONFLICT(member_id, signature_hash) DO NOTHING RETURNING id")
    .bind(id, memberId, signatureHash, agent.slice(0, 120), ip.slice(0, 100), geography.label.slice(0, 120), now, now, memberId, memberId).first();
  if (inserted?.id) return { blocked: false, id: inserted.id };
  const raced = await db.prepare("SELECT id, revoked_at FROM devices WHERE member_id = ? AND signature_hash = ?")
    .bind(memberId, signatureHash).first();
  if (raced && !raced.revoked_at) return { blocked: false, id: raced.id };
  if (raced?.revoked_at) return { blocked: true, reason: "DEVICE_REMOVED", id: raced.id };
  return { blocked: true, reason: "DEVICE_LIMIT_EXCEEDED", id };
}

function safeSuffix(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  const clean = [];
  for (const part of parts) {
    let decoded;
    try { decoded = decodeURIComponent(part); } catch { return null; }
    if (!decoded || decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\") || /[\u0000-\u001f]/u.test(decoded)) return null;
    clean.push(encodeURIComponent(decoded));
  }
  return clean.join("/");
}

function upstreamTarget(resource, suffix, incomingUrl) {
  const base = new URL(resource.upstream_url);
  const basePath = base.pathname.replace(/\/+$/u, "");
  base.pathname = basePath + (suffix ? "/" + suffix : "");
  for (const [key, value] of incomingUrl.searchParams) base.searchParams.append(key, value);
  return base;
}

function isRewriteableAddress(value, key, fields) {
  const text = value.trim();
  if (/^(?:https?:\/\/|\/\/[^/])/iu.test(text)) return true;
  return fields.has(key) && /^(?:\/(?!\/)|\.{1,2}\/|\?.+)/u.test(text);
}

async function fetchBounded(url, allowedHosts, limit, allowPublicTargets = false) {
  let target = new URL(url);
  for (let hop = 0; hop <= 3; hop++) {
    const schemeAllowed = target.protocol === "https:" || (allowPublicTargets && target.protocol === "http:");
    const hostAllowed = allowPublicTargets ? isPublicHostname(target.hostname) : isApprovedHost(target.hostname, allowedHosts);
    if (!schemeAllowed || target.username || target.password || !hostAllowed) {
      return { error: "UPSTREAM_REDIRECT_BLOCKED" };
    }
    const upstream = await fetch(target.href, {
      method: "GET",
      redirect: "manual",
      headers: { accept: "application/json, text/*, application/vnd.apple.mpegurl, application/x-mpegurl, */*;q=0.1", "user-agent": "DTV-Member-Gateway/1.0" },
      signal: AbortSignal.timeout(12_000),
    });
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      const location = upstream.headers.get("location");
      try { await upstream.body?.cancel(); } catch {}
      if (!location || hop === 3) return { error: "UPSTREAM_REDIRECT_BLOCKED" };
      try { target = new URL(location, target); } catch { return { error: "UPSTREAM_REDIRECT_BLOCKED" }; }
      continue;
    }
    const contentType = (upstream.headers.get("content-type") || "application/octet-stream").split(";")[0].trim().toLowerCase();
    const playlistType = contentType.includes("mpegurl") || contentType.includes("x-mpegurl");
    if (!playlistType && (contentType.startsWith("video/") || contentType.startsWith("audio/") || contentType.includes("dash+xml"))) {
      try { await upstream.body?.cancel(); } catch {}
      return { error: "RESOURCE_STREAM_UNSUPPORTED" };
    }
    const announcedSize = Number(upstream.headers.get("content-length") || 0);
    if (announcedSize > limit) {
      try { await upstream.body?.cancel(); } catch {}
      return { error: "UPSTREAM_RESPONSE_TOO_LARGE" };
    }
    const bytes = await readBoundedBody(upstream.body, limit);
    if (!bytes) return { error: "UPSTREAM_RESPONSE_TOO_LARGE" };
    return { upstream, bytes, contentType, finalUrl: target };
  }
  return { error: "UPSTREAM_REDIRECT_BLOCKED" };
}

function passthroughHeaders(upstream) {
  const headers = responseHeaders();
  for (const name of ["content-type", "content-length", "content-range", "accept-ranges", "etag", "last-modified", "content-disposition"]) {
    const value = upstream.headers.get(name);
    if (value) headers[name] = value;
  }
  return headers;
}

function passthroughResponse(upstream, body = upstream.body) {
  const noBody = upstream.status === 204 || upstream.status === 205 || upstream.status === 304 || upstream.status < 200;
  return new Response(noBody ? null : body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: passthroughHeaders(upstream),
  });
}

async function fetchNestedTarget(request, startUrl, limit) {
  let target = new URL(startUrl);
  const requestHeaders = new Headers();
  for (const name of ["accept", "accept-language", "range", "if-range", "if-none-match", "if-modified-since", "user-agent"]) {
    const value = request.headers.get(name);
    if (value) requestHeaders.set(name, value);
  }
  if (!requestHeaders.has("accept")) requestHeaders.set("accept", "*/*");
  if (!requestHeaders.has("user-agent")) requestHeaders.set("user-agent", "DTV-Member-Gateway/1.0");
  for (let hop = 0; hop <= 3; hop++) {
    const protocolAllowed = target.protocol === "https:" || target.protocol === "http:";
    if (!protocolAllowed || target.username || target.password || !isPublicHostname(target.hostname)) return { error: "UPSTREAM_REDIRECT_BLOCKED" };
    let upstream;
    try {
      upstream = await fetch(target.href, { method: request.method, redirect: "manual", headers: requestHeaders, signal: request.signal });
    } catch {
      return { error: "UPSTREAM_FETCH_FAILED" };
    }
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      const location = upstream.headers.get("location");
      try { await upstream.body?.cancel(); } catch {}
      if (!location || hop === 3) return { error: "UPSTREAM_REDIRECT_BLOCKED" };
      try { target = new URL(location, target); } catch { return { error: "UPSTREAM_REDIRECT_BLOCKED" }; }
      continue;
    }
    const contentType = (upstream.headers.get("content-type") || "application/octet-stream").split(";")[0].trim().toLowerCase();
    const announcedSize = Number(upstream.headers.get("content-length") || 0);
    const playlistType = contentType.includes("mpegurl") || contentType.includes("x-mpegurl");
    const inspectableType = contentType.startsWith("text/") || contentType.includes("json") || playlistType || contentType === "application/octet-stream" || contentType === "binary/octet-stream";
    const canInspect = request.method === "GET" && upstream.status === 200 && !request.headers.has("range") &&
      (playlistType || (!contentType.startsWith("video/") && !contentType.startsWith("audio/") && !contentType.includes("dash+xml"))) &&
      inspectableType && (!announcedSize || announcedSize <= limit);
    if (!canInspect || !upstream.body) return { response: passthroughResponse(upstream), finalUrl: target };
    const [inspectionBody, deliveryBody] = upstream.body.tee();
    const bytes = await readBoundedBody(inspectionBody, limit);
    if (!bytes) return { response: passthroughResponse(upstream, deliveryBody), finalUrl: target };
    const text = new TextDecoder().decode(bytes);
    const looksLikeJson = /^[\s]*(?:\{|\[|\/\/|\/\*)/u.test(text);
    const looksLikePlaylist = playlistType || /^\uFEFF?\s*#EXTM3U/mu.test(text);
    if (contentType.includes("json") || looksLikeJson || looksLikePlaylist) {
      try { await deliveryBody.cancel(); } catch {}
      return {
        result: { upstream: new Response(null, { status: 200 }), bytes, contentType, contentDisposition: upstream.headers.get("content-disposition") || "", finalUrl: target },
        finalUrl: target,
      };
    }
    try { await deliveryBody.cancel(); } catch {}
    return { response: passthroughResponse(upstream, bytes), finalUrl: target };
  }
  return { error: "UPSTREAM_REDIRECT_BLOCKED" };
}

async function readBoundedBody(body, limit) {
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function scanJsonStringValues(text) {
  const values = [];
  let index = 0;
  function skipTrivia() {
    while (index < text.length) {
      if (/\s/u.test(text[index])) { index++; continue; }
      if (text[index] === "/" && text[index + 1] === "/") {
        index += 2;
        while (index < text.length && text[index] !== "\n") index++;
        continue;
      }
      if (text[index] === "/" && text[index + 1] === "*") {
        index += 2;
        while (index < text.length && !(text[index] === "*" && text[index + 1] === "/")) index++;
        index = Math.min(text.length, index + 2);
        continue;
      }
      break;
    }
  }
  function readString() {
    const start = index++;
    while (index < text.length) {
      if (text[index] === "\\") { index += 2; continue; }
      if (text[index++] === '"') break;
    }
    const end = index;
    return { start, end, value: JSON.parse(text.slice(start, end)) };
  }
  function parseValue(key = "") {
    skipTrivia();
    if (text[index] === '"') {
      const token = readString();
      values.push({ ...token, key });
      return;
    }
    if (text[index] === "{") {
      index++;
      skipTrivia();
      while (index < text.length && text[index] !== "}") {
        const property = readString().value;
        skipTrivia();
        if (text[index] !== ":") throw new Error("UPSTREAM_JSON_INVALID");
        index++;
        parseValue(property);
        skipTrivia();
        if (text[index] === ",") { index++; skipTrivia(); }
        else break;
      }
      if (text[index] !== "}") throw new Error("UPSTREAM_JSON_INVALID");
      index++;
      return;
    }
    if (text[index] === "[") {
      index++;
      skipTrivia();
      while (index < text.length && text[index] !== "]") {
        parseValue(key);
        skipTrivia();
        if (text[index] === ",") { index++; skipTrivia(); }
        else break;
      }
      if (text[index] !== "]") throw new Error("UPSTREAM_JSON_INVALID");
      index++;
      return;
    }
    while (index < text.length && !/[\s,}\]]/u.test(text[index])) index++;
  }
  parseValue();
  return values;
}

async function rewriteJsonText(text, fields, base, gatewayPrefix, allowedHosts, env) {
  const replacements = [];
  for (const token of scanJsonStringValues(text)) {
    if (!isRewriteableAddress(token.value, token.key, fields)) continue;
    const rewritten = await rewriteUrl(token.value, base, gatewayPrefix, allowedHosts, env);
    if (rewritten !== token.value) replacements.push({ ...token, rewritten });
  }
  let result = text;
  for (const replacement of replacements.reverse()) {
    result = result.slice(0, replacement.start) + JSON.stringify(replacement.rewritten) + result.slice(replacement.end);
  }
  return result;
}

async function rewritePlaylistText(text, base, gatewayPrefix, allowedHosts, env) {
  const pieces = text.split(/(\r\n|\n|\r)/u);
  for (let index = 0; index < pieces.length; index += 2) {
    const line = pieces[index];
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (!trimmed.startsWith("#")) {
      const leading = line.slice(0, line.indexOf(trimmed));
      const trailing = line.slice(line.indexOf(trimmed) + trimmed.length);
      pieces[index] = leading + await rewriteUrl(trimmed, base, gatewayPrefix, allowedHosts, env) + trailing;
      continue;
    }
    const replacements = [];
    const uriPattern = /\bURI=(?:"([^"]*)"|'([^']*)'|([^,\s]*))/giu;
    for (const match of line.matchAll(uriPattern)) {
      const value = match[1] ?? match[2] ?? match[3] ?? "";
      if (!value) continue;
      const offset = match.index + match[0].indexOf(value);
      const rewritten = await rewriteUrl(value, base, gatewayPrefix, allowedHosts, env);
      if (rewritten !== value) replacements.push({ start: offset, end: offset + value.length, value: rewritten });
    }
    for (const replacement of replacements.reverse()) {
      pieces[index] = pieces[index].slice(0, replacement.start) + replacement.value + pieces[index].slice(replacement.end);
    }
  }
  return pieces.join("");
}

async function rewriteUrl(value, base, gatewayPrefix, allowedHosts, env) {
  let url;
  try { url = new URL(value, base); } catch { return value; }
  if (!(url.protocol === "https:" || url.protocol === "http:") || url.username || url.password || url.href.length > 2048 || !isPublicHostname(url.hostname)) return value;
  const encrypted = await encryptOpaque(url.href, env.TOKEN_ENCRYPTION_KEY);
  const basename = url.pathname.split("/").pop() || "";
  const extension = /\.([A-Za-z0-9]{1,10})$/u.exec(basename)?.[1];
  return gatewayPrefix + "/__p/" + encrypted + (extension ? "." + extension.toLowerCase() : "");
}

function gatewayOrigin(request, env) {
  const requestOrigin = new URL(request.url).origin;
  const configuredOrigins = String(env.PUBLIC_BASE_URLS || env.PUBLIC_BASE_URL || "")
    .split(",")
    .map((value) => {
      try { return new URL(value.trim()).origin; } catch { return ""; }
    });
  if (configuredOrigins.includes(requestOrigin)) return requestOrigin;
  return String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "");
}

async function sendGatewayContent(request, result, resource, token, slug, env, nestedTarget = false) {
  if (!result.upstream.ok) return { response: error("UPSTREAM_ERROR", 502) };
  let body = result.bytes;
  let outputContentType = result.contentType || "application/octet-stream";
  const fields = new Set(parseJsonList(resource.rewrite_fields));
  const declaredJson = result.contentType === "application/json" || result.contentType.endsWith("+json");
  const text = new TextDecoder().decode(body);
  const textMime = result.contentType.startsWith("text/");
  const looksLikeJson = /^[\s]*(?:\{|\[|\/\/|\/\*)/u.test(text);
  const looksLikePlaylist = result.contentType.includes("mpegurl") || result.contentType.includes("x-mpegurl") || /^\uFEFF?\s*#EXTM3U/mu.test(text);
  const rewriteJsonBody = nestedTarget
    ? (declaredJson || looksLikeJson)
    : (resource.type === "json" || (fields.size && declaredJson));
  if (!nestedTarget && resource.type === "json" && !declaredJson && !textMime && !looksLikeJson) {
    return { response: error("UPSTREAM_JSON_INVALID", 502) };
  }
  if (looksLikePlaylist) {
    const base = result.finalUrl || new URL(resource.upstream_url);
    const prefix = gatewayOrigin(request, env) + "/" + token + "/" + slug;
    body = encoder.encode(await rewritePlaylistText(text, base, prefix, parseJsonList(resource.allowed_hosts), env));
  } else if (rewriteJsonBody) {
    try {
      parseJsonWithComments(text);
      const base = result.finalUrl || new URL(resource.upstream_url);
      const prefix = gatewayOrigin(request, env) + "/" + token + "/" + slug;
      const rewritten = await rewriteJsonText(text, fields, base, prefix, parseJsonList(resource.allowed_hosts), env);
      body = encoder.encode(stripJsonComments(rewritten));
      outputContentType = "application/json; charset=utf-8";
    } catch (err) {
      if (!nestedTarget) {
        const code = err?.message === "JSON_REWRITE_UNSUPPORTED" ? "JSON_REWRITE_UNSUPPORTED" : "UPSTREAM_JSON_INVALID";
        return { response: error(code, 502) };
      }
      body = result.bytes;
    }
  }
  const headers = responseHeaders({
    "content-type": outputContentType,
    "content-length": String(body.byteLength),
    "x-content-type-options": "nosniff",
  });
  if (result.contentDisposition) headers["content-disposition"] = result.contentDisposition;
  return { response: new Response(body, { status: 200, headers }) };
}

async function serveResource(request, env, token, slug, suffixPath, jsonAlias = false) {
  if (!TOKEN_PATTERN.test(token)) return error("TOKEN_INVALID", 401);
  if (request.method !== "GET" && request.method !== "HEAD") return error("METHOD_NOT_ALLOWED", 405);
  const suffix = safeSuffix(suffixPath);
  if (suffix === null) return error("PATH_INVALID", 400);
  const tokenHash = await sha256Hex(token);
  const lookup = await env.DB.prepare("SELECT t.id AS token_id, t.member_id, t.revoked_at, m.status AS member_status, m.expires_at, m.max_devices, m.plan_id, p.enabled AS plan_enabled, r.id AS resource_id, r.slug, r.name, r.type, r.upstream_url, r.allowed_hosts, r.delivery_mode, r.rewrite_fields, r.max_response_bytes, r.enabled AS resource_enabled, CASE WHEN pr.resource_id IS NULL THEN 0 ELSE 1 END AS allowed FROM tokens t JOIN members m ON m.id = t.member_id LEFT JOIN plans p ON p.id = m.plan_id LEFT JOIN resources r ON r.slug = ? AND (? = 0 OR r.type = 'json') LEFT JOIN plan_resources pr ON pr.plan_id = m.plan_id AND pr.resource_id = r.id WHERE t.token_hash = ? ORDER BY t.created_at DESC LIMIT 1")
    .bind(slug, jsonAlias ? 1 : 0, tokenHash).first();
  const requestKey = lookup?.token_id ? tokenHash : await sha256Hex("ip:" + (request.headers.get("cf-connecting-ip") || "unknown") + ":" + (env.SESSION_SECRET || ""));
  const limited = await env.MEMBER_LIMITER.limit({ key: requestKey });
  if (!limited.success) {
    if (lookup?.member_id && lookup?.resource_id) await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
    return error("RATE_LIMITED", 429);
  }
  if (!lookup?.token_id || lookup.revoked_at) return error("TOKEN_INVALID", 401);
  if (lookup.member_status !== "active" || !lookup.expires_at || Date.parse(lookup.expires_at) <= Date.now()) {
    if (lookup.resource_id) await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
    return error("MEMBER_EXPIRED", 403);
  }
  if (!lookup.resource_id) return error("RESOURCE_NOT_FOUND", 404);
  if (!lookup.plan_enabled) {
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
    return error("PLAN_DISABLED", 403);
  }
  if (!lookup.resource_enabled || !lookup.allowed) {
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
    return error("RESOURCE_FORBIDDEN", 403);
  }
  const device = await noteWeakDevice(env.DB, lookup.member_id, request);
  if (device.blocked) {
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
    return error(device.reason || "DEVICE_REMOVED", 403);
  }
  const resource = { ...lookup, allowed_hosts: lookup.allowed_hosts, upstream_url: lookup.upstream_url, rewrite_fields: lookup.rewrite_fields };
  const allowedHosts = parseJsonList(resource.allowed_hosts);
  let target;
  const isOpaqueSuffix = suffix.startsWith("__p/");
  const opaqueSuffix = isOpaqueSuffix ? suffix.slice("__p/".length) : "";
  const extensionMatch = /\.([A-Za-z0-9]{1,10})$/u.exec(opaqueSuffix);
  const encryptedTarget = extensionMatch ? opaqueSuffix.slice(0, -extensionMatch[0].length) : opaqueSuffix;
  if (isOpaqueSuffix) {
    if (!encryptedTarget || encryptedTarget.includes("/") || (opaqueSuffix.includes(".") && !extensionMatch)) return error("TARGET_INVALID", 400);
    try { target = new URL(await decryptToken(encryptedTarget, env.TOKEN_ENCRYPTION_KEY)); }
    catch { return error("TARGET_INVALID", 400); }
    if (!isPublicHostname(target.hostname) || !(target.protocol === "http:" || target.protocol === "https:") || target.username || target.password || target.href.length > 2048) return error("TARGET_INVALID", 400);
  } else {
    target = upstreamTarget(resource, suffix, new URL(request.url));
  }
  const targetHost = target.hostname.toLowerCase();
  const nestedTarget = isOpaqueSuffix;
  if ((!nestedTarget && (!isApprovedHost(targetHost, allowedHosts) || target.protocol !== "https:")) || (nestedTarget && !isPublicHostname(targetHost))) {
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
    return error("UPSTREAM_NOT_APPROVED", 502);
  }
  if (nestedTarget) {
    const nested = await fetchNestedTarget(request, target.href, Math.min(Number(resource.max_response_bytes || 0) || 2_097_152, Number(env.MAX_UPSTREAM_BYTES || 2_097_152)));
    if (nested.error) {
      await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
      const status = nested.error === "UPSTREAM_RESPONSE_TOO_LARGE" ? 413 : 502;
      return error(nested.error, status);
    }
    if (nested.response) {
      await writeUsage(env.DB, lookup.member_id, lookup.resource_id, nested.response.ok);
      return nested.response;
    }
    const rewritten = (await sendGatewayContent(request, nested.result, resource, token, slug, env, true)).response;
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, rewritten.status >= 200 && rewritten.status < 400);
    return rewritten;
  }
  if (resource.delivery_mode === "redirect" && !nestedTarget) {
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, true);
    return new Response(null, { status: 302, headers: responseHeaders({ location: target.href }) });
  }
  const maxBytes = Math.min(Number(resource.max_response_bytes || 0) || 2_097_152, Number(env.MAX_UPSTREAM_BYTES || 2_097_152));
  const snapshot = resource.type === "json" && !nestedTarget && !suffix
    ? await env.DB.prepare("SELECT content_json FROM resource_snapshots WHERE resource_id = ?").bind(lookup.resource_id).first()
    : null;
  const result = snapshot?.content_json !== undefined
    ? { upstream: new Response(null, { status: 200 }), bytes: encoder.encode(snapshot.content_json), contentType: "application/json", finalUrl: new URL(resource.upstream_url) }
    : await fetchBounded(target.href, allowedHosts, maxBytes, nestedTarget);
  if (result.error) {
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, false);
    const status = result.error === "RESOURCE_STREAM_UNSUPPORTED" ? 415 : result.error === "UPSTREAM_RESPONSE_TOO_LARGE" ? 413 : 502;
    return error(result.error, status);
  }
  if (request.method === "HEAD" && result.upstream.ok) {
    await writeUsage(env.DB, lookup.member_id, lookup.resource_id, true);
    return new Response(null, { status: 200, headers: responseHeaders({ "content-type": result.contentType }) });
  }
  const delivered = (await sendGatewayContent(request, result, resource, token, slug, env, nestedTarget)).response;
  await writeUsage(env.DB, lookup.member_id, lookup.resource_id, delivered.status === 200);
  return delivered;
}

async function adminPage() {
  return new Response(ADMIN_HTML, { headers: responseHeaders({ "content-type": "text/html; charset=utf-8" }) });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/healthz") return json({ ok: true, service: "dtv-member-auth" }, 200, responseHeaders());
      if (url.pathname === "/telegram/webhook" && request.method === "POST") return telegramWebhook(request, env);
      if (url.pathname === "/admin/api" || url.pathname.startsWith("/admin/api/")) {
        const result = await adminApi(request, env);
        return new Response(result.body, { status: result.status, statusText: result.statusText, headers: responseHeaders(Object.fromEntries(result.headers)) });
      }
      if (url.pathname === "/style.css") return new Response(STYLE_CSS, { headers: responseHeaders({ "content-type": "text/css; charset=utf-8" }) });
      if (url.pathname === "/app.js") return new Response(APP_JS, { headers: responseHeaders({ "content-type": "text/javascript; charset=utf-8" }) });
      if (url.pathname === "/logo.png") {
        const binary = atob(LOGO_PNG_BASE64);
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        return new Response(bytes, { headers: responseHeaders({ "content-type": "image/png", "cache-control": "public, max-age=86400" }) });
      }
      if (url.pathname === "/admin" || url.pathname === "/admin/" || url.pathname === "/") return adminPage();
      if (url.pathname === "/favicon.ico") return new Response(null, { status: 204, headers: responseHeaders() });
      const parts = url.pathname.split("/").filter(Boolean);
      if (parts.length >= 2) {
        const token = parts[0];
        const requestedSlug = parts[1];
        if (request.method === "OPTIONS") return subscriptionResponse(new Response(null, { status: 204, headers: responseHeaders() }));
        const jsonAlias = requestedSlug.endsWith(".json");
        const slug = jsonAlias ? requestedSlug.slice(0, -5) : requestedSlug;
        return subscriptionResponse(await serveResource(request, env, token, slug, parts.slice(2).join("/"), jsonAlias));
      }
      return error("NOT_FOUND", 404);
    } catch {
      return error("DATABASE_UNAVAILABLE", 503, "Service is unavailable; protected requests are closed");
    }
  },
  async scheduled(_event, env, context) {
    const confirmationCutoff = new Date(Date.now() - 86_400_000).toISOString();
    const updateCutoff = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const draftCutoff = new Date(Date.now() - 86_400_000).toISOString();
    const usageDays = Math.max(1, Math.min(3650, Number(env.USAGE_RETENTION_DAYS || 90)));
    const usageCutoff = new Date(Date.now() - usageDays * 86_400_000).toISOString().slice(0, 13);
    context.waitUntil(env.DB.batch([
      env.DB.prepare("DELETE FROM telegram_confirmations WHERE expires_at < ? OR used_at IS NOT NULL").bind(confirmationCutoff),
      env.DB.prepare("DELETE FROM telegram_updates WHERE received_at < ?").bind(updateCutoff),
      env.DB.prepare("DELETE FROM signup_drafts WHERE updated_at < ?").bind(draftCutoff),
      env.DB.prepare("DELETE FROM usage_hourly WHERE hour < ?").bind(usageCutoff),
    ]));
  },
};

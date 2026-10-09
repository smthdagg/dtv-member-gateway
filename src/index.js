import { adminApi } from "./admin.js";
import { telegramWebhook } from "./telegram.js";
import { decryptToken, json, parseJsonList, parseJsonWithComments, sha256Hex, stripJsonComments } from "./security.js";
import { ADMIN_HTML, APP_JS, LOGO_PNG_BASE64, STYLE_CSS } from "./ui.js";
import { responseHeaders, error, subscriptionResponse } from "./http.js";
import { noteWeakDevice } from "./devices.js";
import { isPublicHostname, rewriteJsonText, rewritePlaylistText, gatewayOrigin } from "./rewrite.js";
import { regenerateArtifacts, runDueSync } from "./sync.js";
import { serveAggregate, serveMemberPage, serveCatalog, serveCatalogSource } from "./tvbox.js";

const encoder = new TextEncoder();
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{42,48}$/u;

function isApprovedHost(hostname, allowedHosts) {
  const host = hostname.toLowerCase().replace(/\.$/u, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host) || host.includes(":")) return false;
  return allowedHosts.includes(host);
}

async function writeUsage(db, memberId, resourceId, allowed) {
  const now = new Date();
  await db.prepare("INSERT INTO usage_hourly (hour, member_id, resource_id, allowed_count, denied_count, last_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(hour, member_id, resource_id) DO UPDATE SET allowed_count = allowed_count + excluded.allowed_count, denied_count = denied_count + excluded.denied_count, last_seen = excluded.last_seen")
    .bind(now.toISOString().slice(0, 13), memberId, resourceId, allowed ? 1 : 0, allowed ? 0 : 1, now.toISOString()).run();
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
  const lookup = await env.DB.prepare("SELECT t.id AS token_id, t.member_id, t.revoked_at, m.status AS member_status, m.expires_at, m.max_devices, m.plan_id, p.enabled AS plan_enabled, COALESCE(p.include_all, 0) AS include_all, r.id AS resource_id, r.slug, r.name, r.type, r.upstream_url, r.allowed_hosts, r.delivery_mode, r.rewrite_fields, r.max_response_bytes, r.enabled AS resource_enabled, CASE WHEN COALESCE(p.include_all, 0) = 1 THEN 1 WHEN pr.resource_id IS NULL THEN 0 ELSE 1 END AS allowed FROM tokens t JOIN members m ON m.id = t.member_id LEFT JOIN plans p ON p.id = m.plan_id LEFT JOIN resources r ON r.slug = ? AND (? = 0 OR r.type = 'json') LEFT JOIN plan_resources pr ON pr.plan_id = m.plan_id AND pr.resource_id = r.id WHERE t.token_hash = ? ORDER BY t.created_at DESC LIMIT 1")
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
    const proxyHosts = String(env.PROXY_ALLOWED_HOSTS || "0.12yue.de5.net,0.wudaozhe.net,0.cdz.qzz.io,0.wdzb.eu.cc").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
    if (proxyHosts.length && !proxyHosts.includes(target.hostname.toLowerCase())) return error("TARGET_INVALID", 403);
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
      if (url.pathname === "/healthz") return json({ ok: true, service: env.WORKER_NAME || "dtv-member-gateway" }, 200, responseHeaders());
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
      if (url.pathname === "/catalog/tvbox.json" || url.pathname === "/catalog/duocang.json") {
        if (request.method === "OPTIONS") return subscriptionResponse(new Response(null, { status: 204, headers: responseHeaders() }));
        return subscriptionResponse(await serveCatalog(request, env, "tvbox"));
      }
      const linesMatch = url.pathname.match(/^\/lines\/(main|b\d{1,2})\.json$/u);
      if (linesMatch) {
        if (request.method === "OPTIONS") return subscriptionResponse(new Response(null, { status: 204, headers: responseHeaders() }));
        return subscriptionResponse(await serveCatalog(request, env, "lines:" + linesMatch[1]));
      }
      if (url.pathname === "/nodes.json") {
        if (request.method === "OPTIONS") return subscriptionResponse(new Response(null, { status: 204, headers: responseHeaders() }));
        return subscriptionResponse(await serveCatalog(request, env, "nodes"));
      }
      if (url.pathname === "/catalog/all.json") {
        if (request.method === "OPTIONS") return subscriptionResponse(new Response(null, { status: 204, headers: responseHeaders() }));
        return subscriptionResponse(await serveCatalog(request, env, "all"));
      }
      if (url.pathname === "/catalog/status") {
        return subscriptionResponse(await serveCatalog(request, env, "status"));
      }
      const catalogSourceMatch = url.pathname.match(/^\/catalog\/(?:s\/)?([a-z0-9][a-z0-9-]{0,39})(?:\.[a-z0-9]{6,16})?\.json$/iu);
      if (catalogSourceMatch) {
        if (request.method === "OPTIONS") return subscriptionResponse(new Response(null, { status: 204, headers: responseHeaders() }));
        return subscriptionResponse(await serveCatalogSource(request, env, catalogSourceMatch[1]));
      }
      const parts = url.pathname.split("/").filter(Boolean);
      if (parts.length === 1 && (request.method === "GET" || request.method === "HEAD")) {
        return subscriptionResponse(await serveMemberPage(request, env, parts[0]));
      }
      if (parts.length >= 2) {
        const token = parts[0];
        const requestedSlug = parts[1];
        if (request.method === "OPTIONS") return subscriptionResponse(new Response(null, { status: 204, headers: responseHeaders() }));
        const jsonAlias = requestedSlug.endsWith(".json");
        const slug = jsonAlias ? requestedSlug.slice(0, -5) : requestedSlug;
        if (parts.length === 2 && ["tvbox", "all"].includes(slug)) {
          return subscriptionResponse(await serveAggregate(request, env, token, slug));
        }
        if (parts.length === 3 && parts[1] === "lines" && /^(main|b\d{1,2})\.json$/u.test(parts[2])) {
          return subscriptionResponse(await serveAggregate(request, env, token, "lines:" + parts[2].replace(/\.json$/u, "")));
        }
        return subscriptionResponse(await serveResource(request, env, token, slug, parts.slice(2).join("/"), jsonAlias));
      }
      return error("NOT_FOUND", 404);
    } catch (err) {
      console.error("worker.fetch.error", request.url, err);
      return error("DATABASE_UNAVAILABLE", 503, "Service is unavailable; protected requests are closed");
    }
  },
  async scheduled(_event, env, context) {
    context.waitUntil((async () => {
      try {
        const result = await runDueSync(env, { limit: 8 });
        if (result.attempted > 0) await regenerateArtifacts(env);
      } catch {}
    })());
    const confirmationCutoff = new Date(Date.now() - 86_400_000).toISOString();
    const draftCutoff = new Date(Date.now() - 86_400_000).toISOString();
    const retentionRow = await env.DB.prepare("SELECT plain_value FROM app_settings WHERE setting_key = 'log_retention_days'").first();
    const requestedDays = Number(retentionRow?.plain_value || env.USAGE_RETENTION_DAYS || 90);
    const retentionDays = [30, 60, 90].includes(requestedDays) ? requestedDays : 90;
    const logCutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
    const usageCutoff = logCutoff.slice(0, 13);
    context.waitUntil(env.DB.batch([
      env.DB.prepare("DELETE FROM telegram_confirmations WHERE expires_at < ? OR used_at IS NOT NULL").bind(confirmationCutoff),
      env.DB.prepare("DELETE FROM telegram_updates WHERE received_at < ?").bind(logCutoff),
      env.DB.prepare("DELETE FROM signup_drafts WHERE updated_at < ?").bind(draftCutoff),
      env.DB.prepare("DELETE FROM usage_hourly WHERE hour < ?").bind(usageCutoff),
      env.DB.prepare("DELETE FROM audit_events WHERE timestamp < ?").bind(logCutoff),
      env.DB.prepare("DELETE FROM resource_sync_log WHERE started_at < ?").bind(logCutoff),
    ]));
  },
};

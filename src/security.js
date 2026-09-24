const encoder = new TextEncoder();

export const nowIso = () => new Date().toISOString();
export const newId = () => crypto.randomUUID();

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

export function apiError(code, status, message = code) {
  return json({ error: { code, message } }, status, { "cache-control": "no-store" });
}

export function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function fromB64url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function issueToken(env) {
  const raw = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256Hex(raw);
  const tokenCiphertext = await encryptOpaque(raw, env.TOKEN_ENCRYPTION_KEY);
  return { raw, tokenHash, tokenCiphertext };
}

async function encryptionKey(keyValue) {
  if (!keyValue) throw new Error("TOKEN_ENCRYPTION_KEY is not configured");
  const rawKey = fromB64url(keyValue.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, ""));
  if (rawKey.length !== 32) throw new Error("TOKEN_ENCRYPTION_KEY must encode 32 bytes");
  return crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptOpaque(raw, keyValue) {
  const key = await encryptionKey(keyValue);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, encoder.encode(raw)));
  const packed = new Uint8Array(nonce.length + ciphertext.length);
  packed.set(nonce);
  packed.set(ciphertext, nonce.length);
  return b64url(packed);
}

export async function decryptToken(ciphertext, keyValue) {
  const packed = fromB64url(ciphertext);
  if (packed.length < 29) throw new Error("Invalid encrypted token");
  const key = await encryptionKey(keyValue);
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.slice(0, 12) }, key, packed.slice(12));
  return new TextDecoder().decode(raw);
}

async function hmac(value, secret) {
  if (!secret) throw new Error("SESSION_SECRET is not configured");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

function cookies(request) {
  const result = new Map();
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return result;
}

export async function makeSessionCookie(env) {
  const ttl = Math.max(1, Number(env.SESSION_TTL_HOURS || 12)) * 60 * 60;
  const payload = b64url(encoder.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + ttl })));
  return `${payload}.${b64url(await hmac(payload, env.SESSION_SECRET))}`;
}

export async function hasAdminSession(request, env) {
  const cookie = cookies(request).get("dtv_admin");
  if (!cookie) return false;
  const [payload, signature, extra] = cookie.split(".");
  if (!payload || !signature || extra) return false;
  try {
    const key = await crypto.subtle.importKey("raw", encoder.encode(env.SESSION_SECRET || ""), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify("HMAC", key, fromB64url(signature), encoder.encode(payload))) return false;
    const value = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    return Number.isInteger(value.exp) && value.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

export function setSessionCookie(value) {
  return `dtv_admin=${value}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`;
}

export function clearSessionCookie() {
  return "dtv_admin=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

export function safeEqual(left, right) {
  if (!left || !right) return false;
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let different = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) different |= (a[i] || 0) ^ (b[i] || 0);
  return different === 0;
}

export function isSameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export async function audit(db, actorId, action, targetType, targetId, summary = "") {
  await db.prepare(
    "INSERT INTO audit_events (id, actor_id, action, target_type, target_id, timestamp, change_summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).bind(newId(), actorId, action, targetType, targetId, nowIso(), summary.slice(0, 400)).run();
}

export function parseJsonList(value) {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function stripJsonComments(value) {
  let output = "";
  let quoted = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let i = 0; i < value.length; i++) {
    const current = value[i];
    const next = value[i + 1];
    if (lineComment) {
      if (current === "\n" || current === "\r") { lineComment = false; output += current; }
      else output += " ";
      continue;
    }
    if (blockComment) {
      if (current === "*" && next === "/") { blockComment = false; output += "  "; i++; }
      else if (current === "\n" || current === "\r") output += current;
      else output += " ";
      continue;
    }
    if (quoted) {
      output += current;
      if (escaped) escaped = false;
      else if (current === "\\") escaped = true;
      else if (current === '"') quoted = false;
      continue;
    }
    if (current === '"') { quoted = true; output += current; continue; }
    if (current === "/" && next === "/") { lineComment = true; output += "  "; i++; continue; }
    if (current === "/" && next === "*") { blockComment = true; output += "  "; i++; continue; }
    output += current;
  }
  return output;
}

export function parseJsonWithComments(value) {
  return JSON.parse(stripJsonComments(value));
}

export async function readJson(request, maxBytes = 32_768) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > maxBytes) return null;
  const text = await request.text();
  if (new TextEncoder().encode(text).length > maxBytes) return null;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

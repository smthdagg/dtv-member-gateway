import { encryptOpaque } from "./security.js";

const encoder = new TextEncoder();

export function isPublicHostname(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/u, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".lan")) return false;
  if (/^(?:\d{1,3}\.){4}$/u.test(host) || /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host) || host.includes(":" ) || host.startsWith("[")) return false;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(host);
}

export function scanJsonStringValues(text) {
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

export function isRewriteableAddress(value, key, fields) {
  const text = value.trim();
  if (/^(?:https?:\/\/|\/\/[^/])/iu.test(text)) return true;
  return fields.has(key) && /^(?:\/(?!\/)|\.{1,2}\/|\?.+)/u.test(text);
}

export async function rewriteUrl(value, base, gatewayPrefix, allowedHosts, env) {
  let url;
  try { url = new URL(value, base); } catch { return value; }
  if (!(url.protocol === "https:" || url.protocol === "http:") || url.username || url.password || url.href.length > 2048 || !isPublicHostname(url.hostname)) return value;
  const encrypted = await encryptOpaque(url.href, env.TOKEN_ENCRYPTION_KEY);
  const basename = url.pathname.split("/").pop() || "";
  const extension = /\.([A-Za-z0-9]{1,10})$/u.exec(basename)?.[1];
  return gatewayPrefix + "/__p/" + encrypted + (extension ? "." + extension.toLowerCase() : "");
}

export async function rewriteJsonText(text, fields, base, gatewayPrefix, allowedHosts, env) {
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

export async function rewritePlaylistText(text, base, gatewayPrefix, allowedHosts, env) {
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

export function gatewayOrigin(request, env) {
  const requestOrigin = new URL(request.url).origin;
  const configuredOrigins = String(env.PUBLIC_BASE_URLS || env.PUBLIC_BASE_URL || "")
    .split(",")
    .map((value) => {
      try { return new URL(value.trim()).origin; } catch { return ""; }
    });
  if (configuredOrigins.includes(requestOrigin)) return requestOrigin;
  return String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "");
}

export { encoder };

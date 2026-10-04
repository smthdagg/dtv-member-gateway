import { sha256Hex } from "./security.js";

function deviceGeography(request) {
  const cf = request.cf || {};
  const country = String(cf.country || request.headers.get("cf-ipcountry") || "").trim().toLowerCase();
  const region = String(cf.region || cf.regionCode || "").trim().toLowerCase().replace(/\s+/gu, " ");
  const key = [country, region].filter(Boolean).join("|") || "unknown";
  const label = [cf.city, cf.region || cf.regionCode, cf.country].filter(Boolean).map(String).join(", ") || (country || "位置未知");
  return { key, label };
}

function networkBucket(value) {
  const ip = String(value || "").trim().toLowerCase().replace(/^\[|\]$/gu, "").split("%")[0];
  const ipv4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
  if (ipv4 && ipv4.slice(1).every((part) => Number(part) <= 255)) return `${Number(ipv4[1])}.${Number(ipv4[2])}.0.0/16`;
  if (ip.startsWith("::ffff:")) return networkBucket(ip.slice(7));
  if (!ip.includes(":")) return ip ? `raw:${ip.slice(0, 100)}` : "unknown";

  let address = ip;
  if (address.includes(".")) {
    const colon = address.lastIndexOf(":");
    const tail = networkBucket(address.slice(colon + 1));
    const match = tail.match(/^(\d+)\.(\d+)\.0\.0\/16$/u);
    if (!match) return `raw:${ip.slice(0, 100)}`;
    const hi = ((Number(match[1]) << 8) | Number(match[2])).toString(16);
    const lo = "0";
    address = address.slice(0, colon + 1) + hi + ":" + lo;
  }
  const halves = address.split("::");
  if (halves.length > 2) return `raw:${ip.slice(0, 100)}`;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if ([...left, ...right].some((part) => !/^[0-9a-f]{1,4}$/u.test(part))) return `raw:${ip.slice(0, 100)}`;
  const fillCount = 8 - left.length - right.length;
  if ((halves.length === 1 && fillCount !== 0) || fillCount < 0) return `raw:${ip.slice(0, 100)}`;
  const groups = [...left, ...Array.from({ length: fillCount }, () => "0"), ...right].map((part) => part.padStart(4, "0"));
  return groups.slice(0, 4).join(":") + "::/64";
}

function browserBucket(value) {
  const agent = String(value || "unknown").toLowerCase();
  let browser = "other";
  if (/samsungbrowser\//u.test(agent)) browser = "samsung internet";
  else if (/\b(?:edg|edge|edga|edgios)\//u.test(agent)) browser = "edge";
  else if (/\b(?:opr|opera|opios)\//u.test(agent)) browser = "opera";
  else if (/\b(?:silk)\//u.test(agent)) browser = "silk";
  else if (/\b(?:crios|chrome)\//u.test(agent)) browser = "chrome";
  else if (/\b(?:fxios|firefox)\//u.test(agent)) browser = "firefox";
  else if (/safari\//u.test(agent)) browser = "safari";
  else if (/tizenbrowser/u.test(agent)) browser = "tizen browser";
  else if (/stremio/u.test(agent)) browser = "stremio";
  else if (/exoplayer/u.test(agent)) browser = "exoplayer";
  else if (/okhttp/u.test(agent)) browser = "okhttp";
  else if (/roku/u.test(agent)) browser = "roku app";
  return browser;
}

function storedGeoBucket(value) {
  const geo = String(value || "").trim().toLowerCase().replace(/\s+/gu, " ");
  if (!geo || geo === "位置未知" || geo === "unknown") return "unknown";
  const parts = geo.split(",").map((part) => part.trim()).filter(Boolean);
  if (parts.length >= 2) return [parts.at(-1), parts.at(-2)].join("|");
  return parts[0] || "unknown";
}

export async function noteWeakDevice(db, memberId, request) {
  const ip = request.headers.get("cf-connecting-ip") || "";
  const agent = String(request.headers.get("user-agent") || "unknown").replace(/[\r\n\t]/gu, " ").slice(0, 300);
  const geography = deviceGeography(request);
  const network = networkBucket(ip);
  const browser = browserBucket(agent);
  const signatureHash = await sha256Hex("coarse-device:" + network + ":" + geography.key + ":" + browser);
  const id = crypto.randomUUID();
  const current = new Date();
  const now = current.toISOString();
  const day = now.slice(0, 10);
  const prior = await db.prepare("SELECT id, signature_hash, revoked_at, first_seen, last_seen, last_seen_day, ip_address, geo_location, user_agent_hint, network_bucket, geo_region_key, browser_key FROM devices WHERE member_id = ? AND (network_bucket = ? OR network_bucket = '') ORDER BY last_seen DESC LIMIT 200")
    .bind(memberId, network).all();
  const matches = (prior.results || []).filter((row) => row.signature_hash === signatureHash || (
    (row.network_bucket || networkBucket(row.ip_address)) === network &&
    (row.geo_region_key || storedGeoBucket(row.geo_location)) === geography.key &&
    (row.browser_key || browserBucket(row.user_agent_hint)) === browser
  ));
  const revoked = matches.find((row) => row.revoked_at);
  if (revoked) return { blocked: true, reason: "DEVICE_REMOVED", id: revoked.id };
  const activeMatches = matches.filter((row) => !row.revoked_at);
  if (activeMatches.length) {
    const existing = activeMatches.find((row) => row.signature_hash === signatureHash) || activeMatches[0];
    const duplicates = activeMatches.filter((row) => row.id !== existing.id);
    const lastSeen = Date.parse(existing.last_seen || "");
    const touch = !Number.isFinite(lastSeen) || lastSeen < Date.now() - 10 * 60_000 || existing.last_seen_day !== day;
    const identityChanged = existing.signature_hash !== signatureHash || existing.network_bucket !== network || existing.geo_region_key !== geography.key || existing.browser_key !== browser;
    if (touch || identityChanged || duplicates.length) {
      const statements = duplicates.map((row) => db.prepare("DELETE FROM devices WHERE id = ? AND member_id = ? AND revoked_at IS NULL").bind(row.id, memberId));
      statements.push(db.prepare("UPDATE devices SET signature_hash = ?, network_bucket = ?, geo_region_key = ?, browser_key = ?, last_seen = ?, last_seen_day = ?, ip_address = ?, user_agent_hint = ?, geo_location = ? WHERE id = ? AND member_id = ? AND revoked_at IS NULL")
        .bind(signatureHash, network, geography.key, browser, touch ? now : existing.last_seen, touch ? day : existing.last_seen_day, touch ? ip.slice(0, 100) : existing.ip_address, touch ? agent.slice(0, 120) : existing.user_agent_hint, touch ? geography.label.slice(0, 120) : existing.geo_location, existing.id, memberId));
      await db.batch(statements);
      const refreshed = await db.prepare("SELECT revoked_at FROM devices WHERE id = ? AND member_id = ?").bind(existing.id, memberId).first();
      if (refreshed?.revoked_at) return { blocked: true, reason: "DEVICE_REMOVED", id: existing.id };
    }
    return { blocked: false, id: existing.id };
  }
  const inserted = await db.prepare("INSERT INTO devices (id, member_id, signature_hash, trust_level, user_agent_hint, ip_address, geo_location, first_seen, last_seen, network_bucket, geo_region_key, browser_key, last_seen_day) SELECT ?, ?, ?, 'weak', ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM devices WHERE member_id = ? AND revoked_at IS NULL) < (SELECT max_devices FROM members WHERE id = ?) AND true ON CONFLICT(member_id, signature_hash) DO NOTHING RETURNING id")
    .bind(id, memberId, signatureHash, agent.slice(0, 120), ip.slice(0, 100), geography.label.slice(0, 120), now, now, network, geography.key, browser, day, memberId, memberId).first();
  if (inserted?.id) return { blocked: false, id: inserted.id };
  const raced = await db.prepare("SELECT id, revoked_at FROM devices WHERE member_id = ? AND signature_hash = ?")
    .bind(memberId, signatureHash).first();
  if (raced && !raced.revoked_at) return { blocked: false, id: raced.id };
  if (raced?.revoked_at) return { blocked: true, reason: "DEVICE_REMOVED", id: raced.id };
  return { blocked: true, reason: "DEVICE_LIMIT_EXCEEDED", id };
}

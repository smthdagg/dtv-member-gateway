import { sha256Hex } from "./security.js";

// 平台自身基础设施（网关互访）不登记设备
const INFRA_UA = /^(?:DTV-Member-Gateway|AITV-)/iu;

function deviceGeography(request) {
  const cf = request.cf || {};
  const country = String(cf.country || request.headers.get("cf-ipcountry") || "").trim().toLowerCase();
  const region = String(cf.region || cf.regionCode || "").trim().toLowerCase().replace(/\s+/gu, " ");
  const label = [cf.city, cf.region || cf.regionCode, cf.country].filter(Boolean).map(String).join(", ") || (country || "位置未知");
  return { label };
}

// 设备地区键：IP 所在地（国家|省|市）——地区变化才算新设备
function geoKeyOf(request) {
  const cf = request.cf || {};
  const key = [cf.country, cf.region, cf.city].map((value) => String(value || "").trim().toLowerCase()).filter(Boolean).join("|");
  return key || "unknown";
}

// 客户端应用家族（UA 主产品，不含版本）：应用升级只更新指纹，不算新设备
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
  else if (/dalvik/u.test(agent)) browser = "dalvik";
  else if (/apache-httpclient|urlconnection/u.test(agent)) browser = "java http";
  return browser;
}

// 专属设备 ID：客户端 UA 指纹 + 运营商 ASN + 地区 组合哈希
async function deviceSignature(userAgent, network, geoKey) {
  const uaFingerprint = await sha256Hex(userAgent);
  return sha256Hex("aitv-device:" + uaFingerprint + ":" + network + ":" + geoKey);
}

export async function noteWeakDevice(db, memberId, request) {
  const userAgent = String(request.headers.get("user-agent") || "unknown").replace(/[\r\n\t]/gu, " ").trim();
  if (INFRA_UA.test(userAgent)) return { blocked: false, infra: true };

  const ip = String(request.headers.get("cf-connecting-ip") || "").slice(0, 100);
  const cf = request.cf || {};
  const network = "AS" + String(cf.asn ?? "0");
  const geoKey = geoKeyOf(request);
  const { label: geoLabel } = deviceGeography(request);
  const browser = browserBucket(userAgent);
  const uaHint = userAgent.slice(0, 120);
  const signatureHash = await deviceSignature(userAgent, network, geoKey);

  const now = new Date();
  const nowIso = now.toISOString();
  const day = nowIso.slice(0, 10);

  // 1. 专属 ID 完全匹配：同一设备，仅更新活跃时间/最近 IP
  const current = await db.prepare("SELECT id, revoked_at, last_seen, last_seen_day, ip_address FROM devices WHERE member_id = ? AND signature_hash = ?")
    .bind(memberId, signatureHash).first();
  if (current) {
    if (current.revoked_at) return { blocked: true, reason: "DEVICE_REMOVED", id: current.id };
    const lastSeen = Date.parse(current.last_seen || "");
    if (!Number.isFinite(lastSeen) || lastSeen < Date.now() - 10 * 60_000 || current.last_seen_day !== day || current.ip_address !== ip) {
      await db.prepare("UPDATE devices SET last_seen = ?, last_seen_day = ?, ip_address = ?, geo_location = ?, user_agent_hint = ? WHERE id = ?")
        .bind(nowIso, day, ip, geoLabel, uaHint, current.id).run();
    }
    return { blocked: false, id: current.id };
  }

  // 2. UA 漂移（如同应用升级）：同运营商 ASN + 同地区 + 同应用家族 → 视为同一设备，原地更新专属 ID
  const drifted = await db.prepare(
    "SELECT id FROM devices WHERE member_id = ? AND network_bucket = ? AND geo_region_key = ? AND browser_key = ? AND revoked_at IS NULL ORDER BY last_seen DESC LIMIT 1"
  ).bind(memberId, network, geoKey, browser).first();
  if (drifted) {
    await db.prepare("UPDATE devices SET signature_hash = ?, user_agent_hint = ?, ip_address = ?, geo_location = ?, last_seen = ?, last_seen_day = ? WHERE id = ?")
      .bind(signatureHash, uaHint, ip, geoLabel, nowIso, day, drifted.id).run();
    return { blocked: false, id: drifted.id };
  }

  // 3. 新设备：名额未满则登记
  const inserted = await db.prepare(
    "INSERT INTO devices (id, member_id, signature_hash, trust_level, user_agent_hint, ip_address, geo_location, first_seen, last_seen, network_bucket, geo_region_key, browser_key, last_seen_day) VALUES (?, ?, ?, 'weak', ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(member_id, signature_hash) DO NOTHING RETURNING id"
  ).bind(crypto.randomUUID(), memberId, signatureHash, uaHint, ip, geoLabel, nowIso, nowIso, network, geoKey, browser, day).first();
  if (inserted?.id) return { blocked: false, id: inserted.id };

  // 并发竞态兜底：同名设备可能已被并行请求登记
  const raced = await db.prepare("SELECT id, revoked_at FROM devices WHERE member_id = ? AND signature_hash = ?")
    .bind(memberId, signatureHash).first();
  if (raced && !raced.revoked_at) return { blocked: false, id: raced.id };
  if (raced?.revoked_at) return { blocked: true, reason: "DEVICE_REMOVED", id: raced.id };
  return { blocked: true, reason: "DEVICE_LIMIT_EXCEEDED", id: "" };
}

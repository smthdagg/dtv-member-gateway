#!/usr/bin/env node
// 成熟多仓/单仓 vs 我们的 结构解剖
// 用法: node scripts/analyze-mature.mjs
import { readFileSync, writeFileSync } from "node:fs";

const stripCtrl = (t) => String(t).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/gu, "");
const tolerantParse = (t) => JSON.parse(stripCtrl(t));
const fieldUse = (sites) => {
  const u = {};
  for (const s of sites) for (const k of Object.keys(s)) u[k] = (u[k] || 0) + 1;
  return u;
};
const typeDist = (sites) => {
  const u = {};
  for (const s of sites) u[String(s.type)] = (u[String(s.type)] || 0) + 1;
  return u;
};

(async () => {
  // ── 成熟基准 1：jianhancloud room.json（用户验证可用的多仓）──
  let room = null;
  try {
    room = JSON.parse(stripCtrl(readFileSync("/tmp/room.json", "utf8")));
  } catch (e) { console.log("room.json 读取失败:", e.message.slice(0, 60)); }

  // ── 成熟基准 2：dc2 的线路（混淆 .html → base64 → 配置）──
  let mature = null;
  try {
    const raw = readFileSync("/tmp/dc2-1.html", "utf8");
    const b64 = raw.slice(raw.indexOf("**") + 2).trim();
    mature = tolerantParse(Buffer.from(b64, "base64").toString("utf8"));
  } catch (e) { console.log("dc2 线路解码失败:", e.message.slice(0, 60)); }

  // ── 我们的 ──
  const ours = JSON.parse(readFileSync("/tmp/nodes.json", "utf8"));

  if (room) {
    console.log("═".repeat(20), "【基准1】room.json（多仓）", "═".repeat(20));
    console.log("  顶层键:", Object.keys(room).join(", "));
    if (Array.isArray(room.urls)) {
      console.log("  线路条数:", room.urls.length, "| 条目字段:", Object.keys(room.urls[0]).join(","));
      console.log("  首条:", JSON.stringify(room.urls[0]).slice(0, 110));
    }
    if (Array.isArray(room.sites)) console.log("  ⚠ 它直接就是单仓! sites:", room.sites.length);
  }

  if (mature) {
    console.log("═".repeat(20), "【基准2】dc2 线路（成熟单仓）", "═".repeat(20));
    console.log("  顶层键:", Object.keys(mature).join(", "));
    console.log("  sites:", (mature.sites || []).length, "| lives:", (mature.lives || []).length, "| parses:", (mature.parses || []).length);
    const mf = fieldUse(mature.sites || []);
    console.log("  节点字段:", Object.keys(mf).map(k => k + "×" + mf[k]).join(", "));
    console.log("  key 样例:", (mature.sites || []).slice(0, 3).map(s => JSON.stringify(s.key)).join(" "));
    console.log("  name 样例:", (mature.sites || []).slice(0, 3).map(s => JSON.stringify(s.name)).join(" "));
    console.log("  type 分布:", JSON.stringify(typeDist(mature.sites || [])));
    console.log("  api 样例:", (mature.sites || []).slice(0, 3).map(s => String(s.api).slice(0, 50)).join("\n            "));
    console.log("  parses:", (mature.parses || []).length, "→", (mature.parses || []).slice(0, 6).map(p => p.name + "(" + p.type + ")").join(" | "));
    console.log("  lives 组:", (mature.lives || []).length, "| 首组:", JSON.stringify((mature.lives || [])[0] || {}).slice(0, 120));
    console.log("  spider:", String(mature.spider || "").slice(0, 90));
    console.log("  其他顶层:", Object.keys(mature).filter(k => !["sites", "lives", "parses", "spider", "wallpaper"].includes(k)).join(", "));
  }

  console.log("═".repeat(20), "【我们的】nodes.json", "═".repeat(20));
  const of_ = fieldUse(ours.sites || []);
  console.log("  顶层键:", Object.keys(ours).join(", "));
  console.log("  sites:", (ours.sites || []).length, "| lives:", (ours.lives || []).length, "| parses:", (ours.parses || []).length);
  console.log("  节点字段:", Object.keys(of_).map(k => k + "×" + of_[k]).join(", "));
  console.log("  key 样例:", (ours.sites || []).slice(0, 3).map(s => JSON.stringify(s.key)).join(" "));
  console.log("  name 样例:", (ours.sites || []).slice(0, 3).map(s => JSON.stringify(s.name)).join(" "));
  console.log("  type 分布:", JSON.stringify(typeDist(ours.sites || [])));
  console.log("  api 样例:", (ours.sites || []).slice(0, 3).map(s => String(s.api).slice(0, 50)).join("\n            "));
  console.log("  parses:", (ours.parses || []).length, "→", (ours.parses || []).slice(0, 6).map(p => p.name).join(" | "));
  console.log("  lives 组:", (ours.lives || []).length, "| 首组:", JSON.stringify((ours.lives || [])[0] || {}).slice(0, 120));
  console.log("  spider:", String(ours.spider || "").slice(0, 90));

  if (mature) {
    const mKeys = Object.keys(fieldUse(mature.sites || []));
    const oKeys = Object.keys(fieldUse(ours.sites || []));
    console.log("═".repeat(20), "【差异】", "═".repeat(20));
    console.log("  成熟有我们没有:", mKeys.filter(k => !oKeys.includes(k)).join(", ") || "(无)");
    console.log("  我们有成熟没有:", oKeys.filter(k => !mKeys.includes(k)).join(", ") || "(无)");
  }
})().catch(e => { console.error("FATAL", e); process.exit(1); });

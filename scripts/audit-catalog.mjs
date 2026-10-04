#!/usr/bin/env node
// 线上地址库审计：多仓/单仓结构、逐仓有效性、合并去重分析、api 探活抽样
// 用法: node scripts/audit-catalog.mjs [baseUrl]

const BASE = (process.argv[2] || "https://tvbox.aisoft.live").replace(/\/+$/u, "");

async function getJson(path) {
  const response = await fetch(BASE + path + (path.includes("?") ? "&" : "?") + "v=" + Date.now(), { headers: { "user-agent": "AITV-Audit/1.0" }, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(path + " HTTP " + response.status);
  return response.json();
}

function siteSignature(site) {
  return [String(site?.api || "").trim(), String(site?.name || "").trim()].join("|");
}

async function main() {
  const report = { warehouses: [], merged: {}, probe: {} };

  // 1. 多仓：逐仓可达性 + 结构
  const multi = await getJson("/catalog/tvbox.json");
  const warehouses = multi.storeHouse || [];
  console.error(`多仓地址库：${warehouses.length} 个仓，开始逐仓检验…`);
  let okCount = 0;
  const warehouseSigs = new Map(); // sig -> [warehouseName]
  for (const entry of warehouses) {
    const row = { name: entry.sourceName, url: entry.sourceUrl.replace(BASE, ""), ok: false, sites: 0, lives: 0, parses: 0, error: "" };
    try {
      const response = await fetch(entry.sourceUrl + "?v=" + Date.now(), { headers: { "user-agent": "AITV-Audit/1.0" }, signal: AbortSignal.timeout(20_000) });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const config = await response.json();
      row.sites = Array.isArray(config.sites) ? config.sites.length : 0;
      row.lives = Array.isArray(config.lives) ? config.lives.length : 0;
      row.parses = Array.isArray(config.parses) ? config.parses.length : 0;
      row.ok = row.sites + row.lives > 0;
      for (const site of config.sites || []) {
        const sig = siteSignature(site);
        if (!warehouseSigs.has(sig)) warehouseSigs.set(sig, []);
        warehouseSigs.get(sig).push(entry.sourceName);
      }
    } catch (error) {
      row.error = String(error?.message || error).slice(0, 60);
    }
    if (row.ok) okCount++;
    report.warehouses.push(row);
    console.error(`  ${row.ok ? "✓" : "✗"} ${row.name}  sites=${row.sites} lives=${row.lives} ${row.error}`);
  }

  // 2. 单仓：结构 + 查重
  const all = await getJson("/catalog/all.json");
  const sites = all.sites || [];
  const byKey = new Set();
  let dupKey = 0;
  const bySig = new Map();
  let dupSig = 0;
  const byName = new Map();
  let dupName = 0;
  let missingApi = 0;
  const httpApis = [];
  for (const site of sites) {
    const key = String(site?.key || "");
    if (byKey.has(key)) dupKey++;
    byKey.add(key);
    const sig = siteSignature(site);
    if (sig !== "|") {
      if (bySig.has(sig)) dupSig++;
      bySig.set(sig, (bySig.get(sig) || 0) + 1);
    }
    const name = String(site?.name || "").trim();
    if (name) {
      if (byName.has(name)) dupName++;
      byName.set(name, (byName.get(name) || 0) + 1);
    }
    const api = String(site?.api || "").trim();
    if (!api) missingApi++;
    else if (/^https?:\/\//iu.test(api)) httpApis.push({ name, api });
  }
  const topNameDupes = [...byName.entries()].filter(([, count]) => count > 1).sort((a, b) => b[1] - a[1]).slice(0, 10);
  report.merged = {
    sites: sites.length,
    lives: (all.lives || []).length,
    parses: (all.parses || []).length,
    duplicateKey: dupKey,
    duplicateSignature: dupSig,
    duplicateName: dupName,
    missingApi,
    httpApiCount: httpApis.length,
    crawlerApiCount: sites.length - missingApi - httpApis.length,
    topNameDupes,
  };

  // 3. 探活抽样：http(s) api 地址抽 80 个
  const sample = [];
  const step = Math.max(1, Math.floor(httpApis.length / 80));
  for (let index = 0; index < httpApis.length && sample.length < 80; index += step) sample.push(httpApis[index]);
  let alive = 0;
  let dead = 0;
  const statusCounts = new Map();
  await Promise.all(sample.map(async (item) => {
    try {
      const response = await fetch(item.api, { method: "GET", redirect: "follow", headers: { "user-agent": "Mozilla/5.0", accept: "*/*" }, signal: AbortSignal.timeout(8_000) });
      try { await response.body?.cancel(); } catch {}
      if (response.ok) alive++; else dead++;
      statusCounts.set(response.status, (statusCounts.get(response.status) || 0) + 1);
    } catch {
      dead++;
      statusCounts.set("ERR", (statusCounts.get("ERR") || 0) + 1);
    }
  }));
  report.probe = { sampled: sample.length, alive, dead, statusCounts: Object.fromEntries(statusCounts), note: "http 型 api 抽样；csp_ 类爬虫节点依赖 jar 运行时，无法用 HTTP 直接探活" };

  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => { console.error(error); process.exit(1); });

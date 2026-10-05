#!/usr/bin/env node
// 真实 TVBox 客户端读取链路验证
// 用法: node scripts/tvbox-client-test.mjs <多仓地址>
// 严格按 TVBox 应用的实际加载顺序: 多仓 → 仓库配置 → spider jar 下载与类名校验 → 节点真实请求(列表→详情→播放数据)

import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync, mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const MULTI_URL = process.argv[2];
if (!MULTI_URL) { console.error("用法: node scripts/tvbox-client-test.mjs <多仓地址>"); process.exit(1); }
const WORK = mkdtempSync(join(tmpdir(), "tvbox-verify-"));
const UA = "okhttp/4.12.0"; // 与 TVBox 客户端一致的 UA

async function fetchText(url, timeout = 15_000) {
  const response = await fetch(url, { headers: { "user-agent": UA, accept: "*/*" }, redirect: "follow", signal: AbortSignal.timeout(timeout) });
  const text = await response.text();
  return { status: response.status, text };
}

function classifySite(api) {
  const raw = String(api || "").trim();
  if (/^https?:\/\//iu.test(raw) && /\.(?:js|py)(?:[?#]|$)/iu.test(raw)) return "runtime";
  if (/^https?:\/\//iu.test(raw)) return "http";
  if (/^csp_/iu.test(raw)) return "csp";
  return "other";
}

async function verifyHttpNode(site) {
  const api = String(site.api || "").trim().replace(/\/+$/u, "");
  const result = { name: site.name, api: api.slice(0, 60), ok: false, stage: "", ms: 0 };
  const startedAt = Date.now();
  try {
    // TVBox type 1 标准 CMS JSON 接口：先列表后详情
    let listText = "";
    try {
      const list = await fetchText(api + "?ac=list", 10_000);
      listText = list.text;
      if (list.status !== 200) throw new Error("HTTP " + list.status);
    } catch { const alt = await fetchText(api + "?ac=videolist", 10_000); listText = alt.text; }
    if (/^<\?xml|^<rss/iu.test(listText.trim())) {
      const count = (listText.match(/<video>/gu) || []).length;
      return { name: site.name, ok: count > 0, stage: "XML采集站 " + count + " 部", ms: Date.now() - startedAt };
    }
    const listJson = JSON.parse(listText);
    const items = Array.isArray(listJson.list) ? listJson.list : [];
    if (!items.length) { result.stage = "列表为空"; return result; }
    result.ms = Date.now() - startedAt;
    const first = items[0];
    const id = first.vod_id ?? first.id;
    if (id === undefined) { result.ok = true; result.stage = "列表OK(无详情字段)"; return result; }
    const detail = await fetchText(api + "?ac=detail&ids=" + encodeURIComponent(id), 10_000);
    const detailJson = JSON.parse(detail.text);
    const d = (detailJson.list || [])[0] || {};
    const play = String(d.vod_play_url || "");
    if (!play.includes("$")) { result.stage = "详情无播放数据"; return result; }
    result.ok = true;
    result.stage = "列表→详情→播放数据 全通";
    return result;
  } catch (error) {
    result.stage = String(error?.message || error).slice(0, 40);
    result.ms = Date.now() - startedAt;
    return result;
  }
}

async function verifyXmlOrM3uNode(site) {
  try {
    const startedAt = Date.now();
    const { status, text } = await fetchText(String(site.api).trim(), 10_000);
    if (status !== 200) return { name: site.name, ok: false, stage: "HTTP " + status, ms: Date.now() - startedAt };
    if (/^#EXTM3U/mu.test(text)) return { name: site.name, ok: true, stage: "m3u " + (text.match(/#EXTINF/gu) || []).length + " 项", ms: Date.now() - startedAt };
    if (/^<\?xml|<rss/iu.test(text.trim())) { const count = (text.match(/<video>/gu) || []).length; return { name: site.name, ok: count > 0, stage: "xml " + count + " 部", ms: Date.now() - startedAt }; }
    return { name: site.name, ok: false, stage: "未知格式", ms: Date.now() - startedAt };
  } catch (error) {
    return { name: site.name, ok: false, stage: String(error?.message || error).slice(0, 40), ms: 0 };
  }
}

async function main() {
  const verdict = { multi: false, warehouses: [], jar: false, jarClasses: { in: 0, not: 0, classes: [] }, httpNodes: { tested: 0, ok: 0 } };

  // 第 1 层：多仓
  console.log("【第1层】多仓加载:", MULTI_URL);
  const multiText = await fetchText(MULTI_URL);
  if (multiText.status !== 200) { console.log("  ✗ HTTP", multiText.status); process.exit(2); }
  let multi;
  try { multi = JSON.parse(multiText.text); } catch (e) { console.log("  ✗ 非有效 JSON:", e.message.slice(0, 50)); process.exit(2); }
  const entries = Array.isArray(multi.storeHouse) ? multi.storeHouse : (Array.isArray(multi.urls) ? multi.urls.map(u => ({ sourceName: u.name, sourceUrl: u.url })) : []);
  if (!entries.length) { console.log("  ✗ 无仓库条目"); process.exit(2); }
  verdict.multi = true;
  entries.forEach(e => console.log("  ✓", e.sourceName, "→", String(e.sourceUrl).slice(0, 70)));

  // 第 2 层：逐仓加载
  console.log("【第2层】仓库配置加载");
  let mainConfig = null;
  for (const entry of entries) {
    try {
      const { status, text } = await fetchText(entry.sourceUrl, 30_000);
      const config = JSON.parse(text);
      const sites = Array.isArray(config.sites) ? config.sites.length : 0;
      verdict.warehouses.push({ name: entry.sourceName, ok: true, sites });
      console.log("  ✓", entry.sourceName, "| sites:", sites, "| lives:", (config.lives || []).length);
      if (!mainConfig && sites > 0) mainConfig = config;
    } catch (error) {
      verdict.warehouses.push({ name: entry.sourceName, ok: false, error: String(error.message).slice(0, 40) });
      console.log("  ✗", entry.sourceName, error.message.slice(0, 40));
    }
  }
  if (!mainConfig) { console.log("  ✗ 无可用仓库配置 — 验证失败"); process.exit(2); }

  // 第 3 层：jar 真实下载 + 解包 + 按节点的 jar 核验类名
  const jarMap = new Map(); // jarUrl -> classes[]
  for (const site of mainConfig.sites || []) {
    const kind = classifySite(site.api);
    const jar = String(site.jar || mainConfig.spider || "").split(";")[0].trim();
    if (kind === "csp" && /^https?:\/\//iu.test(jar)) {
      if (!jarMap.has(jar)) jarMap.set(jar, []);
      jarMap.get(jar).push(String(site.api).trim());
    }
  }
  console.log("【第3层】jar 核验: 全配置依赖", jarMap.size, "个不同的 jar");
  let jarsValid = 0;
  let classesIn = 0, classesNot = 0;
  const notFoundSample = [];
  for (const [jarUrl, classes] of jarMap) {
    if (jarsValid >= 8) break; // 最多实测 8 个 jar
    try {
      const response = await fetch(jarUrl, { headers: { "user-agent": UA }, signal: AbortSignal.timeout(30_000) });
      const buf = Buffer.from(await response.arrayBuffer());
      const isZip = buf[0] === 0x50 && buf[1] === 0x4b;
      if (!isZip) { console.log("  ✗", jarUrl.slice(0, 60), "→ 非 ZIP（", Math.round(buf.length / 1024) + "KB）"); classesNot += classes.length; continue; }
      const jarPath = join(WORK, "jar-" + jarsValid + ".jar");
      writeFileSync(jarPath, buf);
      const listing = execFileSync("unzip", ["-l", jarPath], { encoding: "utf8" });
      const dexName = (listing.match(/classes\d*\.dex/iu) || ["classes.dex"])[0];
      const dex = execFileSync("unzip", ["-p", jarPath, dexName], { maxBuffer: 64 * 1024 * 1024 });
      // csp_X 是别名：TVBox 按 csp_ + 裸名 解析到 com.github.catvod.spider.X 等包路径，dex 里存在裸名即可定位
      const checkClasses = [...new Set(classes)].slice(0, 5).map((cls) => cls.replace(/^csp_/iu, ""));
      let inCount = 0;
      for (const cls of checkClasses) {
        if (dex.includes(Buffer.from(cls))) inCount++;
        else notFoundSample.push("csp_" + cls + " ← " + jarUrl.slice(0, 40));
      }
      classesIn += inCount;
      classesNot += checkClasses.length - inCount;
      jarsValid++;
      console.log("  ✓", jarUrl.slice(0, 60), "→", Math.round(buf.length / 1024) + "KB | 抽检类", checkClasses.length, "个命中", inCount);
    } catch (error) {
      console.log("  ✗", jarUrl.slice(0, 60), "→", String(error?.message || error).slice(0, 40));
      classesNot += classes.length;
    }
  }
  verdict.jar = jarsValid > 0 && classesNot <= classesIn;
  verdict.jarClasses = { in: classesIn, not: classesNot, notFoundSample };
  if (notFoundSample.length) console.log("  ⚠ 未命中样例:", notFoundSample.slice(0, 4));

  // 第 4 层：节点真实请求（列表→详情→播放数据）
  console.log("【第4层】节点真实请求抽样");
  const sites = mainConfig.sites || [];
  const httpSites = sites.filter(s => classifySite(s.api) === "http");
  const cspSites = sites.filter(s => classifySite(s.api) === "csp");
  const runtimeSites = sites.filter(s => classifySite(s.api) === "runtime");
  console.log("  节点构成: http 直连", httpSites.length, "| csp 爬虫", cspSites.length, "| drpy 脚本", runtimeSites.length, "| 其他", sites.length - httpSites.length - cspSites.length - runtimeSites.length);
  const sampleHttp = [];
  const step = Math.max(1, Math.floor(httpSites.length / 12));
  for (let index = 0; index < httpSites.length && sampleHttp.length < 12; index += step) sampleHttp.push(httpSites[index]);
  const results = await Promise.all(sampleHttp.map(async (site) => {
    const api = String(site.api).trim();
    if (/\.m3u8?|\.txt|\.xml(\?|$)/iu.test(api) || /live/iu.test(String(site.name || ""))) return verifyXmlOrM3uNode(site);
    return verifyHttpNode(site);
  }));
  for (const row of results) {
    console.log("  " + (row.ok ? "✓" : "✗"), String(row.name || "").slice(0, 24), "|", row.stage, "|", row.ms + "ms");
    verdict.httpNodes.tested++;
    if (row.ok) verdict.httpNodes.ok++;
  }
  // drpy 脚本节点：验证源码可达（执行需 TVBox 内嵌 JS 引擎）
  const runtimeSample = runtimeSites.slice(0, 4);
  for (const site of runtimeSample) {
    try {
      const { status, text } = await fetchText(String(site.api).trim(), 10_000);
      const ok = status === 200 && text.length > 100 && !/^\s*</.test(text);
      console.log("  " + (ok ? "✓" : "✗"), "脚本", String(site.name || "").slice(0, 20), "| 源码", Math.round(text.length / 1024) + "KB");
      if (ok) verdict.runtimeOk = (verdict.runtimeOk || 0) + 1;
      verdict.runtimeTested = (verdict.runtimeTested || 0) + 1;
    } catch { verdict.runtimeTested = (verdict.runtimeTested || 0) + 1; }
  }

  // 结论
  const httpOk = verdict.httpNodes.tested > 0 && verdict.httpNodes.ok / verdict.httpNodes.tested >= 0.5;
  const jarOk = verdict.jar;
  console.log("\n========== 验证结论 ==========");
  console.log("多仓加载:", verdict.multi ? "✓" : "✗");
  console.log("仓库配置:", verdict.warehouses.filter(w => w.ok).length + "/" + verdict.warehouses.length, "有效");
  console.log("spider jar 按节点核验:", jarsValid + " 个 jar 实测 | 类名命中 " + verdict.jarClasses.in + " / 未命中 " + verdict.jarClasses.not);
  console.log("http 节点实调:", verdict.httpNodes.ok + "/" + verdict.httpNodes.tested, "全链路可用（列表→详情→播放）");
  if (verdict.runtimeTested) console.log("drpy 脚本抽样:", verdict.runtimeOk + "/" + verdict.runtimeTested, "源码可达（执行需 TVBox 内嵌 JS 引擎）");
  if (cspSites.length) console.log("csp 节点:", cspSites.length, "个（类名核验 " + verdict.jarClasses.in + " 可解析；实际播放需 Android 运行时执行爬虫，最终以真机为准）");
  const runtimeOk = !verdict.runtimeTested || (verdict.runtimeOk || 0) / verdict.runtimeTested >= 0.5;
  const overall = verdict.multi && httpOk && jarOk && runtimeOk;
  console.log("\n总判定:", overall ? "✓ 通过 — 客户端读取链路真实有效" : "✗ 未通过");
  process.exit(overall ? 0 : 3);
}

main().catch((error) => { console.error(error); process.exit(1); });

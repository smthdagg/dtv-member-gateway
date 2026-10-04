#!/usr/bin/env node
// TVBox 多仓/单仓/直播源采集器
// 用法: node scripts/harvest.mjs [--out harvest-output.json]
// 数据来源: 指定站点 + GitHub 仓库/搜索；输出去重、分类、有效性检验后的候选地址。

import { writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";

const BAD_EXTENSIONS = /\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|woff2?|ttf|eot|mp4|mkv|ts|m3u8|zip|apk|txt|html?|php)(?:[?#]|$)/iu;
const HOST_DENY = /(?:^|\.)(?:google\.com|youtube\.com|t\.me|telegram\.me|jqsexy|pornhub|qm\.qq|baidu\.com|hm\.baidu)/iu;
const URL_PATTERN = /https?:\/\/[^\s"'<>()（）【】，。；\\]+/giu;

const DE5_BASE = "https://0.12yue.de5.net/tvbox/";
const DE5_REPO = "lubin776/tvbox-api-backup";
const QIST_REPO = "qist/tvbox";
const JIANGJIANG_URLS = ["https://tv.xn--9swa.com/", "http://tv.xn--9swa.com/"];

function decodeEntities(text) {
  return String(text || "")
    .replace(/\\u002f/giu, "/")
    .replace(/\\\//g, "/")
    .replace(/&amp;/giu, "&")
    .replace(/&#0?38;/g, "&")
    .replace(/&lt;/giu, "<")
    .replace(/&gt;/giu, ">")
    .replace(/&quot;/giu, '"')
    .replace(/&#x2[fF];/g, "/")
    .replace(/&nbsp;/giu, " ");
}

function extractUrls(text) {
  const found = new Set();
  for (const match of decodeEntities(text).matchAll(URL_PATTERN)) {
    let url = match[0].replace(/[.,;：'”）)]+$/u, "").trim();
    if (url.length > 220) continue;
    found.add(url);
  }
  return [...found];
}

async function fetchText(url, { limit = 2_097_152, timeout = 15_000, headers = {} } = {}) {
  const response = await fetch(url, {
    redirect: "follow",
    headers: { "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) DTV-Harvest/1.0", accept: "*/*", ...headers },
    signal: AbortSignal.timeout(timeout),
  });
  if (!response.ok) throw new Error("HTTP " + response.status);
  if (response.body) {
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new Error("响应过大"); }
      chunks.push(value);
    }
    return new TextDecoder().decode(Buffer.concat(chunks)).replace(/^\uFEFF/u, "");
  }
  return "";
}

function classify(text) {
  const trimmed = text.trim();
  if (/^#EXTM3U/mu.test(trimmed)) return { kind: "live", ok: true, channels: (trimmed.match(/^#EXTINF/mgu) || []).length };
  if (!/^[\s]*(?:\{|\[)/u.test(trimmed)) return { kind: "unknown", ok: false };
  let value;
  try { value = JSON.parse(trimmed); } catch { return { kind: "unknown", ok: false }; }
  if (!value || typeof value !== "object") return { kind: "unknown", ok: false };
  if (Array.isArray(value.storeHouse) && value.storeHouse.length) return { kind: "multi", ok: true, entries: value.storeHouse.length };
  if (Array.isArray(value.urls) && value.urls.length && !value.sites) return { kind: "multi", ok: true, entries: value.urls.length };
  const sites = Array.isArray(value.sites) ? value.sites.length : 0;
  const lives = Array.isArray(value.lives) ? value.lives.length : 0;
  if (sites || lives) return { kind: "single", ok: true, sites, lives };
  return { kind: "empty", ok: false };
}

function normalizeUrl(url) {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    let path = parsed.pathname.replace(/\/{2,}/gu, "/");
    if (path.length > 1) path = path.replace(/\/+$/u, "");
    parsed.pathname = path;
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed.href;
  } catch { return String(url).trim(); }
}

function ghApi(path) {
  return JSON.parse(execFileSync("gh", ["api", path, "--cache", "300s"], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }));
}

function decodeIdn(text) {
  try { return decodeURIComponent(text); } catch { return text; }
}

// ---- 采集器：每个返回 [{url, name, kind?, source}] ----

async function collectDe5(add) {
  // 备份站点的全量配置文件清单直接来自 GitHub 仓库 tvbox/ 目录
  try {
    const files = ghApi("repos/" + DE5_REPO + "/contents/tvbox");
    for (const file of files) {
      if (!file.name.endsWith(".json")) continue;
      const name = file.name.replace(/\.json$/u, "");
      add(DE5_BASE + encodeURIComponent(file.name), name, "single", "de5.net");
    }
  } catch (error) {
    console.error("de5 tvbox 目录失败:", String(error.message || error).slice(0, 120));
  }
  // 直播聚合接口
  add("https://0.12yue.de5.net/tvbox/%E6%B5%B7%E9%87%8F%E7%9B%B4%E6%92%AD%E7%BA%BF%E8%B7%AF.json", "海量直播线路", "single", "de5.net");
  // livelist.txt: name|date|size|url|source|ua|
  try {
    const list = await fetchText("https://raw.githubusercontent.com/" + DE5_REPO + "/main/livelist.txt");
    for (const line of list.split(/\r?\n/u)) {
      const parts = line.split("|");
      if (parts.length < 4 || !/^https?:\/\//iu.test(parts[3] || "")) continue;
      add(parts[3].trim(), parts[0].trim(), "live", "de5.livelist");
    }
  } catch (error) {
    console.error("livelist 失败:", String(error.message || error).slice(0, 120));
  }
  // apilinks.txt: 注释分组, "名称, url1, url2"
  try {
    const list = await fetchText("https://raw.githubusercontent.com/" + DE5_REPO + "/main/apilinks.txt");
    for (const line of list.split(/\r?\n/u)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const parts = trimmed.split(",").map((part) => part.trim());
      const name = parts.shift() || "";
      for (const url of parts) {
        if (/^https?:\/\//iu.test(url)) add(url, name, "single", "de5.apilinks");
      }
    }
  } catch (error) {
    console.error("apilinks 失败:", String(error.message || error).slice(0, 120));
  }
}

async function collectQist(add) {
  try {
    const files = ghApi("repos/" + QIST_REPO + "/contents");
    for (const file of files) {
      if (!/\.(json|txt)$/iu.test(file.name)) continue;
      if (/(?:readme|license)/iu.test(file.name)) continue;
      add("https://cdn.jsdelivr.net/gh/" + QIST_REPO + "@main/" + encodeURIComponent(file.name),
        file.name.replace(/\.(json|txt)$/iu, ""), "single", "qist/tvbox");
    }
  } catch (error) {
    console.error("qist 仓库失败:", String(error.message || error).slice(0, 120));
  }
}

async function collectJiangjiang(add) {
  for (const url of JIANGJIANG_URLS) {
    try {
      const html = await fetchText(url, { timeout: 12_000 });
      for (const found of extractUrls(html)) {
        if (BAD_EXTENSIONS.test(found) || HOST_DENY.test(found)) continue;
        add(found, "江江", "single", "tv.江江.com");
      }
      return;
    } catch (error) {
      console.error("江江站抓取失败 (" + url + "):", String(error.message || error).slice(0, 120));
    }
  }
  // TLS 不可达时从 GitHub 已镜像的聚合配置里找江江线路
  try {
    const search = ghApi("search/code?q=%E6%B1%9F%E6%B1%9F+tvbox+in:file+extension:json&per_page=10");
    for (const item of search.items || []) {
      try {
        const content = await fetchText("https://raw.githubusercontent.com/" + item.repository.full_name + "/" + item.path, { limit: 512_000, timeout: 10_000 });
        for (const found of extractUrls(content)) {
          if (/江江|jiangjiang|9swa/iu.test(decodeIdn(found))) add(found, "江江(镜像)", "single", "github-mirror");
        }
      } catch { /* 单文件失败忽略 */ }
    }
  } catch (error) {
    console.error("江江 GitHub 搜索失败:", String(error.message || error).slice(0, 120));
  }
}

async function collectPages(add) {
  const pages = [
    { name: "0.12yue.de5.net", url: "https://0.12yue.de5.net/" },
    { name: "zoo.ink", url: "https://zoo.ink/tvbox.html" },
    { name: "yinghezhinan", url: "https://yinghezhinan.com/tvbox-jsonlist/" },
    { name: "yinghezhinan2", url: "https://yinghezhinan.com/tvbox-warehouse/" },
  ];
  for (const page of pages) {
    try {
      const html = await fetchText(page.url);
      let count = 0;
      for (const found of extractUrls(html)) {
        if (BAD_EXTENSIONS.test(found) || HOST_DENY.test(found)) continue;
        if (/(?:json|tv|config|box|cang|接口|仓)/iu.test(decodeIdn(found)) || /\.json(\?|$)/iu.test(found)) {
          add(found, "", "single", page.name);
          count++;
        }
      }
      console.error(`页面 ${page.name}: 提取 ${count} 条`);
    } catch (error) {
      console.error(`页面 ${page.name} 失败:`, String(error.message || error).slice(0, 120));
    }
  }
}

async function collectGitHubSearch(add) {
  const queries = ["tvbox+多仓", "tvbox+接口", "多仓+storeHouse"];
  const repos = new Map();
  for (const query of queries) {
    try {
      const data = ghApi("search/repositories?q=" + encodeURIComponent(query).replace("%2B", "+") + "&sort=updated&per_page=15");
      for (const repo of data.items || []) repos.set(repo.full_name, repo);
    } catch (error) {
      console.error("GitHub 搜索失败:", query, String(error.message || error).slice(0, 120));
    }
  }
  for (const fullName of repos.keys()) {
    try {
      const readme = ghApi("repos/" + fullName + "/readme");
      const content = Buffer.from(readme.content || "", "base64").toString("utf8");
      for (const found of extractUrls(content)) {
        if (BAD_EXTENSIONS.test(found) || HOST_DENY.test(found)) continue;
        if (/(?:\.json|\/tv\b|tvbox|多仓|单仓|接口)/iu.test(decodeIdn(found))) add(found, "", "single", "github:" + fullName);
      }
    } catch { /* readme 失败跳过 */ }
  }
  console.error("GitHub README 候选来自", repos.size, "个仓库");
}

async function main() {
  const outputIndex = process.argv.indexOf("--out");
  const outputFile = outputIndex > -1 ? process.argv[outputIndex + 1] : "harvest-output.json";
  const candidates = new Map();
  const add = (url, name = "", kind = "", source = "") => {
    const key = normalizeUrl(url);
    if (!key || HOST_DENY.test(key)) return;
    const existing = candidates.get(key);
    if (existing) {
      if (!existing.name && name) existing.name = name;
      return;
    }
    candidates.set(key, { url: key, name: decodeIdn(name), kind, source });
  };

  await collectDe5(add);
  await collectQist(add);
  await collectJiangjiang(add);
  await collectPages(add);
  await collectGitHubSearch(add);

  console.error("候选总数(去重后):", candidates.size, "—— 开始有效性检验");
  const list = [...candidates.values()];
  const results = [];
  let index = 0;
  const worker = async () => {
    while (index < list.length) {
      const item = list[index++];
      const entry = { url: item.url, name: item.name, source: item.source, kind: "unknown", ok: false };
      try {
        const text = await fetchText(item.url, { timeout: 15_000, headers: { accept: "application/json, text/*;q=0.9" } });
        const verdict = classify(text);
        // 站点声明的类型优先，但以实际内容为准修正
        entry.kind = verdict.ok ? verdict.kind : (item.kind || verdict.kind);
        entry.ok = verdict.ok;
        if (verdict.sites !== undefined) entry.sites = verdict.sites;
        if (verdict.lives !== undefined) entry.lives = verdict.lives;
        if (verdict.entries !== undefined) entry.entries = verdict.entries;
        if (verdict.channels !== undefined) entry.channels = verdict.channels;
      } catch (error) {
        entry.kind = item.kind || "unknown";
        entry.error = String(error.message || error).slice(0, 80);
      }
      results.push(entry);
      if (results.length % 20 === 0) console.error(`已检验 ${results.length}/${list.length}`);
    }
  };
  await Promise.all(Array.from({ length: 10 }, worker));

  const ok = results.filter((row) => row.ok);
  const summary = {
    generated_at: new Date().toISOString(),
    candidates: results.length,
    valid: ok.length,
    multi: ok.filter((row) => row.kind === "multi").length,
    single: ok.filter((row) => row.kind === "single").length,
    live: ok.filter((row) => row.kind === "live").length,
  };
  await writeFile(outputFile, JSON.stringify({ summary, results }, null, 2));
  console.error("完成:", JSON.stringify(summary));
  console.error("输出:", outputFile);
}

main().catch((error) => { console.error(error); process.exit(1); });

#!/usr/bin/env node
// 刷新静态节点库：从 Worker 拉最新聚合配置 → 提交推送 GitHub（jsdmirror CDN 自动生效）
// 用法: node scripts/publish-nodes.mjs [workerBase]
import { execFileSync } from "node:child_process";
import { writeFileSync, statSync } from "node:fs";

const BASE = (process.argv[2] || "https://tvbox.aisoft.live").replace(/\/+$/u, "");
const REPO_DIR = "/tmp/aitv-repo";
const response = await fetch(BASE + "/nodes.json", { signal: AbortSignal.timeout(60_000) });
if (!response.ok) { console.error("拉取失败: HTTP " + response.status); process.exit(1); }
const content = await response.text();
JSON.parse(content); // 校验
execFileSync("git", ["clone", "--depth", "1", "https://github.com/smthdagg/aitv-tvbox.git", REPO_DIR], { stdio: "ignore" });
writeFileSync(REPO_DIR + "/tvbox/nodes.json", content);
const changed = execFileSync("git", ["-C", REPO_DIR, "status", "--porcelain"], { encoding: "utf8" });
if (!changed.trim()) { console.log("内容无变化，跳过推送"); process.exit(0); }
execFileSync("git", ["-C", REPO_DIR, "add", "-A"]);
execFileSync("git", ["-C", REPO_DIR, "-c", "user.name=smthdagg", "-c", "user.email=nativeman@gmail.com", "commit", "-qm", "刷新节点库 " + new Date().toISOString().slice(0, 16)]);
execFileSync("git", ["-C", REPO_DIR, "push", "-q", "https://github.com/smthdagg/aitv-tvbox.git", "main"]);
console.log("已发布:", Math.round(content.length / 1024) + "KB → cdn.jsdmirror.com/gh/smthdagg/aitv-tvbox@main/tvbox/nodes.json");

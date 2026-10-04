#!/usr/bin/env bash
# 本地全量回归测试：需要先启动 `npx wrangler dev -c wrangler.share.jsonc --local --port 8787`
set -u
BASE="${BASE:-http://127.0.0.1:8787}"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { # check "<名称>" "<期望>" "<实际>"
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1（期望 $2，实际 $3）"; fi
}
COOKIE=/tmp/test-cookies.txt; rm -f "$COOKIE"
npx wrangler d1 execute dtv-tvbox-share --local -c wrangler.share.jsonc --command "DELETE FROM devices WHERE member_id IN (SELECT id FROM members WHERE telegram_user_id='990000001'); DELETE FROM tokens WHERE member_id IN (SELECT id FROM members WHERE telegram_user_id='990000001'); DELETE FROM usage_hourly WHERE member_id IN (SELECT id FROM members WHERE telegram_user_id='990000001'); DELETE FROM members WHERE telegram_user_id='990000001';" > /dev/null 2>&1
ORIGIN_H=(-H "origin: $BASE" -H "referer: $BASE/admin")

echo "== T1 基础 =="
check "healthz" "200" "$(curl -s -o /dev/null -w '%{http_code}' $BASE/healthz)"
check "后台页" "200" "$(curl -s -o /dev/null -w '%{http_code}' $BASE/admin)"
curl -s -c "$COOKIE" -X POST "$BASE/admin/api/login" -H "content-type: application/json" "${ORIGIN_H[@]}" -d '{"password":"local-test-pass-12345"}' | grep -q '"ok":true' && ok "管理员登录" || bad "管理员登录"

echo "== T2 资源与同步（真实上游）=="
curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -X PUT "$BASE/admin/api/resources/44cc3f2c-31cc-4a72-8245-a274a2c46210" -H "content-type: application/json" -d '{"enabled":false}' > /dev/null
curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -X PUT "$BASE/admin/api/resources/75e014c9-61f5-4566-8c35-e392b2ca64c9" -H "content-type: application/json" -d '{"enabled":false}' > /dev/null
R=$(curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -X POST "$BASE/admin/api/resources/batch" -H "content-type: application/json" -d '{"text":"测试仓|https://cdn.jsdelivr.net/gh/do1linux/tvbox-hub@main/single.json","type":"json","sync_interval_minutes":360}')
echo "$R" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const r=JSON.parse(d);process.exit(r.created===1&&r.results[0].sync_ok?0:1)})' && ok "批量导入+同步成功" || bad "批量导入+同步（$R）"
R=$(curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -X POST "$BASE/admin/api/resources/batch" -H "content-type: application/json" -d '{"text":"坏仓|https://127.0.0.1/x.json"}')
echo "$R" | grep -q '"failed":1' && ok "无效上游被拒绝" || bad "无效上游拒绝（$R）"

echo "== T3 地址库生成 =="
R=$(curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -X POST "$BASE/admin/api/resources/full-update" -d '{}')
echo "$R" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const r=JSON.parse(d);process.exit(r.synced>=1&&r.artifacts&&r.artifacts.resources>=1&&r.artifacts.sites>0?0:1)})' && ok "一键更新（同步+生成两个地址库）" || bad "一键更新"
SLUG=$(echo "$R" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{console.log(JSON.parse(d).results.find(x=>x.ok).slug)})')
check "公开多仓" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/catalog/tvbox.json?v=$RANDOM")"
check "公开单仓" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/catalog/all.json?v=$RANDOM")"
check "单仓内容($SLUG)" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/catalog/$SLUG.json?v=$RANDOM")"
curl -s "$BASE/catalog/tvbox.json" | grep -q "storeHouse" && ok "多仓结构" || bad "多仓结构"
curl -s "$BASE/catalog/all.json" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const j=JSON.parse(d);process.exit(Array.isArray(j.sites)&&j.sites.length>0?0:1)})' && ok "单仓合并有源" || bad "单仓合并"

echo "== T4 会员与两个订阅地址 =="
PLAN=$(curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -X POST "$BASE/admin/api/plans" -H "content-type: application/json" -d '{"name":"测试套餐","duration_days":30,"default_max_devices":3,"enabled":true,"include_all":true,"resource_ids":[]}' | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{console.log(JSON.parse(d).id)})')
[ -n "$PLAN" ] && ok "创建套餐(include_all)" || bad "创建套餐"
TOKEN=$(curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -X POST "$BASE/admin/api/members" -H "content-type: application/json" -d "{\"telegram_user_id\":\"990000001\",\"display_name\":\"回归测试\",\"status\":\"active\",\"plan_id\":\"$PLAN\"}" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{console.log(JSON.parse(d).token||"")})')
[ ${#TOKEN} -ge 42 ] && ok "创建会员+签发Token" || bad "创建会员"
check "会员多仓" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$TOKEN/tvbox.json")"
SITES=$(curl -s "$BASE/$TOKEN/all.json" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{const j=JSON.parse(d);console.log(j.sites.length>0?"ok":"nosites")}catch(e){console.log("parse-fail")}})')
check "会员单仓(网关改写)" "ok" "$SITES"
check "会员分发页含品牌" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$TOKEN")"
curl -s "$BASE/$TOKEN" | grep -q "AITV 共享社区" && ok "分发页品牌/LOGO" || bad "分发页品牌"
# 单仓里的 api 应已改写为本站网关
CODE=$(curl -s -o /tmp/t-all.json -w '%{http_code}' "$BASE/$TOKEN/all.json"); if [ "$CODE" = "200" ]; then node -e 'const j=JSON.parse(require("fs").readFileSync("/tmp/t-all.json"));const gw=(j.sites||[]).filter(s=>String(s.api||"").startsWith("https://tvbox.aisoft.live/"+process.argv[1]+"/")).length;const raw=(j.sites||[]).filter(s=>/^https?:\/\//.test(String(s.api||""))&&!String(s.api).startsWith("https://tvbox.aisoft.live/"+process.argv[1]+"/")).length;process.exit(gw>0&&raw===0?0:1)' "$TOKEN" && ok "单仓 api 全部网关改写（无上游直链泄漏）" || bad "单仓 api 改写"; else bad "单仓改写（HTTP $CODE）"; fi

echo "== T5 设备识别 =="
for i in 1 2 3; do curl -s -o /dev/null -A "okhttp/4.12.0" "$BASE/$TOKEN/tvbox.json"; done
DEV=$(npx wrangler d1 execute dtv-tvbox-share --local -c wrangler.share.jsonc --command "SELECT COUNT(DISTINCT id) AS n FROM devices WHERE member_id=(SELECT m.id FROM members m JOIN tokens t ON t.member_id=m.id WHERE t.token_hash=(SELECT token_hash))" --json 2>/dev/null)
N1=$(npx wrangler d1 execute dtv-tvbox-share --local -c wrangler.share.jsonc --command "SELECT COUNT(DISTINCT id) AS n FROM devices WHERE browser_key='okhttp'" --json 2>/dev/null | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{console.log(JSON.parse(d)[0].results[0].n)})')
check "同客户端反复访问=1台设备" "1" "$N1"
curl -s -o /dev/null -A "DTV-Member-Gateway/1.0" "$BASE/$TOKEN/tvbox.json"
N2=$(npx wrangler d1 execute dtv-tvbox-share --local -c wrangler.share.jsonc --command "SELECT COUNT(DISTINCT id) AS n FROM devices WHERE browser_key='okhttp'" --json 2>/dev/null | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{console.log(JSON.parse(d)[0].results[0].n)})')
check "网关互访不计设备" "$N1" "$N2"
curl -s -o /dev/null -A "okhttp/3.14.9" "$BASE/$TOKEN/tvbox.json"
N3=$(npx wrangler d1 execute dtv-tvbox-share --local -c wrangler.share.jsonc --command "SELECT COUNT(DISTINCT id) AS n FROM devices WHERE browser_key='okhttp'" --json 2>/dev/null | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{console.log(JSON.parse(d)[0].results[0].n)})')
check "同客户端应用升级不算新设备" "$N1" "$N3"
curl -s -o /dev/null -A "Mozilla/5.0 Chrome/126.0" "$BASE/$TOKEN/tvbox.json"
N4=$(npx wrangler d1 execute dtv-tvbox-share --local -c wrangler.share.jsonc --command "SELECT COUNT(DISTINCT id) AS n FROM devices WHERE browser_key='chrome'" --json 2>/dev/null | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{console.log(JSON.parse(d)[0].results[0].n)})')
check "不同客户端算新设备" "1" "$N4"

echo "== T6 安全与异常路径 =="
check "伪造Token→401" "401" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/tvbox.json")"
check "后台API未登录→401" "401" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/admin/api/resources")"
check "保留slug拒绝" "400" "$(curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/admin/api/resources" -H "content-type: application/json" -d '{"slug":"tvbox","name":"x","type":"json","upstream_url":"https://cdn.jsdelivr.net/gh/do1linux/tvbox-hub@main/single.json","allowed_hosts":["cdn.jsdelivr.net"]}')"
check "http上游拒绝(必须https)" "400" "$(curl -s -b "$COOKIE" "${ORIGIN_H[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/admin/api/resources" -H "content-type: application/json" -d '{"slug":"httptest","name":"x","type":"json","upstream_url":"http://example.com/x.json","allowed_hosts":["example.com"]}')"

echo
echo "结果: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ]

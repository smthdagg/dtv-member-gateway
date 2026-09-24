# DTV 会员订阅地址授权系统

Cloudflare Worker 负责 Telegram Bot webhook、管理后台和订阅地址网关；D1 保存会员、套餐、资源权限、Token 摘要、加密后的 Token、审计记录和按小时聚合的请求统计。管理后台位于部署时配置的 `PUBLIC_BASE_URL/admin`。

该项目按附件《会员资源地址授权系统软件需求说明书》实现。Telegram-Stremio 的媒体服务继续运行在原来的服务器上；Cloudflare 这一层负责给它的 Stremio Add-on 地址增加会员入口。Telegram-Stremio README 中的 Add-on 地址格式是 /stremio/{token}/manifest.json，网关可透传该路径结构。[Telegram-Stremio 项目说明](https://github.com/weebzone/Telegram-Stremio)

## 已实现

- 会员、可配置套餐、资源和套餐资源授权。
- 高熵随机会员 Token；D1 保存 SHA-256 摘要及 AES-GCM 密文。原始 Token 只在创建、轮换或会员查询 Bot 地址时解密。
- 路由格式 /{member_token}/{resource_slug}[/{upstream_path}]。每次请求重新检查 Token、状态、到期时间和套餐权限。
- 配置类资源代理、严格 HTTPS 主机白名单、最多 3 次且逐次校验的重定向、响应体大小上限；可显式选用会暴露上游地址的 302 跳转。
- JSON 资源可由管理员一键读取并同步为快照。会员客户端读取时直接得到快照内容，原 JSON 结构保留，聚合 URL 按会员改写为 DTV 网关地址；上游暂时不可用时仍可读取最近一次成功快照。
- JSON 上游快照完整保存。客户端响应保留所有数据项、字段、有效值和顺序，只对可代理的公开 HTTP(S) 地址做网关改写；注释语法会标准化，以兼容严格 JSON 解析器。无法代理的地址会保留，不会由 Worker 抓取。
- 会员 JSON 地址同时兼容 `/{token}/{slug}` 与 `/{token}/{slug}.json`，支持 GET、HEAD 和跨域 OPTIONS 预检，便于不同客户端读取。
- Telegram 自助开通申请：分步收集微信号、会员号和 Telegram 身份信息；管理员批准后自动创建会员、生成地址并通过 Bot 私聊发放。
- Telegram 会员中心：获取当前分发地址、查看会员资料、注册时间、设备数、最近访问时间和 IP；二次确认后可移除单个设备或重置 Token，也可提交续期申请。
- 管理后台：开通申请可勾选多条后批量批准或拒绝；会员创建、资料维护、Token 重置、套餐与资源管理、续期审核、访问汇总和审计记录。
- 开通和续期审核结果会通过 Bot 自动通知会员；后台打开期间自动刷新申请与汇总。暂未接入支付模块。
- Telegram 更新去重；审核员可在后台注册 Telegram webhook；管理员 Bot 身份可通过 /admin 获取后台入口。
- D1 故障时受保护请求失败关闭；后台不会显示完整 Token，资源网关错误不会返回 Token 或上游 URL。

## 与 Telegram-Stremio 配置

在“资源”中新增资源：

- 类型：Telegram-Stremio
- slug：例如 stremio
- 上游 HTTPS 地址：https://你的媒体服务器域名/stremio/原有的媒体服务Token
- 允许的上游域名：媒体服务器的精确主机名
- 返回方式：代理返回
- JSON 改写字段：留空

会员地址会是 `https://你的域名/{会员Token}/{资源代号}/…`。JSON 中可公开代理的 URL 会改写为加密的会员地址；同步保存完整上游快照，客户端响应保留所有数据项、字段、有效值和顺序，并移除 JSON 注释语法以兼容标准解析器。通过已绑定的域名读取文件、图片、文本及媒体响应会原样透传，并支持 Range；二级 JSON 响应按请求使用的域名改写 URL。源内容里的 localhost、内网或 IP 字面量地址仍保留在 JSON 中，但不会由 Worker 访问。

普通 TV 订阅和配置文件可以使用相同网关。JSON 文档中的绝对 HTTP(S) 链接及配置的地址字段会改写为会员网关地址；非 JSON 文本（如 M3U）中的播放地址不会自动改写。

JSON 管理流程：保存资源后，在“资源”页点击“读取并同步全部 JSON”或对应行的“读取并同步”。后台会检查上游响应大小、JSON/JSONC 格式、顶层结构和可改写地址数量，然后保存最新有效快照。快照不会包含会员 Token；每个会员请求时才生成该会员自己的网关地址。更换上游 URL、白名单、资源类型或大小上限会清除旧快照，需要再次同步。同步失败时保留上一次成功快照，并显示错误码。

## Cloudflare 部署

准备 Node.js 20 或更新版本、Cloudflare 账号权限，以及你要绑定域名所在 Cloudflare zone 的写入权限。Cloudflare Custom Domain 会为 Worker 建立 DNS 记录和证书。复制示例配置后填写自己的域名和数据库信息：

~~~sh
npm install
npx wrangler login
npm run prepare:ui
npx wrangler d1 create dtv-member-auth --location apac
cp wrangler.example.jsonc wrangler.jsonc
~~~

编辑本机 `wrangler.jsonc`：将 `member.example.com` 替换为你的自有域名，把创建命令返回的数据库 UUID 写入 `d1_databases[0].database_id`。这个文件包含部署配置，已被 Git 忽略。之后执行：

~~~sh
npx wrangler d1 migrations apply dtv-member-auth --remote
npm run deploy
~~~

`npm run deploy` 会先把 `public/` 中的管理界面嵌入 Worker，再发布版本。

初始迁移会加入两个 `example.com` 占位 JSON 资源和标准套餐。部署后，请在管理后台将占位 URL 替换成你有权分发的资源地址，再执行同步。`0002_seed_initial_catalog.sql` 可重复执行。

部署时不要把密钥放进 wrangler.jsonc、.env、Git 或聊天记录。使用 Wrangler 的交互式 Secret 命令录入：

~~~sh
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SESSION_SECRET
npx wrangler secret put TOKEN_ENCRYPTION_KEY
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TELEGRAM_WEBHOOK_SECRET
npx wrangler secret put ADMIN_TELEGRAM_IDS
~~~

生成密钥的示例（复制命令生成的值到 Wrangler 的隐藏输入提示中）：

~~~sh
openssl rand -base64 32
openssl rand -hex 32
~~~

SESSION_SECRET 用第一条命令生成；TOKEN_ENCRYPTION_KEY 也使用第一条命令生成；TELEGRAM_WEBHOOK_SECRET 使用第二条命令生成。ADMIN_PASSWORD 由你设置；ADMIN_TELEGRAM_IDS 填 Telegram 数字 ID，多个 ID 用逗号分隔。Bot Token 由 BotFather 提供。设置这些 Secret 会发布新 Worker 版本。完成后访问 /admin 登录，点击“绑定 Telegram Bot”完成 webhook 注册。

上线时确认 Worker 的故障模式为 Fail closed。Cloudflare Workers Free 在达到每日请求额度后，可配置为绕过 Worker；这套系统必须让受保护路由在超限时返回错误，不能绕过授权。

## 平台容量

截至 2026-09-24，Cloudflare 文档列出 Workers Free 每日 100,000 次请求，D1 Free 每日 5,000,000 行读取和 100,000 行写入；超过 Free D1 行读写限制时查询会失败直到 UTC 午夜重置。[Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [D1 价格与用量](https://developers.cloudflare.com/d1/platform/pricing/) · [D1 Free 限额执行公告](https://developers.cloudflare.com/changelog/post/2026-09-01-d1-free-tier-limit-enforcement/)

每个授权请求会更新一条小时统计，默认保留 90 天，可通过 USAGE_RETENTION_DAYS 调整；每分钟频控使用 Cloudflare Rate Limiting Binding，不写入 D1。Free 额度下，预计 D1 行写入会先于 Worker 请求额度成为压力点。5,000 个注册会员本身不能说明日请求量；客户端轮询频率、资源数量和实际使用量决定是否应启用 Workers Paid / D1 Paid。Cloudflare Rate Limiting Binding 是按边缘位置的近似频控，不用于精确结算或严格全局配额。[Rate Limiting Binding 说明](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)

## 首次使用

1. 在“资源”中添加一个或多个上游地址。
2. 在“套餐”中选择资源并保存套餐。
3. 新用户私聊 Bot 发送 /start，依次填写微信号、会员号并选择套餐；Bot 将申请自动送到后台并通知管理员。
4. 管理员在“开通申请”勾选一条或多条后点“批准所选”；系统自动创建会员、签发专属地址并由 Bot 私聊发放，也可一键拒绝所选申请。
5. 会员通过 Bot 获取分发地址、查看资料和设备、移除设备、申请增加设备数或申请续期；设备扩容和续期审核通过后会自动更新会员资料。
6. 暂停、撤销、到期或轮换 Token 后，之后的新网关请求会立即被拒绝。

后台密码目前为单一共享管理员密码；ADMIN_TELEGRAM_IDS 用于 Bot 管理员身份检查。Bot 申请保存用户提交的微信号和会员号。设备名额按 User-Agent 与 Cloudflare 提供的 IP 地理位置组合计数，同一组合重复访问只占一个名额。达到上限时仅拒绝新的设备标识，已登记设备继续访问；会员移除设备会释放一个名额，Bot 可提交增加设备数申请，管理员批准后自动提高上限（最多 50）。此识别不读取硬件序列号；同一位置、相同 User-Agent 的不同设备可能合并，地理位置或客户端标识变化也可能产生新记录。完整订阅 JSON 保留全部条目，仅把可代理地址替换为会员专属网关地址；嵌套 JSON 地址同样代理，其他响应以流方式透传并支持 Range。

## 尚需上线前确认

- 实际上游资源地址、资源域名白名单与需要代理的 JSON 地址字段。
- Cloudflare Free 或 Paid 套餐，以及可接受的日请求量与预算。
- 会员展示时区、访问汇总保留期、数据导出和删除流程。
- 上游 Telegram-Stremio 是否会为每位会员签发原生 Token，以及外部播放地址的访问策略。

## API 错误码

TOKEN_INVALID、MEMBER_EXPIRED、MEMBER_SUSPENDED、MEMBER_REVOKED、MEMBER_NOT_ACTIVE、DEVICE_LIMIT_EXCEEDED、DEVICE_REMOVED、RESOURCE_FORBIDDEN、RATE_LIMITED、UPSTREAM_NOT_APPROVED、UPSTREAM_RESPONSE_TOO_LARGE、JSON_REWRITE_UNSUPPORTED、DATABASE_UNAVAILABLE。

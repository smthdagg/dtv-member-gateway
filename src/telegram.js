import {
  apiError, audit, decryptToken, issueToken, json, newId, nowIso, readJson, safeEqual,
} from "./security.js";

const encoder = new TextEncoder();

function keyboard() {
  return {
    inline_keyboard: [
      [{ text: "获取当前分发地址", callback_data: "links" }],
      [{ text: "会员信息", callback_data: "member_profile" }, { text: "设备管理", callback_data: "devices" }],
      [{ text: "续期申请", callback_data: "renew" }],
      [{ text: "申请增加设备数", callback_data: "device_limit_request" }],
      [{ text: "重置订阅地址", callback_data: "reset_start" }],
    ],
  };
}

function guestKeyboard() {
  return { inline_keyboard: [[{ text: "申请开通会员", callback_data: "signup_apply" }], [{ text: "查看开通进度", callback_data: "signup_status" }]] };
}

async function sendMessage(env, chatId, text, replyMarkup) {
  if (!env.TELEGRAM_BOT_TOKEN) return false;
  const body = {
    chat_id: chatId,
    text: String(text).slice(0, 3900),
    disable_web_page_preview: true,
  };
  if (replyMarkup) body.reply_markup = replyMarkup;
  try {
    const response = await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/sendMessage", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const result = await response.json().catch(() => null);
    return response.ok && result?.ok === true;
  } catch {
    return false;
  }
}

async function answerCallback(env, callbackId, text = "") {
  if (!env.TELEGRAM_BOT_TOKEN) return;
  await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/answerCallbackQuery", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ callback_query_id: callbackId, text: String(text).slice(0, 180) }),
  });
}

async function findMember(db, telegramId) {
  return db.prepare("SELECT m.*, p.name AS plan_name, p.duration_days, t.id AS token_id, t.token_hash, t.token_ciphertext FROM members m LEFT JOIN plans p ON p.id = m.plan_id LEFT JOIN tokens t ON t.member_id = m.id AND t.revoked_at IS NULL WHERE m.telegram_user_id = ?").bind(String(telegramId)).first();
}

function currentlyActive(member) {
  return member && member.status === "active" && member.expires_at && Date.parse(member.expires_at) > Date.now();
}

async function permittedResources(db, member) {
  const result = await db.prepare("SELECT r.id, r.slug, r.name, r.type FROM resources r JOIN plan_resources pr ON pr.resource_id = r.id WHERE pr.plan_id = ? AND r.enabled = 1 ORDER BY r.name")
    .bind(member.plan_id).all();
  return result.results || [];
}

function displayDate(value, env) {
  if (!value) return "暂无";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "暂无";
  return parsed.toLocaleString("zh-CN", { timeZone: env.DISPLAY_TIME_ZONE || "Asia/Singapore" });
}

async function activeDevices(db, memberId) {
  const result = await db.prepare("SELECT id, ip_address, geo_location, user_agent_hint, first_seen, last_seen FROM devices WHERE member_id = ? AND revoked_at IS NULL ORDER BY last_seen DESC LIMIT 20")
    .bind(memberId).all();
  return result.results || [];
}

async function memberProfile(env, db, member) {
  if (!member) return "尚未找到会员资料。发送 /start 即可开始申请。";
  const [count, lastSeen, devices] = await Promise.all([
    db.prepare("SELECT COUNT(*) AS count FROM devices WHERE member_id = ? AND revoked_at IS NULL").bind(member.id).first(),
    db.prepare("SELECT MAX(last_seen) AS last_seen FROM devices WHERE member_id = ?").bind(member.id).first(),
    activeDevices(db, member.id),
  ]);
  const status = currentlyActive(member) ? "有效" : (member.status || "未开通");
  const lines = [
    "会员资料",
    "姓名：" + (member.display_name || "未填写"),
    "Telegram：" + (member.telegram_username ? "@" + member.telegram_username + " · " : "") + member.telegram_user_id,
    "微信号：" + (member.wechat_id || "未填写"),
    "会员号：" + (member.member_number || "未填写"),
    "套餐：" + (member.plan_name || "未分配"),
    "状态：" + status,
    "注册时间：" + displayDate(member.created_at, env),
    "到期时间：" + displayDate(member.expires_at, env),
    "当前设备数：" + Number(count?.count || 0) + " / " + Number(member.max_devices || 1),
    "上一次访问：" + displayDate(lastSeen?.last_seen, env),
  ];
  if (devices.length) {
    lines.push("最近设备位置：" + (devices[0].geo_location || "未知"));
    lines.push("最近设备 IP：" + (devices[0].ip_address || "未知"));
  } else {
    lines.push("最近设备位置：暂无记录");
    lines.push("最近设备 IP：暂无记录");
  }
  lines.push("\n设备按 User-Agent 与 Cloudflare 提供的 IP 地理位置组合识别；相同设备的重复访问不会反复占用名额。地理位置变化或客户端标识变化时可能识别为新设备。当前识别不读取客户端硬件序列号。");
  return lines.join("\n");
}

function deviceKeyboard(devices) {
  const rows = devices.map((device) => [{
    text: "移除此设备 · " + (device.geo_location || device.ip_address || "位置未知").slice(0, 28),
    callback_data: "device_remove:" + device.id,
  }]);
  rows.push([{ text: "申请增加设备数", callback_data: "device_limit_request" }]);
  rows.push([{ text: "返回会员菜单", callback_data: "home" }]);
  return { inline_keyboard: rows };
}

async function linkList(env, db, member) {
  if (!currentlyActive(member)) {
    return "当前会员状态：" + (member?.status || "未开通") + "\n到期时间：" + (member?.expires_at || "未设置") + "\n如需开通或续期，请联系管理员。";
  }
  if (!member.token_ciphertext) return "当前账户没有有效订阅地址，请联系管理员。";
  const token = await decryptToken(member.token_ciphertext, env.TOKEN_ENCRYPTION_KEY);
  const resources = await permittedResources(db, member);
  if (!resources.length) return "会员有效，但套餐还没有分配资源。请联系管理员。";
  const base = String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "");
  const lines = [
    "会员状态：有效",
    "套餐：" + (member.plan_name || "未命名"),
    "到期时间：" + new Date(member.expires_at).toLocaleString("zh-CN", { timeZone: env.DISPLAY_TIME_ZONE || "Asia/Singapore" }),
    "",
    "个人订阅地址（请勿转发）：",
  ];
  for (const resource of resources) {
    const suffix = resource.type === "stremio" ? "/manifest.json" : resource.type === "json" ? ".json" : "";
    lines.push(resource.name + "： " + base + "/" + token + "/" + resource.slug + suffix);
  }
  lines.push("", "这些地址包含你的访问凭证。重置后旧地址立即失效。");
  return lines.join("\n");
}

function adminTelegramIds(env) {
  return [...new Set(String(env.ADMIN_TELEGRAM_IDS || "").split(",").map((value) => value.trim()).filter((value) => /^\d{5,20}$/u.test(value)))];
}

async function notifyAdmins(env, text, keyboardMarkup) {
  await Promise.all(adminTelegramIds(env).map((adminId) => sendMessage(env, adminId, text, keyboardMarkup)));
}

async function pendingSignup(db, telegramId) {
  return db.prepare("SELECT s.*, p.name AS plan_name FROM signup_requests s JOIN plans p ON p.id = s.plan_id WHERE s.telegram_user_id = ? AND s.status = 'pending' LIMIT 1")
    .bind(String(telegramId)).first();
}

async function beginSignup(env, db, user, chatId) {
  const telegramId = String(user.id || "");
  if (adminTelegramIds(env).includes(telegramId)) {
    await sendAdminHome(env, db, chatId);
    return;
  }
  const existing = await pendingSignup(db, telegramId);
  if (existing) {
    await sendMessage(env, chatId, "你的开通申请正在审核中。选择“查看开通进度”可再次查看。", guestKeyboard());
    return;
  }
  if (await db.prepare("SELECT id FROM members WHERE telegram_user_id = ?").bind(telegramId).first()) {
    await sendMessage(env, chatId, "已找到你的会员资料，请使用下方菜单管理订阅。", keyboard());
    return;
  }
  const now = nowIso();
  const displayName = [user.first_name, user.last_name].filter(Boolean).join(" ").slice(0, 120);
  const username = String(user.username || "").slice(0, 64);
  await db.prepare("INSERT INTO signup_drafts (telegram_user_id, telegram_username, display_name, step, wechat_id, member_number, created_at, updated_at) VALUES (?, ?, ?, 'wechat_id', '', '', ?, ?) ON CONFLICT(telegram_user_id) DO UPDATE SET telegram_username = excluded.telegram_username, display_name = excluded.display_name, step = 'wechat_id', wechat_id = '', member_number = '', created_at = excluded.created_at, updated_at = excluded.updated_at")
    .bind(telegramId, username, displayName, now, now).run();
  await sendMessage(env, chatId,
    "开始申请会员。请发送你的微信号（仅用于管理员核验）；下一步会询问会员号。提交后资料只用于本次会员审核。\n\n随时发送 /cancel 可取消。\n\n请输入微信号：",
    guestKeyboard(),
  );
}

async function continueSignupAfterDetails(env, db, user, chatId) {
  const plans = await db.prepare("SELECT id, name, duration_days FROM plans WHERE enabled = 1 ORDER BY duration_days, name").all();
  const available = plans.results || [];
  if (!available.length) {
    await db.prepare("DELETE FROM signup_drafts WHERE telegram_user_id = ?").bind(String(user.id)).run();
    await sendMessage(env, chatId, "目前没有可申请的会员套餐，请稍后联系管理员。", guestKeyboard());
    return;
  }
  if (available.length === 1) {
    await submitSignupDraft(env, db, user, chatId, available[0].id);
    return;
  }
  await db.prepare("UPDATE signup_drafts SET step = 'plan', updated_at = ? WHERE telegram_user_id = ?")
    .bind(nowIso(), String(user.id)).run();
  const rows = available.map((plan) => [{ text: plan.name + " · " + plan.duration_days + " 天", callback_data: "signup_plan:" + plan.id }]);
  await sendMessage(env, chatId, "请选择申请的会员套餐：", { inline_keyboard: rows });
}

async function submitSignupDraft(env, db, user, chatId, planId) {
  const telegramId = String(user.id || "");
  const draft = await db.prepare("SELECT * FROM signup_drafts WHERE telegram_user_id = ? AND step = 'plan'")
    .bind(telegramId).first();
  const plan = await db.prepare("SELECT id, name, duration_days FROM plans WHERE id = ? AND enabled = 1")
    .bind(planId).first();
  if (!draft || !plan) {
    await sendMessage(env, chatId, "申请信息已过期，请重新发送 /start。", guestKeyboard());
    return;
  }
  const id = newId();
  const createdAt = nowIso();
  const inserted = await db.prepare("INSERT INTO signup_requests (id, telegram_user_id, telegram_username, display_name, wechat_id, member_number, plan_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?) ON CONFLICT DO NOTHING RETURNING id")
    .bind(id, telegramId, draft.telegram_username, draft.display_name, draft.wechat_id, draft.member_number, plan.id, createdAt).first();
  await db.prepare("DELETE FROM signup_drafts WHERE telegram_user_id = ?").bind(telegramId).run();
  if (!inserted?.id) {
    await sendMessage(env, chatId, "你的申请已提交，请等待管理员审核。", guestKeyboard());
    return;
  }
  await audit(db, "telegram:" + telegramId, "signup.request", "signup_request", id, "plan=" + plan.id);
  const userLabel = (draft.display_name || "Telegram 用户") + (draft.telegram_username ? " (@" + draft.telegram_username + ")" : "");
  await notifyAdmins(env,
    "新的会员开通申请\n" + userLabel + "\nTelegram ID：" + telegramId + "\n微信号：" + draft.wechat_id + "\n会员号：" + draft.member_number + "\n套餐：" + plan.name + "（" + plan.duration_days + " 天）\n申请时间：" + createdAt,
    { inline_keyboard: [[{ text: "批准并开通", callback_data: "signup_approve:" + id }, { text: "拒绝", callback_data: "signup_reject:" + id }], [{ text: "管理后台", url: String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "") + "/admin" }]] },
  );
  await sendMessage(env, chatId, "申请资料已提交，管理员审核通过后，Bot 会自动发送你的专属分发地址。", guestKeyboard());
}

export async function notifyMemberProvisioned(env, db, telegramId, prefix = "会员已开通") {
  const member = await findMember(db, telegramId);
  if (!member) return false;
  return sendMessage(env, telegramId, prefix + "\n\n" + await linkList(env, db, member), keyboard());
}

export async function notifyDeviceLimitDecision(env, telegramId, status, maxDevices, addedDevices) {
  const message = status === "approved"
    ? "增加设备数申请已批准\n新增 " + addedDevices + " 台，总设备上限现为 " + maxDevices + " 台。"
    : "增加设备数申请未获批准；如需说明，请联系管理员。";
  return sendMessage(env, telegramId, message, keyboard());
}

async function notifySignupDecision(env, db, telegramId, approved, note = "") {
  if (approved) return notifyMemberProvisioned(env, db, telegramId, "开通申请已通过");
  return sendMessage(env, telegramId, "开通申请暂未通过。" + (note ? "\n原因：" + note : "") + "\n如需协助，请联系管理员。", guestKeyboard());
}

export async function reviewSignup(db, env, requestId, status, actorId, note = "") {
  if (!["approved", "rejected"].includes(status)) return { error: "SIGNUP_STATUS_INVALID" };
  const application = await db.prepare("SELECT s.*, p.name AS plan_name, p.duration_days, p.default_max_devices, p.enabled AS plan_enabled FROM signup_requests s JOIN plans p ON p.id = s.plan_id WHERE s.id = ? AND s.status = 'pending'")
    .bind(requestId).first();
  if (!application) return { error: "SIGNUP_NOT_PENDING" };
  const now = nowIso();
  if (status === "rejected") {
    const updated = await db.prepare("UPDATE signup_requests SET status = 'rejected', note = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending'")
      .bind(String(note).slice(0, 300), now, actorId, requestId).run();
    if (Number(updated?.meta?.changes || 0) !== 1) return { error: "SIGNUP_NOT_PENDING" };
    await audit(db, actorId, "signup.rejected", "signup_request", requestId, "telegram_user_id=" + application.telegram_user_id);
    await notifySignupDecision(env, db, application.telegram_user_id, false, String(note).slice(0, 300));
    return { request_id: requestId, status };
  }
  if (!application.plan_enabled) return { error: "PLAN_NOT_FOUND" };
  if (await db.prepare("SELECT id FROM members WHERE telegram_user_id = ?").bind(application.telegram_user_id).first()) return { error: "MEMBER_ALREADY_EXISTS" };
  const memberId = newId();
  const tokenId = newId();
  const issued = await issueToken(env);
  const expiresAt = new Date(Date.now() + application.duration_days * 86400000).toISOString();
  const results = await db.batch([
    db.prepare("INSERT INTO members (id, telegram_user_id, telegram_username, display_name, wechat_id, member_number, status, plan_id, expires_at, max_devices, notes, created_at, updated_at) SELECT ?, telegram_user_id, telegram_username, display_name, wechat_id, member_number, 'active', plan_id, ?, ?, '', ?, ? FROM signup_requests WHERE id = ? AND status = 'pending' AND NOT EXISTS (SELECT 1 FROM members WHERE telegram_user_id = signup_requests.telegram_user_id)")
      .bind(memberId, expiresAt, Math.max(1, Number(application.default_max_devices || 1)), now, now, requestId),
    db.prepare("INSERT INTO tokens (id, member_id, token_hash, token_ciphertext, created_at) SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM members WHERE id = ?)")
      .bind(tokenId, memberId, issued.tokenHash, issued.tokenCiphertext, now, memberId),
    db.prepare("UPDATE signup_requests SET status = 'approved', member_id = ?, note = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending' AND EXISTS (SELECT 1 FROM members WHERE id = ?)")
      .bind(memberId, String(note).slice(0, 300), now, actorId, requestId, memberId),
  ]);
  if (Number(results?.[0]?.meta?.changes || 0) !== 1 || Number(results?.[1]?.meta?.changes || 0) !== 1 || Number(results?.[2]?.meta?.changes || 0) !== 1) {
    if (await db.prepare("SELECT id FROM members WHERE telegram_user_id = ?").bind(application.telegram_user_id).first()) return { error: "MEMBER_ALREADY_EXISTS" };
    return { error: "SIGNUP_NOT_PENDING" };
  }
  await audit(db, actorId, "signup.approved", "member", memberId, "signup_request=" + requestId + "; plan=" + application.plan_id);
  await notifySignupDecision(env, db, application.telegram_user_id, true);
  return { request_id: requestId, member_id: memberId, status };
}

async function requestRenewal(env, db, member, telegramId) {
  const id = newId();
  const createdAt = nowIso();
  const inserted = await db.prepare("INSERT INTO renewal_requests (id, member_id, status, note, created_at) VALUES (?, ?, 'pending', '', ?) ON CONFLICT(member_id) WHERE status = 'pending' DO NOTHING RETURNING id")
    .bind(id, member.id, createdAt).first();
  if (inserted?.id) {
    await audit(db, "telegram:" + telegramId, "renewal.request", "member", member.id, "request=" + id);
    const userLabel = (member.display_name || "會員") + (member.telegram_username ? " (@" + member.telegram_username + ")" : "");
    await notifyAdmins(env,
      "新的续期申请\n" + userLabel + "\nTelegram ID：" + telegramId + "\n当前套餐：" + (member.plan_name || "未命名") + "\n申请时间：" + createdAt,
      { inline_keyboard: [[{ text: "批准续期", callback_data: "renew_approve:" + id }, { text: "拒绝", callback_data: "renew_reject:" + id }], [{ text: "管理后台", url: String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "") + "/admin" }]] },
    );
  }
  return Boolean(inserted?.id);
}

async function requestDeviceLimit(env, db, member, telegramId, additionalDevices) {
  const amount = Number(additionalDevices);
  const max = Number(member.max_devices || 1);
  if (!Number.isInteger(amount) || amount < 1 || amount > 5 || max + amount > 50) return { error: "DEVICE_LIMIT_REQUEST_INVALID" };
  const id = newId();
  const createdAt = nowIso();
  const inserted = await db.prepare("INSERT INTO device_limit_requests (id, member_id, additional_devices, status, created_at) VALUES (?, ?, ?, 'pending', ?) ON CONFLICT(member_id) WHERE status = 'pending' DO NOTHING RETURNING id")
    .bind(id, member.id, amount, createdAt).first();
  if (!inserted?.id) return { pending: true };
  await audit(db, "telegram:" + telegramId, "device_limit.request", "member", member.id, "additional_devices=" + amount);
  const active = await db.prepare("SELECT COUNT(*) AS count FROM devices WHERE member_id = ? AND revoked_at IS NULL").bind(member.id).first();
  const label = (member.display_name || "会员") + (member.telegram_username ? " (@" + member.telegram_username + ")" : "");
  await notifyAdmins(env,
    "增加设备数申请\n" + label + "\nTelegram ID：" + telegramId + "\n会员号：" + (member.member_number || "未填写") +
    "\n当前设备：" + Number(active?.count || 0) + " / " + max + "\n申请新增：" + amount + " 台\n申请时间：" + createdAt,
    { inline_keyboard: [[{ text: "打开后台审核", url: String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "") + "/admin" }]] },
  );
  return { request_id: id };
}

export async function reviewRenewal(db, env, requestId, status, actorId, note = "") {
  if (!["approved", "rejected"].includes(status)) return { error: "RENEWAL_STATUS_INVALID" };
  const renewal = await db.prepare("SELECT r.id, r.member_id, m.telegram_user_id, m.expires_at, p.duration_days FROM renewal_requests r JOIN members m ON m.id = r.member_id JOIN plans p ON p.id = m.plan_id WHERE r.id = ? AND r.status = 'pending'")
    .bind(requestId).first();
  if (!renewal) return { error: "RENEWAL_NOT_FOUND" };
  const reviewedAt = nowIso();
  let changes = 0;
  if (status === "approved") {
    const base = Math.max(Date.now(), Date.parse(renewal.expires_at || "") || 0);
    const expiry = new Date(base + renewal.duration_days * 86400000).toISOString();
    const results = await db.batch([
      db.prepare("UPDATE members SET status = 'active', expires_at = ?, updated_at = ? WHERE id = ? AND EXISTS (SELECT 1 FROM renewal_requests WHERE id = ? AND status = 'pending')")
        .bind(expiry, reviewedAt, renewal.member_id, requestId),
      db.prepare("UPDATE renewal_requests SET status = 'approved', note = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'")
        .bind(String(note).slice(0, 300), reviewedAt, requestId),
    ]);
    changes = Number(results?.[1]?.meta?.changes || 0);
    if (changes !== 1) return { error: "RENEWAL_NOT_FOUND" };
  } else {
    const result = await db.prepare("UPDATE renewal_requests SET status = 'rejected', note = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'")
      .bind(String(note).slice(0, 300), reviewedAt, requestId).run();
    changes = Number(result?.meta?.changes || 0);
    if (changes !== 1) return { error: "RENEWAL_NOT_FOUND" };
  }
  await audit(db, actorId, "renewal." + status, "member", renewal.member_id, "request=" + requestId);
  if (status === "approved") await notifyMemberProvisioned(env, db, renewal.telegram_user_id, "续期申请已通过");
  else await sendMessage(env, renewal.telegram_user_id, "续期申请暂未通过。" + (note ? "\n原因：" + String(note).slice(0, 300) : "") + "\n如需协助，请联系管理员。", keyboard());
  return { id: requestId, status };
}

function adminKeyboard(env) {
  const base = String(env.PUBLIC_BASE_URL || "https://member.example.com").replace(/\/+$/u, "");
  return { inline_keyboard: [
    [{ text: "待审开通申请", callback_data: "admin_apps:0" }, { text: "待审续期", callback_data: "admin_renewals:0" }],
    [{ text: "设备扩容申请管理", url: base + "/admin" }],
    [{ text: "会员管理", callback_data: "admin_members:0" }],
    [{ text: "套餐", callback_data: "admin_plans" }, { text: "资源", callback_data: "admin_resources" }],
    [{ text: "打开完整管理后台", url: base + "/admin" }],
  ] };
}

async function sendAdminHome(env, db, chatId) {
  const [applications, renewals, deviceRequests, members] = await Promise.all([
    db.prepare("SELECT COUNT(*) AS count FROM signup_requests WHERE status = 'pending'").first(),
    db.prepare("SELECT COUNT(*) AS count FROM renewal_requests WHERE status = 'pending'").first(),
    db.prepare("SELECT COUNT(*) AS count FROM device_limit_requests WHERE status = 'pending'").first(),
    db.prepare("SELECT COUNT(*) AS count FROM members WHERE status = 'active' AND expires_at > ?").bind(nowIso()).first(),
  ]);
  await sendMessage(env, chatId,
    "管理员控制台\n待审开通：" + Number(applications?.count || 0) + "\n待审续期：" + Number(renewals?.count || 0) + "\n待审设备扩容：" + Number(deviceRequests?.count || 0) + "\n有效会员：" + Number(members?.count || 0) + "\n\n可在 Bot 内审核申请、管理会员和切换套餐/资源状态；设备扩容审核和批量管理可打开管理后台。",
    adminKeyboard(env),
  );
}

async function handleAdminAction(env, db, telegramId, chatId, action) {
  if (action === "admin_home") return sendAdminHome(env, db, chatId);
  if (action === "admin_overview") return sendAdminHome(env, db, chatId);
  if (action.startsWith("admin_apps")) {
    const offset = Math.max(0, Math.min(1000, Number(action.split(":")[1] || 0)));
    const result = await db.prepare("SELECT s.id, s.telegram_user_id, s.telegram_username, s.display_name, s.wechat_id, s.member_number, s.created_at, p.name AS plan_name, p.duration_days FROM signup_requests s JOIN plans p ON p.id = s.plan_id WHERE s.status = 'pending' ORDER BY s.created_at LIMIT 8 OFFSET ?")
      .bind(offset).all();
    const rows = result.results || [];
    if (!rows.length) {
      await sendMessage(env, chatId, "当前没有待审核的开通申请。", adminKeyboard(env));
      return;
    }
    for (const item of rows) {
      const name = item.display_name || "Telegram 用户";
      await sendMessage(env, chatId,
        "开通申请\n" + name + (item.telegram_username ? " (@" + item.telegram_username + ")" : "") +
        "\nTelegram ID：" + item.telegram_user_id + "\n微信号：" + item.wechat_id + "\n会员号：" + item.member_number +
        "\n套餐：" + item.plan_name + "（" + item.duration_days + " 天）\n申请时间：" + displayDate(item.created_at, env),
        { inline_keyboard: [[{ text: "批准并发放地址", callback_data: "signup_approve:" + item.id }, { text: "拒绝", callback_data: "signup_reject:" + item.id }]] },
      );
    }
    const nav = [[{ text: "返回管理员菜单", callback_data: "admin_home" }]];
    if (rows.length === 8) nav.unshift([{ text: "下一页", callback_data: "admin_apps:" + (offset + 8) }]);
    await sendMessage(env, chatId, "开通申请列表 · " + (offset + 1) + "–" + (offset + rows.length), { inline_keyboard: nav });
    return;
  }
  if (action.startsWith("admin_renewals")) {
    const offset = Math.max(0, Math.min(1000, Number(action.split(":")[1] || 0)));
    const result = await db.prepare("SELECT r.id, r.created_at, m.telegram_user_id, m.telegram_username, m.display_name, p.name AS plan_name FROM renewal_requests r JOIN members m ON m.id = r.member_id LEFT JOIN plans p ON p.id = m.plan_id WHERE r.status = 'pending' ORDER BY r.created_at LIMIT 8 OFFSET ?")
      .bind(offset).all();
    const rows = result.results || [];
    if (!rows.length) {
      await sendMessage(env, chatId, "当前没有待审核的续期申请。", adminKeyboard(env));
      return;
    }
    for (const item of rows) {
      await sendMessage(env, chatId,
        "续期申请\n" + (item.display_name || "会员") + (item.telegram_username ? " (@" + item.telegram_username + ")" : "") +
        "\nTelegram ID：" + item.telegram_user_id + "\n套餐：" + (item.plan_name || "未分配") + "\n申请时间：" + displayDate(item.created_at, env),
        { inline_keyboard: [[{ text: "批准续期", callback_data: "renew_approve:" + item.id }, { text: "拒绝", callback_data: "renew_reject:" + item.id }]] },
      );
    }
    const nav = [[{ text: "返回管理员菜单", callback_data: "admin_home" }]];
    if (rows.length === 8) nav.unshift([{ text: "下一页", callback_data: "admin_renewals:" + (offset + 8) }]);
    await sendMessage(env, chatId, "续期申请列表 · " + (offset + 1) + "–" + (offset + rows.length), { inline_keyboard: nav });
    return;
  }
  if (action.startsWith("admin_members:")) {
    const offset = Math.max(0, Math.min(1000, Number(action.split(":")[1] || 0)));
    const result = await db.prepare("SELECT m.id, m.telegram_user_id, m.display_name, m.telegram_username, m.status, m.expires_at, m.max_devices, (SELECT COUNT(*) FROM devices d WHERE d.member_id = m.id AND d.revoked_at IS NULL) AS active_devices, p.name AS plan_name FROM members m LEFT JOIN plans p ON p.id = m.plan_id ORDER BY m.created_at DESC LIMIT 8 OFFSET ?")
      .bind(offset).all();
    const rows = result.results || [];
    if (!rows.length) {
      await sendMessage(env, chatId, "还没有会员记录。", adminKeyboard(env));
      return;
    }
    const buttons = rows.map((item) => [{ text: (item.display_name || item.telegram_user_id) + " · " + Number(item.active_devices || 0) + "/" + Number(item.max_devices || 1) + " 台 · " + item.status, callback_data: "admin_member:" + item.id }]);
    if (rows.length === 8) buttons.push([{ text: "下一页", callback_data: "admin_members:" + (offset + 8) }]);
    buttons.push([{ text: "返回管理员菜单", callback_data: "admin_home" }]);
    await sendMessage(env, chatId, "会员管理 · " + (offset + 1) + "–" + (offset + rows.length) + "\n选择会员查看资料与操作：", { inline_keyboard: buttons });
    return;
  }
  const memberMatch = action.match(/^admin_member:([0-9a-f-]{20,40})$/iu);
  if (memberMatch) {
    const member = await findMember(db, (await db.prepare("SELECT telegram_user_id FROM members WHERE id = ?").bind(memberMatch[1]).first())?.telegram_user_id || "");
    if (!member) {
      await sendMessage(env, chatId, "未找到会员。", adminKeyboard(env));
      return;
    }
    const devices = await activeDevices(db, member.id);
    const [count, last] = await Promise.all([
      db.prepare("SELECT COUNT(*) AS count FROM devices WHERE member_id = ? AND revoked_at IS NULL").bind(member.id).first(),
      db.prepare("SELECT MAX(last_seen) AS last_seen FROM devices WHERE member_id = ?").bind(member.id).first(),
    ]);
    const message = await memberProfile(env, db, member) + "\n\n活跃设备数：" + Number(count?.count || 0) + " / " + Number(member.max_devices || 1) + " · 最近访问：" + displayDate(last?.last_seen, env) +
      "\n\n设备列表：" + (devices.length ? devices.map((device) => (device.geo_location || "位置未知") + " · " + (device.user_agent_hint || "未知客户端")).join("\n") : "暂无");
    const statusButton = member.status === "active"
      ? { text: "暂停会员", callback_data: "admin_member_status:" + member.id + ":paused" }
      : (Date.parse(member.expires_at || "") > Date.now() && member.status !== "revoked"
        ? { text: "恢复会员", callback_data: "admin_member_status:" + member.id + ":active" }
        : null);
    const buttons = [
      [...(statusButton ? [statusButton] : []), { text: "续期一个套餐周期", callback_data: "admin_member_renew:" + member.id }],
      [{ text: "重置此会员地址", callback_data: "admin_member_reset:" + member.id }, { text: "刷新资料", callback_data: "admin_member:" + member.id }],
      ...devices.map((device) => [{ text: "移除设备 · " + (device.geo_location || device.ip_address || "位置未知").slice(0, 20), callback_data: "admin_device_remove:" + device.id }]),
      [{ text: "返回会员列表", callback_data: "admin_members:0" }, { text: "管理员菜单", callback_data: "admin_home" }],
    ];
    await sendMessage(env, chatId, message, { inline_keyboard: buttons });
    return;
  }
  const statusMatch = action.match(/^admin_member_status:([0-9a-f-]{20,40}):(active|paused|revoked)$/iu);
  if (statusMatch) {
    const member = await db.prepare("SELECT telegram_user_id FROM members WHERE id = ?").bind(statusMatch[1]).first();
    if (!member) return sendMessage(env, chatId, "未找到会员。", adminKeyboard(env));
    await db.prepare("UPDATE members SET status = ?, updated_at = ? WHERE id = ?").bind(statusMatch[2], nowIso(), statusMatch[1]).run();
    await audit(db, "telegram:" + telegramId, "member.status", "member", statusMatch[1], "status=" + statusMatch[2]);
    if (statusMatch[2] === "active") await notifyMemberProvisioned(env, db, member.telegram_user_id, "管理员已恢复你的会员");
    await sendMessage(env, chatId, "会员状态已更新。", { inline_keyboard: [[{ text: "查看会员", callback_data: "admin_member:" + statusMatch[1] }], [{ text: "管理员菜单", callback_data: "admin_home" }]] });
    return;
  }
  const renewMatch = action.match(/^admin_member_renew:([0-9a-f-]{20,40})$/iu);
  if (renewMatch) {
    const member = await db.prepare("SELECT m.id, m.telegram_user_id, m.expires_at, m.plan_id, p.duration_days FROM members m JOIN plans p ON p.id = m.plan_id AND p.enabled = 1 WHERE m.id = ?").bind(renewMatch[1]).first();
    if (!member) return sendMessage(env, chatId, "会员没有有效套餐，无法快捷续期。请在完整管理后台调整套餐。", adminKeyboard(env));
    const base = Math.max(Date.now(), Date.parse(member.expires_at || "") || 0);
    const expiry = new Date(base + member.duration_days * 86400000).toISOString();
    await db.prepare("UPDATE members SET status = 'active', expires_at = ?, updated_at = ? WHERE id = ?").bind(expiry, nowIso(), member.id).run();
    await audit(db, "telegram:" + telegramId, "member.renew", "member", member.id, "plan=" + member.plan_id + "; expires_at=" + expiry);
    await notifyMemberProvisioned(env, db, member.telegram_user_id, "管理员已为你续期");
    await sendMessage(env, chatId, "已续期，到期时间：" + displayDate(expiry, env), { inline_keyboard: [[{ text: "返回会员", callback_data: "admin_member:" + member.id }], [{ text: "管理员菜单", callback_data: "admin_home" }]] });
    return;
  }
  const resetMatch = action.match(/^admin_member_reset:([0-9a-f-]{20,40})$/iu);
  if (resetMatch) {
    const member = await db.prepare("SELECT id FROM members WHERE id = ?").bind(resetMatch[1]).first();
    if (!member) return sendMessage(env, chatId, "未找到会员。", adminKeyboard(env));
    const confirmationId = newId();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    await db.prepare("INSERT INTO telegram_confirmations (id, member_id, telegram_user_id, action, target_id, expires_at) VALUES (?, ?, ?, 'token.rotate.admin', ?, ?)")
      .bind(confirmationId, member.id, telegramId, member.id, expiresAt).run();
    await sendMessage(env, chatId, "确认重置该会员地址？旧地址会立即失效，新地址由 Bot 私聊发送。", { inline_keyboard: [[{ text: "确认重置", callback_data: "admin_member_reset_confirm:" + confirmationId }], [{ text: "取消", callback_data: "admin_member:" + member.id }]] });
    return;
  }
  if (action.startsWith("admin_member_reset_confirm:")) {
    const confirmationId = action.slice("admin_member_reset_confirm:".length);
    const now = nowIso();
    const confirmation = await db.prepare("SELECT member_id, target_id FROM telegram_confirmations WHERE id = ? AND telegram_user_id = ? AND action = 'token.rotate.admin' AND used_at IS NULL AND expires_at > ?")
      .bind(confirmationId, telegramId, now).first();
    if (!confirmation) return sendMessage(env, chatId, "确认已过期或已使用。", adminKeyboard(env));
    const target = await db.prepare("SELECT telegram_user_id FROM members WHERE id = ?").bind(confirmation.member_id).first();
    if (!target) return sendMessage(env, chatId, "未找到会员。", adminKeyboard(env));
    const issued = await issueToken(env);
    const tokenId = newId();
    const results = await db.batch([
      db.prepare("UPDATE tokens SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM telegram_confirmations WHERE id = ? AND telegram_user_id = ? AND action = 'token.rotate.admin' AND used_at IS NULL AND expires_at > ?)")
        .bind(now, confirmation.member_id, confirmationId, telegramId, now),
      db.prepare("INSERT INTO tokens (id, member_id, token_hash, token_ciphertext, created_at) SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM telegram_confirmations WHERE id = ? AND telegram_user_id = ? AND action = 'token.rotate.admin' AND used_at IS NULL AND expires_at > ?) AND NOT EXISTS (SELECT 1 FROM tokens WHERE member_id = ? AND revoked_at IS NULL)")
        .bind(tokenId, confirmation.member_id, issued.tokenHash, issued.tokenCiphertext, now, confirmationId, telegramId, now, confirmation.member_id),
      db.prepare("UPDATE telegram_confirmations SET used_at = ? WHERE id = ? AND telegram_user_id = ? AND action = 'token.rotate.admin' AND used_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM tokens WHERE member_id = ? AND token_hash = ? AND revoked_at IS NULL)")
        .bind(now, confirmationId, telegramId, now, confirmation.member_id, issued.tokenHash),
    ]);
    if (Number(results?.[1]?.meta?.changes || 0) !== 1 || Number(results?.[2]?.meta?.changes || 0) !== 1) return sendMessage(env, chatId, "重置失败，地址可能已变化或确认失效。", adminKeyboard(env));
    await audit(db, "telegram:" + telegramId, "token.rotate.admin", "member", confirmation.member_id, "admin rotated member token");
    await notifyMemberProvisioned(env, db, target.telegram_user_id, "管理员已重置你的订阅地址");
    await sendMessage(env, chatId, "已重置并私聊发送新地址。", { inline_keyboard: [[{ text: "返回会员", callback_data: "admin_member:" + confirmation.member_id }], [{ text: "管理员菜单", callback_data: "admin_home" }]] });
    return;
  }
  if (action.startsWith("admin_member_devices:")) {
    const memberId = action.slice("admin_member_devices:".length);
    const devices = await activeDevices(db, memberId);
    const rows = devices.map((device) => [{ text: "移除 · " + (device.geo_location || "位置未知").slice(0, 18) + " · " + displayDate(device.last_seen, env), callback_data: "admin_device_remove:" + device.id }]);
    rows.push([{ text: "返回会员", callback_data: "admin_member:" + memberId }]);
    await sendMessage(env, chatId, devices.length ? "选择要移除的设备：" : "没有活跃设备。", { inline_keyboard: rows });
    return;
  }
  const deviceRemove = action.match(/^admin_device_remove:([0-9a-f-]{20,40})$/iu);
  if (deviceRemove) {
    const device = await db.prepare("SELECT member_id FROM devices WHERE id = ? AND revoked_at IS NULL").bind(deviceRemove[1]).first();
    if (!device) return sendMessage(env, chatId, "设备不存在或已移除。", adminKeyboard(env));
    await db.prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(nowIso(), deviceRemove[1]).run();
    await audit(db, "telegram:" + telegramId, "device.remove.admin", "member", device.member_id, "device=" + deviceRemove[1]);
    await sendMessage(env, chatId, "已移除设备。", { inline_keyboard: [[{ text: "返回会员", callback_data: "admin_member:" + device.member_id }], [{ text: "管理员菜单", callback_data: "admin_home" }]] });
    return;
  }
  if (action === "admin_plans") {
    const result = await db.prepare("SELECT id, name, duration_days, enabled FROM plans ORDER BY name").all();
    const rows = (result.results || []).map((plan) => [{ text: (plan.enabled ? "停用" : "启用") + " · " + plan.name + " · " + plan.duration_days + "天", callback_data: "admin_plan_toggle:" + plan.id }]);
    rows.push([{ text: "返回管理员菜单", callback_data: "admin_home" }]);
    await sendMessage(env, chatId, "套餐管理（点击可启用/停用）：", { inline_keyboard: rows });
    return;
  }
  const planToggle = action.match(/^admin_plan_toggle:([0-9a-f-]{20,40})$/iu);
  if (planToggle) {
    const result = await db.prepare("UPDATE plans SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id = ?").bind(planToggle[1]).run();
    if (result.meta.changes) await audit(db, "telegram:" + telegramId, "plan.toggle", "plan", planToggle[1], "enabled toggled");
    await sendMessage(env, chatId, result.meta.changes ? "套餐状态已切换。" : "未找到套餐。", { inline_keyboard: [[{ text: "返回套餐", callback_data: "admin_plans" }], [{ text: "管理员菜单", callback_data: "admin_home" }]] });
    return;
  }
  if (action === "admin_resources") {
    const result = await db.prepare("SELECT id, name, slug, type, enabled FROM resources ORDER BY name").all();
    const rows = (result.results || []).map((resource) => [{ text: (resource.enabled ? "停用" : "启用") + " · " + resource.name + " (" + resource.slug + ")", callback_data: "admin_resource_toggle:" + resource.id }]);
    rows.push([{ text: "返回管理员菜单", callback_data: "admin_home" }]);
    await sendMessage(env, chatId, "资源管理（点击可启用/停用）：", { inline_keyboard: rows });
    return;
  }
  const resourceToggle = action.match(/^admin_resource_toggle:([0-9a-f-]{20,40})$/iu);
  if (resourceToggle) {
    const result = await db.prepare("UPDATE resources SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END, updated_at = ? WHERE id = ?")
      .bind(nowIso(), resourceToggle[1]).run();
    if (result.meta.changes) await audit(db, "telegram:" + telegramId, "resource.toggle", "resource", resourceToggle[1], "enabled toggled");
    await sendMessage(env, chatId, result.meta.changes ? "资源状态已切换。" : "未找到资源。", { inline_keyboard: [[{ text: "返回资源", callback_data: "admin_resources" }], [{ text: "管理员菜单", callback_data: "admin_home" }]] });
    return;
  }
  await sendMessage(env, chatId, "无法识别管理员操作。", adminKeyboard(env));
}

async function resumeSignup(env, db, user, chatId) {
  const telegramId = String(user.id || "");
  const pending = await pendingSignup(db, telegramId);
  if (pending) {
    await sendMessage(env, chatId, "你的开通申请正在审核中。审核通过后，Bot 会自动发送专属分发地址。", guestKeyboard());
    return;
  }
  const draft = await db.prepare("SELECT * FROM signup_drafts WHERE telegram_user_id = ?").bind(telegramId).first();
  if (!draft) return beginSignup(env, db, user, chatId);
  if (draft.step === "wechat_id") {
    await sendMessage(env, chatId, "请发送你的微信号；发送 /cancel 可取消。", guestKeyboard());
    return;
  }
  if (draft.step === "member_number") {
    await sendMessage(env, chatId, "请发送你的会员号；发送 /cancel 可取消。", guestKeyboard());
    return;
  }
  const plans = await db.prepare("SELECT id, name, duration_days FROM plans WHERE enabled = 1 ORDER BY duration_days, name").all();
  const rows = (plans.results || []).map((plan) => [{ text: plan.name + " · " + plan.duration_days + " 天", callback_data: "signup_plan:" + plan.id }]);
  if (rows.length) await sendMessage(env, chatId, "请选择申请的会员套餐：", { inline_keyboard: rows });
  else await sendMessage(env, chatId, "目前没有可申请的会员套餐，请稍后联系管理员。", guestKeyboard());
}

async function rotateTokenForMember(env, db, member, telegramId, confirmationId = null) {
  const since = new Date(Date.now() - 86_400_000).toISOString();
  const resetCount = await db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE actor_id = ? AND action = 'token.rotate.self' AND timestamp >= ?")
    .bind("telegram:" + telegramId, since).first();
  if (Number(resetCount?.count || 0) >= 3) return { error: "24 小时内最多重置 3 次，请稍后再试。" };
  const issued = await issueToken(env);
  const now = nowIso();
  let statements;
  if (confirmationId) {
    statements = [
      db.prepare("UPDATE tokens SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM telegram_confirmations WHERE id = ? AND member_id = ? AND telegram_user_id = ? AND action = 'token.rotate' AND used_at IS NULL AND expires_at > ?)")
        .bind(now, member.id, confirmationId, member.id, telegramId, now),
      db.prepare("INSERT INTO tokens (id, member_id, token_hash, token_ciphertext, created_at) SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM telegram_confirmations WHERE id = ? AND member_id = ? AND telegram_user_id = ? AND action = 'token.rotate' AND used_at IS NULL AND expires_at > ?) AND NOT EXISTS (SELECT 1 FROM tokens WHERE member_id = ? AND revoked_at IS NULL)")
        .bind(newId(), member.id, issued.tokenHash, issued.tokenCiphertext, now, confirmationId, member.id, telegramId, now, member.id),
      db.prepare("UPDATE telegram_confirmations SET used_at = ? WHERE id = ? AND member_id = ? AND telegram_user_id = ? AND action = 'token.rotate' AND used_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM tokens WHERE member_id = ? AND token_hash = ? AND revoked_at IS NULL)")
        .bind(now, confirmationId, member.id, telegramId, now, member.id, issued.tokenHash),
      db.prepare("INSERT INTO audit_events (id, actor_id, action, target_type, target_id, timestamp, change_summary) SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM telegram_confirmations WHERE id = ? AND used_at = ?)")
        .bind(newId(), "telegram:" + telegramId, "token.rotate.self", "member", member.id, now, "member self-service rotation", confirmationId, now),
    ];
    const results = await db.batch(statements);
    if (Number(results?.[0]?.meta?.changes || 0) !== 1) return { error: "确认已过期或已使用，请重新发起。" };
  } else {
    statements = [
      db.prepare("UPDATE tokens SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL").bind(now, member.id),
      db.prepare("INSERT INTO tokens (id, member_id, token_hash, token_ciphertext, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(newId(), member.id, issued.tokenHash, issued.tokenCiphertext, now),
      db.prepare("INSERT INTO audit_events (id, actor_id, action, target_type, target_id, timestamp, change_summary) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(newId(), "telegram:" + telegramId, "token.rotate.self", "member", member.id, now, "member self-service rotation"),
    ];
    await db.batch(statements);
  }
  return { token: issued.raw };
}

async function handleButton(env, db, callback) {
  const telegramId = String(callback.from?.id || "");
  const chatId = callback.message?.chat?.id;
  const action = String(callback.data || "");
  if (!telegramId || !chatId || callback.message?.chat?.type !== "private") {
    await answerCallback(env, callback.id, "请在与机器人私聊中操作");
    return;
  }
  await answerCallback(env, callback.id);
  const admins = new Set(adminTelegramIds(env));
  const signupReview = action.match(/^signup_(approve|reject):([0-9a-f-]{20,40})$/iu);
  const renewalReview = action.match(/^renew_(approve|reject):([0-9a-f-]{20,40})$/iu);
  if (signupReview || renewalReview) {
    if (!admins.has(telegramId)) {
      await sendMessage(env, chatId, "此操作仅供管理员使用。");
      return;
    }
    const match = signupReview || renewalReview;
    const status = match[1].toLowerCase() === "approve" ? "approved" : "rejected";
    const requestId = match[2];
    const result = signupReview
      ? await reviewSignup(db, env, requestId, status, "telegram:" + telegramId)
      : await reviewRenewal(db, env, requestId, status, "telegram:" + telegramId);
    await sendMessage(env, chatId, result.error ? "处理失败：" + result.error : (status === "approved" ? "已批准并完成开通/续期。" : "已拒绝申请。"));
    return;
  }
  if (action.startsWith("admin_")) {
    if (!admins.has(telegramId)) {
      await sendMessage(env, chatId, "此操作仅供管理员使用。");
      return;
    }
    await handleAdminAction(env, db, telegramId, chatId, action);
    return;
  }
  if (action === "signup_apply" || action === "signup_status") {
    if (admins.has(telegramId)) return sendAdminHome(env, db, chatId);
    await resumeSignup(env, db, callback.from, chatId);
    return;
  }
  if (action.startsWith("signup_plan:")) {
    await submitSignupDraft(env, db, callback.from, chatId, action.slice("signup_plan:".length));
    return;
  }
  const member = await findMember(db, telegramId);
  if (action === "reset_start") {
    if (!currentlyActive(member)) {
      await sendMessage(env, chatId, "只有有效会员可以自助重置地址。", keyboard());
      return;
    }
    const confirmationId = newId();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    await db.prepare("INSERT INTO telegram_confirmations (id, member_id, telegram_user_id, action, expires_at) VALUES (?, ?, ?, 'token.rotate', ?)")
      .bind(confirmationId, member.id, telegramId, expiresAt).run();
    await sendMessage(env, chatId, "重置会立即撤销所有旧订阅地址。请在 60 秒内确认。", {
      inline_keyboard: [[{ text: "确认重置", callback_data: "reset_confirm:" + confirmationId }, { text: "取消", callback_data: "home" }]],
    });
    return;
  }
  if (action.startsWith("reset_confirm:")) {
    if (!currentlyActive(member)) {
      await sendMessage(env, chatId, "只有有效会员可以自助重置地址。", keyboard());
      return;
    }
    const confirmationId = action.slice("reset_confirm:".length);
    const confirmation = await db.prepare("SELECT id FROM telegram_confirmations WHERE id = ? AND member_id = ? AND telegram_user_id = ? AND action = 'token.rotate' AND used_at IS NULL AND expires_at > ?")
      .bind(confirmationId, member.id, telegramId, nowIso()).first();
    if (!confirmation) {
      await sendMessage(env, chatId, "确认已过期或已使用，请重新发起。", keyboard());
      return;
    }
    const result = await rotateTokenForMember(env, db, member, telegramId, confirmationId);
    if (result.error) {
      await sendMessage(env, chatId, result.error, keyboard());
      return;
    }
    const refreshed = await findMember(db, telegramId);
    await sendMessage(env, chatId, "已重置订阅地址，所有旧地址立即失效。\n\n" + await linkList(env, db, refreshed), keyboard());
    return;
  }
  if (action === "home" || action === "links") {
    await sendMessage(env, chatId, member ? await linkList(env, db, member) : "尚未找到会员资料。发送 /start 即可申请开通。", member ? keyboard() : guestKeyboard());
    return;
  }
  if (action === "member_profile") {
    await sendMessage(env, chatId, await memberProfile(env, db, member), member ? keyboard() : guestKeyboard());
    return;
  }
  if (action === "devices") {
    if (!member) {
      await sendMessage(env, chatId, "目前没有找到你的会员记录。发送 /start 即可申请开通。", guestKeyboard());
      return;
    }
    const devices = await activeDevices(db, member.id);
    const count = await db.prepare("SELECT COUNT(*) AS count FROM devices WHERE member_id = ? AND revoked_at IS NULL").bind(member.id).first();
    const summary = devices.length
      ? devices.map((item, index) => (index + 1) + ". 位置：" + (item.geo_location || "未知") + "\n   客户端：" + (item.user_agent_hint || "未知") + "\n   首次访问：" + displayDate(item.first_seen, env) + "\n   上一次访问：" + displayDate(item.last_seen, env)).join("\n")
      : "暂时没有活跃设备记录。首次通过订阅地址访问后会显示。";
    await sendMessage(env, chatId, "当前设备数：" + Number(count?.count || 0) + " / " + Number(member.max_devices || 1) + "\n选择下方按钮可移除单个设备，释放一个名额。设备满额只会阻止新设备加载，不影响已识别设备继续播放。\n\n" + summary + "\n\n识别依据为 User-Agent 与 Cloudflare 提供的 IP 地理位置；相同标识的重复请求只记为一台。", deviceKeyboard(devices));
    return;
  }
  if (action === "device_limit_request") {
    if (!member || !currentlyActive(member)) {
      await sendMessage(env, chatId, "只有有效会员可以申请增加设备数。", member ? keyboard() : guestKeyboard());
      return;
    }
    const max = Number(member.max_devices || 1);
    const pending = await db.prepare("SELECT id, additional_devices FROM device_limit_requests WHERE member_id = ? AND status = 'pending'").bind(member.id).first();
    if (pending) {
      await sendMessage(env, chatId, "你已有一条增加设备申请待审核：申请新增 " + pending.additional_devices + " 台。", keyboard());
      return;
    }
    const amount = Math.min(5, 50 - max);
    if (amount < 1) {
      await sendMessage(env, chatId, "当前设备上限已达到系统允许的最大值 50 台。", keyboard());
      return;
    }
    const rows = [];
    for (let count = 1; count <= amount; count++) rows.push([{ text: "申请新增 " + count + " 台", callback_data: "device_limit:" + count }]);
    rows.push([{ text: "取消", callback_data: "home" }]);
    await sendMessage(env, chatId, "当前上限：" + max + " 台。请选择要申请增加的数量（最多 5 台），提交后由管理员审核：", { inline_keyboard: rows });
    return;
  }
  if (action.startsWith("device_limit:")) {
    if (!member || !currentlyActive(member)) {
      await sendMessage(env, chatId, "只有有效会员可以申请增加设备数。", member ? keyboard() : guestKeyboard());
      return;
    }
    const amount = Number(action.slice("device_limit:".length));
    const result = await requestDeviceLimit(env, db, member, telegramId, amount);
    if (result.error) await sendMessage(env, chatId, "申请数量超出当前可申请范围，请重新选择。", keyboard());
    else if (result.pending) await sendMessage(env, chatId, "你已有一条增加设备申请待审核。", keyboard());
    else await sendMessage(env, chatId, "设备扩容申请已提交，管理员批准后设备上限会自动增加。", keyboard());
    return;
  }
  if (action.startsWith("device_remove:")) {
    if (!member) {
      await sendMessage(env, chatId, "目前没有找到你的会员资料。", guestKeyboard());
      return;
    }
    const deviceId = action.slice("device_remove:".length);
    const device = await db.prepare("SELECT id, ip_address, geo_location, user_agent_hint FROM devices WHERE id = ? AND member_id = ? AND revoked_at IS NULL")
      .bind(deviceId, member.id).first();
    if (!device) {
      await sendMessage(env, chatId, "设备不存在或已移除。", keyboard());
      return;
    }
    const confirmationId = newId();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    await db.prepare("INSERT INTO telegram_confirmations (id, member_id, telegram_user_id, action, target_id, expires_at) VALUES (?, ?, ?, 'device.remove', ?, ?)")
      .bind(confirmationId, member.id, telegramId, device.id, expiresAt).run();
    await sendMessage(env, chatId, "确认移除此设备？\n地理位置：" + (device.geo_location || "未知") + "\nIP：" + (device.ip_address || "未知") + "\n客户端：" + (device.user_agent_hint || "未知") + "\n确认后该设备标识会被拒绝并释放一个名额。", {
      inline_keyboard: [[{ text: "确认移除", callback_data: "device_remove_confirm:" + confirmationId }, { text: "取消", callback_data: "devices" }]],
    });
    return;
  }
  if (action.startsWith("device_remove_confirm:")) {
    if (!member) {
      await sendMessage(env, chatId, "目前没有找到你的会员资料。", guestKeyboard());
      return;
    }
    const confirmationId = action.slice("device_remove_confirm:".length);
    const now = nowIso();
    const confirmation = await db.prepare("SELECT target_id FROM telegram_confirmations WHERE id = ? AND member_id = ? AND telegram_user_id = ? AND action = 'device.remove' AND used_at IS NULL AND expires_at > ?")
      .bind(confirmationId, member.id, telegramId, now).first();
    if (!confirmation) {
      await sendMessage(env, chatId, "确认已过期或已使用，请重新打开设备管理。", keyboard());
      return;
    }
    const results = await db.batch([
      db.prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND member_id = ? AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM telegram_confirmations WHERE id = ? AND member_id = ? AND telegram_user_id = ? AND action = 'device.remove' AND used_at IS NULL AND expires_at > ?)")
        .bind(now, confirmation.target_id, member.id, confirmationId, member.id, telegramId, now),
      db.prepare("UPDATE telegram_confirmations SET used_at = ? WHERE id = ? AND member_id = ? AND telegram_user_id = ? AND action = 'device.remove' AND used_at IS NULL AND expires_at > ?")
        .bind(now, confirmationId, member.id, telegramId, now),
    ]);
    if (Number(results?.[0]?.meta?.changes || 0) !== 1) {
      await sendMessage(env, chatId, "设备已移除或确认已过期。", keyboard());
      return;
    }
    await audit(db, "telegram:" + telegramId, "device.remove.self", "member", member.id, "device=" + confirmation.target_id);
    const devices = await activeDevices(db, member.id);
    const count = await db.prepare("SELECT COUNT(*) AS count FROM devices WHERE member_id = ? AND revoked_at IS NULL").bind(member.id).first();
    const summary = devices.length
      ? devices.map((item, index) => (index + 1) + ". 位置：" + (item.geo_location || "未知") + " · " + (item.user_agent_hint || "未知") + " · 最近：" + displayDate(item.last_seen, env)).join("\n")
      : "暂无活跃设备记录。";
    await sendMessage(env, chatId, "设备已移除。\n当前设备数：" + Number(count?.count || 0) + " / " + Number(member.max_devices || 1) + "\n\n" + summary, deviceKeyboard(devices));
    return;
  }
  if (action === "renew") {
    if (!member) {
      await sendMessage(env, chatId, "目前没有找到你的会员记录。发送 /start 即可申请开通。", guestKeyboard());
      return;
    }
    const created = await requestRenewal(env, db, member, telegramId);
    await sendMessage(env, chatId, created ? "续期申请已提交。管理员会收到通知，审核结果会通过 Bot 告知你。" : "已有一条续期申请正在审核中。审核结果会通过 Bot 告知你。", keyboard());
    return;
  }
  await sendMessage(env, chatId, member ? "请选择要办理的操作。" : "发送 /start 开始申请会员。", member ? keyboard() : guestKeyboard());
}

async function processUpdate(env, update) {
  const db = env.DB;
  if (update.callback_query) return handleButton(env, db, update.callback_query);
  const message = update.message;
  if (!message || message.chat?.type !== "private" || !message.from?.id) return;
  const telegramId = String(message.from.id);
  const text = String(message.text || "").trim();
  const chatId = message.chat.id;
  const isAdmin = adminTelegramIds(env).includes(telegramId);
  if ((text === "/start" || text.startsWith("/start ")) && isAdmin) {
    await sendAdminHome(env, db, chatId);
    return;
  }
  const member = await findMember(db, telegramId);
  if (text === "/start" || text.startsWith("/start ")) {
    await db.prepare("UPDATE members SET telegram_username = ?, display_name = ?, updated_at = ? WHERE telegram_user_id = ?")
      .bind(String(message.from.username || "").slice(0, 64), [message.from.first_name, message.from.last_name].filter(Boolean).join(" ").slice(0, 120), nowIso(), telegramId).run();
    const current = await findMember(db, telegramId);
    if (current) await sendMessage(env, chatId, "欢迎回来。\n\n" + await linkList(env, db, current), keyboard());
    else await resumeSignup(env, db, message.from, chatId);
    return;
  }
  if (text === "/cancel") {
    await db.prepare("DELETE FROM signup_drafts WHERE telegram_user_id = ?").bind(telegramId).run();
    if (isAdmin) return sendAdminHome(env, db, chatId);
    await sendMessage(env, chatId, "已取消当前申请资料填写。发送 /start 可重新开始。", guestKeyboard());
    return;
  }
  if (text === "/id") {
    await sendMessage(env, chatId, "你的 Telegram User ID： " + telegramId);
    return;
  }
  if (/^\/admin(?:@\w+)?(?:\s|$)/u.test(text)) {
    if (isAdmin) return sendAdminHome(env, db, chatId);
    await sendMessage(env, chatId, "此命令仅供管理员使用。");
    return;
  }
  if (text === "/help") {
    if (isAdmin) return sendAdminHome(env, db, chatId);
    await sendMessage(env, chatId, member ? "使用菜单获取分发地址、查看会员信息、管理设备、申请续期或重置地址。" : "发送 /start 填写微信号和会员号即可提交开通申请。发送 /cancel 可取消。", member ? keyboard() : guestKeyboard());
    return;
  }
  const draft = await db.prepare("SELECT * FROM signup_drafts WHERE telegram_user_id = ?").bind(telegramId).first();
  if (draft) {
    if (text.startsWith("/")) {
      const prompt = draft.step === "wechat_id" ? "请发送你的微信号，或发送 /cancel 取消。" : draft.step === "member_number" ? "请发送你的会员号，或发送 /cancel 取消。" : "请点击套餐按钮继续申请。";
      await sendMessage(env, chatId, prompt, guestKeyboard());
      return;
    }
    if (!text || text.length > 100 || /[\u0000-\u001f]/u.test(text)) {
      await sendMessage(env, chatId, "内容请控制在 1 到 100 个字符内。请重新输入。", guestKeyboard());
      return;
    }
    if (draft.step === "wechat_id") {
      await db.prepare("UPDATE signup_drafts SET wechat_id = ?, step = 'member_number', updated_at = ? WHERE telegram_user_id = ?")
        .bind(text, nowIso(), telegramId).run();
      await sendMessage(env, chatId, "已记录。请发送你的会员号：");
      return;
    }
    if (draft.step === "member_number") {
      await db.prepare("UPDATE signup_drafts SET member_number = ?, step = 'plan', updated_at = ? WHERE telegram_user_id = ?")
        .bind(text, nowIso(), telegramId).run();
      await continueSignupAfterDetails(env, db, message.from, chatId);
      return;
    }
    await resumeSignup(env, db, message.from, chatId);
    return;
  }
  if (!member && (text === "/apply" || text === "申请开通")) {
    await beginSignup(env, db, message.from, chatId);
    return;
  }
  await sendMessage(env, chatId, member ? await linkList(env, db, member) : "欢迎使用会员订阅服务。发送 /start 即可提交开通申请。", member ? keyboard() : guestKeyboard());
}

export async function telegramWebhook(request, env) {
  if (!env.TELEGRAM_WEBHOOK_SECRET || !safeEqual(request.headers.get("x-telegram-bot-api-secret-token") || "", env.TELEGRAM_WEBHOOK_SECRET)) {
    return apiError("WEBHOOK_SECRET_INVALID", 403);
  }
  const update = await readJson(request, 256_000);
  if (!update || !Number.isInteger(update.update_id)) return apiError("UPDATE_INVALID", 400);
  const inserted = await env.DB.prepare("INSERT INTO telegram_updates (update_id, received_at) VALUES (?, ?) ON CONFLICT(update_id) DO NOTHING RETURNING update_id")
    .bind(update.update_id, nowIso()).first();
  if (!inserted) return json({ ok: true, duplicate: true });
  try {
    await processUpdate(env, update);
  } catch (err) {
    await env.DB.prepare("DELETE FROM telegram_updates WHERE update_id = ?").bind(update.update_id).run();
    throw err;
  }
  return json({ ok: true });
}

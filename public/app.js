const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { plans: [], resources: [], currentMember: null, toastTimer: null, refreshTimer: null };
const statusText = { active: "有效", pending: "待开通", paused: "暂停", expired: "到期", revoked: "撤销" };
const typeText = { tv: "TV 订阅", json: "JSON 配置", repository: "仓库", stremio: "Stremio", url: "普通 URL" };
const BASE = location.origin;

function element(tag, text = "", className = "") {
  const node = document.createElement(tag);
  if (text !== "") node.textContent = text;
  if (className) node.className = className;
  return node;
}

function toast(message) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.add("show");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => box.classList.remove("show"), 2600);
}

async function api(path, options = {}) {
  const response = await fetch("/admin/api" + path, {
    credentials: "same-origin",
    ...options,
    headers: { ...(options.body ? { "content-type": "application/json" } : {}), ...(options.headers || {}) },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== "/login") showAuthenticated(false);
    throw new Error(payload?.error?.message || payload?.error?.code || "请求失败");
  }
  return payload;
}

function showAuthenticated(authenticated) {
  $("#login-view").classList.toggle("hidden", authenticated);
  $("#app-view").classList.toggle("hidden", !authenticated);
  $("#logout").classList.toggle("hidden", !authenticated);
  $("#connection").classList.toggle("offline", !authenticated);
  $("#connection").lastChild.textContent = authenticated ? "已登录" : "待登录";
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  state.refreshTimer = authenticated ? setInterval(refreshDashboard, 30000) : null;
}

async function init() {
  try {
    const health = await fetch("/healthz", { cache: "no-store" });
    $("#connection").classList.toggle("offline", !health.ok);
    $("#connection").lastChild.textContent = health.ok ? "服务在线" : "服务异常";
    const me = await api("/me");
    showAuthenticated(me.authenticated);
    if (me.authenticated) await loadAll();
  } catch {
    showAuthenticated(false);
    $("#connection").classList.add("offline");
    $("#connection").lastChild.textContent = "服务异常";
  }
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#login-error").textContent = "";
  try {
    await api("/login", { method: "POST", body: JSON.stringify({ password: $("#password").value }) });
    $("#password").value = "";
    showAuthenticated(true);
    await loadAll();
  } catch (error) {
    $("#login-error").textContent = error.message === "LOGIN_FAILED" ? "密码不正确。" : error.message;
  }
});

$("#logout").addEventListener("click", async () => {
  try { await api("/logout", { method: "POST", body: "{}" }); } catch {}
  showAuthenticated(false);
});

$$(".tab").forEach((button) => button.addEventListener("click", () => {
  $$(".tab").forEach((tab) => tab.classList.toggle("active", tab === button));
  $$(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === "panel-" + button.dataset.tab));
  if (button.dataset.tab === "applications") loadApplications();
  if (button.dataset.tab === "renewals") loadRenewals();
  if (button.dataset.tab === "device-requests") loadDeviceLimitRequests();
  if (button.dataset.tab === "audit") loadAudit();
}));

async function loadAll() {
  try {
    const [plans, resources] = await Promise.all([api("/plans"), api("/resources")]);
    state.plans = plans;
    state.resources = resources;
    fillPlanOptions();
    renderPlanChecks();
    renderPlans();
    renderResources();
    await Promise.all([loadOverview(), loadMembers(), loadApplications(), loadRenewals(), loadDeviceLimitRequests()]);
  } catch (error) { toast(error.message); }
}

async function refreshDashboard() {
  if (document.hidden || $("#app-view").classList.contains("hidden")) return;
  const selected = $$("[data-application-id]:checked").length > 0;
  const tasks = [loadOverview(), loadRenewals(), loadDeviceLimitRequests()];
  if (!selected) tasks.push(loadApplications());
  try { await Promise.all(tasks); } catch {}
}

async function loadOverview() {
  const data = await api("/overview");
  $("#metric-active").textContent = data.members?.active || 0;
  $("#metric-pending").textContent = data.members?.pending || 0;
  $("#metric-applications").textContent = data.applications?.pending || 0;
  $("#metric-paused").textContent = data.members?.paused || 0;
  $("#metric-expired").textContent = data.members?.expired || 0;
  $("#metric-allowed").textContent = data.requests?.allowed || 0;
  $("#metric-denied").textContent = data.requests?.denied || 0;
  $("#device-request-count").textContent = data.device_limit_requests?.pending || 0;
  $("#device-request-count").classList.toggle("hidden", !Number(data.device_limit_requests?.pending || 0));
}

function updateApplicationSelection() {
  const checked = $$("[data-application-id]:checked").length;
  const all = $("#applications-select-all");
  const total = $$("[data-application-id]").length;
  all.checked = total > 0 && checked === total;
  all.indeterminate = checked > 0 && checked < total;
  $("#applications-approve").disabled = checked === 0;
  $("#applications-reject").disabled = checked === 0;
}

async function processApplications(ids, status) {
  if (!ids.length) return;
  const label = status === "approved" ? "批准并开通" : "拒绝";
  if (!confirm(`确定${label}所选 ${ids.length} 条申请？`)) return;
  let processed = 0;
  let failed = 0;
  try {
    for (let offset = 0; offset < ids.length; offset += 50) {
      const result = await api("/applications/batch", { method: "POST", body: JSON.stringify({ ids: ids.slice(offset, offset + 50), status }) });
      processed += Number(result.processed || 0);
      failed += Number(result.failed || 0);
    }
    toast(`${label}完成 ${processed} 条，失败 ${failed} 条`);
  } catch (error) {
    toast(`已处理 ${processed} 条；后续批次失败：${error.message}。请刷新确认结果`);
  } finally {
    await Promise.all([loadApplications(), loadOverview(), loadMembers()]);
  }
}

async function loadApplications() {
  try {
    const rows = await api("/applications");
    const box = $("#applications-list");
    box.replaceChildren();
    $("#application-count").textContent = rows.length;
    $("#application-count").classList.toggle("hidden", rows.length === 0);
    if (!rows.length) {
      box.append(element("div", "目前没有待审核的开通申请。新用户在 Bot 填完资料后会自动出现在这里。", "empty"));
      updateApplicationSelection();
      return;
    }
    for (const row of rows) {
      const card = element("article", "", "request-card application-card");
      const left = element("div", "", "application-info");
      const heading = element("div", "", "application-heading");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.dataset.applicationId = row.id;
      checkbox.setAttribute("aria-label", "选择" + (row.display_name || row.telegram_user_id));
      checkbox.addEventListener("change", updateApplicationSelection);
      heading.append(checkbox, element("strong", (row.display_name || "Telegram 用户") + (row.telegram_username ? " · @" + row.telegram_username : "")));
      left.append(heading,
        element("small", "Telegram ID：" + row.telegram_user_id),
        element("small", "微信号：" + (row.wechat_id || "未填写") + " · 会员号：" + (row.member_number || "未填写")),
        element("small", "套餐：" + row.plan_name + "（" + row.duration_days + " 天） · 申请时间：" + new Date(row.created_at).toLocaleString("zh-CN")));
      const actions = element("div", "", "row-actions");
      for (const [label, status, cls] of [["批准并开通", "approved", "mini-button"], ["拒绝", "rejected", "mini-button warn"]]) {
        const button = element("button", label, cls);
        button.type = "button";
        button.addEventListener("click", () => processApplications([row.id], status));
        actions.append(button);
      }
      card.append(left, actions);
      box.append(card);
    }
    updateApplicationSelection();
  } catch (error) { toast(error.message); }
}

$("#applications-select-all").addEventListener("change", (event) => {
  $$("[data-application-id]").forEach((input) => { input.checked = event.currentTarget.checked; });
  updateApplicationSelection();
});
$("#applications-approve").addEventListener("click", () => processApplications($$("[data-application-id]:checked").map((input) => input.dataset.applicationId), "approved"));
$("#applications-reject").addEventListener("click", () => processApplications($$("[data-application-id]:checked").map((input) => input.dataset.applicationId), "rejected"));
$("#refresh-applications").addEventListener("click", () => loadApplications());

$("#configure-bot").addEventListener("click", async () => {
  if (!confirm("使用当前 Cloudflare Bot 密钥，将当前管理域名的 /telegram/webhook 注册为 Telegram Bot 的接收地址？")) return;
  try {
    await api("/bot/configure", { method: "POST", body: "{}" });
    toast("Telegram Bot 已连接");
  } catch (error) { toast(error.message); }
});

function fillPlanOptions(selectedId = "") {
  for (const select of $$('select[name="plan_id"]')) {
    const current = selectedId || select.value;
    select.replaceChildren();
    const blank = element("option", "选择套餐");
    blank.value = "";
    select.append(blank);
    for (const plan of state.plans.filter((item) => item.enabled)) {
      const option = element("option", plan.name + " · " + plan.duration_days + " 天");
      option.value = plan.id;
      select.append(option);
    }
    if (current) select.value = current;
  }
}

function statusPill(status) {
  return element("span", statusText[status] || status, "state " + (status || ""));
}

function renderMembers(items) {
  const body = $("#members-body");
  body.replaceChildren();
  $("#member-count").textContent = items.length + " 位会员";
  $("#members-empty").classList.toggle("hidden", items.length !== 0);
  for (const member of items) {
    const row = document.createElement("tr");
    const name = element("td");
    name.append(element("span", member.display_name || "未命名会员", "member-name"));
    name.append(element("span", member.telegram_username ? "@" + member.telegram_username : "会员", "member-sub"));
    row.append(name, element("td", member.telegram_user_id), element("td", member.plan_name || "未分配"),
      element("td", Number(member.active_devices || 0) + " / " + Number(member.max_devices || 1)));
    const status = element("td"); status.append(statusPill(member.status)); row.append(status);
    row.append(element("td", member.expires_at ? new Date(member.expires_at).toLocaleString("zh-CN") : "—"));
    row.append(element("td", member.token_suffix || "—"));
    const actions = element("td");
    const group = element("div", "", "row-actions");
    const detail = element("button", "详情", "mini-button");
    detail.type = "button";
    detail.addEventListener("click", () => openMember(member.id));
    const edit = element("button", "编辑", "mini-button");
    edit.type = "button";
    edit.addEventListener("click", () => openMember(member.id, true));
    group.append(detail, edit); actions.append(group); row.append(actions);
    body.append(row);
  }
}

let memberTimer;
async function loadMembers() {
  const q = encodeURIComponent($("#member-search").value.trim());
  const items = await api("/members?q=" + q);
  renderMembers(items);
}
$("#refresh-members").addEventListener("click", () => loadMembers().catch((error) => toast(error.message)));
$("#member-search").addEventListener("input", () => {
  clearTimeout(memberTimer);
  memberTimer = setTimeout(() => loadMembers().catch((error) => toast(error.message)), 250);
});

$("#member-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const data = Object.fromEntries(form.entries());
  try {
    const created = await api("/members", { method: "POST", body: JSON.stringify(data) });
    const plan = state.plans.find((item) => item.id === created.member.plan_id);
    const lines = (plan?.resource_ids || []).map((resourceId) => {
      const resource = state.resources.find((item) => item.id === resourceId && item.enabled);
      if (!resource) return "";
      const tail = resource.type === "stremio" ? "/manifest.json" : resource.type === "json" ? ".json" : "";
      return resource.name + "： " + BASE + "/" + created.token + "/" + resource.slug + tail;
    }).filter(Boolean);
    const delivery = created.member.status !== "active" ? "会员状态为待开通，激活后才会发送分发地址。" : created.bot_notified ? "Bot 已自动私聊发送分发地址。" : "Bot 未能推送（用户可能尚未打开 Bot）；请让会员向 Bot 发送 /start 获取地址。";
    $("#member-form-note").textContent = (lines.join("\n") || "会员已创建。") + "\n" + delivery;
    $("#member-form-note").style.whiteSpace = "pre-wrap";
    event.currentTarget.reset();
    await Promise.all([loadMembers(), loadOverview()]);
    toast("会员创建成功");
  } catch (error) { $("#member-form-note").textContent = error.message; }
});

function parseCsv(text) {
  const rows = [];
  let row = [], cell = "", quoted = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (char === '"') {
      if (quoted && text[index + 1] === '"') { cell += '"'; index++; }
      else quoted = !quoted;
    } else if (char === "," && !quoted) {
      row.push(cell); cell = "";
    } else if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && text[index + 1] === "\n") index++;
      row.push(cell); cell = "";
      if (row.some((value) => value.trim())) rows.push(row);
      row = [];
    } else cell += char;
  }
  row.push(cell);
  if (row.some((value) => value.trim())) rows.push(row);
  if (rows.length < 2) return [];
  const headers = rows.shift().map((value) => value.trim().toLowerCase());
  return rows.map((values) => Object.fromEntries(headers.map((header, index) => [header, (values[index] || "").trim()])));
}

$("#member-import").addEventListener("click", async () => {
  const file = $("#member-import-file").files[0];
  if (!file) { $("#member-import-note").textContent = "先选择 CSV 文件。"; return; }
  try {
    const members = parseCsv(await file.text());
    if (!members.length) { $("#member-import-note").textContent = "文件没有可导入的会员行。"; return; }
    const result = await api("/members/import", { method: "POST", body: JSON.stringify({ members }) });
    $("#member-import-note").textContent = "创建 " + result.created + " 人，失败 " + result.failed + " 人" +
      (result.failed ? "。失败行：" + result.results.filter((row) => row.status === "failed").map((row) => row.row + " (" + row.error + ")").join("、") : "");
    await Promise.all([loadMembers(), loadOverview()]);
  } catch (error) { $("#member-import-note").textContent = error.message; }
});

function renderResourceOptions(selected = []) {
  const box = $("#plan-resource-options");
  box.replaceChildren();
  if (!state.resources.length) box.append(element("span", "先创建至少一个资源。", "muted"));
  for (const resource of state.resources) {
    const label = element("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "resource_ids";
    input.value = resource.id;
    input.checked = selected.includes(resource.id);
    label.append(input, document.createTextNode(resource.name + " · " + resource.slug));
    box.append(label);
  }
}

function renderPlanChecks() { renderResourceOptions(); }

function renderPlans() {
  const box = $("#plans-list");
  box.replaceChildren();
  for (const plan of state.plans) {
    const card = element("article", "", "plan-card");
    const heading = element("div", "", "panel-heading");
    const title = element("div");
    title.append(element("h3", plan.name), element("div", (plan.enabled ? "启用" : "已停用") + " · " + plan.duration_days + " 天 · 设备上限 " + plan.default_max_devices, "plan-meta"));
    const edit = element("button", "编辑", "mini-button"); edit.type = "button";
    edit.addEventListener("click", () => editPlan(plan));
    heading.append(title, edit);
    const tags = element("div", "", "plan-resources");
    for (const id of plan.resource_ids || []) {
      const resource = state.resources.find((item) => item.id === id);
      if (resource) tags.append(element("span", resource.name, "tag"));
    }
    if (!tags.childElementCount) tags.append(element("span", "未分配资源", "muted"));
    card.append(heading, tags);
    box.append(card);
  }
}

function editPlan(plan) {
  const form = $("#plan-form");
  form.elements.id.value = plan.id;
  form.elements.name.value = plan.name;
  form.elements.duration_days.value = plan.duration_days;
  form.elements.default_max_devices.value = plan.default_max_devices;
  form.elements.enabled.checked = Boolean(plan.enabled);
  renderResourceOptions(plan.resource_ids || []);
  form.scrollIntoView({ behavior: "smooth", block: "center" });
}

$("#plan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form).entries());
  data.enabled = form.elements.enabled.checked;
  data.resource_ids = $$('input[name="resource_ids"]:checked', form).map((input) => input.value);
  const id = form.elements.id.value;
  try {
    await api("/plans" + (id ? "/" + id : ""), { method: id ? "PUT" : "POST", body: JSON.stringify(data) });
    form.reset(); form.elements.id.value = ""; form.elements.duration_days.value = "30"; form.elements.default_max_devices.value = "1"; form.elements.enabled.checked = true;
    $("#plan-form-note").textContent = "已保存";
    await loadAll();
    toast("套餐已保存");
  } catch (error) { $("#plan-form-note").textContent = error.message; }
});
$("#reset-plan-form").addEventListener("click", () => {
  const form = $("#plan-form"); form.reset(); form.elements.id.value = ""; form.elements.duration_days.value = "30"; form.elements.default_max_devices.value = "1"; form.elements.enabled.checked = true; renderResourceOptions();
});

function renderResources() {
  const body = $("#resources-body");
  body.replaceChildren();
  for (const resource of state.resources) {
    const row = document.createElement("tr");
    row.append(element("td", resource.name), element("td", typeText[resource.type] || resource.type), element("td", resource.slug));
    const stateCell = element("td"); stateCell.append(statusPill(resource.enabled ? "active" : "paused")); row.append(stateCell);
    const snapshotCell = element("td");
    if (resource.type === "json") {
      if (resource.last_sync_error) {
        snapshotCell.textContent = "读取失败 · " + resource.last_sync_error;
        snapshotCell.className = "sync-error";
        snapshotCell.title = "最近尝试：" + (resource.last_sync_attempt_at ? new Date(resource.last_sync_attempt_at).toLocaleString("zh-CN") : "未知") +
          (resource.snapshot_synced_at ? "；会员仍使用上一次成功读取的数据：" + new Date(resource.snapshot_synced_at).toLocaleString("zh-CN") : "；尚无可用快照");
      } else if (resource.snapshot_synced_at) {
        const urlCount = Number(resource.snapshot_url_count || 0);
        const blockedCount = Number(resource.snapshot_blocked_url_count || 0);
        snapshotCell.textContent = "已同步 · " + urlCount + " 个地址" + (blockedCount ? " · " + blockedCount + " 个不能转发（原值保留）" : "");
        snapshotCell.title = "最近同步：" + new Date(resource.snapshot_synced_at).toLocaleString("zh-CN") +
          (resource.snapshot_top_level_keys?.length ? "；顶层字段：" + resource.snapshot_top_level_keys.join("、") : "");
      } else snapshotCell.textContent = "尚未读取";
    } else snapshotCell.textContent = "—";
    row.append(snapshotCell);
    const planNames = (resource.plan_ids || []).map((id) => state.plans.find((plan) => plan.id === id)?.name).filter(Boolean).join("、") || "未分配";
    row.append(element("td", planNames));
    const actionCell = element("td");
    if (resource.type === "json") {
      const sync = element("button", resource.snapshot_synced_at ? "重新读取" : "读取并同步", "mini-button");
      sync.type = "button";
      sync.addEventListener("click", async () => {
        sync.disabled = true;
        try {
          const result = await api("/resources/" + encodeURIComponent(resource.id) + "/sync", { method: "POST", body: "{}" });
          toast("读取完成：发现 " + result.url_count + " 个地址" + (result.unusable_url_count ? "，其中 " + result.unusable_url_count + " 个不能转发（原值保留）" : ""));
          await loadAll();
        } catch (error) { toast(error.message); sync.disabled = false; }
      });
      actionCell.append(sync);
    }
    const button = element("button", "编辑", "mini-button"); button.type = "button";
    button.addEventListener("click", () => editResource(resource));
    actionCell.append(button); row.append(actionCell); body.append(row);
  }
}

$("#sync-all-resources").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api("/resources/sync", { method: "POST", body: "{}" });
    const summaries = (result.results || []).map((item) => item.ok
      ? item.slug + "：" + item.url_count + " 个地址" + (item.unusable_url_count ? "（" + item.unusable_url_count + " 个不能转发，原值保留）" : "")
      : item.slug + "：读取失败 " + (item.error_detail || item.error));
    $("#resource-form-note").textContent = summaries.join("；") || "没有已启用的 JSON 资源。";
    toast("JSON 同步完成：成功 " + result.synced + "，失败 " + result.failed);
    await loadAll();
  } catch (error) {
    toast(error.message);
  } finally { button.disabled = false; }
});

function editResource(resource) {
  const form = $("#resource-form");
  form.elements.id.value = resource.id;
  form.elements.name.value = resource.name;
  form.elements.slug.value = resource.slug;
  form.elements.type.value = resource.type;
  form.elements.delivery_mode.value = resource.delivery_mode;
  form.elements.upstream_url.value = resource.upstream_url;
  form.elements.allowed_hosts.value = (resource.allowed_hosts || []).join(", ");
  form.elements.rewrite_fields.value = (resource.rewrite_fields || []).join(", ");
  form.elements.max_response_bytes.value = resource.max_response_bytes;
  form.elements.enabled.checked = Boolean(resource.enabled);
  form.scrollIntoView({ behavior: "smooth", block: "center" });
}

$("#resource-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form).entries());
  data.enabled = form.elements.enabled.checked;
  data.allowed_hosts = data.allowed_hosts.split(",").map((value) => value.trim()).filter(Boolean);
  data.rewrite_fields = data.rewrite_fields.split(",").map((value) => value.trim()).filter(Boolean);
  const id = form.elements.id.value;
  try {
    await api("/resources" + (id ? "/" + id : ""), { method: id ? "PUT" : "POST", body: JSON.stringify(data) });
    $("#resource-form-note").textContent = "已保存";
    form.reset(); form.elements.id.value = ""; form.elements.max_response_bytes.value = "2097152"; form.elements.enabled.checked = true;
    await loadAll();
    toast("资源已保存");
  } catch (error) { $("#resource-form-note").textContent = error.message; }
});
$("#reset-resource-form").addEventListener("click", () => {
  const form = $("#resource-form"); form.reset(); form.elements.id.value = ""; form.elements.max_response_bytes.value = "2097152"; form.elements.enabled.checked = true;
});
$("#resource-form").elements.upstream_url.addEventListener("change", () => {
  const hostInput = $("#resource-form").elements.allowed_hosts;
  if (!hostInput.value.trim()) {
    try { hostInput.value = new URL($("#resource-form").elements.upstream_url.value).hostname; } catch {}
  }
});

function setDetailHtml(container, data) {
  container.replaceChildren();
  const member = data.member;
  const summary = element("div", "Telegram ID：" + member.telegram_user_id + " · Token 尾段：" + (member.token_suffix || "—") +
    "\n微信号：" + (member.wechat_id || "未填写") + " · 会员号：" + (member.member_number || "未填写") +
    "\n注册时间：" + new Date(member.created_at).toLocaleString("zh-CN"));
  summary.style.whiteSpace = "pre-line";
  container.append(summary);
  container.append(element("h3", "设备记录"));
  const activeDevices = (data.devices || []).filter((device) => !device.revoked_at);
  container.append(element("div", "当前活跃设备数：" + activeDevices.length + " / " + Number(member.max_devices || 1), "muted"));
  container.append(element("div", "设备以 User-Agent 和 Cloudflare 提供的 IP 地理位置识别；满额时仅阻止新设备加载，已登记设备继续可用。", "muted"));
  if (!data.devices?.length) container.append(element("div", "暂无设备记录。"));
  for (const device of data.devices || []) {
    const card = element("article", "", "request-card device-card");
    const info = element("div", "", "application-info");
    info.append(element("strong", (device.geo_location || "位置未知") + " · " + (device.ip_address || "IP 未知") + (device.revoked_at ? " · 已移除" : " · 使用中")),
      element("small", device.user_agent_hint || "未知客户端"),
      element("small", "首次：" + new Date(device.first_seen).toLocaleString("zh-CN") + " · 最近：" + new Date(device.last_seen).toLocaleString("zh-CN")));
    card.append(info);
    if (!device.revoked_at) {
      const remove = element("button", "移除设备", "mini-button warn");
      remove.type = "button";
      remove.addEventListener("click", async () => {
        if (!confirm("移除此设备并释放一个名额？该 User-Agent 与地理位置组合的后续请求会被拒绝。")) return;
        try {
          await api("/members/" + encodeURIComponent(member.id) + "/devices/" + encodeURIComponent(device.id), { method: "DELETE", body: "{}" });
          await openMember(member.id);
          toast("设备已移除");
        } catch (error) { toast(error.message); }
      });
      card.append(remove);
    }
    container.append(card);
  }
  const clearDevices = element("button", "清除弱识别记录", "mini-button");
  clearDevices.type = "button";
  clearDevices.addEventListener("click", async () => {
    if (!confirm("删除全部设备识别记录会释放当前名额；之后重新请求的设备会重新登记。继续？")) return;
    try {
      await api("/members/" + encodeURIComponent(data.member.id) + "/devices", { method: "DELETE", body: "{}" });
      await openMember(data.member.id);
      toast("设备记录已清除");
    } catch (error) { toast(error.message); }
  });
  container.append(clearDevices);
  for (const [title, rows] of [["最近使用统计", data.usage], ["会员操作历史", data.events]]) {
    container.append(element("h3", title));
    const pre = element("pre", JSON.stringify(rows, null, 2));
    pre.className = "token-result";
    container.append(pre);
  }
}

async function openMember(id) {
  try {
    const data = await api("/members/" + encodeURIComponent(id));
    state.currentMember = data.member;
    setDetailHtml($("#member-detail"), data);
    $("#token-result").classList.add("hidden");
    const form = $("#edit-member-form");
    form.elements.id.value = id;
    form.elements.status.value = data.member.status;
    fillPlanOptions(data.member.plan_id || "");
    form.elements.plan_id.value = data.member.plan_id || "";
    form.elements.expires_at.value = data.member.expires_at ? new Date(new Date(data.member.expires_at).getTime() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : "";
    form.elements.max_devices.value = data.member.max_devices;
    form.elements.wechat_id.value = data.member.wechat_id || "";
    form.elements.member_number.value = data.member.member_number || "";
    form.elements.notes.value = data.member.notes || "";
    updateRenewPreview();
    $("#member-dialog").showModal();
  } catch (error) { toast(error.message); }
}

function updateRenewPreview() {
  if (!state.currentMember) return;
  const plan = state.plans.find((item) => item.id === $("#edit-member-form").elements.plan_id.value);
  if (!plan) { $("#renew-preview").textContent = "选择套餐后显示新的到期时间。"; return; }
  const current = Date.parse(state.currentMember.expires_at || "");
  const base = $("#renew-mode").value === "from_expiry" && Number.isFinite(current) && current > Date.now() ? current : Date.now();
  $("#renew-preview").textContent = "预计到期：" + new Date(base + Number(plan.duration_days) * 86400000).toLocaleString("zh-CN") + "（" + plan.duration_days + " 天）";
}

$("#edit-member-form").elements.plan_id.addEventListener("change", updateRenewPreview);
$("#renew-mode").addEventListener("change", updateRenewPreview);

$("#renew-member").addEventListener("click", async () => {
  if (!state.currentMember) return;
  const memberId = state.currentMember.id;
  const planId = $("#edit-member-form").elements.plan_id.value;
  if (!planId) { toast("请选择一个有效套餐"); return; }
  updateRenewPreview();
  const mode = $("#renew-mode").value;
  if (!confirm("将会员设为有效并延长到预览日期。继续？")) return;
  try {
    const result = await api("/members/" + encodeURIComponent(state.currentMember.id) + "/renew", { method: "POST", body: JSON.stringify({ plan_id: planId, mode }) });
    state.currentMember.expires_at = result.expires_at;
    state.currentMember.plan_id = result.plan_id;
    await Promise.all([loadMembers(), loadOverview()]);
    $("#member-dialog").close();
    await openMember(memberId);
    toast("续期完成");
  } catch (error) { toast(error.message); }
});

$("#edit-member-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const expiryLocal = form.elements.expires_at.value;
  const data = {
    status: form.elements.status.value,
    plan_id: form.elements.plan_id.value || null,
    expires_at: expiryLocal ? new Date(expiryLocal).toISOString() : null,
    max_devices: Number(form.elements.max_devices.value),
    wechat_id: form.elements.wechat_id.value,
    member_number: form.elements.member_number.value,
    notes: form.elements.notes.value,
  };
  try {
    await api("/members/" + encodeURIComponent(form.elements.id.value), { method: "PATCH", body: JSON.stringify(data) });
    await Promise.all([loadMembers(), loadOverview()]);
    toast("会员信息已保存");
    $("#member-dialog").close();
  } catch (error) { toast(error.message); }
});

$("#rotate-token").addEventListener("click", async () => {
  if (!state.currentMember || !confirm("这会立即撤销所有旧地址，确定重置？")) return;
  try {
    const result = await api("/members/" + encodeURIComponent(state.currentMember.id) + "/reset-token", { method: "POST", body: "{}" });
    const plan = state.plans.find((item) => item.id === state.currentMember.plan_id);
    const links = (plan?.resource_ids || []).map((resourceId) => {
      const resource = state.resources.find((item) => item.id === resourceId && item.enabled);
      return resource ? resource.name + "： " + BASE + "/" + result.token + "/" + resource.slug + (resource.type === "stremio" ? "/manifest.json" : resource.type === "json" ? ".json" : "") : "";
    }).filter(Boolean);
    $("#token-result").textContent = "新地址仅在本次显示：\n" + links.join("\n") + "\n\n也可让会员通过 Telegram Bot 的“获取当前分发地址”按钮重新查看。请勿转发给其他人。";
    $("#token-result").classList.remove("hidden");
    await Promise.all([loadMembers(), loadOverview()]);
  } catch (error) { toast(error.message); }
});

$$("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => $("#member-dialog").close()));

async function loadRenewals() {
  try {
    const rows = await api("/renewals");
    $("#renewal-count").textContent = rows.length;
    $("#renewal-count").classList.toggle("hidden", rows.length === 0);
    const box = $("#renewals-list");
    box.replaceChildren();
    if (!rows.length) { box.append(element("div", "目前没有待审核的续期申请。", "empty")); return; }
    for (const row of rows) {
      const card = element("article", "", "request-card");
      const left = element("div");
      left.append(element("strong", (row.display_name || "会员") + " · Telegram " + row.telegram_user_id), element("small", "申请时间 " + row.created_at));
      const actions = element("div", "", "row-actions");
      for (const [label, status, cls] of [["批准", "approved", "mini-button"], ["拒绝", "rejected", "mini-button warn"]]) {
        const button = element("button", label, cls); button.type = "button";
        button.addEventListener("click", async () => {
          if (!confirm(`确定${label}这条续期申请？`)) return;
          try { await api("/renewals/" + encodeURIComponent(row.id), { method: "POST", body: JSON.stringify({ status }) }); await Promise.all([loadRenewals(), loadMembers(), loadOverview()]); toast("已" + label); }
          catch (error) { toast(error.message); }
        });
        actions.append(button);
      }
      card.append(left, actions); box.append(card);
    }
  } catch (error) { toast(error.message); }
}

function updateDeviceLimitSelection() {
  const checked = $$(`[data-device-request-id]:checked`).length;
  const total = $$(`[data-device-request-id]`).length;
  const all = $("#device-requests-select-all");
  all.checked = total > 0 && checked === total;
  all.indeterminate = checked > 0 && checked < total;
  $("#device-requests-approve").disabled = checked === 0;
  $("#device-requests-reject").disabled = checked === 0;
}

async function processDeviceLimitRequests(ids, status) {
  if (!ids.length) return;
  const label = status === "approved" ? "批准" : "拒绝";
  if (!confirm(`确定${label}所选 ${ids.length} 条设备扩容申请？`)) return;
  let processed = 0;
  let failed = 0;
  const errors = [];
  try {
    for (let offset = 0; offset < ids.length; offset += 50) {
      const result = await api("/device-limit-requests/batch", { method: "POST", body: JSON.stringify({ ids: ids.slice(offset, offset + 50), status }) });
      processed += Number(result.processed || 0);
      failed += Number(result.failed || 0);
      for (const row of result.results || []) if (!row.ok) errors.push(row.error);
    }
    const reasons = [...new Set(errors)].map((code) => code === "DEVICE_LIMIT_CAP_REACHED" ? "达到50台总上限" : code === "DEVICE_LIMIT_NOT_PENDING" ? "申请已被处理" : code).join("、");
    toast(`${label}完成 ${processed} 条，失败 ${failed} 条${reasons ? "（" + reasons + "）" : ""}`);
  } catch (error) {
    toast(`已处理 ${processed} 条；后续操作失败：${error.message}。请刷新确认结果`);
  } finally {
    await Promise.all([loadDeviceLimitRequests(), loadMembers(), loadOverview()]);
  }
}

async function loadDeviceLimitRequests() {
  try {
    const rows = await api("/device-limit-requests");
    const box = $("#device-requests-list");
    box.replaceChildren();
    $("#device-request-count").textContent = rows.length;
    $("#device-request-count").classList.toggle("hidden", rows.length === 0);
    if (!rows.length) {
      box.append(element("div", "目前没有待审核的设备扩容申请。", "empty"));
      updateDeviceLimitSelection();
      return;
    }
    for (const row of rows) {
      const card = element("article", "", "request-card application-card");
      const left = element("div", "", "application-info");
      const heading = element("div", "", "application-heading");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.dataset.deviceRequestId = row.id;
      checkbox.setAttribute("aria-label", "选择" + (row.display_name || row.telegram_user_id));
      checkbox.addEventListener("change", updateDeviceLimitSelection);
      heading.append(checkbox, element("strong", (row.display_name || "会员") + (row.telegram_username ? " · @" + row.telegram_username : "")));
      left.append(heading,
        element("small", "Telegram ID：" + row.telegram_user_id + " · 会员号：" + (row.member_number || "未填写")),
        element("small", "当前设备：" + Number(row.active_devices || 0) + " / " + Number(row.max_devices || 1) + " · 申请新增：" + Number(row.additional_devices || 0) + " 台"),
        element("small", "申请时间：" + new Date(row.created_at).toLocaleString("zh-CN")));
      const actions = element("div", "", "row-actions");
      for (const [buttonText, result] of [["批准", "approved"], ["拒绝", "rejected"]]) {
        const button = element("button", buttonText, result === "approved" ? "mini-button" : "mini-button warn");
        button.type = "button";
        button.addEventListener("click", () => processDeviceLimitRequests([row.id], result));
        actions.append(button);
      }
      card.append(left, actions);
      box.append(card);
    }
    updateDeviceLimitSelection();
  } catch (error) { toast(error.message); }
}

$("#device-requests-select-all").addEventListener("change", (event) => {
  $$(`[data-device-request-id]`).forEach((input) => { input.checked = event.currentTarget.checked; });
  updateDeviceLimitSelection();
});
$("#device-requests-approve").addEventListener("click", () => processDeviceLimitRequests($$(`[data-device-request-id]:checked`).map((input) => input.dataset.deviceRequestId), "approved"));
$("#device-requests-reject").addEventListener("click", () => processDeviceLimitRequests($$(`[data-device-request-id]:checked`).map((input) => input.dataset.deviceRequestId), "rejected"));
$("#refresh-device-requests").addEventListener("click", () => loadDeviceLimitRequests());

async function loadAudit() {
  try {
    const rows = await api("/audit");
    const body = $("#audit-body"); body.replaceChildren();
    for (const row of rows) {
      const tr = document.createElement("tr");
      [new Date(row.timestamp).toLocaleString("zh-CN"), row.actor_id, row.action, row.target_type + " · " + row.target_id.slice(0, 8), row.change_summary].forEach((value) => tr.append(element("td", value || "")));
      body.append(tr);
    }
  } catch (error) { toast(error.message); }
}

init();

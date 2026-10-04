(function () {
  "use strict";
  var data = window.__DTV__ || {};
  var app = document.getElementById("app");
  if (!app) return;
  var origin = String(data.origin || location.origin).replace(/\/+$/, "");
  var token = String(data.token || "");

  function fullUrl(path) {
    return origin + "/" + token + path;
  }

  function toast(text) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = text;
    el.classList.add("show");
    clearTimeout(el._timer);
    el._timer = setTimeout(function () { el.classList.remove("show"); }, 1600);
  }

  function copyText(text) {
    function done() { toast("已复制到剪贴板"); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { legacy(); });
      return;
    }
    legacy();
    function legacy() {
      var area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try { document.execCommand("copy"); done(); } catch (error) { toast("复制失败，请长按地址手动复制"); }
      document.body.removeChild(area);
    }
  }

  function makeQr(container, text) {
    if (container.dataset.rendered === text) { container.classList.toggle("show"); return; }
    container.innerHTML = "";
    container.dataset.rendered = text;
    try {
      var qr = window.qrcode(0, "M");
      qr.addData(text);
      qr.make();
      container.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
      var svg = container.querySelector("svg");
      if (svg) { svg.style.width = "220px"; svg.style.height = "220px"; }
    } catch (error) {
      container.textContent = "二维码生成失败，请直接复制地址";
    }
    container.classList.add("show");
  }

  function card(options) {
    var section = document.createElement("div");
    section.className = "card";
    var title = document.createElement("h2");
    title.textContent = options.title;
    section.appendChild(title);
    if (options.desc) {
      var desc = document.createElement("div");
      desc.className = "desc";
      desc.textContent = options.desc;
      section.appendChild(desc);
    }
    var row = document.createElement("div");
    row.className = "urlrow";
    var code = document.createElement("code");
    code.textContent = options.url;
    row.appendChild(code);
    section.appendChild(row);
    var actions = document.createElement("div");
    actions.className = "actions";
    var copy = document.createElement("button");
    copy.textContent = "复制地址";
    copy.addEventListener("click", function () { copyText(options.url); });
    actions.appendChild(copy);
    var qrButton = document.createElement("button");
    qrButton.className = "ghost";
    qrButton.textContent = "显示二维码";
    var qrBox = document.createElement("div");
    qrBox.className = "qr";
    qrButton.addEventListener("click", function () {
      makeQr(qrBox, options.url);
      qrButton.textContent = qrBox.classList.contains("show") ? "隐藏二维码" : "显示二维码";
    });
    actions.appendChild(qrButton);
    section.appendChild(actions);
    section.appendChild(qrBox);
    return section;
  }

  if (!data.usable) {
    var notice = document.createElement("div");
    notice.className = "card";
    var noticeTitle = document.createElement("h2");
    noticeTitle.textContent = "订阅暂不可用";
    var noticeDesc = document.createElement("div");
    noticeDesc.className = "desc";
    noticeDesc.textContent = "会员状态为「" + (data.status_label || data.status || "未知") +
      "」，订阅地址已停止服务。如有疑问请联系管理员，或在 Telegram Bot 中查看会员状态。";
    notice.appendChild(noticeTitle);
    notice.appendChild(noticeDesc);
    app.appendChild(notice);
    return;
  }

  if (!data.resources || !data.resources.length) {
    var empty = document.createElement("div");
    empty.className = "card";
    var emptyTitle = document.createElement("h2");
    emptyTitle.textContent = "暂无可用仓库";
    var emptyDesc = document.createElement("div");
    emptyDesc.className = "desc";
    emptyDesc.textContent = "你的套餐还没有可用的资源快照，请联系管理员同步资源后再试。";
    empty.appendChild(emptyTitle);
    empty.appendChild(emptyDesc);
    app.appendChild(empty);
    return;
  }

  app.appendChild(card({
    title: "① 多仓地址（推荐）",
    desc: "在 TVBox「配置地址」里填这个，保存后可在应用的仓库列表中切换全部仓库。",
    url: fullUrl("/tvbox.json"),
  }));
  app.appendChild(card({
    title: "② 单仓地址",
    desc: "全部片源聚合为一份配置的仓库，和不支持多仓切换的客户端兼容。",
    url: fullUrl("/all.json"),
  }));
})();

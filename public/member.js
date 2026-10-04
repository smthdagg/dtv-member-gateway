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
    title: "多仓订阅地址（推荐，TVBox 填这个）",
    desc: "包含你套餐内的全部仓库，保存后在应用的仓库列表中切换。",
    url: fullUrl("/tvbox.json"),
  }));
  app.appendChild(card({
    title: "聚合单仓地址（全部源合并为一个）",
    desc: "把所有仓库的片源合并成一份配置，适合不支持多仓切换的客户端。",
    url: fullUrl("/all.json"),
  }));

  var listCard = document.createElement("div");
  listCard.className = "card";
  listCard.innerHTML = "<h2>单独订阅某个仓库</h2><div class='desc'>各仓库独立地址，可按需添加。</div>";
  var list = document.createElement("ul");
  list.className = "reslist";
  data.resources.forEach(function (resource) {
    var item = document.createElement("li");
    var left = document.createElement("div");
    var name = document.createElement("div");
    name.className = "resname";
    name.textContent = resource.name || resource.slug;
    var sub = document.createElement("div");
    sub.className = "ressub";
    sub.textContent = "代号 " + resource.slug + " · " + (resource.url_count || 0) + " 个地址" +
      (resource.synced_at ? " · 同步于 " + String(resource.synced_at).slice(0, 16).replace("T", " ") : "");
    left.appendChild(name);
    left.appendChild(sub);
    var right = document.createElement("div");
    right.className = "actions";
    right.style.marginTop = "0";
    var copy = document.createElement("button");
    copy.className = "ghost";
    copy.textContent = "复制";
    var url = fullUrl("/" + resource.slug + ".json");
    copy.addEventListener("click", function () { copyText(url); });
    right.appendChild(copy);
    item.appendChild(left);
    item.appendChild(right);
    list.appendChild(item);
  });
  listCard.appendChild(list);
  app.appendChild(listCard);
})();

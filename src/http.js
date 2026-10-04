import { json } from "./security.js";

function responseHeaders(extra = {}) {
  return {
    "cache-control": "no-store, private",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    ...extra,
  };
}

const ERROR_MESSAGES = {
  DEVICE_LIMIT_EXCEEDED: "设备数量已达到上限。请在 Bot 的设备管理中移除旧设备，或申请增加设备数。",
  DEVICE_REMOVED: "此设备记录已被移除，当前设备标识不能继续访问。",
  UPSTREAM_FETCH_FAILED: "上游接口连接失败，请稍后重试或联系管理员检查资源同步。",
  UPSTREAM_HTTP_ERROR: "上游接口返回错误，请管理员检查资源地址和访问权限。",
  UPSTREAM_JSON_INVALID: "上游内容不是有效 JSON，请管理员检查接口格式。",
  UPSTREAM_REDIRECT_BLOCKED: "上游接口跳转到了不受支持的地址，请管理员检查资源配置。",
  UPSTREAM_RESPONSE_TOO_LARGE: "上游接口返回内容超过允许大小。",
  RESOURCE_STREAM_UNSUPPORTED: "此资源返回了不支持的音视频流。",
  TARGET_INVALID: "此分发地址的转发凭证无效，请从 Bot 重新获取当前地址。",
  AGGREGATE_EMPTY: "你的套餐当前没有可用的订阅资源，请联系管理员。",
  AGGREGATE_TOO_LARGE: "聚合订阅内容超过大小限制，请改用多仓订阅地址。",
  AGGREGATE_FAILED: "聚合订阅生成失败，请稍后重试。",
};

function error(code, status, message = code) {
  if (message === code && ERROR_MESSAGES[code]) message = ERROR_MESSAGES[code];
  return json({ error: { code, message } }, status, responseHeaders());
}

function subscriptionResponse(response) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET, HEAD, OPTIONS");
  headers.set("access-control-allow-headers", "Accept, Authorization, Content-Type, Range");
  headers.set("access-control-expose-headers", "Accept-Ranges, Content-Length, Content-Range, Content-Type, ETag");
  headers.set("access-control-max-age", "86400");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export { responseHeaders, error, subscriptionResponse };

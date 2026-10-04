import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const [html, css, js, logo, memberJs, vendorQr] = await Promise.all([
  readFile(join(root, "public/index.html"), "utf8"),
  readFile(join(root, "public/style.css"), "utf8"),
  readFile(join(root, "public/app.js"), "utf8"),
  readFile(join(root, "public/logo.png")),
  readFile(join(root, "public/member.js"), "utf8"),
  readFile(join(root, "public/vendor/qrcode.js"), "utf8").catch(() => ""),
]);

const memberBundle = (vendorQr ? vendorQr + "\n" : "") + memberJs;

const source = [
  `export const ADMIN_HTML = ${JSON.stringify(html)};`,
  `export const STYLE_CSS = ${JSON.stringify(css)};`,
  `export const APP_JS = ${JSON.stringify(js)};`,
  `export const LOGO_PNG_BASE64 = ${JSON.stringify(logo.toString("base64"))};`,
  `export const MEMBER_JS = ${JSON.stringify(memberBundle)};`,
  "",
].join("\n");

await writeFile(join(root, "src/ui.js"), source);

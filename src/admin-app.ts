import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const APP_VERSION = (
  JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  ) as { version: string }
).version;

const HTMX_SOURCE = readFileSync(
  new URL("../node_modules/htmx.org/dist/htmx.min.js", import.meta.url),
  "utf8",
);

// Tiny event-delegation script: copy button, delete confirm, restart health poll.
// Served from /admin/static/admin.js so CSP 'script-src self' allows it.
const ADMIN_JS = `
document.addEventListener('click',function(e){
  var btn=e.target.closest('.copy-btn');
  if(btn){
    var box=btn.parentElement;
    var node=Array.from(box.childNodes).find(function(n){return n.nodeType===3;});
    if(node)navigator.clipboard.writeText(node.textContent.trim()).then(function(){btn.textContent='✓ Copied';});
    return;
  }
  var conf=e.target.closest('[data-confirm]');
  if(conf&&!confirm(conf.getAttribute('data-confirm')))e.preventDefault();
});
document.addEventListener('htmx:afterRequest',function(e){
  if(e.detail.successful&&e.target.id==='status')window.location.href='/admin/dashboard';
});
`.trim();

import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifyFormbody from "@fastify/formbody";
import type { DatabaseSync } from "node:sqlite";
import { parse as yamlParse, stringify as yamlStringify } from "yaml";
import type { GatewayConfig } from "./config.js";
import { loadConfig } from "./config.js";
import { writeConfigAtomic } from "./config-writer.js";
import { discoverTools } from "./upstream-mcp-client.js";
import { createUpstreamDispatcher } from "./upstream-dispatcher.js";
import {
  appendAuditEvent,
  consumeBootstrap,
  createSession,
  deleteSession,
  hasAdminCredentials,
  initBootstrap,
  isLoginRateLimited,
  lookupSession,
  pruneExpiredSessions,
  pruneLoginAttempts,
  recordLoginAttempt,
  rotateSession,
  setAdminPassword,
  validateBootstrapToken,
  verifyAdminPassword,
} from "./admin-auth.js";
import {
  issueToken,
  listTokens,
  revokeToken,
  tokenStatus,
} from "./oauth-token-store.js";
import { setOAuthUserPassword } from "./oauth-authorization-server.js";

const COOKIE_NAME = "mcp_admin_session";
const THEME_COOKIE = "mcp_admin_theme";
const CSRF_FIELD = "_csrf";
const ADMIN_BODY_LIMIT = 65_536;

// ── Embedded CSS design system ────────────────────────────────────────────────

const ADMIN_CSS = `
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f8fafc;--surface:#ffffff;--surface-2:#f1f5f9;
  --border:#e2e8f0;--border-2:#cbd5e1;
  --text:#0f172a;--text-2:#475569;--muted:#64748b;
  --accent:#2563eb;--accent-h:#1d4ed8;--accent-t:color-mix(in srgb,#2563eb 12%,transparent);
  --success:#059669;--success-t:color-mix(in srgb,#059669 12%,transparent);
  --warning:#d97706;--warning-t:color-mix(in srgb,#d97706 12%,transparent);
  --danger:#dc2626;--danger-h:#b91c1c;--danger-t:color-mix(in srgb,#dc2626 12%,transparent);
  --code-bg:#f1f5f9;--code-text:#0f172a;
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.05);
  --radius:6px;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#0f172a;--surface:#1e293b;--surface-2:#0f172a;
  --border:#334155;--border-2:#475569;
  --text:#f1f5f9;--text-2:#cbd5e1;--muted:#94a3b8;
  --accent:#3b82f6;--accent-h:#60a5fa;--accent-t:color-mix(in srgb,#3b82f6 15%,transparent);
  --success:#10b981;--success-t:color-mix(in srgb,#10b981 15%,transparent);
  --warning:#f59e0b;--warning-t:color-mix(in srgb,#f59e0b 15%,transparent);
  --danger:#ef4444;--danger-h:#f87171;--danger-t:color-mix(in srgb,#ef4444 15%,transparent);
  --code-bg:#020617;--code-text:#e2e8f0;
  --shadow:0 1px 3px rgba(0,0,0,.4),0 1px 2px rgba(0,0,0,.3);
}}
[data-theme="light"]{
  --bg:#f8fafc;--surface:#ffffff;--surface-2:#f1f5f9;
  --border:#e2e8f0;--border-2:#cbd5e1;
  --text:#0f172a;--text-2:#475569;--muted:#64748b;
  --accent:#2563eb;--accent-h:#1d4ed8;--accent-t:color-mix(in srgb,#2563eb 12%,transparent);
  --success:#059669;--success-t:color-mix(in srgb,#059669 12%,transparent);
  --warning:#d97706;--warning-t:color-mix(in srgb,#d97706 12%,transparent);
  --danger:#dc2626;--danger-h:#b91c1c;--danger-t:color-mix(in srgb,#dc2626 12%,transparent);
  --code-bg:#f1f5f9;--code-text:#0f172a;
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.05);
}
[data-theme="dark"]{
  --bg:#0f172a;--surface:#1e293b;--surface-2:#0f172a;
  --border:#334155;--border-2:#475569;
  --text:#f1f5f9;--text-2:#cbd5e1;--muted:#94a3b8;
  --accent:#3b82f6;--accent-h:#60a5fa;--accent-t:color-mix(in srgb,#3b82f6 15%,transparent);
  --success:#10b981;--success-t:color-mix(in srgb,#10b981 15%,transparent);
  --warning:#f59e0b;--warning-t:color-mix(in srgb,#f59e0b 15%,transparent);
  --danger:#ef4444;--danger-h:#f87171;--danger-t:color-mix(in srgb,#ef4444 15%,transparent);
  --code-bg:#020617;--code-text:#e2e8f0;
  --shadow:0 1px 3px rgba(0,0,0,.4),0 1px 2px rgba(0,0,0,.3);
}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.5}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:ui-monospace,'Cascadia Code','Fira Code',monospace;font-size:.85em;background:var(--surface-2);padding:.1em .35em;border-radius:3px}
pre{font-family:ui-monospace,'Cascadia Code','Fira Code',monospace;background:var(--code-bg);color:var(--code-text);padding:1rem;border-radius:var(--radius);font-size:.85rem;white-space:pre-wrap;word-break:break-all;overflow-x:auto;margin:0}
/* Layout */
.app-layout{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
.sidebar{background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
.sidebar-header{padding:1.25rem 1.25rem 1rem;border-bottom:1px solid var(--border)}
.sidebar-logo{font-size:.95rem;font-weight:700;color:var(--accent);letter-spacing:-.01em;display:flex;align-items:center;gap:.5rem}
.sidebar-logo span{opacity:.6;font-weight:400;font-size:.8rem}
.sidebar-nav{padding:.5rem 0;flex:1}
.nav-item{display:flex;align-items:center;gap:.6rem;padding:.5rem 1.25rem;color:var(--text-2);font-size:.875rem;transition:background .1s,color .1s}
.nav-item:hover{background:var(--surface-2);color:var(--text);text-decoration:none}
.nav-item.active{background:var(--accent-t);color:var(--accent);font-weight:600}
.nav-icon{width:1.1em;text-align:center;flex-shrink:0;opacity:.7}
.nav-item.active .nav-icon{opacity:1}
.sidebar-footer{padding:1rem 1.25rem;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:.6rem}
.theme-toggle{display:flex;gap:.3rem}
.theme-btn{padding:.25rem .5rem;border:1px solid var(--border);border-radius:4px;background:transparent;color:var(--muted);cursor:pointer;font-size:.8rem;line-height:1.4;transition:background .1s,border-color .1s,color .1s}
.theme-btn:hover{border-color:var(--border-2);color:var(--text)}
.theme-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.sidebar-version{font-size:.72rem;color:var(--muted)}
/* Main */
.main{padding:2rem;max-width:1100px;min-width:0}
/* Page header */
.page-header{margin-bottom:1.5rem;display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.page-title{font-size:1.2rem;font-weight:700;margin:0}
.page-subtitle{color:var(--muted);font-size:.875rem;margin-top:.2rem}
.page-actions{display:flex;gap:.5rem;align-items:center;flex-shrink:0}
/* Auth layout */
.auth-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;background:var(--bg);padding:1rem}
.auth-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:2.5rem;width:100%;max-width:420px;box-shadow:var(--shadow)}
.auth-logo{font-size:1rem;font-weight:700;color:var(--accent);margin-bottom:.25rem}
.auth-title{font-size:1.25rem;font-weight:700;margin:0 0 .25rem}
.auth-subtitle{color:var(--muted);font-size:.875rem;margin-bottom:1.75rem}
/* Cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.5rem;box-shadow:var(--shadow)}
.card+.card{margin-top:1rem}
.card-title{font-size:.95rem;font-weight:600;margin:0 0 1rem;color:var(--text)}
/* Stat grid */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.25rem;box-shadow:var(--shadow)}
.stat-value{font-size:1.75rem;font-weight:700;color:var(--accent);line-height:1}
.stat-label{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.4rem}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:.4rem;padding:.45rem 1rem;border-radius:var(--radius);font-size:.875rem;font-weight:500;cursor:pointer;border:1px solid transparent;text-decoration:none;transition:background .15s,border-color .15s,color .15s;line-height:1.4;white-space:nowrap}
.btn:hover{text-decoration:none}
.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-primary:hover{background:var(--accent-h);border-color:var(--accent-h)}
.btn-secondary{background:transparent;border-color:var(--border-2);color:var(--text-2)}
.btn-secondary:hover{background:var(--surface-2);color:var(--text)}
.btn-danger{background:var(--danger);color:#fff;border-color:var(--danger)}
.btn-danger:hover{background:var(--danger-h);border-color:var(--danger-h)}
.btn-danger-outline{background:transparent;border-color:var(--danger);color:var(--danger)}
.btn-danger-outline:hover{background:var(--danger);color:#fff}
.btn-warning{background:var(--warning);color:#fff;border-color:var(--warning)}
.btn-warning:hover{background:color-mix(in srgb,var(--warning) 85%,#000);border-color:color-mix(in srgb,var(--warning) 85%,#000)}
.btn-sm{padding:.25rem .6rem;font-size:.8rem}
.btn-group{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
/* Badges */
.badge{display:inline-flex;align-items:center;padding:.15rem .5rem;border-radius:99px;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge-success{background:var(--success-t);color:var(--success)}
.badge-warning{background:var(--warning-t);color:var(--warning)}
.badge-danger{background:var(--danger-t);color:var(--danger)}
.badge-muted{background:var(--surface-2);color:var(--muted)}
/* Alerts */
.alert{padding:.75rem 1rem;border-radius:var(--radius);border-left:4px solid;margin-bottom:1rem;font-size:.875rem}
.alert strong{display:block;margin-bottom:.2rem}
.alert-success{background:var(--success-t);border-color:var(--success)}
.alert-warning{background:var(--warning-t);border-color:var(--warning)}
.alert-error{background:var(--danger-t);border-color:var(--danger)}
.alert-info{background:var(--accent-t);border-color:var(--accent)}
/* Restart banner */
.restart-banner{background:var(--warning-t);border:1px solid var(--warning);border-radius:var(--radius);padding:.6rem 1rem;margin-bottom:1.25rem;font-size:.875rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
/* Forms */
.form-group{margin-bottom:1.25rem}
.form-label{display:block;font-size:.875rem;font-weight:500;margin-bottom:.375rem}
.form-input,.form-select,.form-textarea{display:block;width:100%;padding:.5rem .75rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--text);font-size:.875rem;transition:border-color .15s,outline .15s}
.form-input:focus,.form-select:focus,.form-textarea:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
.form-hint{font-size:.75rem;color:var(--muted);margin-top:.35rem}
.form-textarea{font-family:ui-monospace,'Cascadia Code',monospace;resize:vertical}
.form-select{cursor:pointer}
.form-check{display:flex;align-items:flex-start;gap:.6rem;cursor:pointer}
.form-check input[type=checkbox]{margin-top:.15rem;accent-color:var(--accent);width:1em;height:1em;flex-shrink:0}
.form-actions{display:flex;gap:.5rem;align-items:center;margin-top:1.5rem;flex-wrap:wrap}
fieldset.form-section{border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin-bottom:1.25rem;background:var(--surface)}
fieldset.form-section legend{font-weight:600;font-size:.875rem;padding:0 .5rem;color:var(--text)}
/* Tables */
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
thead th{text-align:left;font-size:.72rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;padding:.65rem 1rem;border-bottom:1px solid var(--border);white-space:nowrap;background:var(--surface-2)}
tbody td{padding:.75rem 1rem;border-bottom:1px solid var(--border);vertical-align:middle;font-size:.875rem}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:var(--surface-2)}
.td-mono{font-family:ui-monospace,'Cascadia Code',monospace;font-size:.8rem}
.td-muted{color:var(--muted);font-size:.8rem}
/* Token display */
.token-box{background:var(--warning-t);border:1px solid var(--warning);border-radius:var(--radius);padding:1rem;font-family:ui-monospace,'Cascadia Code',monospace;font-size:.85rem;word-break:break-all;margin:1rem 0;position:relative}
.copy-btn{position:absolute;top:.5rem;right:.5rem;padding:.2rem .5rem;font-size:.75rem;border-radius:4px;border:1px solid var(--warning);background:transparent;color:var(--warning);cursor:pointer}
.copy-btn:hover{background:var(--warning);color:#fff}
/* Spinner */
.spinner{display:inline-block;width:1em;height:1em;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.htmx-indicator{opacity:0;transition:opacity .2s}
.htmx-request .htmx-indicator,.htmx-request.htmx-indicator{opacity:1}
/* Utils */
.flex{display:flex}.items-center{align-items:center}.gap-2{gap:.5rem}.gap-3{gap:.75rem}
.mt-1{margin-top:.25rem}.mt-2{margin-top:.5rem}.mt-4{margin-top:1rem}.mb-4{margin-bottom:1rem}
.text-muted{color:var(--muted)}.text-danger{color:var(--danger)}.text-success{color:var(--success)}
.w-full{width:100%}
.empty-state{text-align:center;padding:3rem 1rem;color:var(--muted)}
.empty-state p{margin:.5rem 0}
/* Divider */
hr{border:none;border-top:1px solid var(--border);margin:1.5rem 0}
`;

// ── HTML shell helpers ────────────────────────────────────────────────────────

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(str: string): string {
  return str.replace(/[&<>"']/g, (c) => HTML_ESCAPE_MAP[c] ?? c);
}

function getTheme(request: FastifyRequest): string {
  const t = (request.cookies as Record<string, string>)[THEME_COOKIE] ?? "";
  return t === "light" || t === "dark" ? t : "";
}

const NAV_ITEMS = [
  { href: "/admin/dashboard", icon: "◈", label: "Dashboard", key: "dashboard" },
  { href: "/admin/routes", icon: "⇌", label: "Routes", key: "routes" },
  { href: "/admin/tokens", icon: "◎", label: "Tokens", key: "tokens" },
  { href: "/admin/config", icon: "✎", label: "Config", key: "config" },
  { href: "/admin/settings", icon: "⚙", label: "Settings", key: "settings" },
  {
    href: "/admin/oauth-user",
    icon: "◷",
    label: "OAuth User",
    key: "oauth-user",
  },
];

function htmlShell(
  title: string,
  body: string,
  opts: {
    active: string;
    csrf: string;
    theme: string;
    restartRequired: boolean;
  },
): string {
  const { active, csrf, theme, restartRequired } = opts;
  const themeAttr = theme ? ` data-theme="${escapeHtml(theme)}"` : "";
  const navHtml = NAV_ITEMS.map(
    (item) =>
      `<a href="${item.href}" class="nav-item${active === item.key ? " active" : ""}">` +
      `<span class="nav-icon">${item.icon}</span>${item.label}</a>`,
  ).join("");
  const activeTheme = theme || "auto";
  const themeBtns = (
    [
      { key: "auto", label: "⊙" },
      { key: "light", label: "☀" },
      { key: "dark", label: "☾" },
    ] as const
  )
    .map(
      (t) =>
        `<a href="/admin/theme/${t.key}" class="theme-btn${activeTheme === t.key ? " active" : ""}" title="${t.key}">${t.label}</a>`,
    )
    .join("");

  const restartBanner = restartRequired
    ? `<div class="restart-banner">
        <span>⚠ Configuration saved — restart required to apply changes</span>
        <form method="POST" action="/admin/restart" style="display:inline">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(csrf)}">
          <button type="submit" class="btn btn-sm btn-warning">Restart now</button>
        </form>
      </div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en"${themeAttr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — MCP Gateway</title>
<style>${ADMIN_CSS}</style>
<script src="/admin/static/htmx.min.js"></script>
<script src="/admin/static/admin.js"></script>
</head>
<body>
<div class="app-layout">
<aside class="sidebar">
  <div class="sidebar-header">
    <div class="sidebar-logo">MCP Gateway <span>Admin</span></div>
  </div>
  <nav class="sidebar-nav">${navHtml}</nav>
  <div class="sidebar-footer">
    <div class="theme-toggle">${themeBtns}</div>
    <form method="POST" action="/admin/logout">
      <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(csrf)}">
      <button type="submit" class="btn btn-danger-outline btn-sm w-full">Log out</button>
    </form>
    <div class="sidebar-version">v${APP_VERSION}</div>
  </div>
</aside>
<main class="main">
${restartBanner}${body}
</main>
</div>
</body>
</html>`;
}

function htmlAuth(
  title: string,
  body: string,
  theme: string,
  headExtra = "",
): string {
  const themeAttr = theme ? ` data-theme="${escapeHtml(theme)}"` : "";
  return `<!DOCTYPE html>
<html lang="en"${themeAttr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — MCP Gateway</title>
<style>${ADMIN_CSS}</style>
${headExtra}</head>
<body>
<div class="auth-wrap">
<div class="auth-card">
${body}
</div>
</div>
</body>
</html>`;
}

function htmlError(title: string, message: string, backHref?: string): string {
  const back = backHref
    ? `<p style="margin-top:1rem"><a href="${escapeHtml(backHref)}" class="btn btn-secondary btn-sm">← Back</a></p>`
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — MCP Gateway</title>
<style>${ADMIN_CSS}</style>
</head>
<body>
<div class="auth-wrap">
<div class="auth-card">
<div class="auth-logo">MCP Gateway</div>
<h2 class="auth-title">${escapeHtml(title)}</h2>
<div class="alert alert-error">${message}</div>
${back}
</div>
</div>
</body>
</html>`;
}

// ── Exports / options ─────────────────────────────────────────────────────────

export interface BuildAdminAppOptions {
  db: DatabaseSync;
  config: GatewayConfig;
  configPath: string;
  onConfigSaved?: () => void;
}

export function buildAdminApp(options: BuildAdminAppOptions) {
  const { db, config, configPath } = options;
  const adminConfig = config.admin;

  let restartRequired = false;

  const app = Fastify({
    bodyLimit: ADMIN_BODY_LIMIT,
    logger: {
      level: config.server.logLevel,
      redact: {
        paths: [
          "req.headers.cookie",
          "req.body.password",
          "req.body.confirm",
          "req.body.token",
        ],
        censor: "[REDACTED]",
      },
    },
  });

  void app.register(fastifyCookie);
  void app.register(fastifyFormbody);

  app.addHook("onSend", async (req, reply) => {
    reply.header("X-Frame-Options", "DENY");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'",
    );
    if (!req.url?.startsWith("/admin/static/")) {
      reply.header("Cache-Control", "no-store");
    }
  });

  // ── Auth helpers ─────────────────────────────────────────────────────────

  function getSessionToken(request: FastifyRequest): string | undefined {
    return (request.cookies as Record<string, string>)[COOKIE_NAME];
  }

  function setSessionCookie(reply: FastifyReply, token: string): void {
    reply.setCookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: !adminConfig.insecureAllowHttpCookies,
      sameSite: "strict",
      path: "/admin",
    });
  }

  function clearSessionCookie(reply: FastifyReply): void {
    reply.clearCookie(COOKIE_NAME, {
      path: "/admin",
      secure: !adminConfig.insecureAllowHttpCookies,
    });
  }

  async function requireAuth(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<string | undefined> {
    const token = getSessionToken(request);
    if (!token) {
      await reply.redirect("/admin/login");
      return undefined;
    }
    const session = lookupSession(db, token);
    if (!session) {
      clearSessionCookie(reply);
      await reply.redirect("/admin/login");
      return undefined;
    }
    return token;
  }

  function requireCsrf(
    request: FastifyRequest,
    reply: FastifyReply,
    sessionToken: string,
  ): boolean {
    const session = lookupSession(db, sessionToken);
    if (!session) {
      reply
        .code(403)
        .send(htmlError("Forbidden", "Session expired.", "/admin/login"));
      return false;
    }
    const submitted = (request.body as Record<string, string>)[CSRF_FIELD];
    if (!submitted || submitted !== session.csrfToken) {
      reply.code(403).send(htmlError("Forbidden", "Invalid CSRF token."));
      return false;
    }
    return true;
  }

  function clientIp(request: FastifyRequest): string {
    return request.ip ?? "unknown";
  }

  // ── Static assets ─────────────────────────────────────────────────────────

  app.get("/admin/static/htmx.min.js", async (_request, reply) => {
    reply.header("Content-Type", "application/javascript; charset=utf-8");
    reply.header("Cache-Control", "public, max-age=31536000, immutable");
    return reply.send(HTMX_SOURCE);
  });

  app.get("/admin/static/admin.js", async (_request, reply) => {
    reply.header("Content-Type", "application/javascript; charset=utf-8");
    reply.header("Cache-Control", "public, max-age=31536000, immutable");
    return reply.send(ADMIN_JS);
  });

  // ── Theme toggle ──────────────────────────────────────────────────────────

  app.get("/admin/theme/:mode", async (request, reply) => {
    const mode = (request.params as Record<string, string>).mode ?? "";
    if (mode === "auto") {
      reply.clearCookie(THEME_COOKIE, { path: "/admin" });
    } else if (mode === "light" || mode === "dark") {
      reply.setCookie(THEME_COOKIE, mode, {
        httpOnly: false,
        sameSite: "strict",
        path: "/admin",
        maxAge: 365 * 24 * 60 * 60,
      });
    } else {
      return reply.redirect("/admin/dashboard");
    }
    const referer = (request.headers as Record<string, string>).referer ?? "";
    let safePath = "/admin/dashboard";
    try {
      const url = new URL(referer);
      if (url.pathname.startsWith("/admin/")) safePath = url.pathname;
    } catch {
      /* keep default */
    }
    return reply.redirect(safePath);
  });

  // ── GET /admin ────────────────────────────────────────────────────────────

  app.get("/admin", async (_request, reply) => {
    return reply.redirect("/admin/login");
  });

  // ── Setup flow ────────────────────────────────────────────────────────────

  app.get("/admin/setup", async (request, reply) => {
    if (hasAdminCredentials(db)) {
      return reply.redirect("/admin/login");
    }
    const bootstrapResult = initBootstrap(db);
    if (bootstrapResult.alreadyConsumed) {
      return reply.redirect("/admin/login");
    }
    const theme = getTheme(request);
    return reply.type("text/html").send(
      htmlAuth(
        "First-Run Setup",
        `<div class="auth-logo">MCP Gateway</div>
        <h2 class="auth-title">Gateway Setup</h2>
        <p class="auth-subtitle">Enter the Bootstrap token printed to the gateway logs, then choose an admin password.</p>
        <form method="POST" action="/admin/setup">
          <div class="form-group">
            <label class="form-label" for="setup-token">Bootstrap token</label>
            <input id="setup-token" name="token" type="password" class="form-input" required autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label" for="setup-pw">New password</label>
            <input id="setup-pw" name="password" type="password" class="form-input" required minlength="12">
            <div class="form-hint">Minimum 12 characters</div>
          </div>
          <div class="form-group">
            <label class="form-label" for="setup-confirm">Confirm password</label>
            <input id="setup-confirm" name="confirm" type="password" class="form-input" required minlength="12">
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary w-full">Complete Setup</button>
          </div>
        </form>`,
        theme,
      ),
    );
  });

  app.post("/admin/setup", async (request, reply) => {
    if (hasAdminCredentials(db)) {
      return reply.redirect("/admin/login");
    }

    const ip = clientIp(request);
    const body = request.body as Record<string, string>;
    const token = body.token ?? "";
    const password = body.password ?? "";
    const confirm = body.confirm ?? "";
    const theme = getTheme(request);

    if (isLoginRateLimited(db, adminConfig, ip)) {
      appendAuditEvent(db, "login_locked", ip);
      return reply
        .code(429)
        .type("text/html")
        .send(
          htmlAuth(
            "Too Many Attempts",
            `<div class="auth-logo">MCP Gateway</div>
          <h2 class="auth-title">Too Many Attempts</h2>
          <div class="alert alert-error">Too many attempts. Try again later.</div>`,
            theme,
          ),
        );
    }

    if (!validateBootstrapToken(db, token)) {
      recordLoginAttempt(db, ip, false);
      pruneLoginAttempts(db);
      appendAuditEvent(db, "login_failure", ip, {
        reason: "bad_bootstrap_token",
      });
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlAuth(
            "Setup Failed",
            `<div class="auth-logo">MCP Gateway</div>
          <h2 class="auth-title">Setup Failed</h2>
          <div class="alert alert-error">Invalid bootstrap token.</div>
          <a href="/admin/setup" class="btn btn-secondary btn-sm">← Try again</a>`,
            theme,
          ),
        );
    }

    if (password.length < 12) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlAuth(
            "Setup Failed",
            `<div class="auth-logo">MCP Gateway</div>
          <h2 class="auth-title">Setup Failed</h2>
          <div class="alert alert-error">Password must be at least 12 characters.</div>
          <a href="/admin/setup" class="btn btn-secondary btn-sm">← Try again</a>`,
            theme,
          ),
        );
    }

    if (password !== confirm) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlAuth(
            "Setup Failed",
            `<div class="auth-logo">MCP Gateway</div>
          <h2 class="auth-title">Setup Failed</h2>
          <div class="alert alert-error">Passwords do not match.</div>
          <a href="/admin/setup" class="btn btn-secondary btn-sm">← Try again</a>`,
            theme,
          ),
        );
    }

    await setAdminPassword(db, password);
    consumeBootstrap(db);
    appendAuditEvent(db, "bootstrap_used", ip);

    const { sessionToken } = createSession(db, adminConfig, ip);
    setSessionCookie(reply, sessionToken);
    return reply.redirect("/admin/dashboard");
  });

  // ── Login ─────────────────────────────────────────────────────────────────

  app.get("/admin/login", async (request, reply) => {
    const token = getSessionToken(request);
    if (token && lookupSession(db, token)) {
      return reply.redirect("/admin/dashboard");
    }
    const theme = getTheme(request);
    return reply.type("text/html").send(
      htmlAuth(
        "Login",
        `<div class="auth-logo">MCP Gateway</div>
        <h2 class="auth-title">Gateway Administration</h2>
        <p class="auth-subtitle">Sign in to manage your MCP gateway.</p>
        <form method="POST" action="/admin/login">
          <div class="form-group">
            <label class="form-label" for="login-pw">Password</label>
            <input id="login-pw" name="password" type="password" class="form-input" required autocomplete="current-password">
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary w-full">Log in</button>
          </div>
        </form>`,
        theme,
      ),
    );
  });

  app.post("/admin/login", async (request, reply) => {
    const ip = clientIp(request);
    const body = request.body as Record<string, string>;
    const password = body.password ?? "";
    const theme = getTheme(request);

    if (isLoginRateLimited(db, adminConfig, ip)) {
      appendAuditEvent(db, "login_locked", ip);
      return reply
        .code(429)
        .type("text/html")
        .send(
          htmlAuth(
            "Too Many Attempts",
            `<div class="auth-logo">MCP Gateway</div>
          <h2 class="auth-title">Too Many Attempts</h2>
          <div class="alert alert-error">Too many attempts. Try again later.</div>`,
            theme,
          ),
        );
    }

    if (!hasAdminCredentials(db)) {
      return reply.redirect("/admin/setup");
    }

    const valid = await verifyAdminPassword(db, password);
    recordLoginAttempt(db, ip, valid);
    pruneLoginAttempts(db);

    if (!valid) {
      appendAuditEvent(db, "login_failure", ip);
      return reply
        .code(401)
        .type("text/html")
        .send(
          htmlAuth(
            "Login Failed",
            `<div class="auth-logo">MCP Gateway</div>
          <h2 class="auth-title">Login Failed</h2>
          <div class="alert alert-error">Incorrect password.</div>
          <a href="/admin/login" class="btn btn-secondary btn-sm">← Try again</a>`,
            theme,
          ),
        );
    }

    appendAuditEvent(db, "login_success", ip);
    const { sessionToken } = createSession(db, adminConfig, ip);
    setSessionCookie(reply, sessionToken);
    return reply.redirect("/admin/dashboard");
  });

  // ── Logout ────────────────────────────────────────────────────────────────

  app.post("/admin/logout", async (request, reply) => {
    const token = await requireAuth(request, reply);
    if (!token) return;
    if (!requireCsrf(request, reply, token)) return;

    deleteSession(db, token);
    clearSessionCookie(reply);
    appendAuditEvent(db, "logout", clientIp(request));
    return reply.redirect("/admin/login");
  });

  // ── Dashboard ─────────────────────────────────────────────────────────────

  app.get("/admin/dashboard", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;

    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    const routeCount = config.routes.length;
    const tokenCount = listTokens(db).filter(
      (t) => tokenStatus(t) === "active",
    ).length;

    const routeRows = config.routes
      .map(
        (r) =>
          `<tr>
            <td class="td-mono">${escapeHtml(r.path)}</td>
            <td class="td-mono td-muted">${escapeHtml(r.upstream)}</td>
          </tr>`,
      )
      .join("\n");

    return reply.type("text/html").send(
      htmlShell(
        "Dashboard",
        `<div class="page-header">
          <div>
            <h1 class="page-title">Dashboard</h1>
            <div class="page-subtitle">Gateway status and overview</div>
          </div>
          <div class="page-actions">
            <a href="/admin/routes/new" class="btn btn-primary btn-sm">+ Add Route</a>
          </div>
        </div>
        <div class="stat-grid">
          <div class="stat-card">
            <div class="stat-value">${routeCount}</div>
            <div class="stat-label">Active Routes</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">${tokenCount}</div>
            <div class="stat-label">Active Tokens</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">${escapeHtml(String(adminConfig.port))}</div>
            <div class="stat-label">Admin Port</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">${escapeHtml(String(config.server.port))}</div>
            <div class="stat-label">Gateway Port</div>
          </div>
        </div>
        <div class="card">
          <div class="card-title">Configured Routes</div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Path</th><th>Upstream</th></tr></thead>
              <tbody>${routeRows || '<tr><td colspan="2" class="empty-state">No routes configured</td></tr>'}</tbody>
            </table>
          </div>
        </div>`,
        {
          active: "dashboard",
          csrf: session.csrfToken,
          theme,
          restartRequired,
        },
      ),
    );
  });

  // ── Config editor ─────────────────────────────────────────────────────────

  app.get("/admin/config", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;

    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    let currentYaml = "# Could not read current config";
    try {
      currentYaml = readFileSync(configPath, "utf8");
    } catch {
      /* keep fallback */
    }

    return reply.type("text/html").send(
      htmlShell(
        "Edit Configuration",
        `<div class="page-header">
          <div>
            <h1 class="page-title">Edit Configuration</h1>
            <div class="page-subtitle">Edit gateway.yaml directly. Validate before saving.</div>
          </div>
        </div>
        <div class="card">
          <form method="POST" action="/admin/config" id="config-form">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
            <div class="form-group">
              <label class="form-label" for="yaml-editor">gateway.yaml</label>
              <textarea id="yaml-editor" name="yaml" rows="28" class="form-textarea" spellcheck="false">${escapeHtml(currentYaml)}</textarea>
            </div>
            <div class="form-actions">
              <button type="button" class="btn btn-secondary"
                      hx-post="/admin/config/preview"
                      hx-target="#preview-result"
                      hx-swap="innerHTML"
                      hx-include="closest form"
                      hx-indicator="#validate-spinner">
                <span class="htmx-indicator spinner" id="validate-spinner"></span>
                Validate
              </button>
              <button type="submit" class="btn btn-primary">Save</button>
            </div>
          </form>
          <div id="preview-result" style="margin-top:1rem"></div>
        </div>`,
        { active: "config", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/config/preview", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const yaml = ((request.body as Record<string, string>).yaml ?? "").trim();

    let validationMessage: string;
    let isValid = false;
    try {
      const dir = mkdtempSync(join(tmpdir(), "mcp-preview-"));
      const tmpPath = join(dir, "gateway.yaml");
      try {
        writeFileSync(tmpPath, yaml, { encoding: "utf8", mode: 0o600 });
        loadConfig(tmpPath);
        validationMessage = "✓ Configuration is valid.";
        isValid = true;
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    } catch (error) {
      validationMessage = `✗ ${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}`;
    }

    appendAuditEvent(db, "config_preview", clientIp(request));

    const isHtmx =
      (request.headers as Record<string, string>)["hx-request"] === "true";
    if (isHtmx) {
      return reply
        .type("text/html")
        .send(
          `<div class="alert ${isValid ? "alert-success" : "alert-error"}">${validationMessage}</div>`,
        );
    }

    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    return reply.type("text/html").send(
      htmlShell(
        "Validation Result",
        `<div class="page-header"><h1 class="page-title">Validation Result</h1></div>
        <div class="alert ${isValid ? "alert-success" : "alert-error"}">${validationMessage}</div>
        <a href="/admin/config" class="btn btn-secondary btn-sm">← Back to editor</a>`,
        { active: "config", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/config", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const body = request.body as Record<string, string>;
    const yaml = (body.yaml ?? "").trim();
    const ip = clientIp(request);
    const theme = getTheme(request);

    try {
      writeConfigAtomic(configPath, yaml);
    } catch (error) {
      const session = lookupSession(db, sessionToken)!;
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlShell(
            "Save Failed",
            `<div class="page-header"><h1 class="page-title">Save Failed</h1></div>
          <div class="alert alert-error"><strong>Could not save configuration</strong>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</div>
          <a href="/admin/config" class="btn btn-secondary btn-sm">← Back to editor</a>`,
            {
              active: "config",
              csrf: session.csrfToken,
              theme,
              restartRequired,
            },
          ),
        );
    }

    appendAuditEvent(db, "config_saved", ip);
    restartRequired = true;
    options.onConfigSaved?.();

    const rotated = rotateSession(db, adminConfig, sessionToken, ip);
    if (rotated) {
      setSessionCookie(reply, rotated.sessionToken);
    }

    const newSession = rotated
      ? lookupSession(db, rotated.sessionToken)!
      : lookupSession(db, sessionToken)!;

    return reply.type("text/html").send(
      htmlShell(
        "Configuration Saved",
        `<div class="page-header"><h1 class="page-title">Configuration Saved</h1></div>
        <div class="alert alert-success">
          <strong>Saved successfully</strong>
          Configuration written atomically and backed up.
        </div>
        <div class="alert alert-warning">
          <strong>Restart required</strong>
          Restart the gateway process to apply the saved configuration.
        </div>
        <div class="btn-group">
          <a href="/admin/dashboard" class="btn btn-secondary btn-sm">Back to dashboard</a>
        </div>`,
        {
          active: "config",
          csrf: newSession?.csrfToken ?? "",
          theme,
          restartRequired,
        },
      ),
    );
  });

  // ── Server / admin settings ───────────────────────────────────────────────

  app.get("/admin/settings", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);

    const logLevelOptions = ["debug", "info", "warn", "error"]
      .map(
        (l) =>
          `<option${l === config.server.logLevel ? " selected" : ""}>${l}</option>`,
      )
      .join("");

    return reply.type("text/html").send(
      htmlShell(
        "Server Settings",
        `<div class="page-header">
          <div>
            <h1 class="page-title">Server Settings</h1>
            <div class="page-subtitle">Configure listener addresses and ports. Requires restart to take effect.</div>
          </div>
        </div>
        <form method="POST" action="/admin/settings">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <fieldset class="form-section">
            <legend>Public MCP Listener</legend>
            <div class="form-group">
              <label class="form-label" for="s-host">Bind address <code>server.host</code></label>
              <input id="s-host" name="serverHost" type="text" class="form-input" value="${escapeHtml(config.server.host)}" required style="max-width:22em">
              <div class="form-hint">Use <code>0.0.0.0</code> to accept connections from outside the container, or <code>127.0.0.1</code> for loopback only.</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="s-port">Port <code>server.port</code></label>
              <input id="s-port" name="serverPort" type="number" min="1" max="65535" class="form-input" value="${escapeHtml(String(config.server.port))}" required style="max-width:10em">
            </div>
            <div class="form-group">
              <label class="form-label" for="s-log">Log level <code>server.logLevel</code></label>
              <select id="s-log" name="serverLogLevel" class="form-select" style="max-width:12em">${logLevelOptions}</select>
            </div>
          </fieldset>
          <fieldset class="form-section">
            <legend>Admin Listener</legend>
            <div class="form-group">
              <label class="form-label" for="a-host">Bind address <code>admin.host</code></label>
              <input id="a-host" name="adminHost" type="text" class="form-input" value="${escapeHtml(adminConfig.host)}" required style="max-width:22em">
              <div class="form-hint">Use <code>0.0.0.0</code> to access the admin UI from outside the container. Default is <code>127.0.0.1</code> (loopback only).</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="a-port">Port <code>admin.port</code></label>
              <input id="a-port" name="adminPort" type="number" min="1" max="65535" class="form-input" value="${escapeHtml(String(adminConfig.port))}" required style="max-width:10em">
            </div>
            <div class="form-group">
              <label class="form-check">
                <input name="adminInsecureAllowHttpCookies" type="checkbox"${adminConfig.insecureAllowHttpCookies ? " checked" : ""} value="1">
                <span>Allow HTTP cookies <code>admin.insecureAllowHttpCookies</code> — required for non-HTTPS LAN access</span>
              </label>
            </div>
          </fieldset>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Save settings</button>
            <span class="text-muted" style="font-size:.8rem">Restart required to apply changes</span>
          </div>
        </form>`,
        { active: "settings", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/settings", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const body = request.body as Record<string, string>;
    const serverHost = (body.serverHost ?? "").trim();
    const serverPort = parseInt(body.serverPort ?? "", 10);
    const serverLogLevel = (body.serverLogLevel ?? "info").trim();
    const adminHost = (body.adminHost ?? "").trim();
    const adminPort = parseInt(body.adminPort ?? "", 10);
    const adminInsecureAllowHttpCookies =
      body.adminInsecureAllowHttpCookies === "1";
    const theme = getTheme(request);

    const VALID_LOG_LEVELS = ["debug", "info", "warn", "error"];
    if (
      !serverHost ||
      isNaN(serverPort) ||
      serverPort < 1 ||
      serverPort > 65535 ||
      !VALID_LOG_LEVELS.includes(serverLogLevel) ||
      !adminHost ||
      isNaN(adminPort) ||
      adminPort < 1 ||
      adminPort > 65535 ||
      serverPort === adminPort
    ) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlError(
            "Settings Error",
            "Invalid settings: ports must be 1–65535, must not conflict, and log level must be debug/info/warn/error.",
            "/admin/settings",
          ),
        );
    }

    let newYaml: string;
    try {
      newYaml = setServerSettingsInYaml(configPath, {
        serverHost,
        serverPort,
        serverLogLevel,
        adminHost,
        adminPort,
        adminInsecureAllowHttpCookies,
      });
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlError(
            "Settings Error",
            error instanceof Error
              ? escapeHtml(error.message)
              : "Unknown error",
            "/admin/settings",
          ),
        );
    }

    try {
      writeConfigAtomic(configPath, newYaml);
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlError(
            "Save Failed",
            error instanceof Error
              ? escapeHtml(error.message)
              : "Unknown error",
            "/admin/settings",
          ),
        );
    }

    const ip = clientIp(request);
    appendAuditEvent(db, "settings_saved", ip);
    restartRequired = true;
    options.onConfigSaved?.();

    const rotated = rotateSession(db, adminConfig, sessionToken, ip);
    if (rotated) {
      setSessionCookie(reply, rotated.sessionToken);
    }

    const newSession = rotated
      ? lookupSession(db, rotated.sessionToken)!
      : lookupSession(db, sessionToken)!;

    return reply.type("text/html").send(
      htmlShell(
        "Settings Saved",
        `<div class="page-header"><h1 class="page-title">Settings Saved</h1></div>
        <div class="alert alert-success"><strong>Settings Saved</strong>Server and admin listener settings saved successfully.</div>
        <div class="alert alert-warning"><strong>Restart required</strong>Restart the gateway to apply the new settings.</div>
        <div class="btn-group">
          <a href="/admin/dashboard" class="btn btn-secondary btn-sm">Back to dashboard</a>
        </div>`,
        {
          active: "settings",
          csrf: newSession?.csrfToken ?? "",
          theme,
          restartRequired,
        },
      ),
    );
  });

  // ── Token management ──────────────────────────────────────────────────────

  app.get("/admin/tokens", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;

    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    const tokens = listTokens(db);

    const rows = tokens
      .map((t) => {
        const status = tokenStatus(t);
        const badgeClass =
          status === "active"
            ? "badge-success"
            : status === "expired"
              ? "badge-warning"
              : "badge-muted";
        const expiryLabel = t.expiresAt
          ? new Date(t.expiresAt * 1000).toLocaleDateString("en-CA")
          : "—";
        return `<tr>
          <td class="td-mono">${t.id}</td>
          <td>${escapeHtml(t.description ?? "")}</td>
          <td class="td-mono">${escapeHtml(t.scope || "(none)")}</td>
          <td class="td-mono">${escapeHtml(t.routes === "*" ? "all routes" : t.routes)}</td>
          <td class="td-muted">${expiryLabel}</td>
          <td><span class="badge ${badgeClass}">${status}</span></td>
          <td>
            ${
              status === "active"
                ? `<form method="POST" action="/admin/tokens/${t.id}/revoke" style="display:inline">
                <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
                <button type="submit" class="btn btn-danger-outline btn-sm">Revoke</button>
              </form>`
                : ""
            }
          </td>
        </tr>`;
      })
      .join("\n");

    return reply.type("text/html").send(
      htmlShell(
        "Tokens",
        `<div class="page-header">
          <div>
            <h1 class="page-title">OAuth Tokens</h1>
            <div class="page-subtitle">Bearer tokens issued for MCP client access</div>
          </div>
          <div class="page-actions">
            <a href="/admin/tokens/new" class="btn btn-primary btn-sm">+ Issue token</a>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>ID</th><th>Description</th><th>Scope</th><th>Routes</th><th>Expires</th><th>Status</th><th>Actions</th>
            </tr></thead>
            <tbody>${rows || '<tr><td colspan="7"><div class="empty-state"><p>No tokens issued.</p><p><a href="/admin/tokens/new">Issue your first token →</a></p></div></td></tr>'}</tbody>
          </table>
        </div>`,
        { active: "tokens", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.get("/admin/tokens/new", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;

    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    const routeList = config.routes
      .map(
        (r) =>
          `<option value="${escapeHtml(r.path)}">${escapeHtml(r.path)}</option>`,
      )
      .join("\n");

    return reply.type("text/html").send(
      htmlShell(
        "Issue Token",
        `<div class="page-header">
          <div>
            <h1 class="page-title">Issue New Token</h1>
            <div class="page-subtitle">Create a Bearer token for MCP client access</div>
          </div>
        </div>
        <div class="card" style="max-width:560px">
          <form method="POST" action="/admin/tokens">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
            <div class="form-group">
              <label class="form-label" for="t-desc">Description (optional)</label>
              <input id="t-desc" name="description" type="text" class="form-input">
            </div>
            <div class="form-group">
              <label class="form-label" for="t-scope">Scope (space-separated, optional)</label>
              <input id="t-scope" name="scope" type="text" class="form-input" placeholder="read write">
            </div>
            <div class="form-group">
              <label class="form-label" for="t-routes">Routes (hold Ctrl/Cmd to select multiple; leave unselected for all routes)</label>
              <select id="t-routes" name="routes" multiple size="4" class="form-select">${routeList}</select>
            </div>
            <div class="form-group">
              <label class="form-label" for="t-exp">Expires in days (0 = no expiry)</label>
              <input id="t-exp" name="expiresInDays" type="number" min="0" value="0" class="form-input" style="max-width:10em">
            </div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary">Issue Token</button>
              <a href="/admin/tokens" class="btn btn-secondary">Cancel</a>
            </div>
          </form>
        </div>`,
        { active: "tokens", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/tokens", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    const body = request.body as Record<string, string | string[]>;
    const description =
      (body.description as string | undefined)?.trim() || undefined;
    const scope = ((body.scope as string | undefined) ?? "").trim();
    const routesRaw = body.routes;
    const routes = Array.isArray(routesRaw)
      ? routesRaw.filter(Boolean)
      : typeof routesRaw === "string" && routesRaw
        ? [routesRaw]
        : [];
    const expiresInDays = parseInt(
      (body.expiresInDays as string | undefined) ?? "0",
      10,
    );
    const expiresAt =
      expiresInDays > 0
        ? Math.floor(Date.now() / 1000) + expiresInDays * 86400
        : undefined;

    const { id, plaintext } = issueToken(db, {
      description,
      scope,
      routes,
      expiresAt,
    });
    appendAuditEvent(db, "token_issued", clientIp(request), { id });

    return reply.type("text/html").send(
      htmlShell(
        "Token Issued",
        `<div class="page-header"><h1 class="page-title">Token Issued</h1></div>
        <div class="alert alert-warning">
          <strong>Copy this token now — it will not be shown again</strong>
          This is the only time the plaintext token is displayed. Store it securely.
        </div>
        <p class="text-muted" style="font-size:.875rem"><strong>Token ID:</strong> ${id}</p>
        <div class="token-box" id="token-text">${escapeHtml(plaintext)}
          <button class="copy-btn">Copy</button>
        </div>
        <div class="btn-group">
          <a href="/admin/tokens" class="btn btn-secondary btn-sm">← Back to tokens</a>
        </div>`,
        { active: "tokens", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/tokens/:id/revoke", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const id = parseInt((request.params as Record<string, string>).id, 10);
    if (!Number.isFinite(id)) {
      return reply
        .code(400)
        .send(htmlError("Bad Request", "Invalid token ID.", "/admin/tokens"));
    }

    const revoked = revokeToken(db, id);
    if (revoked) {
      appendAuditEvent(db, "token_revoked", clientIp(request), { id });
    }

    return reply.redirect("/admin/tokens");
  });

  // ── OAuth user ────────────────────────────────────────────────────────────

  app.get("/admin/oauth-user", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    return reply.type("text/html").send(
      htmlShell(
        "OAuth User",
        `<div class="page-header">
          <div>
            <h1 class="page-title">OAuth Resource-Owner Password</h1>
            <div class="page-subtitle">Separate from the LAN administration password. Used for OAuth authorization flows.</div>
          </div>
        </div>
        <div class="card" style="max-width:480px">
          <form method="POST" action="/admin/oauth-user">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
            <div class="form-group">
              <label class="form-label" for="ou-pw">New password</label>
              <input id="ou-pw" type="password" name="password" class="form-input" required minlength="12">
              <div class="form-hint">Minimum 12 characters</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="ou-confirm">Confirm password</label>
              <input id="ou-confirm" type="password" name="confirm" class="form-input" required minlength="12">
            </div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary">Set OAuth password</button>
            </div>
          </form>
        </div>`,
        {
          active: "oauth-user",
          csrf: session.csrfToken,
          theme,
          restartRequired,
        },
      ),
    );
  });

  app.post("/admin/oauth-user", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;
    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);
    const body = request.body as Record<string, string | undefined>;
    if (
      !body.password ||
      body.password.length < 12 ||
      body.password !== body.confirm
    ) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlShell(
            "OAuth User",
            `<div class="page-header"><h1 class="page-title">OAuth Resource-Owner Password</h1></div>
          <div class="alert alert-error">Password must match and contain at least 12 characters.</div>
          <a href="/admin/oauth-user" class="btn btn-secondary btn-sm">← Try again</a>`,
            {
              active: "oauth-user",
              csrf: session.csrfToken,
              theme,
              restartRequired,
            },
          ),
        );
    }
    await setOAuthUserPassword(db, body.password);
    appendAuditEvent(db, "oauth_user_password_changed", clientIp(request));
    return reply.type("text/html").send(
      htmlShell(
        "OAuth User",
        `<div class="page-header"><h1 class="page-title">OAuth Resource-Owner Password</h1></div>
        <div class="alert alert-success"><strong>Password updated</strong>OAuth resource-owner password updated successfully.</div>
        <a href="/admin/dashboard" class="btn btn-secondary btn-sm">Back to dashboard</a>`,
        {
          active: "oauth-user",
          csrf: session.csrfToken,
          theme,
          restartRequired,
        },
      ),
    );
  });

  // ── Route management ──────────────────────────────────────────────────────

  app.get("/admin/routes", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);

    const rows = config.routes
      .map((r) => {
        const cachedTools = getCachedTools(db, r.path);
        const allowlistCount = r.tools?.allowlist?.length ?? 0;
        const toolsLabel =
          cachedTools.length > 0
            ? `${allowlistCount > 0 ? allowlistCount + " allowlisted / " : ""}${cachedTools.length} discovered`
            : '<span class="text-muted">Not discovered</span>';
        return `<tr>
          <td class="td-mono">${escapeHtml(r.path)}</td>
          <td class="td-mono td-muted">${escapeHtml(r.upstream)}</td>
          <td>${toolsLabel}</td>
          <td>
            <div class="btn-group">
              <a href="/admin/routes${encodeURIComponent(r.path)}/tools" class="btn btn-secondary btn-sm">Manage tools</a>
              <form method="POST" action="/admin/routes${encodeURIComponent(r.path)}/delete" style="display:inline">
                <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
                <button type="submit" class="btn btn-danger-outline btn-sm"
                        data-confirm="Delete route ${escapeHtml(r.path)}?">Delete</button>
              </form>
            </div>
          </td>
        </tr>`;
      })
      .join("\n");

    return reply.type("text/html").send(
      htmlShell(
        "Routes",
        `<div class="page-header">
          <div>
            <h1 class="page-title">MCP Backend Routes</h1>
            <div class="page-subtitle">Path-based proxying to local MCP servers</div>
          </div>
          <div class="page-actions">
            <a href="/admin/routes/new" class="btn btn-primary btn-sm">+ Add route</a>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Path</th><th>Upstream</th><th>Tools</th><th>Actions</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="4"><div class="empty-state"><p>No routes configured.</p><p><a href="/admin/routes/new">Add your first route →</a></p></div></td></tr>'}</tbody>
          </table>
        </div>`,
        { active: "routes", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.get("/admin/routes/new", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);

    return reply.type("text/html").send(
      htmlShell(
        "Add Route",
        `<div class="page-header">
          <div>
            <h1 class="page-title">Add MCP Backend Route</h1>
            <div class="page-subtitle">Register a new upstream MCP server</div>
          </div>
        </div>
        <div class="card" style="max-width:600px">
          <form method="POST" action="/admin/routes">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
            <div class="form-group">
              <label class="form-label" for="r-path">Path prefix</label>
              <input id="r-path" name="path" type="text" class="form-input" required pattern="^/[^/].*" placeholder="/unraid">
              <div class="form-hint">Must start with <code>/</code> and not end with <code>/mcp</code>, <code>/sse</code>, or <code>/messages</code>.</div>
            </div>
            <div class="form-group">
              <label class="form-label" for="r-upstream">Upstream base URL</label>
              <input id="r-upstream" name="upstream" type="text" class="form-input" required placeholder="http://host.local:8043">
              <div class="form-hint">Base URL only — do not include <code>/mcp</code>, <code>/sse</code>, or <code>/messages</code> suffix.</div>
            </div>
            <fieldset class="form-section">
              <legend>Upstream Authentication (optional)</legend>
              <div class="form-group">
                <label class="form-label" for="r-auth-type">Auth type</label>
                <select id="r-auth-type" name="authType" class="form-select" style="max-width:20em">
                  <option value="">None</option>
                  <option value="bearer">Bearer token (env var)</option>
                  <option value="header">Custom header (env var)</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label" for="r-auth-env">Env var name holding the token/secret</label>
                <input id="r-auth-env" name="authEnv" type="text" class="form-input" placeholder="MY_UPSTREAM_TOKEN" style="max-width:22em">
              </div>
              <div class="form-group">
                <label class="form-label" for="r-auth-header">Header name (for custom header type only)</label>
                <input id="r-auth-header" name="authHeader" type="text" class="form-input" placeholder="X-Api-Key" style="max-width:18em">
              </div>
            </fieldset>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary">Add route</button>
              <a href="/admin/routes" class="btn btn-secondary">Cancel</a>
            </div>
          </form>
        </div>`,
        { active: "routes", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/routes", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const session = lookupSession(db, sessionToken)!;
    const body = request.body as Record<string, string>;
    const path = (body.path ?? "").trim();
    const upstream = (body.upstream ?? "").trim();
    const authType = (body.authType ?? "").trim();
    const authEnv = (body.authEnv ?? "").trim();
    const authHeader = (body.authHeader ?? "").trim();
    const theme = getTheme(request);

    if (!path || !upstream) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlShell(
            "Add Route",
            `<div class="page-header"><h1 class="page-title">Add MCP Backend Route</h1></div>
          <div class="alert alert-error">Path and upstream are required.</div>
          <a href="/admin/routes/new" class="btn btn-secondary btn-sm">← Back</a>`,
            {
              active: "routes",
              csrf: session.csrfToken,
              theme,
              restartRequired,
            },
          ),
        );
    }

    let newYaml: string;
    try {
      newYaml = addRouteToYaml(
        configPath,
        path,
        upstream,
        authType,
        authEnv,
        authHeader,
      );
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlShell(
            "Add Route Failed",
            `<div class="page-header"><h1 class="page-title">Add Route Failed</h1></div>
          <div class="alert alert-error">${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</div>
          <a href="/admin/routes/new" class="btn btn-secondary btn-sm">← Back</a>`,
            {
              active: "routes",
              csrf: session.csrfToken,
              theme,
              restartRequired,
            },
          ),
        );
    }

    try {
      writeConfigAtomic(configPath, newYaml);
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlShell(
            "Save Failed",
            `<div class="page-header"><h1 class="page-title">Save Failed</h1></div>
          <div class="alert alert-error">${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</div>
          <a href="/admin/routes/new" class="btn btn-secondary btn-sm">← Back</a>`,
            {
              active: "routes",
              csrf: session.csrfToken,
              theme,
              restartRequired,
            },
          ),
        );
    }

    appendAuditEvent(db, "route_added", clientIp(request), { path });
    restartRequired = true;
    options.onConfigSaved?.();

    const upstreamDispatcher = createUpstreamDispatcher(config.security);
    const discovery = await discoverTools(upstream, upstreamDispatcher);
    await upstreamDispatcher.close();

    if (discovery.tools.length > 0) {
      upsertCachedTools(db, path, discovery.tools);
      return reply.redirect(`/admin/routes${encodeURIComponent(path)}/tools`);
    }

    return reply.type("text/html").send(
      htmlShell(
        "Route Added",
        `<div class="page-header"><h1 class="page-title">Route Added</h1></div>
        <div class="alert alert-success">
          <strong>Route saved</strong>
          <code>${escapeHtml(path)}</code> → <code>${escapeHtml(upstream)}</code>
        </div>
        ${discovery.error ? `<div class="alert alert-warning"><strong>Tool discovery failed</strong>${escapeHtml(discovery.error)}. You can retry from the tools page.</div>` : '<div class="alert alert-info">No tools discovered.</div>'}
        <div class="alert alert-warning"><strong>Restart required</strong>Restart the gateway to activate the new route.</div>
        <a href="/admin/routes" class="btn btn-secondary btn-sm">← Back to routes</a>`,
        { active: "routes", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/routes:encodedPath/delete", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const encodedPath =
      (request.params as Record<string, string>).encodedPath ?? "";
    const routePath = decodeURIComponent(encodedPath);

    let newYaml: string;
    try {
      newYaml = removeRouteFromYaml(configPath, routePath);
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlError(
            "Delete Failed",
            error instanceof Error
              ? escapeHtml(error.message)
              : "Unknown error",
            "/admin/routes",
          ),
        );
    }

    try {
      writeConfigAtomic(configPath, newYaml);
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlError(
            "Delete Failed",
            error instanceof Error
              ? escapeHtml(error.message)
              : "Unknown error",
            "/admin/routes",
          ),
        );
    }

    clearCachedTools(db, routePath);
    appendAuditEvent(db, "route_deleted", clientIp(request), {
      path: routePath,
    });
    restartRequired = true;
    options.onConfigSaved?.();

    return reply.redirect("/admin/routes");
  });

  // ── Tool allowlist management ─────────────────────────────────────────────

  app.get("/admin/routes:encodedPath/tools", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;
    const theme = getTheme(request);

    const encodedPath =
      (request.params as Record<string, string>).encodedPath ?? "";
    const routePath = decodeURIComponent(encodedPath);
    const route = config.routes.find((r) => r.path === routePath);
    if (!route) {
      return reply
        .code(404)
        .type("text/html")
        .send(
          htmlError(
            "Not Found",
            `Route <code>${escapeHtml(routePath)}</code> not found. It may have been added after the last restart.`,
            "/admin/routes",
          ),
        );
    }

    const cachedTools = getCachedTools(db, routePath);
    const currentAllowlist = new Set(
      getAllowlistFromYaml(configPath, routePath),
    );
    const DANGEROUS = new Set([
      "shell",
      "exec",
      "write",
      "delete",
      "restart",
      "stop",
      "start",
      "reboot",
      "shutdown",
      "update",
      "install",
    ]);
    const isDangerous = (name: string) =>
      DANGEROUS.has(name.toLowerCase()) ||
      [...DANGEROUS].some((kw) => name.toLowerCase().includes(kw));

    let toolsContent: string;
    if (cachedTools.length === 0) {
      toolsContent = `<div class="empty-state">
        <p>No tools discovered yet.</p>
        <p>Click "Refresh tools" to query the upstream MCP server.</p>
      </div>`;
    } else {
      const toolRows = cachedTools
        .map((t) => {
          const dangerous = isDangerous(t.name);
          const checked =
            currentAllowlist.size > 0
              ? currentAllowlist.has(t.name)
              : !dangerous;
          return `<tr>
            <td style="width:3rem;text-align:center">
              <input type="checkbox" name="tool" value="${escapeHtml(t.name)}"${checked ? " checked" : ""} style="accent-color:var(--accent)">
            </td>
            <td class="td-mono">${escapeHtml(t.name)}${dangerous ? ' <span class="badge badge-danger">dangerous</span>' : ""}</td>
            <td class="td-muted">${escapeHtml(t.description ?? "")}</td>
          </tr>`;
        })
        .join("\n");

      toolsContent = `<div id="tools-table">
        <form method="POST" action="/admin/routes${encodeURIComponent(routePath)}/tools">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <div class="table-wrap" style="margin-bottom:1rem">
            <table>
              <thead><tr><th style="width:3rem">Allow</th><th>Tool</th><th>Description</th></tr></thead>
              <tbody>${toolRows}</tbody>
            </table>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Save allowlist</button>
            <a href="/admin/routes" class="btn btn-secondary">Cancel</a>
          </div>
        </form>
      </div>`;
    }

    return reply.type("text/html").send(
      htmlShell(
        `Tools: ${routePath}`,
        `<div class="page-header">
          <div>
            <h1 class="page-title">Tool Allowlist</h1>
            <div class="page-subtitle"><code>${escapeHtml(routePath)}</code> — checked tools are allowed; unchecked are blocked</div>
          </div>
          <div class="page-actions">
            <form method="POST" action="/admin/routes${encodeURIComponent(routePath)}/discover"
                  hx-post="/admin/routes${encodeURIComponent(routePath)}/discover"
                  hx-target="#tools-table"
                  hx-swap="outerHTML"
                  hx-indicator="#discover-spinner">
              <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
              <button type="submit" class="btn btn-secondary btn-sm">
                <span class="htmx-indicator spinner" id="discover-spinner"></span>
                ↺ Refresh tools
              </button>
            </form>
          </div>
        </div>
        ${toolsContent}`,
        { active: "routes", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  app.post("/admin/routes:encodedPath/tools", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const encodedPath =
      (request.params as Record<string, string>).encodedPath ?? "";
    const routePath = decodeURIComponent(encodedPath);
    const theme = getTheme(request);

    const body = request.body as Record<string, string | string[]>;
    const selected = body.tool;
    const allowlist = Array.isArray(selected)
      ? selected
      : typeof selected === "string"
        ? [selected]
        : [];

    let newYaml: string;
    try {
      newYaml = setRouteAllowlistInYaml(configPath, routePath, allowlist);
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlError(
            "Save Failed",
            error instanceof Error
              ? escapeHtml(error.message)
              : "Unknown error",
            `/admin/routes${encodeURIComponent(routePath)}/tools`,
          ),
        );
    }

    try {
      writeConfigAtomic(configPath, newYaml);
    } catch (error) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlError(
            "Save Failed",
            error instanceof Error
              ? escapeHtml(error.message)
              : "Unknown error",
            `/admin/routes${encodeURIComponent(routePath)}/tools`,
          ),
        );
    }

    appendAuditEvent(db, "route_allowlist_saved", clientIp(request), {
      path: routePath,
      count: allowlist.length,
    });
    restartRequired = true;
    options.onConfigSaved?.();

    const session = lookupSession(db, sessionToken)!;

    return reply.type("text/html").send(
      htmlShell(
        "Allowlist Saved",
        `<div class="page-header"><h1 class="page-title">Allowlist Saved</h1></div>
        <div class="alert alert-success">
          <strong>${allowlist.length} tool(s) allowlisted</strong>
          Allowlist for <code>${escapeHtml(routePath)}</code> saved.
        </div>
        <div class="alert alert-warning"><strong>Restart required</strong>Restart the gateway to apply the allowlist.</div>
        <a href="/admin/routes" class="btn btn-secondary btn-sm">← Back to routes</a>`,
        { active: "routes", csrf: session.csrfToken, theme, restartRequired },
      ),
    );
  });

  // Tool discovery — HTMX endpoint: returns tools-table fragment or full page
  app.post("/admin/routes:encodedPath/discover", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const session = lookupSession(db, sessionToken)!;
    const encodedPath =
      (request.params as Record<string, string>).encodedPath ?? "";
    const routePath = decodeURIComponent(encodedPath);
    const route = config.routes.find((r) => r.path === routePath);

    if (!route) {
      return reply
        .code(404)
        .type("text/html")
        .send(
          htmlError(
            "Not Found",
            `Route <code>${escapeHtml(routePath)}</code> not found. Restart the gateway after adding routes.`,
            "/admin/routes",
          ),
        );
    }

    const upstreamDispatcher = createUpstreamDispatcher(config.security);
    const result = await discoverTools(route.upstream, upstreamDispatcher);
    await upstreamDispatcher.close();

    if (result.tools.length > 0) {
      upsertCachedTools(db, routePath, result.tools);
    }

    const isHtmx =
      (request.headers as Record<string, string>)["hx-request"] === "true";

    if (isHtmx) {
      const cachedTools = getCachedTools(db, routePath);
      const currentAllowlist = new Set(
        getAllowlistFromYaml(configPath, routePath),
      );
      const DANGEROUS = new Set([
        "shell",
        "exec",
        "write",
        "delete",
        "restart",
        "stop",
        "start",
        "reboot",
        "shutdown",
        "update",
        "install",
      ]);
      const isDangerous = (name: string) =>
        DANGEROUS.has(name.toLowerCase()) ||
        [...DANGEROUS].some((kw) => name.toLowerCase().includes(kw));

      if (cachedTools.length === 0) {
        return reply
          .type("text/html")
          .send(
            `<div id="tools-table"><div class="alert alert-warning">${result.error ? escapeHtml(result.error) : "No tools discovered."}</div></div>`,
          );
      }

      const toolRows = cachedTools
        .map((t) => {
          const dangerous = isDangerous(t.name);
          const checked =
            currentAllowlist.size > 0
              ? currentAllowlist.has(t.name)
              : !dangerous;
          return `<tr>
            <td style="width:3rem;text-align:center">
              <input type="checkbox" name="tool" value="${escapeHtml(t.name)}"${checked ? " checked" : ""} style="accent-color:var(--accent)">
            </td>
            <td class="td-mono">${escapeHtml(t.name)}${dangerous ? ' <span class="badge badge-danger">dangerous</span>' : ""}</td>
            <td class="td-muted">${escapeHtml(t.description ?? "")}</td>
          </tr>`;
        })
        .join("\n");

      return reply.type("text/html").send(
        `<div id="tools-table">
          <form method="POST" action="/admin/routes${encodeURIComponent(routePath)}/tools">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
            <div class="table-wrap" style="margin-bottom:1rem">
              <table>
                <thead><tr><th style="width:3rem">Allow</th><th>Tool</th><th>Description</th></tr></thead>
                <tbody>${toolRows}</tbody>
              </table>
            </div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary">Save allowlist</button>
              <a href="/admin/routes" class="btn btn-secondary">Cancel</a>
            </div>
          </form>
        </div>`,
      );
    }

    return reply.redirect(
      `/admin/routes${encodeURIComponent(routePath)}/tools`,
    );
  });

  // ── Restart ───────────────────────────────────────────────────────────────

  app.post("/admin/restart", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const theme = getTheme(request);
    // Send the response first, then exit after a short delay
    void reply.type("text/html").send(
      htmlAuth(
        "Restarting",
        `<div class="auth-logo">MCP Gateway</div>
        <h2 class="auth-title">Gateway Restarting…</h2>
        <p class="auth-subtitle">The gateway is restarting. This page will redirect automatically when it comes back online.</p>
        <div style="text-align:center;margin:1.5rem 0"><div class="spinner" style="width:2em;height:2em;border-width:3px"></div></div>
        <div id="status" hx-get="/admin/health" hx-trigger="every 2s" hx-swap="none"></div>`,
        theme,
        `<script src="/admin/static/htmx.min.js"></script>
<script src="/admin/static/admin.js"></script>`,
      ),
    );
    setTimeout(() => process.exit(0), 500);
  });

  // ── Health ────────────────────────────────────────────────────────────────

  app.get("/admin/health", async () => ({ status: "ok" }));

  // ── Periodic cleanup ──────────────────────────────────────────────────────

  const cleanupInterval = setInterval(() => {
    pruneExpiredSessions(db);
    pruneLoginAttempts(db);
  }, 3_600_000);
  cleanupInterval.unref();

  app.addHook("onClose", async () => {
    clearInterval(cleanupInterval);
  });

  return app;
}

// ── Route YAML manipulation ───────────────────────────────────────────────────

function readParsedYaml(configPath: string): Record<string, unknown> {
  const raw: unknown = yamlParse(readFileSync(configPath, "utf8"));
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("gateway.yaml does not contain a YAML object");
  }
  return raw as Record<string, unknown>;
}

function addRouteToYaml(
  configPath: string,
  path: string,
  upstream: string,
  authType: string,
  authEnv: string,
  authHeaderName: string,
): string {
  const doc = readParsedYaml(configPath);
  const routes = Array.isArray(doc.routes) ? [...doc.routes] : [];

  if (
    routes.some(
      (r) =>
        typeof r === "object" &&
        r !== null &&
        (r as Record<string, unknown>).path === path,
    )
  ) {
    throw new Error(`Route ${path} already exists`);
  }

  const entry: Record<string, unknown> = { path, upstream };
  if (authType === "bearer" && authEnv) {
    entry.upstreamAuth = { type: "bearer", tokenEnv: authEnv };
  } else if (authType === "header" && authEnv && authHeaderName) {
    entry.upstreamAuth = {
      type: "header",
      headerName: authHeaderName,
      secretEnv: authEnv,
    };
  }

  doc.routes = [...routes, entry];
  return yamlStringify(doc, { lineWidth: 0 });
}

function removeRouteFromYaml(configPath: string, routePath: string): string {
  const doc = readParsedYaml(configPath);
  if (!Array.isArray(doc.routes)) {
    throw new Error("No routes in gateway.yaml");
  }
  const filtered = doc.routes.filter(
    (r) =>
      !(
        typeof r === "object" &&
        r !== null &&
        (r as Record<string, unknown>).path === routePath
      ),
  );
  if (filtered.length === doc.routes.length) {
    throw new Error(`Route ${routePath} not found in gateway.yaml`);
  }
  if (filtered.length === 0) {
    throw new Error("Cannot delete the last route");
  }
  doc.routes = filtered;
  return yamlStringify(doc, { lineWidth: 0 });
}

function setRouteAllowlistInYaml(
  configPath: string,
  routePath: string,
  allowlist: string[],
): string {
  const doc = readParsedYaml(configPath);
  if (!Array.isArray(doc.routes)) {
    throw new Error("No routes in gateway.yaml");
  }
  doc.routes = doc.routes.map((r) => {
    if (
      typeof r !== "object" ||
      r === null ||
      (r as Record<string, unknown>).path !== routePath
    ) {
      return r;
    }
    const route = r as Record<string, unknown>;
    const tools = (
      typeof route.tools === "object" && route.tools !== null
        ? { ...(route.tools as Record<string, unknown>) }
        : {}
    ) as Record<string, unknown>;
    if (allowlist.length > 0) {
      tools.allowlist = allowlist;
    } else {
      delete tools.allowlist;
    }
    return {
      ...route,
      tools: Object.keys(tools).length > 0 ? tools : undefined,
    };
  });
  return yamlStringify(doc, { lineWidth: 0 });
}

function getAllowlistFromYaml(configPath: string, routePath: string): string[] {
  try {
    const doc = readParsedYaml(configPath);
    if (!Array.isArray(doc.routes)) return [];
    const route = doc.routes.find(
      (r) =>
        typeof r === "object" &&
        r !== null &&
        (r as Record<string, unknown>).path === routePath,
    ) as Record<string, unknown> | undefined;
    if (!route) return [];
    const tools = route.tools;
    if (typeof tools !== "object" || tools === null) return [];
    const allowlist = (tools as Record<string, unknown>).allowlist;
    return Array.isArray(allowlist)
      ? allowlist.filter((x): x is string => typeof x === "string")
      : [];
  } catch {
    return [];
  }
}

function setServerSettingsInYaml(
  configPath: string,
  settings: {
    serverHost: string;
    serverPort: number;
    serverLogLevel: string;
    adminHost: string;
    adminPort: number;
    adminInsecureAllowHttpCookies: boolean;
  },
): string {
  const doc = readParsedYaml(configPath);

  if (typeof doc.server !== "object" || doc.server === null) {
    doc.server = {};
  }
  const server = doc.server as Record<string, unknown>;
  server.host = settings.serverHost;
  server.port = settings.serverPort;
  server.logLevel = settings.serverLogLevel;

  if (typeof doc.admin !== "object" || doc.admin === null) {
    doc.admin = {};
  }
  const admin = doc.admin as Record<string, unknown>;
  admin.host = settings.adminHost;
  admin.port = settings.adminPort;
  if (settings.adminInsecureAllowHttpCookies) {
    admin.insecureAllowHttpCookies = true;
  } else {
    delete admin.insecureAllowHttpCookies;
  }

  return yamlStringify(doc, { lineWidth: 0 });
}

// ── Route tool cache (DB) ─────────────────────────────────────────────────────

interface CachedTool {
  name: string;
  description?: string;
}

function getCachedTools(db: DatabaseSync, routePath: string): CachedTool[] {
  return (
    db
      .prepare(
        "SELECT tool_name, description FROM route_tool_cache WHERE route_path = ? ORDER BY tool_name",
      )
      .all(routePath) as Array<{
      tool_name: string;
      description: string | null;
    }>
  ).map((r) => ({
    name: r.tool_name,
    description: r.description ?? undefined,
  }));
}

function upsertCachedTools(
  db: DatabaseSync,
  routePath: string,
  tools: CachedTool[],
): void {
  db.exec("BEGIN");
  try {
    db.prepare("DELETE FROM route_tool_cache WHERE route_path = ?").run(
      routePath,
    );
    const insert = db.prepare(
      "INSERT INTO route_tool_cache (route_path, tool_name, description) VALUES (?, ?, ?)",
    );
    for (const tool of tools) {
      insert.run(routePath, tool.name, tool.description ?? null);
    }
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

function clearCachedTools(db: DatabaseSync, routePath: string): void {
  db.prepare("DELETE FROM route_tool_cache WHERE route_path = ?").run(
    routePath,
  );
}

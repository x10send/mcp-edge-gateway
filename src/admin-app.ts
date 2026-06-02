import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const APP_VERSION = (
  JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  ) as { version: string }
).version;
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
const CSRF_FIELD = "_csrf";
// 64 KB limit for config form body (YAML is small; this is generous headroom)
const ADMIN_BODY_LIMIT = 65_536;

export interface BuildAdminAppOptions {
  db: DatabaseSync;
  config: GatewayConfig;
  configPath: string;
  onConfigSaved?: () => void;
}

export function buildAdminApp(options: BuildAdminAppOptions) {
  const { db, config, configPath } = options;
  const adminConfig = config.admin;

  const app = Fastify({
    bodyLimit: ADMIN_BODY_LIMIT,
    logger: {
      level: config.server.logLevel,
      redact: {
        paths: ["req.headers.cookie", "req.body.password", "req.body.token"],
        censor: "[REDACTED]",
      },
    },
  });

  void app.register(fastifyCookie);
  void app.register(fastifyFormbody);

  // Security headers on every response
  app.addHook("onSend", async (_req, reply) => {
    reply.header("X-Frame-Options", "DENY");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self' 'unsafe-inline'",
    );
    reply.header("Cache-Control", "no-store");
  });

  // ── Auth helpers ──────────────────────────────────────────────────────────

  function getSessionToken(request: FastifyRequest): string | undefined {
    return request.cookies[COOKIE_NAME];
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
      reply.code(403).send(htmlPage("Forbidden", "<p>Session expired.</p>"));
      return false;
    }
    const submitted = (request.body as Record<string, string>)[CSRF_FIELD];
    if (!submitted || submitted !== session.csrfToken) {
      reply.code(403).send(htmlPage("Forbidden", "<p>Invalid CSRF token.</p>"));
      return false;
    }
    return true;
  }

  function clientIp(request: FastifyRequest): string {
    return request.ip ?? "unknown";
  }

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
    return reply.type("text/html").send(
      htmlPage(
        "First-Run Setup",
        `<form method="POST" action="/admin/setup">
          <h2>Gateway Administration Setup</h2>
          <p>Enter the bootstrap token printed to the gateway logs, then choose a password.</p>
          <label>Bootstrap token<br>
            <input name="token" type="password" required autocomplete="off">
          </label><br><br>
          <label>New password<br>
            <input name="password" type="password" required minlength="12">
          </label><br><br>
          <label>Confirm password<br>
            <input name="confirm" type="password" required minlength="12">
          </label><br><br>
          <button type="submit">Complete Setup</button>
        </form>`,
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

    if (isLoginRateLimited(db, adminConfig, ip)) {
      appendAuditEvent(db, "login_locked", ip);
      return reply
        .code(429)
        .type("text/html")
        .send(
          htmlPage(
            "Too Many Attempts",
            "<p>Too many attempts. Try again later.</p>",
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
        .send(htmlPage("Setup Failed", "<p>Invalid bootstrap token.</p>"));
    }

    if (password.length < 12) {
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlPage(
            "Setup Failed",
            "<p>Password must be at least 12 characters.</p>",
          ),
        );
    }

    if (password !== confirm) {
      return reply
        .code(400)
        .type("text/html")
        .send(htmlPage("Setup Failed", "<p>Passwords do not match.</p>"));
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
    return reply.type("text/html").send(
      htmlPage(
        "Login",
        `<form method="POST" action="/admin/login">
          <h2>Gateway Administration</h2>
          <label>Password<br>
            <input name="password" type="password" required autocomplete="current-password">
          </label><br><br>
          <button type="submit">Log in</button>
        </form>`,
      ),
    );
  });

  app.post("/admin/login", async (request, reply) => {
    const ip = clientIp(request);
    const body = request.body as Record<string, string>;
    const password = body.password ?? "";

    if (isLoginRateLimited(db, adminConfig, ip)) {
      appendAuditEvent(db, "login_locked", ip);
      return reply
        .code(429)
        .type("text/html")
        .send(
          htmlPage(
            "Too Many Attempts",
            "<p>Too many attempts. Try again later.</p>",
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
          htmlPage(
            "Login Failed",
            `<p>Incorrect password. <a href="/admin/login">Try again</a></p>`,
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
    const routeList = config.routes
      .map(
        (r) =>
          `<li><code>${escapeHtml(r.path)}</code> → <code>${escapeHtml(r.upstream)}</code></li>`,
      )
      .join("\n");

    return reply.type("text/html").send(
      htmlPage(
        "Dashboard",
        `<h2>Gateway Administration</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <h3>Active Routes</h3>
        <ul>${routeList}</ul>
        <h3>Admin Listener</h3>
        <p>Port: ${escapeHtml(String(adminConfig.port))} | Host: ${escapeHtml(adminConfig.host)}</p>`,
      ),
    );
  });

  // ── Config editor ─────────────────────────────────────────────────────────

  app.get("/admin/config", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;

    const session = lookupSession(db, sessionToken)!;
    let currentYaml = "# Could not read current config";
    try {
      currentYaml = readFileSync(configPath, "utf8");
    } catch {
      // keep fallback
    }

    return reply.type("text/html").send(
      htmlPage(
        "Edit Configuration",
        `<h2>Edit Configuration</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <form method="POST" action="/admin/config/preview">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <label>gateway.yaml<br>
            <textarea name="yaml" rows="30" cols="80" spellcheck="false">${escapeHtml(currentYaml)}</textarea>
          </label><br><br>
          <button type="submit" name="action" value="preview">Validate</button>
          &nbsp;
          <button type="submit" name="action" value="save" formaction="/admin/config">Save</button>
        </form>`,
      ),
    );
  });

  app.post("/admin/config/preview", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const session = lookupSession(db, sessionToken)!;
    const yaml = ((request.body as Record<string, string>).yaml ?? "").trim();

    let validationMessage: string;
    try {
      const dir = mkdtempSync(join(tmpdir(), "mcp-preview-"));
      const tmpPath = join(dir, "gateway.yaml");
      try {
        writeFileSync(tmpPath, yaml, { encoding: "utf8", mode: 0o600 });
        loadConfig(tmpPath);
        validationMessage = "✓ Configuration is valid.";
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    } catch (error) {
      validationMessage = `✗ ${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}`;
    }

    appendAuditEvent(db, "config_preview", clientIp(request));

    return reply.type("text/html").send(
      htmlPage(
        "Validation Result",
        `<h2>Validation Result</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <pre>${validationMessage}</pre>
        <a href="/admin/config">← Back to editor</a>`,
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

    try {
      writeConfigAtomic(configPath, yaml);
    } catch (error) {
      const session = lookupSession(db, sessionToken)!;
      return reply
        .code(400)
        .type("text/html")
        .send(
          htmlPage(
            "Save Failed",
            `<h2>Save Failed</h2>
          <nav>${navLinks(session.csrfToken)}</nav>
          <pre>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</pre>
          <a href="/admin/config">← Back to editor</a>`,
          ),
        );
    }

    appendAuditEvent(db, "config_saved", ip);
    options.onConfigSaved?.();

    // Rotate session on successful save
    const rotated = rotateSession(db, adminConfig, sessionToken, ip);
    if (rotated) {
      setSessionCookie(reply, rotated.sessionToken);
    }

    return reply.type("text/html").send(
      htmlPage(
        "Configuration Saved",
        `<h2>Configuration Saved</h2>
        <p>The validated configuration was written atomically and backed up.</p>
        <p><strong>Restart required:</strong> restart the gateway process to apply the saved configuration.</p>
        <a href="/admin/dashboard">Back to dashboard</a>`,
      ),
    );
  });

  // ── Server / admin settings ───────────────────────────────────────────────

  app.get("/admin/settings", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;

    const logLevelOptions = ["debug", "info", "warn", "error"]
      .map(
        (l) =>
          `<option${l === config.server.logLevel ? " selected" : ""}>${l}</option>`,
      )
      .join("");

    return reply.type("text/html").send(
      htmlPage(
        "Server Settings",
        `<h2>Server Settings</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <form method="POST" action="/admin/settings">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <fieldset><legend>Public MCP Listener</legend>
            <label>Bind address (server.host)<br>
              <input name="serverHost" type="text" value="${escapeHtml(config.server.host)}" required style="width:20em">
            </label>
            <small>Use <code>0.0.0.0</code> to accept connections from outside the container, or <code>127.0.0.1</code> for loopback only.</small><br><br>
            <label>Port (server.port)<br>
              <input name="serverPort" type="number" min="1" max="65535" value="${escapeHtml(String(config.server.port))}" required style="width:8em">
            </label><br><br>
            <label>Log level (server.logLevel)<br>
              <select name="serverLogLevel">${logLevelOptions}</select>
            </label>
          </fieldset><br>
          <fieldset><legend>Admin Listener</legend>
            <label>Bind address (admin.host)<br>
              <input name="adminHost" type="text" value="${escapeHtml(config.admin.host)}" required style="width:20em">
            </label>
            <small>Use <code>0.0.0.0</code> to access the admin UI from outside the container. Default is <code>127.0.0.1</code> (loopback only).</small><br><br>
            <label>Port (admin.port)<br>
              <input name="adminPort" type="number" min="1" max="65535" value="${escapeHtml(String(config.admin.port))}" required style="width:8em">
            </label><br><br>
            <label>
              <input name="adminInsecureAllowHttpCookies" type="checkbox"${config.admin.insecureAllowHttpCookies ? " checked" : ""} value="1">
              Allow HTTP cookies (admin.insecureAllowHttpCookies) — required for non-HTTPS LAN access
            </label>
          </fieldset><br>
          <button type="submit">Save settings</button>
          &nbsp;<small>A gateway restart is required for changes to take effect.</small>
        </form>`,
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
          htmlPage(
            "Settings Error",
            `<p>Invalid settings: ports must be 1–65535, must not conflict, and log level must be debug/info/warn/error.</p><a href="/admin/settings">← Back</a>`,
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
          htmlPage(
            "Settings Error",
            `<p>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</p>
            <a href="/admin/settings">← Back</a>`,
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
          htmlPage(
            "Save Failed",
            `<pre>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</pre>
            <a href="/admin/settings">← Back</a>`,
          ),
        );
    }

    const ip = clientIp(request);
    appendAuditEvent(db, "settings_saved", ip);
    options.onConfigSaved?.();

    const rotated = rotateSession(db, adminConfig, sessionToken, ip);
    if (rotated) {
      setSessionCookie(reply, rotated.sessionToken);
    }

    return reply.type("text/html").send(
      htmlPage(
        "Settings Saved",
        `<h2>Settings Saved</h2>
        <p>Server and admin listener settings saved successfully.</p>
        <p><strong>Restart required</strong> to apply the new settings.</p>
        <a href="/admin/dashboard">Back to dashboard</a>`,
      ),
    );
  });

  // ── Token management ──────────────────────────────────────────────────────

  app.get("/admin/tokens", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;

    const session = lookupSession(db, sessionToken)!;
    const tokens = listTokens(db);
    const rows = tokens
      .map((t) => {
        const status = tokenStatus(t);
        const statusLabel =
          status === "active"
            ? "active"
            : status === "expired"
              ? "expired"
              : "revoked";
        return `<tr>
          <td>${t.id}</td>
          <td>${escapeHtml(t.description ?? "")}</td>
          <td><code>${escapeHtml(t.scope || "(none)")}</code></td>
          <td>${escapeHtml(t.routes === "*" ? "all routes" : t.routes)}</td>
          <td>${statusLabel}</td>
          <td>
            ${
              status === "active"
                ? `<form method="POST" action="/admin/tokens/${t.id}/revoke" style="display:inline">
                <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
                <button type="submit">Revoke</button>
              </form>`
                : ""
            }
          </td>
        </tr>`;
      })
      .join("\n");

    return reply.type("text/html").send(
      htmlPage(
        "Tokens",
        `<h2>OAuth Tokens</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <p><a href="/admin/tokens/new">+ Issue new token</a></p>
        <table border="1" cellpadding="4" style="border-collapse:collapse;width:100%">
          <thead><tr>
            <th>ID</th><th>Description</th><th>Scope</th><th>Routes</th><th>Status</th><th>Actions</th>
          </tr></thead>
          <tbody>${rows || "<tr><td colspan='6'>No tokens issued.</td></tr>"}</tbody>
        </table>`,
      ),
    );
  });

  app.get("/admin/tokens/new", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;

    const session = lookupSession(db, sessionToken)!;
    const routeList = config.routes
      .map(
        (r) =>
          `<option value="${escapeHtml(r.path)}">${escapeHtml(r.path)}</option>`,
      )
      .join("\n");

    return reply.type("text/html").send(
      htmlPage(
        "Issue Token",
        `<h2>Issue New Token</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <form method="POST" action="/admin/tokens">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <label>Description (optional)<br>
            <input name="description" type="text" style="width:100%">
          </label><br><br>
          <label>Scope (space-separated, optional)<br>
            <input name="scope" type="text" placeholder="read write" style="width:100%">
          </label><br><br>
          <label>Routes (leave blank for all routes)<br>
            <select name="routes" multiple size="4" style="width:100%">
              ${routeList}
            </select>
          </label><br><br>
          <label>Expires in days (0 = no expiry)<br>
            <input name="expiresInDays" type="number" min="0" value="0" style="width:8em">
          </label><br><br>
          <button type="submit">Issue Token</button>
        </form>`,
      ),
    );
  });

  app.post("/admin/tokens", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const session = lookupSession(db, sessionToken)!;
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
      htmlPage(
        "Token Issued",
        `<h2>Token Issued</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <p><strong>Token ID:</strong> ${id}</p>
        <p><strong>Copy this token now — it will not be shown again:</strong></p>
        <pre style="background:#fffbe6;border:1px solid #e6c700;padding:1rem;word-break:break-all">${escapeHtml(plaintext)}</pre>
        <p><a href="/admin/tokens">← Back to tokens</a></p>`,
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
        .send(htmlPage("Bad Request", "<p>Invalid token ID.</p>"));
    }

    const revoked = revokeToken(db, id);
    if (revoked) {
      appendAuditEvent(db, "token_revoked", clientIp(request), { id });
    }

    return reply.redirect("/admin/tokens");
  });

  app.get("/admin/oauth-user", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;
    return reply.type("text/html").send(
      htmlPage(
        "OAuth User",
        `<h2>OAuth Resource-Owner Password</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <p>This credential is separate from the LAN administration password.</p>
        <form method="POST" action="/admin/oauth-user">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <label>New password<br><input type="password" name="password" required minlength="12"></label><br><br>
          <label>Confirm password<br><input type="password" name="confirm" required minlength="12"></label><br><br>
          <button type="submit">Set OAuth password</button>
        </form>`,
      ),
    );
  });

  app.post("/admin/oauth-user", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;
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
          htmlPage(
            "OAuth User",
            "<p>Password must match and contain at least 12 characters.</p>",
          ),
        );
    }
    await setOAuthUserPassword(db, body.password);
    appendAuditEvent(db, "oauth_user_password_changed", clientIp(request));
    return reply
      .type("text/html")
      .send(
        htmlPage("OAuth User", "<p>OAuth resource-owner password updated.</p>"),
      );
  });

  // ── Route management ─────────────────────────────────────────────────────

  app.get("/admin/routes", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;

    const rows = config.routes
      .map((r) => {
        const cachedTools = getCachedTools(db, r.path);
        const allowlistCount = r.tools?.allowlist?.length ?? 0;
        return `<tr>
          <td><code>${escapeHtml(r.path)}</code></td>
          <td><code>${escapeHtml(r.upstream)}</code></td>
          <td>${cachedTools.length > 0 ? `${allowlistCount > 0 ? allowlistCount + " allowlisted / " : ""}${cachedTools.length} discovered` : "Not discovered"}</td>
          <td>
            <a href="/admin/routes${encodeURIComponent(r.path)}/tools">Manage tools</a>
            &nbsp;
            <form method="POST" action="/admin/routes${encodeURIComponent(r.path)}/delete" style="display:inline">
              <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
              <button type="submit" onclick="return confirm('Delete route ${escapeHtml(r.path)}?')">Delete</button>
            </form>
          </td>
        </tr>`;
      })
      .join("\n");

    return reply.type("text/html").send(
      htmlPage(
        "Routes",
        `<h2>MCP Backend Routes</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <p><a href="/admin/routes/new">+ Add route</a></p>
        <table border="1" cellpadding="4" style="border-collapse:collapse;width:100%">
          <thead><tr><th>Path</th><th>Upstream</th><th>Tools</th><th>Actions</th></tr></thead>
          <tbody>${rows || "<tr><td colspan='4'>No routes configured.</td></tr>"}</tbody>
        </table>`,
      ),
    );
  });

  app.get("/admin/routes/new", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    const session = lookupSession(db, sessionToken)!;

    return reply.type("text/html").send(
      htmlPage(
        "Add Route",
        `<h2>Add MCP Backend Route</h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <form method="POST" action="/admin/routes">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <label>Path prefix (e.g. /unraid)<br>
            <input name="path" type="text" required pattern="^/[^/].*" placeholder="/unraid" style="width:20em">
          </label><br><br>
          <label>Upstream base URL (e.g. http://host.local:8043)<br>
            <input name="upstream" type="text" required placeholder="http://host.local:8043" style="width:30em">
          </label><br><br>
          <fieldset><legend>Upstream authentication (optional)</legend>
            <label>Auth type<br>
              <select name="authType">
                <option value="">None</option>
                <option value="bearer">Bearer token (env var)</option>
                <option value="header">Custom header (env var)</option>
              </select>
            </label><br><br>
            <label>Env var name holding the token/secret<br>
              <input name="authEnv" type="text" placeholder="MY_UPSTREAM_TOKEN" style="width:20em">
            </label><br><br>
            <label>Header name (for custom header type only)<br>
              <input name="authHeader" type="text" placeholder="X-Api-Key" style="width:20em">
            </label>
          </fieldset><br>
          <button type="submit">Add route</button>
        </form>`,
      ),
    );
  });

  app.post("/admin/routes", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const body = request.body as Record<string, string>;
    const path = (body.path ?? "").trim();
    const upstream = (body.upstream ?? "").trim();
    const authType = (body.authType ?? "").trim();
    const authEnv = (body.authEnv ?? "").trim();
    const authHeader = (body.authHeader ?? "").trim();

    if (!path || !upstream) {
      return reply
        .code(400)
        .type("text/html")
        .send(htmlPage("Add Route", "<p>Path and upstream are required.</p>"));
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
          htmlPage(
            "Add Route Failed",
            `<p>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</p>
          <a href="/admin/routes/new">← Back</a>`,
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
          htmlPage(
            "Save Failed",
            `<pre>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</pre>
          <a href="/admin/routes/new">← Back</a>`,
          ),
        );
    }

    appendAuditEvent(db, "route_added", clientIp(request), { path });
    options.onConfigSaved?.();

    // Attempt tool discovery against the new upstream
    const upstreamDispatcher = createUpstreamDispatcher(config.security);
    const discovery = await discoverTools(upstream, upstreamDispatcher);
    await upstreamDispatcher.close();

    if (discovery.tools.length > 0) {
      upsertCachedTools(db, path, discovery.tools);
      return reply.redirect(`/admin/routes${encodeURIComponent(path)}/tools`);
    }

    return reply.type("text/html").send(
      htmlPage(
        "Route Added",
        `<h2>Route Added</h2>
        <p>Route <code>${escapeHtml(path)}</code> → <code>${escapeHtml(upstream)}</code> saved.</p>
        ${discovery.error ? `<p>Tool discovery failed: ${escapeHtml(discovery.error)}. You can retry from the tools page later.</p>` : "<p>No tools discovered.</p>"}
        <p><strong>Restart required</strong> to activate the new route.</p>
        <a href="/admin/routes">← Back to routes</a>`,
      ),
    );
  });

  // Route path is percent-encoded in the URL; decode it back.
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
          htmlPage(
            "Delete Failed",
            `<p>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</p>`,
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
          htmlPage(
            "Delete Failed",
            `<pre>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</pre>`,
          ),
        );
    }

    clearCachedTools(db, routePath);
    appendAuditEvent(db, "route_deleted", clientIp(request), {
      path: routePath,
    });
    options.onConfigSaved?.();

    return reply.redirect("/admin/routes");
  });

  // Tool allowlist management — list discovered tools with checkboxes
  app.get("/admin/routes:encodedPath/tools", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
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
          htmlPage(
            "Not Found",
            `<p>Route <code>${escapeHtml(routePath)}</code> not found. It may have been added after the last restart.</p>`,
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

    let toolRows = "";
    if (cachedTools.length > 0) {
      toolRows = cachedTools
        .map((t) => {
          const dangerous = isDangerous(t.name);
          const checked =
            currentAllowlist.size > 0
              ? currentAllowlist.has(t.name)
              : !dangerous;
          return `<tr>
            <td><input type="checkbox" name="tool" value="${escapeHtml(t.name)}"${checked ? " checked" : ""}></td>
            <td><code>${escapeHtml(t.name)}</code>${dangerous ? " <span style='color:#c00'>(dangerous)</span>" : ""}</td>
            <td style="font-size:.9em;color:#555">${escapeHtml(t.description ?? "")}</td>
          </tr>`;
        })
        .join("\n");
    }

    return reply.type("text/html").send(
      htmlPage(
        `Tools: ${routePath}`,
        `<h2>Tool Allowlist: <code>${escapeHtml(routePath)}</code></h2>
        <nav>${navLinks(session.csrfToken)}</nav>
        <p>Checked tools are allowed; unchecked tools are blocked. If no tools are discovered, the global deny policy applies.</p>
        <form method="POST" action="/admin/routes${encodeURIComponent(routePath)}/discover" style="display:inline">
          <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
          <button type="submit">↺ Refresh tools from upstream</button>
        </form>
        <br><br>
        ${
          cachedTools.length === 0
            ? "<p>No tools discovered yet. Click Refresh to query the upstream.</p>"
            : `<form method="POST" action="/admin/routes${encodeURIComponent(routePath)}/tools">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(session.csrfToken)}">
            <table border="1" cellpadding="4" style="border-collapse:collapse;width:100%">
              <thead><tr><th>Allow</th><th>Tool</th><th>Description</th></tr></thead>
              <tbody>${toolRows}</tbody>
            </table><br>
            <button type="submit">Save allowlist</button>
            &nbsp;
            <a href="/admin/routes">Cancel</a>
          </form>`
        }`,
      ),
    );
  });

  // Save tool allowlist
  app.post("/admin/routes:encodedPath/tools", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const encodedPath =
      (request.params as Record<string, string>).encodedPath ?? "";
    const routePath = decodeURIComponent(encodedPath);

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
          htmlPage(
            "Save Failed",
            `<pre>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</pre>`,
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
          htmlPage(
            "Save Failed",
            `<pre>${error instanceof Error ? escapeHtml(error.message) : "Unknown error"}</pre>`,
          ),
        );
    }

    appendAuditEvent(db, "route_allowlist_saved", clientIp(request), {
      path: routePath,
      count: allowlist.length,
    });
    options.onConfigSaved?.();

    return reply.type("text/html").send(
      htmlPage(
        "Allowlist Saved",
        `<h2>Allowlist Saved</h2>
        <p>${allowlist.length} tool(s) allowlisted for <code>${escapeHtml(routePath)}</code>.</p>
        <p><strong>Restart required</strong> to apply the allowlist.</p>
        <a href="/admin/routes">← Back to routes</a>`,
      ),
    );
  });

  // Trigger tool discovery (re-query upstream, update cache)
  app.post("/admin/routes:encodedPath/discover", async (request, reply) => {
    const sessionToken = await requireAuth(request, reply);
    if (!sessionToken) return;
    if (!requireCsrf(request, reply, sessionToken)) return;

    const encodedPath =
      (request.params as Record<string, string>).encodedPath ?? "";
    const routePath = decodeURIComponent(encodedPath);
    const route = config.routes.find((r) => r.path === routePath);
    if (!route) {
      return reply
        .code(404)
        .type("text/html")
        .send(
          htmlPage(
            "Not Found",
            `<p>Route <code>${escapeHtml(routePath)}</code> not found. Restart the gateway after adding routes.</p>`,
          ),
        );
    }

    const upstreamDispatcher = createUpstreamDispatcher(config.security);
    const result = await discoverTools(route.upstream, upstreamDispatcher);
    await upstreamDispatcher.close();

    if (result.tools.length > 0) {
      upsertCachedTools(db, routePath, result.tools);
    }

    return reply.redirect(
      `/admin/routes${encodeURIComponent(routePath)}/tools`,
    );
  });

  // ── Health (internal liveness) ────────────────────────────────────────────

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

// ── HTML helpers ──────────────────────────────────────────────────────────────

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

function htmlPage(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} — MCP Gateway Admin</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
  nav a { margin-right: 1rem; }
  textarea { font-family: monospace; width: 100%; }
  label { display: block; margin-bottom: .25rem; font-weight: bold; }
  input, textarea { margin-top: .25rem; }
  pre { background: #f4f4f4; padding: 1rem; white-space: pre-wrap; word-break: break-word; }
  button { padding: .4rem 1rem; cursor: pointer; }
</style>
</head>
<body>
${body}
<hr style="margin-top:3rem">
<footer style="color:#888;font-size:.85rem">MCP Gateway v${APP_VERSION}</footer>
</body>
</html>`;
}

function navLinks(csrfToken: string): string {
  return `<a href="/admin/dashboard">Dashboard</a>
          <a href="/admin/routes">Routes</a>
          <a href="/admin/settings">Settings</a>
          <a href="/admin/config">Edit Config</a>
          <a href="/admin/tokens">Tokens</a>
          <a href="/admin/oauth-user">OAuth User</a>
          <form method="POST" action="/admin/logout" style="display:inline">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(csrfToken)}">
            <button type="submit">Log out</button>
          </form>`;
}

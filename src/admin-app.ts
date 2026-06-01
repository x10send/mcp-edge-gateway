import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifyFormbody from "@fastify/formbody";
import type { DatabaseSync } from "node:sqlite";
import type { GatewayConfig } from "./config.js";
import { loadConfig } from "./config.js";
import { writeConfigAtomic } from "./config-writer.js";
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
      sameSite: "strict",
      path: "/admin",
    });
  }

  function clearSessionCookie(reply: FastifyReply): void {
    reply.clearCookie(COOKIE_NAME, { path: "/admin" });
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
    const token = getSessionToken(request);
    if (token) {
      deleteSession(db, token);
    }
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
        <p>Port: ${adminConfig.port} | Host: ${escapeHtml(adminConfig.host)}</p>`,
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

    return reply.redirect("/admin/dashboard");
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
</body>
</html>`;
}

function navLinks(csrfToken: string): string {
  return `<a href="/admin/dashboard">Dashboard</a>
          <a href="/admin/config">Edit Config</a>
          <a href="/admin/tokens">Tokens</a>
          <form method="POST" action="/admin/logout" style="display:inline">
            <input type="hidden" name="${CSRF_FIELD}" value="${escapeHtml(csrfToken)}">
            <button type="submit">Log out</button>
          </form>`;
}

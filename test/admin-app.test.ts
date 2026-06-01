import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { buildAdminApp } from "../src/admin-app.js";
import { buildApp } from "../src/app.js";
import { StateStore, MIGRATIONS } from "../src/state.js";
import { consumeBootstrap, initBootstrap } from "../src/admin-auth.js";
import { issueToken } from "../src/oauth-token-store.js";
import type { GatewayConfig } from "../src/config.js";

const VALID_YAML = `
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`.trim();

const BASE_CONFIG: GatewayConfig = {
  server: { host: "127.0.0.1", port: 8788, logLevel: "silent" },
  diagnostics: { enabled: false, tokenEnv: "GATEWAY_DIAGNOSTICS_TOKEN" },
  admin: {
    enabled: true,
    port: 8789,
    host: "127.0.0.1",
    sessionTtlSeconds: 3600,
    maxLoginAttemptsPerHour: 10,
    loginLockoutSeconds: 900,
  },
  security: {
    allowedHosts: ["localhost", "127.0.0.1"],
    trustedProxies: [],
    allowPrivateUpstreamsOnly: true,
    requireAuth: false,
    bodyLimitBytes: 1_048_576,
    jsonResponseLimitBytes: 4_194_304,
    maxConcurrentRequests: 100,
    maxConcurrentStreams: 20,
    sseMaxDurationMs: 300_000,
    upstreamConnectTimeoutMs: 5_000,
    upstreamHeadersTimeoutMs: 10_000,
    upstreamBodyTimeoutMs: 30_000,
    upstreamResponseHeaderLimitBytes: 16_384,
  },
  tools: {},
  routes: [{ path: "/unraid", upstream: "http://unraid-agent.local:8043" }],
};

interface TestContext {
  app: ReturnType<typeof buildAdminApp>;
  db: import("node:sqlite").DatabaseSync;
  configPath: string;
  cleanup: () => Promise<void>;
}

function setupTest(config: GatewayConfig = BASE_CONFIG): TestContext {
  const dir = mkdtempSync(join(tmpdir(), "mcp-admin-app-"));
  const configPath = join(dir, "gateway.yaml");
  writeFileSync(configPath, VALID_YAML, { encoding: "utf8", mode: 0o600 });

  const store = new StateStore(join(dir, "state"), MIGRATIONS);
  store.open();
  const db = store.database;

  const app = buildAdminApp({ db, config, configPath });

  return {
    app,
    db,
    configPath,
    cleanup: async () => {
      await app.close();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// Helper: complete setup and return a session cookie + CSRF token
async function doSetup(
  ctx: TestContext,
  password = "correct-horse-battery-staple",
): Promise<{ cookie: string; csrfToken: string }> {
  const { plaintext } = initBootstrap(ctx.db);
  const setupRes = await ctx.app.inject({
    method: "POST",
    url: "/admin/setup",
    payload: `token=${encodeURIComponent(plaintext!)}&password=${encodeURIComponent(password)}&confirm=${encodeURIComponent(password)}`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
  });
  const setCookie = setupRes.headers["set-cookie"] as string;
  assert.ok(setCookie, "setup should set a session cookie");
  const cookie = setCookie.split(";")[0]!;
  // Read the CSRF token directly from the session store — it is no longer
  // exposed in the redirect URL (which would leak it into logs/history).
  const sessionRow = ctx.db
    .prepare("SELECT csrf_token FROM admin_sessions ORDER BY id DESC LIMIT 1")
    .get() as { csrf_token: string } | undefined;
  const csrfToken = sessionRow?.csrf_token ?? "";
  assert.ok(csrfToken, "session should have a CSRF token");
  return { cookie, csrfToken };
}

// ── Security headers ──────────────────────────────────────────────────────────

test("admin app sets security headers on every response", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({ method: "GET", url: "/admin/login" });
    assert.equal(res.headers["x-frame-options"], "DENY");
    assert.equal(res.headers["x-content-type-options"], "nosniff");
    assert.equal(res.headers["referrer-policy"], "no-referrer");
    assert.ok(res.headers["content-security-policy"]);
    assert.ok((res.headers["cache-control"] as string).includes("no-store"));
  } finally {
    await ctx.cleanup();
  }
});

// ── Root redirect ─────────────────────────────────────────────────────────────

test("GET /admin redirects to login", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({ method: "GET", url: "/admin" });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/login"));
  } finally {
    await ctx.cleanup();
  }
});

// ── Setup flow ────────────────────────────────────────────────────────────────

test("GET /admin/setup renders the setup form before credentials exist", async () => {
  const ctx = setupTest();
  try {
    initBootstrap(ctx.db);
    const res = await ctx.app.inject({ method: "GET", url: "/admin/setup" });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("Bootstrap token"));
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/setup redirects to login when bootstrap is consumed", async () => {
  const ctx = setupTest();
  try {
    initBootstrap(ctx.db);
    consumeBootstrap(ctx.db);
    // Bootstrap consumed, no credentials yet → alreadyConsumed=true path
    const res = await ctx.app.inject({ method: "GET", url: "/admin/setup" });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/login"));
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/setup redirects to login after credentials exist", async () => {
  const ctx = setupTest();
  try {
    await doSetup(ctx);
    const res = await ctx.app.inject({ method: "GET", url: "/admin/setup" });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/login"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/setup rejects an invalid bootstrap token", async () => {
  const ctx = setupTest();
  try {
    initBootstrap(ctx.db);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/setup",
      payload:
        "token=wrong&password=correct-horse-battery-staple&confirm=correct-horse-battery-staple",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.includes("Invalid bootstrap token"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/setup rejects mismatched passwords", async () => {
  const ctx = setupTest();
  try {
    const { plaintext } = initBootstrap(ctx.db);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/setup",
      payload: `token=${encodeURIComponent(plaintext!)}&password=correct-horse-battery-staple&confirm=different-password-xyz`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.includes("Passwords do not match"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/setup rejects passwords shorter than 12 characters", async () => {
  const ctx = setupTest();
  try {
    const { plaintext } = initBootstrap(ctx.db);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/setup",
      payload: `token=${encodeURIComponent(plaintext!)}&password=short&confirm=short`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.includes("12 characters"));
  } finally {
    await ctx.cleanup();
  }
});

// ── Login ─────────────────────────────────────────────────────────────────────

test("GET /admin/login renders the login form", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({ method: "GET", url: "/admin/login" });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("Password"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/login accepts the correct password and sets a session cookie", async () => {
  const ctx = setupTest();
  try {
    await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/login",
      payload: "password=correct-horse-battery-staple",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 302);
    assert.ok(res.headers["set-cookie"]);
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/login rejects wrong passwords", async () => {
  const ctx = setupTest();
  try {
    await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/login",
      payload: "password=wrong-password-xyz",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 401);
    assert.ok(res.body.includes("Incorrect password"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/login rate-limits after too many failures", async () => {
  const ctx = setupTest({
    ...BASE_CONFIG,
    admin: { ...BASE_CONFIG.admin, maxLoginAttemptsPerHour: 3 },
  });
  try {
    await doSetup(ctx);
    for (let i = 0; i < 3; i++) {
      await ctx.app.inject({
        method: "POST",
        url: "/admin/login",
        payload: "password=wrong",
        headers: { "content-type": "application/x-www-form-urlencoded" },
      });
    }
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/login",
      payload: "password=wrong",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 429);
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/login redirects authenticated users to dashboard", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/login",
      headers: { cookie },
    });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/dashboard"));
  } finally {
    await ctx.cleanup();
  }
});

// ── Logout ────────────────────────────────────────────────────────────────────

test("POST /admin/logout clears the session and redirects", async () => {
  const ctx = setupTest();
  try {
    const { cookie, csrfToken } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/logout",
      payload: `_csrf=${encodeURIComponent(csrfToken)}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/login"));
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/dashboard clears stale cookie when session does not exist", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    // Wipe all sessions from the DB to simulate expiry
    ctx.db.prepare("DELETE FROM admin_sessions").run();
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/dashboard",
      headers: { cookie },
    });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/login"));
    // Response should clear the cookie
    const setCookie = res.headers["set-cookie"] as string;
    assert.ok(
      setCookie?.includes("mcp_admin_session=;"),
      "stale cookie should be cleared",
    );
  } finally {
    await ctx.cleanup();
  }
});

// ── Dashboard ─────────────────────────────────────────────────────────────────

test("GET /admin/dashboard requires authentication", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/dashboard",
    });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/login"));
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/dashboard shows routes for authenticated users", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/dashboard",
      headers: { cookie },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("/unraid"));
  } finally {
    await ctx.cleanup();
  }
});

// ── Config editor ─────────────────────────────────────────────────────────────

test("GET /admin/config requires authentication", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({ method: "GET", url: "/admin/config" });
    assert.equal(res.statusCode, 302);
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/config shows current YAML for authenticated users", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/config",
      headers: { cookie },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("textarea"));
    assert.ok(res.body.includes("/unraid"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/config/preview validates YAML and returns result", async () => {
  const ctx = setupTest();
  try {
    const { cookie, csrfToken } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/config/preview",
      payload: `_csrf=${encodeURIComponent(csrfToken)}&yaml=${encodeURIComponent(VALID_YAML)}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("valid"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/config/preview reports invalid YAML", async () => {
  const ctx = setupTest();
  try {
    const { cookie, csrfToken } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/config/preview",
      payload: `_csrf=${encodeURIComponent(csrfToken)}&yaml=${encodeURIComponent("routes: not-an-array")}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("✗"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/config saves valid YAML and rotates the session", async () => {
  const ctx = setupTest();
  try {
    const { cookie: oldCookie, csrfToken } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/config",
      payload: `_csrf=${encodeURIComponent(csrfToken)}&yaml=${encodeURIComponent(VALID_YAML)}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: oldCookie,
      },
    });
    assert.equal(res.statusCode, 302);
    const newCookie = res.headers["set-cookie"] as string;
    assert.ok(newCookie, "session should be rotated on save");
    // Old cookie no longer works
    const dashRes = await ctx.app.inject({
      method: "GET",
      url: "/admin/dashboard",
      headers: { cookie: oldCookie },
    });
    assert.equal(dashRes.statusCode, 302, "old session should be invalidated");
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/config rejects invalid YAML and keeps the original file", async () => {
  const ctx = setupTest();
  try {
    const { cookie, csrfToken } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/config",
      payload: `_csrf=${encodeURIComponent(csrfToken)}&yaml=${encodeURIComponent("routes: not-an-array")}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.includes("Save Failed"));
  } finally {
    await ctx.cleanup();
  }
});

// ── CSRF ──────────────────────────────────────────────────────────────────────

test("POST /admin/config rejects requests with missing CSRF token", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/config",
      payload: `yaml=${encodeURIComponent(VALID_YAML)}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/config rejects requests with wrong CSRF token", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/config",
      payload: `_csrf=wrong-csrf-token&yaml=${encodeURIComponent(VALID_YAML)}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

// ── Security: CSRF token not exposed in redirect URLs ────────────────────────

test("POST /admin/login redirect does not expose CSRF token in URL", async () => {
  const ctx = setupTest();
  try {
    await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/login",
      payload: "password=correct-horse-battery-staple",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 302);
    assert.ok(
      !(res.headers.location as string).includes("_csrf"),
      "CSRF token must not appear in the redirect URL",
    );
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/setup redirect does not expose CSRF token in URL", async () => {
  const ctx = setupTest();
  try {
    const { plaintext } = initBootstrap(ctx.db);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/setup",
      payload: `token=${encodeURIComponent(plaintext!)}&password=correct-horse-battery-staple&confirm=correct-horse-battery-staple`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 302);
    assert.ok(
      !(res.headers.location as string).includes("_csrf"),
      "CSRF token must not appear in the redirect URL",
    );
  } finally {
    await ctx.cleanup();
  }
});

// ── Isolation: admin routes absent from public listener ───────────────────────

test("admin routes are absent from the public MCP listener", async () => {
  const publicApp = buildApp(BASE_CONFIG);
  try {
    const routes = [
      "/admin",
      "/admin/login",
      "/admin/dashboard",
      "/admin/config",
    ];
    for (const route of routes) {
      const res = await publicApp.inject({ method: "GET", url: route });
      assert.equal(
        res.statusCode,
        404,
        `${route} should return 404 on the public listener`,
      );
    }
  } finally {
    await publicApp.close();
  }
});

// ── Health ────────────────────────────────────────────────────────────────────

test("GET /admin/health returns ok", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({ method: "GET", url: "/admin/health" });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.json(), { status: "ok" });
  } finally {
    await ctx.cleanup();
  }
});

// ── Token management ──────────────────────────────────────────────────────────

test("GET /admin/tokens requires authentication", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({ method: "GET", url: "/admin/tokens" });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/login"));
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/tokens lists issued tokens for authenticated users", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    issueToken(ctx.db, { description: "my-token", scope: "read" });
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/tokens",
      headers: { cookie },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("my-token"));
    assert.ok(res.body.includes("active"));
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/tokens shows empty state when no tokens exist", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/tokens",
      headers: { cookie },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("No tokens issued"));
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/tokens/new requires authentication", async () => {
  const ctx = setupTest();
  try {
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/tokens/new",
    });
    assert.equal(res.statusCode, 302);
  } finally {
    await ctx.cleanup();
  }
});

test("GET /admin/tokens/new shows the token creation form", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "GET",
      url: "/admin/tokens/new",
      headers: { cookie },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(
      res.body.includes("Issue Token") || res.body.includes("Issue New Token"),
    );
    assert.ok(res.body.includes("Scope"));
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/tokens issues a token and shows the plaintext once", async () => {
  const ctx = setupTest();
  try {
    const { cookie, csrfToken } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/tokens",
      payload: `_csrf=${encodeURIComponent(csrfToken)}&description=test+token&scope=read`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes("Token Issued"));
    assert.ok(res.body.includes("will not be shown again"));
    // The plaintext token should appear in the response
    const tokens = ctx.db.prepare("SELECT id FROM oauth_tokens").all() as {
      id: number;
    }[];
    assert.equal(tokens.length, 1);
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/tokens requires CSRF token", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/tokens",
      payload: "description=test&scope=read",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/tokens/:id/revoke revokes the token and redirects", async () => {
  const ctx = setupTest();
  try {
    const { cookie, csrfToken } = await doSetup(ctx);
    const { id } = issueToken(ctx.db, { description: "to-revoke" });
    const res = await ctx.app.inject({
      method: "POST",
      url: `/admin/tokens/${id}/revoke`,
      payload: `_csrf=${encodeURIComponent(csrfToken)}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 302);
    assert.ok((res.headers.location as string).includes("/admin/tokens"));
    // Verify revoked in DB
    const row = ctx.db
      .prepare("SELECT revoked_at FROM oauth_tokens WHERE id = ?")
      .get(id) as { revoked_at: number | null };
    assert.ok(row.revoked_at !== null, "token should be revoked");
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/tokens/:id/revoke rejects non-numeric id", async () => {
  const ctx = setupTest();
  try {
    const { cookie, csrfToken } = await doSetup(ctx);
    const res = await ctx.app.inject({
      method: "POST",
      url: "/admin/tokens/not-a-number/revoke",
      payload: `_csrf=${encodeURIComponent(csrfToken)}`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("POST /admin/tokens/:id/revoke requires CSRF token", async () => {
  const ctx = setupTest();
  try {
    const { cookie } = await doSetup(ctx);
    const { id } = issueToken(ctx.db, {});
    const res = await ctx.app.inject({
      method: "POST",
      url: `/admin/tokens/${id}/revoke`,
      payload: "",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie,
      },
    });
    assert.equal(res.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

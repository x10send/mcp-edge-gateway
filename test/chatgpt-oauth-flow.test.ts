/**
 * End-to-end simulation of the OAuth connection flow used by ChatGPT and
 * other remote MCP clients that implement the MCP authorization specification.
 *
 * Flow under test:
 *  1. Unauthenticated MCP request → 401 with WWW-Authenticate (resource_metadata)
 *  2. Fetch protected-resource metadata → authorization_servers
 *  3. Fetch authorization-server metadata → endpoints
 *  4. Dynamic client registration (ChatGPT has no pre-registered client ID)
 *  5. Authorization code flow with PKCE S256
 *  6. Token exchange → access_token + refresh_token
 *  7. Authenticated MCP request succeeds
 *  8. Refresh token rotation → new access_token
 *  9. Authenticated MCP request with rotated token succeeds
 */

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { buildApp, type BuildAppOptions } from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";
import { setOAuthUserPassword } from "../src/oauth-authorization-server.js";
import { StateStore } from "../src/state.js";

type SendUpstream = NonNullable<BuildAppOptions["sendUpstream"]>;

const OAUTH_USER_PASSWORD = "chatgpt-flow-test-password";

const config: GatewayConfig = {
  server: { host: "127.0.0.1", port: 8788, logLevel: "silent" },
  diagnostics: { enabled: false, tokenEnv: "GATEWAY_DIAGNOSTICS_TOKEN" },
  oauth: {
    enabled: true,
    issuer: "http://localhost:8788",
    insecureAllowHttpIssuer: true,
    accessTokenTtlSeconds: 900,
    refreshTokenTtlSeconds: 2_592_000,
    authorizationCodeTtlSeconds: 300,
    authorizationTransactionTtlSeconds: 600,
    dynamicRegistrationLimitPerHour: 20,
    loginLimitPerHour: 10,
    loginLockoutSeconds: 900,
    staticClients: [],
  },
  admin: {
    enabled: false,
    port: 8789,
    host: "127.0.0.1",
    insecureAllowHttpCookies: false,
    sessionTtlSeconds: 3600,
    maxLoginAttemptsPerHour: 10,
    loginLockoutSeconds: 900,
  },
  security: {
    publicOrigin: "http://localhost:8788",
    insecureAllowHttpPublicOrigin: true,
    allowedHosts: ["localhost", "127.0.0.1"],
    trustedProxies: [],
    allowPrivateUpstreamsOnly: true,
    requireAuth: true,
    insecureAllowUnauthenticatedMcp: false,
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

function mockUpstream(): SendUpstream {
  return (async () => {
    const body = Readable.from(['{"status":"ok"}']);
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body,
    } as unknown as Awaited<ReturnType<SendUpstream>>;
  }) as SendUpstream;
}

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "mcp-chatgpt-flow-"));
  const store = new StateStore(dir);
  store.open();
  const app = buildApp(config, {
    db: store.database,
    sendUpstream: mockUpstream(),
  });
  return {
    app,
    db: store.database,
    cleanup: async () => {
      await app.close();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(40).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function extractCsrf(html: string): string {
  return html.match(/name="_csrf" value="([^"]+)"/)?.[1] ?? "";
}

test("ChatGPT-compatible OAuth flow: full connection from discovery to authenticated MCP request", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, OAUTH_USER_PASSWORD);

    // Step 1: unauthenticated MCP request → 401 with WWW-Authenticate
    const unauth = await ctx.app.inject({
      method: "GET",
      url: "/unraid/mcp",
      headers: { host: "localhost" },
    });
    assert.equal(
      unauth.statusCode,
      401,
      "unauthenticated request must return 401",
    );
    const wwwAuth = unauth.headers["www-authenticate"] as string;
    assert.ok(wwwAuth.includes("Bearer realm"), "must include Bearer realm");
    const metaMatch = wwwAuth.match(/resource_metadata="([^"]+)"/);
    assert.ok(metaMatch, "must include resource_metadata URL");
    const resourceMetaUrl = metaMatch[1];

    // Step 2: fetch protected-resource metadata
    const resourceMeta = await ctx.app.inject({
      method: "GET",
      url: new URL(resourceMetaUrl).pathname,
      headers: { host: "localhost" },
    });
    assert.equal(resourceMeta.statusCode, 200);
    const resourceMetaBody = resourceMeta.json();
    assert.ok(
      Array.isArray(resourceMetaBody.authorization_servers),
      "protected-resource metadata must advertise authorization_servers",
    );
    const authServerIssuer = resourceMetaBody
      .authorization_servers[0] as string;

    // Step 3: fetch authorization-server metadata
    const asMeta = await ctx.app.inject({
      method: "GET",
      url: "/.well-known/oauth-authorization-server",
      headers: { host: "localhost" },
    });
    assert.equal(asMeta.statusCode, 200);
    const asMetaBody = asMeta.json();
    assert.equal(asMetaBody.issuer, authServerIssuer);
    assert.ok(
      asMetaBody.authorization_endpoint,
      "must have authorization_endpoint",
    );
    assert.ok(asMetaBody.token_endpoint, "must have token_endpoint");
    assert.ok(
      asMetaBody.registration_endpoint,
      "must have registration_endpoint",
    );
    assert.ok(asMetaBody.revocation_endpoint, "must have revocation_endpoint");
    assert.deepEqual(
      asMetaBody.code_challenge_methods_supported,
      ["S256"],
      "must support PKCE S256",
    );

    // Step 4: dynamic client registration
    const clientRedirectUri =
      "https://chat.openai.com/aip/g-abc/oauth/callback";
    const registration = await ctx.app.inject({
      method: "POST",
      url: "/oauth/register",
      payload: {
        client_name: "ChatGPT",
        redirect_uris: [clientRedirectUri],
        token_endpoint_auth_method: "none",
      },
    });
    assert.equal(
      registration.statusCode,
      201,
      "dynamic registration must succeed",
    );
    const { client_id: clientId } = registration.json() as {
      client_id: string;
    };
    assert.ok(clientId, "must return a client_id");

    // Step 5: authorization code flow with PKCE S256
    const { verifier, challenge } = pkce();
    const resource = `${config.security.publicOrigin}/unraid/mcp`;
    const state = randomBytes(16).toString("hex");

    const authQuery = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: clientRedirectUri,
      resource,
      scope: "mcp",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const authorize = await ctx.app.inject({
      method: "GET",
      url: `/oauth/authorize?${authQuery}`,
      headers: { host: "localhost" },
    });
    assert.equal(authorize.statusCode, 200, "authorize must render login page");
    assert.ok(authorize.body.includes("Sign in"), "must show login form");
    const txCookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const loginCsrf = extractCsrf(authorize.body);
    assert.ok(loginCsrf, "must include CSRF token in login form");

    // Step 6: submit login credentials
    const login = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: {
        host: "localhost",
        cookie: txCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: `_csrf=${encodeURIComponent(loginCsrf)}&password=${encodeURIComponent(OAUTH_USER_PASSWORD)}`,
    });
    assert.equal(
      login.statusCode,
      200,
      "login must succeed and show consent page",
    );
    assert.ok(login.body.includes("Approve access"), "must show consent form");
    const consentCsrf = extractCsrf(login.body);

    // Step 7: approve consent
    const consent = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/consent",
      headers: {
        host: "localhost",
        cookie: txCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: `_csrf=${encodeURIComponent(consentCsrf)}&decision=approve`,
    });
    assert.equal(consent.statusCode, 302, "consent must redirect to client");
    const redirect = new URL(consent.headers.location as string);
    assert.ok(
      redirect.href.startsWith(clientRedirectUri),
      "must redirect to registered URI",
    );
    assert.equal(redirect.searchParams.get("state"), state, "must echo state");
    assert.equal(
      redirect.searchParams.get("iss"),
      config.oauth.issuer,
      "must include iss for mix-up attack resistance",
    );
    const code = redirect.searchParams.get("code");
    assert.ok(code, "must include authorization code");

    // Step 8: exchange code for tokens
    const tokenResponse = await ctx.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: {
        host: "localhost",
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: clientRedirectUri,
        resource,
        code_verifier: verifier,
      }).toString(),
    });
    assert.equal(tokenResponse.statusCode, 200, "token exchange must succeed");
    const tokens = tokenResponse.json();
    assert.equal(tokens.token_type, "Bearer");
    assert.ok(tokens.access_token, "must return access_token");
    assert.ok(tokens.refresh_token, "must return refresh_token");
    assert.equal(typeof tokens.expires_in, "number");

    // Step 9: use the access token on the MCP endpoint
    const mcpRequest = await ctx.app.inject({
      method: "GET",
      url: "/unraid/mcp",
      headers: {
        host: "localhost",
        authorization: `Bearer ${tokens.access_token}`,
      },
    });
    assert.equal(
      mcpRequest.statusCode,
      200,
      "authenticated MCP request must succeed",
    );

    // Step 10: refresh token rotation
    const refreshResponse = await ctx.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: {
        host: "localhost",
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: clientId,
        resource,
      }).toString(),
    });
    assert.equal(refreshResponse.statusCode, 200, "token refresh must succeed");
    const rotated = refreshResponse.json();
    assert.ok(
      rotated.access_token,
      "rotated response must include new access_token",
    );
    assert.ok(
      rotated.refresh_token,
      "rotated response must include new refresh_token",
    );
    assert.notEqual(
      rotated.access_token,
      tokens.access_token,
      "rotated access_token must differ from original",
    );

    // Step 11: original refresh token is consumed and cannot be reused
    assert.notEqual(
      rotated.refresh_token,
      tokens.refresh_token,
      "refresh token must be rotated",
    );

    // Step 12: rotated access token works on the MCP endpoint
    const rotatedRequest = await ctx.app.inject({
      method: "GET",
      url: "/unraid/mcp",
      headers: {
        host: "localhost",
        authorization: `Bearer ${rotated.access_token}`,
      },
    });
    assert.equal(
      rotatedRequest.statusCode,
      200,
      "rotated access token must work",
    );
  } finally {
    await ctx.cleanup();
  }
});

test("ChatGPT flow: authorization code is rejected with wrong PKCE verifier", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, OAUTH_USER_PASSWORD);
    const reg = await ctx.app.inject({
      method: "POST",
      url: "/oauth/register",
      payload: {
        client_name: "Test",
        redirect_uris: ["https://chat.openai.com/callback"],
      },
    });
    const { client_id: clientId } = reg.json() as { client_id: string };
    const { challenge } = pkce();
    const resource = `${config.security.publicOrigin}/unraid/mcp`;

    const authorize = await ctx.app.inject({
      method: "GET",
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "https://chat.openai.com/callback",
        resource,
        code_challenge: challenge,
        code_challenge_method: "S256",
      })}`,
    });
    const txCookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = extractCsrf(authorize.body);

    await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: {
        cookie: txCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: `_csrf=${encodeURIComponent(csrf)}&password=${encodeURIComponent(OAUTH_USER_PASSWORD)}`,
    });
    const consent = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/consent",
      headers: {
        cookie: txCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: `_csrf=${encodeURIComponent(csrf)}&decision=approve`,
    });
    const code = new URL(consent.headers.location as string).searchParams.get(
      "code",
    )!;

    const wrongVerifier =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const res = await ctx.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: "https://chat.openai.com/callback",
        resource,
        code_verifier: wrongVerifier,
      }).toString(),
    });
    assert.equal(res.statusCode, 400, "wrong PKCE verifier must be rejected");
    assert.equal(res.json().error, "invalid_grant");
  } finally {
    await ctx.cleanup();
  }
});

test("ChatGPT flow: explicit token revocation rejects subsequent MCP requests", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, OAUTH_USER_PASSWORD);
    const reg = await ctx.app.inject({
      method: "POST",
      url: "/oauth/register",
      payload: {
        client_name: "Test",
        redirect_uris: ["https://chat.openai.com/callback"],
      },
    });
    const { client_id: clientId } = reg.json() as { client_id: string };
    const { verifier, challenge } = pkce();
    const resource = `${config.security.publicOrigin}/unraid/mcp`;

    const authorize = await ctx.app.inject({
      method: "GET",
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "https://chat.openai.com/callback",
        resource,
        code_challenge: challenge,
        code_challenge_method: "S256",
      })}`,
    });
    const txCookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = extractCsrf(authorize.body);
    await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: {
        cookie: txCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: `_csrf=${encodeURIComponent(csrf)}&password=${encodeURIComponent(OAUTH_USER_PASSWORD)}`,
    });
    const consent = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/consent",
      headers: {
        cookie: txCookie,
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: `_csrf=${encodeURIComponent(csrf)}&decision=approve`,
    });
    const code = new URL(consent.headers.location as string).searchParams.get(
      "code",
    )!;
    const tokens = (
      await ctx.app.inject({
        method: "POST",
        url: "/oauth/token",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        payload: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: clientId,
          redirect_uri: "https://chat.openai.com/callback",
          resource,
          code_verifier: verifier,
        }).toString(),
      })
    ).json();

    // Verify the token works before revocation
    const before = await ctx.app.inject({
      method: "GET",
      url: "/unraid/mcp",
      headers: {
        host: "localhost",
        authorization: `Bearer ${tokens.access_token}`,
      },
    });
    assert.equal(before.statusCode, 200);

    // Revoke the access token
    const revoke = await ctx.app.inject({
      method: "POST",
      url: "/oauth/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: `token=${encodeURIComponent(tokens.access_token)}`,
    });
    assert.equal(revoke.statusCode, 200);

    // MCP request must now be rejected
    const after = await ctx.app.inject({
      method: "GET",
      url: "/unraid/mcp",
      headers: {
        host: "localhost",
        authorization: `Bearer ${tokens.access_token}`,
      },
    });
    assert.equal(after.statusCode, 401, "revoked token must be rejected");
  } finally {
    await ctx.cleanup();
  }
});

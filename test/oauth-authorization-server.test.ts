import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildApp } from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";
import {
  fetchClientMetadata,
  isDisallowedMetadataHostname,
  setOAuthUserPassword,
} from "../src/oauth-authorization-server.js";
import { lookupToken } from "../src/oauth-token-store.js";
import { StateStore } from "../src/state.js";

const VERIFIER =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");
const RESOURCE = "http://localhost:8788/unraid/mcp";
const REDIRECT_URI = "https://client.example/callback";

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
    dynamicRegistrationLimitPerHour: 2,
    loginLimitPerHour: 2,
    loginLockoutSeconds: 900,
    tokenRateLimitPerMinute: 100,
    revokeRateLimitPerMinute: 100,
    staticClients: [
      {
        clientId: "static-client",
        clientName: "Static Test Client",
        redirectUris: [REDIRECT_URI],
      },
    ],
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

function setup(
  options: Parameters<typeof buildApp>[1] & {
    overrideConfig?: GatewayConfig;
  } = {},
) {
  const { overrideConfig, ...appOptions } = options;
  const dir = mkdtempSync(join(tmpdir(), "mcp-oauth-server-"));
  const store = new StateStore(dir);
  store.open();
  const app = buildApp(overrideConfig ?? config, {
    ...appOptions,
    db: store.database,
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

function authorizeUrl(clientId = "static-client", redirectUri = REDIRECT_URI) {
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    resource: RESOURCE,
    scope: "read write",
    state: "client-state",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
  });
  return `/oauth/authorize?${query}`;
}

function hiddenCsrf(html: string): string {
  return html.match(/name="_csrf" value="([^"]+)"/)?.[1] ?? "";
}

async function issueCode(ctx: ReturnType<typeof setup>): Promise<string> {
  await setOAuthUserPassword(ctx.db, "oauth-user-password");
  const authorize = await ctx.app.inject({
    method: "GET",
    url: authorizeUrl(),
  });
  const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
  const csrf = hiddenCsrf(authorize.body);
  const login = await ctx.app.inject({
    method: "POST",
    url: "/oauth/authorize/login",
    headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    payload: `_csrf=${encodeURIComponent(csrf)}&password=oauth-user-password`,
  });
  assert.equal(login.statusCode, 200);
  assert.ok(login.body.includes("Allow access"));
  const consent = await ctx.app.inject({
    method: "POST",
    url: "/oauth/authorize/consent",
    headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    payload: `_csrf=${encodeURIComponent(csrf)}&decision=approve`,
  });
  assert.equal(consent.statusCode, 302);
  const redirect = new URL(consent.headers.location as string);
  assert.equal(redirect.searchParams.get("state"), "client-state");
  assert.equal(redirect.searchParams.get("iss"), config.oauth.issuer);
  return redirect.searchParams.get("code")!;
}

async function exchangeCode(
  ctx: ReturnType<typeof setup>,
  code: string,
  verifier = VERIFIER,
) {
  return ctx.app.inject({
    method: "POST",
    url: "/oauth/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: "static-client",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_verifier: verifier,
    }).toString(),
  });
}

test("authorization-server metadata advertises OAuth endpoints and PKCE S256", async () => {
  const ctx = setup();
  try {
    const res = await ctx.app.inject({
      method: "GET",
      url: "/.well-known/oauth-authorization-server",
    });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json().issuer, config.oauth.issuer);
    assert.deepEqual(res.json().code_challenge_methods_supported, ["S256"]);
    assert.ok(res.headers["content-security-policy"]);
  } finally {
    await ctx.cleanup();
  }
});

test("protected-resource metadata advertises the authorization server", async () => {
  const ctx = setup();
  try {
    const res = await ctx.app.inject({
      method: "GET",
      url: "/.well-known/oauth-protected-resource/unraid/mcp",
    });
    assert.deepEqual(res.json().authorization_servers, [config.oauth.issuer]);
  } finally {
    await ctx.cleanup();
  }
});

test("authorization code flow issues audience-bound access and refresh tokens", async () => {
  const ctx = setup();
  try {
    const code = await issueCode(ctx);
    const exchanged = await exchangeCode(ctx, code);
    assert.equal(exchanged.statusCode, 200);
    const tokens = exchanged.json();
    assert.equal(tokens.token_type, "Bearer");
    assert.ok(tokens.refresh_token);
    assert.ok(lookupToken(ctx.db, tokens.access_token, "/unraid"));
    assert.equal(lookupToken(ctx.db, tokens.access_token, "/other"), undefined);
  } finally {
    await ctx.cleanup();
  }
});

test("authorization request rejects redirect mismatch, missing PKCE, and wrong resource", async () => {
  const ctx = setup();
  try {
    const mismatch = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl("static-client", "https://attacker.example/callback"),
    });
    assert.equal(mismatch.statusCode, 400);
    const missingPkce = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl().replace(`&code_challenge=${CHALLENGE}`, ""),
    });
    assert.equal(missingPkce.statusCode, 400);
    const wrongResource = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl().replace(
        encodeURIComponent(RESOURCE),
        encodeURIComponent("http://localhost:8788/other/mcp"),
      ),
    });
    assert.equal(wrongResource.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("authorization code is single-use and requires the PKCE verifier", async () => {
  const ctx = setup();
  try {
    const code = await issueCode(ctx);
    const wrongVerifier = await exchangeCode(ctx, code, `${VERIFIER}x`);
    assert.equal(wrongVerifier.statusCode, 400);
    const malformedVerifier = await exchangeCode(ctx, code, "short");
    assert.equal(malformedVerifier.statusCode, 400);
    const first = await exchangeCode(ctx, code);
    assert.equal(first.statusCode, 200);
    const second = await exchangeCode(ctx, code);
    assert.equal(second.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("refresh tokens rotate and replay revokes the token family", async () => {
  const ctx = setup();
  try {
    const initial = (await exchangeCode(ctx, await issueCode(ctx))).json();
    const refresh = (token: string) =>
      ctx.app.inject({
        method: "POST",
        url: "/oauth/token",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        payload: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: token,
          client_id: "static-client",
          resource: RESOURCE,
        }).toString(),
      });
    const rotated = await refresh(initial.refresh_token);
    assert.equal(rotated.statusCode, 200);
    assert.ok(rotated.json().refresh_token);
    assert.equal((await refresh(initial.refresh_token)).statusCode, 400);
    assert.equal((await refresh(rotated.json().refresh_token)).statusCode, 400);
    assert.equal(
      lookupToken(ctx.db, rotated.json().access_token, "/unraid"),
      undefined,
    );
  } finally {
    await ctx.cleanup();
  }
});

test("OAuth login is rate-limited after repeated failures", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, "oauth-user-password");
    const authorize = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = hiddenCsrf(authorize.body);
    const login = () =>
      ctx.app.inject({
        method: "POST",
        url: "/oauth/authorize/login",
        headers: {
          cookie,
          "content-type": "application/x-www-form-urlencoded",
        },
        payload: `_csrf=${encodeURIComponent(csrf)}&password=wrong-password`,
      });
    assert.equal((await login()).statusCode, 401);
    assert.equal((await login()).statusCode, 401);
    assert.equal((await login()).statusCode, 429);
  } finally {
    await ctx.cleanup();
  }
});

test("revocation endpoint revokes refresh token families", async () => {
  const ctx = setup();
  try {
    const tokens = (await exchangeCode(ctx, await issueCode(ctx))).json();
    const revoke = await ctx.app.inject({
      method: "POST",
      url: "/oauth/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: `token=${encodeURIComponent(tokens.refresh_token)}`,
    });
    assert.equal(revoke.statusCode, 200);
    const refresh = await ctx.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: "static-client",
        resource: RESOURCE,
      }).toString(),
    });
    assert.equal(refresh.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("dynamic registration validates redirects and rate-limits attempts", async () => {
  const ctx = setup();
  try {
    const register = (redirectUri: string) =>
      ctx.app.inject({
        method: "POST",
        url: "/oauth/register",
        payload: { client_name: "Dynamic", redirect_uris: [redirectUri] },
      });
    assert.equal(
      (await register("https://client.example/callback")).statusCode,
      201,
    );
    assert.equal(
      (await register("http://attacker.example/callback")).statusCode,
      400,
    );
    assert.equal(
      (await register("https://client.example/second")).statusCode,
      429,
    );
  } finally {
    await ctx.cleanup();
  }
});

test("dynamic registration rejects redirect URIs containing credentials", async () => {
  const ctx = setup();
  try {
    const response = await ctx.app.inject({
      method: "POST",
      url: "/oauth/register",
      payload: {
        client_name: "Dynamic",
        redirect_uris: ["https://user@client.example/callback"],
      },
    });
    assert.equal(response.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("Client ID Metadata Document clients are loaded once and cached", async () => {
  let loads = 0;
  const clientId = "https://client.example/oauth-client.json";
  const ctx = setup({
    oauth: {
      loadClientMetadata: async () => {
        loads += 1;
        return {
          client_id: clientId,
          client_name: "Metadata Client",
          redirect_uris: [REDIRECT_URI],
          token_endpoint_auth_method: "none",
        };
      },
    },
  });
  try {
    assert.equal(
      (await ctx.app.inject({ method: "GET", url: authorizeUrl(clientId) }))
        .statusCode,
      200,
    );
    assert.equal(
      (await ctx.app.inject({ method: "GET", url: authorizeUrl(clientId) }))
        .statusCode,
      200,
    );
    assert.equal(loads, 1);
  } finally {
    await ctx.cleanup();
  }
});

test("Client ID Metadata Document client_id must match the requested URL", async () => {
  const clientId = "https://client.example/oauth-client.json";
  const ctx = setup({
    oauth: {
      loadClientMetadata: async () => ({
        client_id: "https://attacker.example/oauth-client.json",
        client_name: "Mismatched Metadata Client",
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: "none",
      }),
    },
  });
  try {
    assert.equal(
      (await ctx.app.inject({ method: "GET", url: authorizeUrl(clientId) }))
        .statusCode,
      400,
    );
  } finally {
    await ctx.cleanup();
  }
});

test("Client ID Metadata Document fetch blocks private and special-use hosts", () => {
  assert.equal(isDisallowedMetadataHostname("127.0.0.1"), true);
  assert.equal(isDisallowedMetadataHostname("169.254.169.254"), true);
  assert.equal(isDisallowedMetadataHostname("10.0.0.1"), true);
  assert.equal(isDisallowedMetadataHostname("100.64.0.1"), true);
  assert.equal(isDisallowedMetadataHostname("192.0.0.1"), true);
  assert.equal(isDisallowedMetadataHostname("198.18.0.1"), true);
  assert.equal(isDisallowedMetadataHostname("224.0.0.1"), true);
  assert.equal(isDisallowedMetadataHostname("::1"), true);
  assert.equal(isDisallowedMetadataHostname("[::1]"), true);
  assert.equal(isDisallowedMetadataHostname("::ffff:127.0.0.1"), true);
  assert.equal(isDisallowedMetadataHostname("fe80::1"), true);
  assert.equal(isDisallowedMetadataHostname("ff02::1"), true);
  assert.equal(isDisallowedMetadataHostname("203.0.113.10"), false);
});

test("authorization request rejects invalid scope syntax", async () => {
  const ctx = setup();
  try {
    const res = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl().replace("scope=read+write", "scope=read%22write"),
    });
    assert.equal(res.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("Client ID Metadata Document loader rejects private HTTPS URLs before dispatch", async () => {
  await assert.rejects(
    () => fetchClientMetadata("https://127.0.0.1/oauth-client.json"),
    /public HTTPS URL/,
  );
  await assert.rejects(
    () => fetchClientMetadata("https://user@client.example/oauth-client.json"),
    /public HTTPS URL/,
  );
  await assert.rejects(
    () => fetchClientMetadata("https://client.example/oauth-client.json#bad"),
    /public HTTPS URL/,
  );
});

test("OAuth endpoints return protocol errors for malformed request shapes", async () => {
  const ctx = setup();
  try {
    assert.equal(
      (
        await ctx.app.inject({
          method: "GET",
          url: `${authorizeUrl()}&client_id=duplicate`,
        })
      ).statusCode,
      400,
    );
    assert.equal(
      (await ctx.app.inject({ method: "POST", url: "/oauth/token" }))
        .statusCode,
      400,
    );
    assert.equal(
      (await ctx.app.inject({ method: "POST", url: "/oauth/revoke" }))
        .statusCode,
      400,
    );
    assert.equal(
      (await ctx.app.inject({ method: "POST", url: "/oauth/register" }))
        .statusCode,
      400,
    );
  } finally {
    await ctx.cleanup();
  }
});

test("user denies consent redirects back with error=access_denied and iss", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, "oauth-user-password");
    const authorize = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = hiddenCsrf(authorize.body);
    await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=${encodeURIComponent(csrf)}&password=oauth-user-password`,
    });
    const consent = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/consent",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=${encodeURIComponent(csrf)}&decision=deny`,
    });
    assert.equal(consent.statusCode, 302);
    const location = new URL(consent.headers.location as string);
    assert.equal(location.searchParams.get("error"), "access_denied");
    assert.equal(location.searchParams.get("iss"), config.oauth.issuer);
    assert.ok(
      location.href.startsWith(REDIRECT_URI),
      "redirect must go to the registered redirect URI",
    );
  } finally {
    await ctx.cleanup();
  }
});

test("login returns 401 when no OAuth user password has been set", async () => {
  const ctx = setup();
  try {
    const authorize = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = hiddenCsrf(authorize.body);
    const login = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=${encodeURIComponent(csrf)}&password=any-password`,
    });
    assert.equal(login.statusCode, 401);
    assert.ok(login.body.includes("Incorrect password"));
  } finally {
    await ctx.cleanup();
  }
});

test("login and consent reject requests with missing transaction cookie", async () => {
  const ctx = setup();
  try {
    const missingLogin = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "_csrf=anything&password=anything",
    });
    assert.equal(missingLogin.statusCode, 400);
    const missingConsent = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/consent",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "_csrf=anything&decision=approve",
    });
    assert.equal(missingConsent.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("consent rejects approval on an unauthenticated transaction", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, "oauth-user-password");
    const authorize = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = hiddenCsrf(authorize.body);
    const consent = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/consent",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=${encodeURIComponent(csrf)}&decision=approve`,
    });
    assert.equal(consent.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

test("refresh token rejects wrong resource indicator", async () => {
  const ctx = setup();
  try {
    const tokens = (await exchangeCode(ctx, await issueCode(ctx))).json();
    const res = await ctx.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: "static-client",
        resource: "http://localhost:8788/other/mcp",
      }).toString(),
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error, "invalid_grant");
  } finally {
    await ctx.cleanup();
  }
});

test("login rejects CSRF token with same length but wrong value", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, "oauth-user-password");
    const authorize = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = hiddenCsrf(authorize.body);
    const wrongToken =
      csrf[0] === "A" ? "B" + csrf.slice(1) : "A" + csrf.slice(1);
    assert.equal(
      wrongToken.length,
      csrf.length,
      "lengths must match for this test",
    );
    const login = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=${encodeURIComponent(wrongToken)}&password=oauth-user-password`,
    });
    assert.equal(login.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

test("login rejects empty CSRF token", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, "oauth-user-password");
    const authorize = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const login = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=&password=oauth-user-password`,
    });
    assert.equal(login.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

test("consent rejects CSRF token with same length but wrong value", async () => {
  const ctx = setup();
  try {
    await setOAuthUserPassword(ctx.db, "oauth-user-password");
    const authorize = await ctx.app.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    const cookie = (authorize.headers["set-cookie"] as string).split(";")[0]!;
    const csrf = hiddenCsrf(authorize.body);
    // Login successfully
    const login = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/login",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=${encodeURIComponent(csrf)}&password=oauth-user-password`,
    });
    assert.equal(login.statusCode, 200);
    // Consent with same-length wrong CSRF
    const wrongToken =
      csrf[0] === "A" ? "B" + csrf.slice(1) : "A" + csrf.slice(1);
    assert.equal(
      wrongToken.length,
      csrf.length,
      "lengths must match for this test",
    );
    const consent = await ctx.app.inject({
      method: "POST",
      url: "/oauth/authorize/consent",
      headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
      payload: `_csrf=${encodeURIComponent(wrongToken)}&decision=approve`,
    });
    assert.equal(consent.statusCode, 403);
  } finally {
    await ctx.cleanup();
  }
});

test("/oauth/token is rate-limited per IP", async () => {
  const ctx = setup({
    overrideConfig: {
      ...config,
      oauth: { ...config.oauth, tokenRateLimitPerMinute: 2 },
    },
  });
  try {
    const tokenRequest = () =>
      ctx.app.inject({
        method: "POST",
        url: "/oauth/token",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        payload: new URLSearchParams({
          grant_type: "authorization_code",
          code: "bogus-code",
          client_id: "static-client",
          redirect_uri: REDIRECT_URI,
          resource: RESOURCE,
          code_verifier: VERIFIER,
        }).toString(),
      });
    assert.equal((await tokenRequest()).statusCode, 400);
    assert.equal((await tokenRequest()).statusCode, 400);
    assert.equal((await tokenRequest()).statusCode, 429);
  } finally {
    await ctx.cleanup();
  }
});

test("/oauth/revoke is rate-limited per IP", async () => {
  const ctx = setup({
    overrideConfig: {
      ...config,
      oauth: { ...config.oauth, revokeRateLimitPerMinute: 2 },
    },
  });
  try {
    const revokeRequest = () =>
      ctx.app.inject({
        method: "POST",
        url: "/oauth/revoke",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        payload: "token=bogus-token",
      });
    assert.equal((await revokeRequest()).statusCode, 200);
    assert.equal((await revokeRequest()).statusCode, 200);
    assert.equal((await revokeRequest()).statusCode, 429);
  } finally {
    await ctx.cleanup();
  }
});

test("authorization request rejects state parameter longer than 512 characters", async () => {
  const ctx = setup();
  try {
    const longState = "a".repeat(513);
    const url = authorizeUrl().replace(
      "state=client-state",
      `state=${encodeURIComponent(longState)}`,
    );
    const res = await ctx.app.inject({ method: "GET", url });
    assert.equal(res.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("authorization request rejects state parameter with invalid characters", async () => {
  const ctx = setup();
  try {
    const url = authorizeUrl().replace(
      "state=client-state",
      `state=${encodeURIComponent("<script>")}`,
    );
    const res = await ctx.app.inject({ method: "GET", url });
    assert.equal(res.statusCode, 400);
  } finally {
    await ctx.cleanup();
  }
});

test("removed static clients do not survive an application restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-oauth-static-client-"));
  const store = new StateStore(dir);
  store.open();
  const first = buildApp(config, { db: store.database });
  await first.ready();
  await first.close();
  const withoutStatic = buildApp(
    { ...config, oauth: { ...config.oauth, staticClients: [] } },
    { db: store.database },
  );
  try {
    const res = await withoutStatic.inject({
      method: "GET",
      url: authorizeUrl(),
    });
    assert.equal(res.statusCode, 400);
  } finally {
    await withoutStatic.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

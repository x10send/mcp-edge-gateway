import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import test from "node:test";
import {
  buildApp,
  LOGGER_REDACT_PATHS,
  type BuildAppOptions,
} from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";
import { issueToken } from "../src/oauth-token-store.js";
import { StateStore } from "../src/state.js";
import type { DatabaseSync } from "node:sqlite";

type SendUpstream = NonNullable<BuildAppOptions["sendUpstream"]>;
type UpstreamResponse = Awaited<ReturnType<SendUpstream>>;

const config: GatewayConfig = {
  server: { host: "127.0.0.1", port: 8788, logLevel: "silent" },
  diagnostics: { enabled: false, tokenEnv: "GATEWAY_DIAGNOSTICS_TOKEN" },
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

function makeDb(): { db: DatabaseSync; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mcp-app-test-"));
  const store = new StateStore(dir);
  store.open();
  return {
    db: store.database,
    cleanup: () => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

test("health reports liveness without exposing configured routes", async () => {
  const app = buildApp(config);

  const response = await app.inject({ method: "GET", url: "/health" });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { status: "ok" });
  await app.close();
});

test("proxy strips gateway credentials and proxy headers before dispatch", async () => {
  let requestHeaders: Record<string, string | string[]> | undefined;
  const sendUpstream = (async (
    _url: URL,
    options: { headers?: Record<string, string | string[]> },
  ) => {
    requestHeaders = options.headers;
    return upstreamResponse("{}", "application/json");
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: {
      authorization: "Bearer gateway-token",
      cookie: "session=secret",
      "mcp-session-id": "client-session",
      "x-forwarded-for": "203.0.113.2",
      "x-forwarded-custom": "must-not-pass",
      "cf-access-jwt-assertion": "must-not-pass",
    },
  });

  assert.equal(requestHeaders?.authorization, undefined);
  assert.equal(requestHeaders?.cookie, undefined);
  assert.equal(requestHeaders?.["x-forwarded-for"], undefined);
  assert.equal(requestHeaders?.["x-forwarded-custom"], undefined);
  assert.equal(requestHeaders?.["cf-access-jwt-assertion"], undefined);
  assert.equal(requestHeaders?.["mcp-session-id"], "client-session");
  await app.close();
});

test("proxy strips upstream cookies before returning responses", async () => {
  const sendUpstream = (async () =>
    upstreamResponse("{}", "application/json", {
      location: "http://private-upstream.local/secret",
      server: "private-upstream",
      "set-cookie": "upstream=secret",
      "x-powered-by": "private-framework",
    })) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({ method: "GET", url: "/unraid/mcp" });

  assert.equal(response.headers["set-cookie"], undefined);
  assert.equal(response.headers.location, undefined);
  assert.equal(response.headers.server, undefined);
  assert.equal(response.headers["x-powered-by"], undefined);
  await app.close();
});

test("proxy rejects unknown host headers", async () => {
  const app = buildApp(config);

  const response = await app.inject({
    method: "GET",
    url: "/health",
    headers: { host: "attacker.example" },
  });

  assert.equal(response.statusCode, 400);
  await app.close();
});

test("diagnostics require a configured bearer token", async () => {
  const app = buildApp(
    {
      ...config,
      diagnostics: { enabled: true, tokenEnv: "TEST_DIAGNOSTICS_TOKEN" },
    },
    { env: { TEST_DIAGNOSTICS_TOKEN: "00000000000000000000000000000000" } },
  );

  const denied = await app.inject({ method: "GET", url: "/diagnostics" });
  const allowed = await app.inject({
    method: "GET",
    url: "/diagnostics",
    headers: { authorization: "Bearer 00000000000000000000000000000000" },
  });

  assert.equal(denied.statusCode, 401);
  assert.deepEqual(allowed.json(), {
    status: "ok",
    routes: ["/unraid/mcp", "/unraid/sse", "/unraid/messages"],
  });
  await app.close();
});

test("diagnostics fail closed when their token is missing", () => {
  assert.throws(
    () =>
      buildApp(
        {
          ...config,
          diagnostics: { enabled: true, tokenEnv: "MISSING_DIAGNOSTICS_TOKEN" },
        },
        { env: {} },
      ),
    /MISSING_DIAGNOSTICS_TOKEN is not set/,
  );
});

test("diagnostics reject weak bearer tokens at startup", () => {
  assert.throws(
    () =>
      buildApp(
        {
          ...config,
          diagnostics: { enabled: true, tokenEnv: "WEAK_DIAGNOSTICS_TOKEN" },
        },
        { env: { WEAK_DIAGNOSTICS_TOKEN: "too-short" } },
      ),
    /at least 32 characters/,
  );
});

test("body limit rejects oversized requests", async () => {
  const app = buildApp({
    ...config,
    security: { ...config.security, bodyLimitBytes: 16 },
  });

  const response = await app.inject({
    method: "POST",
    url: "/unraid/mcp",
    payload: { value: "this payload is too large" },
  });

  assert.equal(response.statusCode, 413);
  await app.close();
});

test("proxy rejects oversized buffered JSON responses", async () => {
  const sendUpstream = (async () =>
    upstreamResponse(
      '{"value":"too large"}',
      "application/json",
    )) as SendUpstream;
  const app = buildApp(
    {
      ...config,
      security: { ...config.security, jsonResponseLimitBytes: 8 },
    },
    { sendUpstream },
  );

  const response = await app.inject({ method: "GET", url: "/unraid/mcp" });

  assert.equal(response.statusCode, 500);
  await app.close();
});

test("proxy rejects requests above the configured concurrency limit", async () => {
  let resolveUpstream: ((value: UpstreamResponse) => void) | undefined;
  const sendUpstream = (() =>
    new Promise<UpstreamResponse>((resolve) => {
      resolveUpstream = resolve;
    })) as SendUpstream;
  const app = buildApp(
    {
      ...config,
      security: { ...config.security, maxConcurrentRequests: 1 },
    },
    { sendUpstream },
  );

  const firstRequest = app.inject({ method: "GET", url: "/unraid/mcp" });
  await new Promise((resolve) => setImmediate(resolve));
  const rejected = await app.inject({ method: "GET", url: "/health" });
  resolveUpstream?.(upstreamResponse("{}", "application/json"));
  await firstRequest;

  assert.equal(rejected.statusCode, 503, rejected.body);
  await app.close();
});

test("proxy applies configured upstream timeouts and dispatcher", async () => {
  let requestOptions: Record<string, unknown> | undefined;
  const sendUpstream = (async (_url: URL, options: Record<string, unknown>) => {
    requestOptions = options;
    return upstreamResponse("{}", "application/json");
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  await app.inject({ method: "GET", url: "/unraid/mcp" });

  assert.equal(
    requestOptions?.headersTimeout,
    config.security.upstreamHeadersTimeoutMs,
  );
  assert.equal(
    requestOptions?.bodyTimeout,
    config.security.upstreamBodyTimeoutMs,
  );
  assert.ok(requestOptions?.dispatcher);
  await app.close();
});

test("proxy rejects SSE streams above the configured concurrency limit", async () => {
  const streams: PassThrough[] = [];
  const sendUpstream = (async () => {
    const body = new PassThrough();
    streams.push(body);
    return {
      statusCode: 200,
      headers: { "content-type": "text/event-stream" },
      body,
    } as unknown as UpstreamResponse;
  }) as SendUpstream;
  const app = buildApp(
    {
      ...config,
      security: { ...config.security, maxConcurrentStreams: 1 },
    },
    { sendUpstream },
  );

  const firstRequest = app.inject({ method: "GET", url: "/unraid/mcp" });
  await new Promise((resolve) => setImmediate(resolve));
  const rejected = await app.inject({ method: "GET", url: "/unraid/mcp" });
  streams[0]?.end();
  await firstRequest;

  assert.equal(rejected.statusCode, 503, rejected.body);
  await app.close();
});

test("logger redaction covers credential-bearing headers", () => {
  assert.deepEqual(LOGGER_REDACT_PATHS, [
    "req.headers.authorization",
    "req.headers.cookie",
    "req.headers.proxy-authorization",
    "res.headers.set-cookie",
  ]);
});

test("proxy preserves session headers, query strings, and SSE streaming", async () => {
  let requestUrl: URL | undefined;
  let requestHeaders: Record<string, string | string[]> | undefined;
  const sendUpstream = (async (
    url: URL,
    options: { headers?: Record<string, string | string[]> },
  ) => {
    requestUrl = url;
    requestHeaders = options.headers;
    return upstreamResponse(
      "event: message\ndata: streamed\n\n",
      "text/event-stream",
      {
        "mcp-session-id": "upstream-session",
      },
    );
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp?stream=1",
    headers: { "mcp-session-id": "client-session" },
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.body, "event: message\ndata: streamed\n\n");
  assert.equal(response.headers["mcp-session-id"], "upstream-session");
  assert.equal(requestUrl?.search, "?stream=1");
  assert.equal(requestHeaders?.["mcp-session-id"], "client-session");
  await app.close();
});

test("proxy filters denied tools from JSON tools/list responses", async () => {
  const sendUpstream = (async () =>
    upstreamResponse(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: { tools: [{ name: "read_status" }, { name: "run_shell" }] },
      }),
      "application/json",
    )) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "POST",
    url: "/unraid/mcp",
    payload: { jsonrpc: "2.0", id: 1, method: "tools/list" },
  });

  assert.deepEqual(response.json(), {
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: "read_status" }] },
  });
  await app.close();
});

test("proxy rejects denied tools/call requests before upstream dispatch", async () => {
  let dispatchCount = 0;
  const sendUpstream = (async () => {
    dispatchCount += 1;
    return upstreamResponse("{}", "application/json");
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "POST",
    url: "/unraid/mcp",
    payload: {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "restart_server" },
    },
  });

  assert.equal(response.statusCode, 403);
  assert.equal(response.json().error.code, -32001);
  assert.equal(dispatchCount, 0);
  await app.close();
});

test("legacy SSE endpoint proxies to upstream /sse and rewrites endpoint URL", async () => {
  let capturedUrl: URL | undefined;
  const sendUpstream = (async (url: URL) => {
    capturedUrl = url;
    return upstreamResponse(
      "event: endpoint\ndata: http://unraid-agent.local:8043/messages?sessionId=abc\n\n",
      "text/event-stream",
    );
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/sse",
    headers: { host: "localhost:8788" },
  });

  assert.equal(response.statusCode, 200);
  assert.equal(capturedUrl?.pathname, "/sse");
  assert.equal(
    response.body,
    "event: endpoint\ndata: http://localhost:8788/unraid/messages?sessionId=abc\n\n",
  );
  await app.close();
});

test("legacy SSE endpoint preserves query string on endpoint URL", async () => {
  const sendUpstream = (async () =>
    upstreamResponse(
      "event: endpoint\ndata: http://upstream/messages?sessionId=xyz&foo=bar\n\n",
      "text/event-stream",
    )) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/sse",
    headers: { host: "localhost:8788" },
  });

  assert.ok(
    response.body.includes(
      "data: http://localhost:8788/unraid/messages?sessionId=xyz&foo=bar",
    ),
    response.body,
  );
  await app.close();
});

test("legacy SSE endpoint passes non-endpoint events through unchanged", async () => {
  const sendUpstream = (async () =>
    upstreamResponse(
      "event: endpoint\ndata: http://upstream/messages?sessionId=s1\n\nevent: message\ndata: hello\n\n",
      "text/event-stream",
    )) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/sse",
    headers: { host: "localhost" },
  });

  assert.ok(response.body.includes("event: message\ndata: hello\n\n"));
  await app.close();
});

test("legacy SSE endpoint rewrites endpoint URL when data arrives in multiple chunks", async () => {
  const sendUpstream = (async () => {
    const body = new PassThrough();
    // Emit endpoint event in chunk 1, then a message event in chunk 2
    setImmediate(() => {
      body.write(
        "event: endpoint\ndata: http://upstream/messages?sessionId=s2\n\n",
      );
      body.end("event: message\ndata: late\n\n");
    });
    return {
      statusCode: 200,
      headers: { "content-type": "text/event-stream" },
      body,
    } as unknown as UpstreamResponse;
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/sse",
    headers: { host: "localhost:8788" },
  });

  assert.ok(
    response.body.includes(
      "data: http://localhost:8788/unraid/messages?sessionId=s2",
    ),
  );
  assert.ok(response.body.includes("event: message\ndata: late\n\n"));
  await app.close();
});

test("legacy SSE endpoint handles non-endpoint events arriving before the endpoint event", async () => {
  const sendUpstream = (async () =>
    upstreamResponse(
      "event: message\ndata: early\n\nevent: endpoint\ndata: http://upstream/messages?sessionId=s3\n\n",
      "text/event-stream",
    )) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/sse",
    headers: { host: "localhost:8788" },
  });

  assert.ok(response.body.includes("event: message\ndata: early\n\n"));
  assert.ok(
    response.body.includes(
      "data: http://localhost:8788/unraid/messages?sessionId=s3",
    ),
  );
  await app.close();
});

test("legacy SSE endpoint rewrites endpoint URL when data field is not a valid URL", async () => {
  const sendUpstream = (async () =>
    upstreamResponse(
      "event: endpoint\ndata: /messages?sessionId=s4\n\n",
      "text/event-stream",
    )) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/sse",
    headers: { host: "localhost:8788" },
  });

  // Malformed base URL falls back to extracting the query string by index
  assert.ok(
    response.body.includes(
      "data: http://localhost:8788/unraid/messages?sessionId=s4",
    ),
  );
  await app.close();
});

test("proxy returns upstream 3xx responses without following redirects", async () => {
  const sendUpstream = (async () => {
    const body = Readable.from([""]);
    return {
      statusCode: 301,
      headers: {
        "content-type": "text/html",
        location: "http://internal.local/secret",
      },
      body,
    } as unknown as UpstreamResponse;
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  const response = await app.inject({ method: "GET", url: "/unraid/mcp" });

  // Gateway forwards the 301 status but strips the Location header.
  assert.equal(response.statusCode, 301);
  assert.equal(
    response.headers.location,
    undefined,
    "Location header must be stripped",
  );
  await app.close();
});

test("legacy SSE messages endpoint proxies to upstream /messages with tool policy", async () => {
  let capturedUrl: URL | undefined;
  let dispatchCount = 0;
  const sendUpstream = (async (url: URL) => {
    capturedUrl = url;
    dispatchCount += 1;
    return upstreamResponse("{}", "application/json");
  }) as SendUpstream;
  const app = buildApp(config, { sendUpstream });

  // Allowed tool call reaches upstream
  const allowed = await app.inject({
    method: "POST",
    url: "/unraid/messages?sessionId=abc",
    payload: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "read_status" },
    },
  });
  assert.equal(allowed.statusCode, 200);
  assert.equal(capturedUrl?.pathname, "/messages");
  assert.equal(capturedUrl?.search, "?sessionId=abc");

  // Denied tool call is blocked before upstream
  const denied = await app.inject({
    method: "POST",
    url: "/unraid/messages",
    payload: {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "run_shell" },
    },
  });
  assert.equal(denied.statusCode, 403);
  assert.equal(dispatchCount, 1); // only the allowed call reached upstream

  await app.close();
});

test("root protected-resource metadata endpoint returns RFC 9728 document", async () => {
  const app = buildApp(config);

  const response = await app.inject({
    method: "GET",
    url: "/.well-known/oauth-protected-resource",
    headers: { host: "localhost" },
  });

  assert.equal(response.statusCode, 200);
  assert.equal(
    response.headers["content-type"],
    "application/json; charset=utf-8",
  );
  const body = response.json();
  assert.equal(body.resource, "http://localhost");
  assert.deepEqual(body.bearer_methods_supported, ["header"]);
  await app.close();
});

test("per-route protected-resource metadata endpoint returns route-scoped document", async () => {
  const app = buildApp(config);

  const response = await app.inject({
    method: "GET",
    url: "/unraid/.well-known/oauth-protected-resource",
    headers: { host: "localhost" },
  });

  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.resource, "http://localhost/unraid");
  assert.deepEqual(body.bearer_methods_supported, ["header"]);
  await app.close();
});

test("proxy rejects access_token in query string with 400", async () => {
  const app = buildApp(config);

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp?access_token=secret",
    headers: { host: "localhost" },
  });

  assert.equal(response.statusCode, 400);
  assert.ok(response.json().error.includes("query string"));
  await app.close();
});

test("proxy allows request without auth when requireAuth is false and no requiredScopes", async () => {
  const { db, cleanup } = makeDb();
  const sendUpstream = (async () =>
    upstreamResponse("{}", "application/json")) as SendUpstream;
  const app = buildApp(config, { sendUpstream, db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost" },
  });

  assert.equal(response.statusCode, 200);
  await app.close();
  cleanup();
});

test("proxy requires auth when security.requireAuth is true", async () => {
  const { db, cleanup } = makeDb();
  const authConfig: GatewayConfig = {
    ...config,
    security: { ...config.security, requireAuth: true },
  };
  const app = buildApp(authConfig, { db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost" },
  });

  assert.equal(response.statusCode, 401);
  assert.ok(response.headers["www-authenticate"]);
  assert.ok(
    (response.headers["www-authenticate"] as string).includes("Bearer realm"),
  );
  await app.close();
  cleanup();
});

test("proxy requires auth when route has requiredScopes", async () => {
  const { db, cleanup } = makeDb();
  const authConfig: GatewayConfig = {
    ...config,
    routes: [
      {
        path: "/unraid",
        upstream: "http://unraid-agent.local:8043",
        requiredScopes: ["read"],
      },
    ],
  };
  const app = buildApp(authConfig, { db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost" },
  });

  assert.equal(response.statusCode, 401);
  await app.close();
  cleanup();
});

test("proxy returns 401 for invalid Bearer token", async () => {
  const { db, cleanup } = makeDb();
  const authConfig: GatewayConfig = {
    ...config,
    security: { ...config.security, requireAuth: true },
  };
  const app = buildApp(authConfig, { db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: "Bearer invalid-token" },
  });

  assert.equal(response.statusCode, 401);
  const wwwAuth = response.headers["www-authenticate"] as string;
  assert.ok(wwwAuth.includes("invalid_token"));
  await app.close();
  cleanup();
});

test("proxy returns 403 when token lacks required scope", async () => {
  const { db, cleanup } = makeDb();
  const { plaintext } = issueToken(db, { scope: "read" });
  const authConfig: GatewayConfig = {
    ...config,
    routes: [
      {
        path: "/unraid",
        upstream: "http://unraid-agent.local:8043",
        requiredScopes: ["write"],
      },
    ],
  };
  const app = buildApp(authConfig, { db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: `Bearer ${plaintext}` },
  });

  assert.equal(response.statusCode, 403);
  const wwwAuth = response.headers["www-authenticate"] as string;
  assert.ok(wwwAuth.includes("insufficient_scope"));
  await app.close();
  cleanup();
});

test("proxy allows request with valid token and correct scope", async () => {
  const { db, cleanup } = makeDb();
  const { plaintext } = issueToken(db, { scope: "read write" });
  const sendUpstream = (async () =>
    upstreamResponse("{}", "application/json")) as SendUpstream;
  const authConfig: GatewayConfig = {
    ...config,
    routes: [
      {
        path: "/unraid",
        upstream: "http://unraid-agent.local:8043",
        requiredScopes: ["read"],
      },
    ],
  };
  const app = buildApp(authConfig, { sendUpstream, db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: `Bearer ${plaintext}` },
  });

  assert.equal(response.statusCode, 200);
  await app.close();
  cleanup();
});

test("proxy returns 403 when token lacks scope for specific tool", async () => {
  const { db, cleanup } = makeDb();
  const { plaintext } = issueToken(db, { scope: "read" }); // no 'admin' scope
  const sendUpstream = (async () =>
    upstreamResponse("{}", "application/json")) as SendUpstream;
  const authConfig: GatewayConfig = {
    ...config,
    security: { ...config.security, requireAuth: true },
    routes: [
      {
        path: "/unraid",
        upstream: "http://unraid-agent.local:8043",
        tools: {
          toolScopes: { read_status: ["read"], dangerous_op: ["admin"] },
        },
      },
    ],
  };
  const app = buildApp(authConfig, { sendUpstream, db });

  const denied = await app.inject({
    method: "POST",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: `Bearer ${plaintext}` },
    payload: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "dangerous_op" },
    },
  });
  assert.equal(denied.statusCode, 403);
  assert.ok(denied.json().error.includes("dangerous_op"));

  // Allowed tool (token has 'read' scope)
  const allowed = await app.inject({
    method: "POST",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: `Bearer ${plaintext}` },
    payload: {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "read_status" },
    },
  });
  assert.equal(allowed.statusCode, 200);

  await app.close();
  cleanup();
});

test("proxy accepts lowercase 'bearer' scheme in Authorization header (RFC 7235 case-insensitive)", async () => {
  const { db, cleanup } = makeDb();
  const { plaintext } = issueToken(db, {});
  const sendUpstream = (async () =>
    upstreamResponse("{}", "application/json")) as SendUpstream;
  const authConfig: GatewayConfig = {
    ...config,
    security: { ...config.security, requireAuth: true },
  };
  const app = buildApp(authConfig, { sendUpstream, db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: `bearer ${plaintext}` },
  });

  assert.equal(
    response.statusCode,
    200,
    "lowercase bearer scheme should be accepted",
  );
  await app.close();
  cleanup();
});

test("tool-scope check with prototype-key tool name does not crash (DoS regression)", async () => {
  const { db, cleanup } = makeDb();
  const { plaintext } = issueToken(db, { scope: "read" });
  const sendUpstream = (async () =>
    upstreamResponse("{}", "application/json")) as SendUpstream;
  const authConfig: GatewayConfig = {
    ...config,
    security: { ...config.security, requireAuth: true },
    routes: [
      {
        path: "/unraid",
        upstream: "http://unraid-agent.local:8043",
        tools: { toolScopes: { safe_tool: ["read"] } },
      },
    ],
  };
  const app = buildApp(authConfig, { sendUpstream, db });

  // Sending __proto__ as tool name must not cause a 500
  const response = await app.inject({
    method: "POST",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: `Bearer ${plaintext}` },
    payload: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "__proto__" },
    },
  });

  assert.notEqual(
    response.statusCode,
    500,
    "__proto__ tool name must not cause a server error",
  );
  await app.close();
  cleanup();
});

test("proxy returns 401 when token is scoped to a different route", async () => {
  const { db, cleanup } = makeDb();
  const { plaintext } = issueToken(db, { routes: ["/other-route"] });
  const authConfig: GatewayConfig = {
    ...config,
    security: { ...config.security, requireAuth: true },
  };
  const app = buildApp(authConfig, { db });

  const response = await app.inject({
    method: "GET",
    url: "/unraid/mcp",
    headers: { host: "localhost", authorization: `Bearer ${plaintext}` },
  });

  assert.equal(response.statusCode, 401);
  await app.close();
  cleanup();
});

function upstreamResponse(
  payload: string,
  contentType: string,
  additionalHeaders: Record<string, string> = {},
): UpstreamResponse {
  const body = Readable.from([payload]);
  Object.assign(body, { text: async () => payload });

  return {
    statusCode: 200,
    headers: { "content-type": contentType, ...additionalHeaders },
    body,
  } as unknown as UpstreamResponse;
}

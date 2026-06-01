import assert from "node:assert/strict";
import { PassThrough, Readable } from "node:stream";
import test from "node:test";
import {
  buildApp,
  LOGGER_REDACT_PATHS,
  type BuildAppOptions,
} from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";

type SendUpstream = NonNullable<BuildAppOptions["sendUpstream"]>;
type UpstreamResponse = Awaited<ReturnType<SendUpstream>>;

const config: GatewayConfig = {
  server: { host: "127.0.0.1", port: 8788, logLevel: "silent" },
  diagnostics: { enabled: false, tokenEnv: "GATEWAY_DIAGNOSTICS_TOKEN" },
  security: {
    allowedHosts: ["localhost", "127.0.0.1"],
    trustedProxies: [],
    allowPrivateUpstreamsOnly: true,
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
  routes: [
    { path: "/unraid/mcp", upstream: "http://unraid-agent.local:8043/mcp" },
  ],
};

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
    { env: { TEST_DIAGNOSTICS_TOKEN: "diagnostic-secret-with-32-characters" } },
  );

  const denied = await app.inject({ method: "GET", url: "/diagnostics" });
  const allowed = await app.inject({
    method: "GET",
    url: "/diagnostics",
    headers: { authorization: "Bearer diagnostic-secret-with-32-characters" },
  });

  assert.equal(denied.statusCode, 401);
  assert.deepEqual(allowed.json(), {
    status: "ok",
    routes: ["/unraid/mcp"],
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

import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";
import { buildApp, type BuildAppOptions } from "../src/app.js";
import type { GatewayConfig } from "../src/config.js";

type SendUpstream = NonNullable<BuildAppOptions["sendUpstream"]>;
type UpstreamResponse = Awaited<ReturnType<SendUpstream>>;

const config: GatewayConfig = {
  server: { host: "127.0.0.1", port: 8788, logLevel: "silent" },
  tools: {},
  routes: [
    { path: "/unraid/mcp", upstream: "http://unraid-agent.local:8043/mcp" },
  ],
};

test("health reports configured routes", async () => {
  const app = buildApp(config);

  const response = await app.inject({ method: "GET", url: "/health" });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { status: "ok", routes: ["/unraid/mcp"] });
  await app.close();
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

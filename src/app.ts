import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { request as defaultSendUpstream, type Dispatcher } from "undici";
import type { GatewayConfig, RouteConfig } from "./config.js";
import { ToolPolicy } from "./tool-policy.js";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export interface BuildAppOptions {
  sendUpstream?: typeof defaultSendUpstream;
}

export function buildApp(config: GatewayConfig, options: BuildAppOptions = {}) {
  const sendUpstream = options.sendUpstream ?? defaultSendUpstream;
  const app = Fastify({
    logger: { level: config.server.logLevel },
    trustProxy: true,
  });

  app.get("/health", async () => ({
    status: "ok",
    routes: config.routes.map((route) => route.path),
  }));

  for (const route of config.routes) {
    const policy = new ToolPolicy(config.tools, route.tools);
    app.route({
      method: ["GET", "POST", "DELETE"],
      url: route.path,
      handler: createProxyHandler(route, policy, sendUpstream),
    });
  }

  return app;
}

function createProxyHandler(
  route: RouteConfig,
  policy: ToolPolicy,
  sendUpstream: typeof defaultSendUpstream,
) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const body = serializeBody(request.body);
    const jsonBody = parseJson(body);
    const blockedCall = policy.findBlockedCall(jsonBody);

    if (blockedCall) {
      request.log.warn(
        { route: route.path, tool: blockedCall.name },
        "blocked MCP tool call",
      );
      return reply.code(403).send({
        jsonrpc: "2.0",
        id: blockedCall.id,
        error: {
          code: -32001,
          message: "Tool call blocked by gateway policy",
          data: { tool: blockedCall.name, reason: blockedCall.reason },
        },
      });
    }

    const upstreamUrl = buildUpstreamUrl(route.upstream, request.raw.url);
    request.log.info(
      {
        route: route.path,
        upstream: upstreamUrl.origin,
        hasSessionId: request.headers["mcp-session-id"] !== undefined,
      },
      "proxying MCP request",
    );

    const upstream = await sendUpstream(upstreamUrl, {
      method: request.method as Dispatcher.HttpMethod,
      headers: copyRequestHeaders(request.headers),
      body,
    });

    copyResponseHeaders(upstream.headers, reply);
    reply.code(upstream.statusCode);

    const contentType = headerValue(upstream.headers["content-type"]);
    if (contentType?.toLowerCase().startsWith("application/json")) {
      const responseText = await upstream.body.text();
      const responseJson = parseJson(responseText);
      if (responseJson !== undefined) {
        reply.removeHeader("content-length");
        return reply.send(
          JSON.stringify(policy.filterToolsListPayload(responseJson)),
        );
      }
      return reply.send(responseText);
    }

    return reply.send(upstream.body);
  };
}

function buildUpstreamUrl(
  upstream: string,
  incomingUrl: string | undefined,
): URL {
  const target = new URL(upstream);
  if (incomingUrl) {
    target.search = new URL(incomingUrl, "http://gateway.local").search;
  }
  return target;
}

function serializeBody(body: unknown): string | Buffer | undefined {
  if (body === undefined || body === null) {
    return undefined;
  }
  if (typeof body === "string" || Buffer.isBuffer(body)) {
    return body;
  }
  return JSON.stringify(body);
}

function parseJson(body: string | Buffer | undefined): unknown {
  if (body === undefined) {
    return undefined;
  }
  try {
    return JSON.parse(body.toString());
  } catch {
    return undefined;
  }
}

function copyRequestHeaders(
  headers: FastifyRequest["headers"],
): Record<string, string | string[]> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter(
        ([name, value]) =>
          value !== undefined && !HOP_BY_HOP_HEADERS.has(name.toLowerCase()),
      )
      .filter(([name]) => name.toLowerCase() !== "host")
      .map(([name, value]) => [name, value as string | string[]]),
  );
}

function copyResponseHeaders(
  headers: Record<string, string | string[] | undefined>,
  reply: FastifyReply,
): void {
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined && !HOP_BY_HOP_HEADERS.has(name.toLowerCase())) {
      reply.header(name, value);
    }
  }
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

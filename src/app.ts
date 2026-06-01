import { createHash, timingSafeEqual } from "node:crypto";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { request as defaultSendUpstream, type Dispatcher } from "undici";
import type { GatewayConfig, RouteConfig } from "./config.js";
import { ToolPolicy } from "./tool-policy.js";
import { createUpstreamDispatcher } from "./upstream-dispatcher.js";

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

const SENSITIVE_REQUEST_HEADERS = new Set([
  "authorization",
  "cookie",
  "forwarded",
  "proxy-authorization",
  "x-real-ip",
]);

const SENSITIVE_RESPONSE_HEADERS = new Set([
  "location",
  "server",
  "set-cookie",
  "x-powered-by",
]);

export const LOGGER_REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  "req.headers.proxy-authorization",
  "res.headers.set-cookie",
];

export interface BuildAppOptions {
  sendUpstream?: typeof defaultSendUpstream;
  env?: NodeJS.ProcessEnv;
}

export function buildApp(config: GatewayConfig, options: BuildAppOptions = {}) {
  const sendUpstream = options.sendUpstream ?? defaultSendUpstream;
  const env = options.env ?? process.env;
  const diagnosticToken = config.diagnostics.enabled
    ? env[config.diagnostics.tokenEnv]
    : undefined;
  if (config.diagnostics.enabled && !diagnosticToken) {
    throw new Error(
      `Diagnostics are enabled but ${config.diagnostics.tokenEnv} is not set`,
    );
  }
  if (diagnosticToken && diagnosticToken.length < 32) {
    throw new Error("Diagnostics token must contain at least 32 characters");
  }

  const upstreamDispatcher = createUpstreamDispatcher(config.security);
  let activeRequests = 0;
  let activeStreams = 0;

  const app = Fastify({
    bodyLimit: config.security.bodyLimitBytes,
    logger: {
      level: config.server.logLevel,
      redact: {
        paths: LOGGER_REDACT_PATHS,
        censor: "[REDACTED]",
      },
    },
    trustProxy:
      config.security.trustedProxies.length > 0
        ? config.security.trustedProxies
        : false,
  });

  app.get("/health", async () => ({
    status: "ok",
  }));

  app.addHook("onClose", async () => {
    await upstreamDispatcher.close();
  });

  if (config.diagnostics.enabled) {
    app.get("/diagnostics", async (request, reply) => {
      if (
        !hasBearerToken(
          request.headers.authorization,
          diagnosticToken as string,
        )
      ) {
        return reply.code(401).send({ error: "Unauthorized" });
      }
      return {
        status: "ok",
        routes: config.routes.map((route) => route.path),
      };
    });
  }

  app.addHook("onRequest", async (request, reply) => {
    if (!isAllowedHost(request.headers.host, config.security.allowedHosts)) {
      return reply.code(400).send({ error: "Invalid Host header" });
    }
    if (activeRequests >= config.security.maxConcurrentRequests) {
      return reply.code(503).send({ error: "Too many concurrent requests" });
    }

    activeRequests += 1;
    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        activeRequests -= 1;
      }
    };
    reply.raw.once("close", release);
    reply.raw.once("finish", release);
  });

  for (const route of config.routes) {
    const policy = new ToolPolicy(config.tools, route.tools);
    app.route({
      method: ["GET", "POST", "DELETE"],
      url: route.path,
      handler: createProxyHandler(
        route,
        policy,
        sendUpstream,
        upstreamDispatcher,
        config,
        () => {
          if (activeStreams >= config.security.maxConcurrentStreams) {
            return undefined;
          }
          activeStreams += 1;
          let released = false;
          return () => {
            if (!released) {
              released = true;
              activeStreams -= 1;
            }
          };
        },
      ),
    });
  }

  return app;
}

function createProxyHandler(
  route: RouteConfig,
  policy: ToolPolicy,
  sendUpstream: typeof defaultSendUpstream,
  upstreamDispatcher: Dispatcher,
  config: GatewayConfig,
  acquireStream: () => (() => void) | undefined,
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
      headersTimeout: config.security.upstreamHeadersTimeoutMs,
      bodyTimeout: config.security.upstreamBodyTimeoutMs,
      dispatcher: upstreamDispatcher,
    });

    copyResponseHeaders(upstream.headers, reply);
    reply.code(upstream.statusCode);

    const contentType = headerValue(upstream.headers["content-type"]);
    if (contentType?.toLowerCase().startsWith("application/json")) {
      const responseText = await readBoundedText(
        upstream.body,
        config.security.jsonResponseLimitBytes,
      );
      const responseJson = parseJson(responseText);
      if (responseJson !== undefined) {
        reply.removeHeader("content-length");
        return reply.send(
          JSON.stringify(policy.filterToolsListPayload(responseJson)),
        );
      }
      return reply.send(responseText);
    }

    if (contentType?.toLowerCase().startsWith("text/event-stream")) {
      const releaseStream = acquireStream();
      if (!releaseStream) {
        upstream.body.destroy();
        reply.removeHeader("content-type");
        return reply.code(503).send({ error: "Too many concurrent streams" });
      }

      const timeout = setTimeout(() => {
        upstream.body.destroy(new Error("SSE stream lifetime limit exceeded"));
      }, config.security.sseMaxDurationMs);
      timeout.unref();

      const release = () => {
        clearTimeout(timeout);
        releaseStream();
      };
      reply.raw.once("close", release);
      reply.raw.once("finish", release);
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
          value !== undefined &&
          !HOP_BY_HOP_HEADERS.has(name.toLowerCase()) &&
          isForwardableRequestHeader(name),
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
    if (
      value !== undefined &&
      !HOP_BY_HOP_HEADERS.has(name.toLowerCase()) &&
      !SENSITIVE_RESPONSE_HEADERS.has(name.toLowerCase())
    ) {
      reply.header(name, value);
    }
  }
}

function isForwardableRequestHeader(name: string): boolean {
  const normalized = name.toLowerCase();
  return (
    !SENSITIVE_REQUEST_HEADERS.has(normalized) &&
    !normalized.startsWith("cf-") &&
    !normalized.startsWith("x-forwarded-")
  );
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

async function readBoundedText(
  body: Dispatcher.ResponseData["body"],
  limitBytes: number,
): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of body) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > limitBytes) {
      body.destroy();
      throw new Error("Upstream JSON response exceeded configured limit");
    }
    chunks.push(buffer);
  }

  return Buffer.concat(chunks).toString("utf8");
}

function isAllowedHost(
  host: string | undefined,
  allowedHosts: string[],
): boolean {
  if (!host) {
    return false;
  }

  const hostname = host.startsWith("[")
    ? host.slice(1, host.indexOf("]"))
    : host.split(":")[0];
  return allowedHosts.some(
    (allowedHost) =>
      allowedHost.replace(/^\[|\]$/g, "").toLowerCase() ===
      hostname.toLowerCase(),
  );
}

function hasBearerToken(
  header: string | undefined,
  expectedToken: string,
): boolean {
  if (!header?.startsWith("Bearer ")) {
    return false;
  }

  const actualHash = createHash("sha256").update(header.slice(7)).digest();
  const expectedHash = createHash("sha256").update(expectedToken).digest();
  return timingSafeEqual(actualHash, expectedHash);
}

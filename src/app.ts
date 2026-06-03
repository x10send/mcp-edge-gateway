import { createHash, timingSafeEqual } from "node:crypto";
import { Readable } from "node:stream";
import type { DatabaseSync } from "node:sqlite";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifyFormbody from "@fastify/formbody";
import {
  errors as undiciErrors,
  request as defaultSendUpstream,
  type Dispatcher,
} from "undici";
import type { GatewayConfig, UpstreamAuthConfig } from "./config.js";
import { hasScope, lookupToken } from "./oauth-token-store.js";
import {
  registerOAuthAuthorizationServer,
  type RegisterOAuthOptions,
} from "./oauth-authorization-server.js";
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
  "req.body.code",
  "req.body.code_verifier",
  "req.body.password",
  "req.body.refresh_token",
  "req.body.token",
  "res.headers.set-cookie",
];

interface RouteAuthOptions {
  db: DatabaseSync;
  requireAuth: boolean;
  requiredScopes: string[];
  toolScopes: Record<string, string[]>;
}

export interface BuildAppOptions {
  sendUpstream?: typeof defaultSendUpstream;
  env?: NodeJS.ProcessEnv;
  db?: DatabaseSync;
  oauth?: RegisterOAuthOptions;
}

export function buildApp(config: GatewayConfig, options: BuildAppOptions = {}) {
  const sendUpstream = options.sendUpstream ?? defaultSendUpstream;
  const env = options.env ?? process.env;
  const db = options.db;
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
  if (
    !config.security.requireAuth &&
    !config.security.insecureAllowUnauthenticatedMcp
  ) {
    throw new Error(
      "Unauthenticated MCP requires security.insecureAllowUnauthenticatedMcp",
    );
  }
  if (
    config.security.publicOrigin.startsWith("http:") &&
    !config.security.insecureAllowHttpPublicOrigin
  ) {
    throw new Error(
      "HTTP publicOrigin requires security.insecureAllowHttpPublicOrigin",
    );
  }

  // Fail fast if auth is required by config but no database was provided.
  // Without a db, routeAuth is undefined and auth checks are silently skipped.
  const authRequired =
    config.oauth.enabled ||
    config.security.requireAuth ||
    config.routes.some((r) => r.requiredScopes && r.requiredScopes.length > 0);
  if (authRequired && !db) {
    throw new Error(
      "A database (options.db) is required when requireAuth or requiredScopes are configured",
    );
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
  // Accept any content type for proxy passthrough. Fastify's built-in
  // application/json parser takes precedence; this catches everything else
  // (e.g. no Content-Type, text/plain variants, multipart) so MCP clients
  // that don't send a recognised type don't get a 415 before they reach auth.
  app.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) => {
    done(null, body);
  });

  if (config.oauth.enabled) {
    void app.register(fastifyCookie);
    void app.register(fastifyFormbody);
    registerOAuthAuthorizationServer(
      app,
      config,
      db as DatabaseSync,
      options.oauth,
    );
  }

  app.get("/health", async () => ({
    status: "ok",
  }));

  app.get("/.well-known/oauth-protected-resource", async (_request, reply) => {
    return reply.type("application/json").send({
      resource: config.security.publicOrigin,
      bearer_methods_supported: ["header"],
      ...(config.oauth.enabled
        ? { authorization_servers: [config.oauth.issuer] }
        : {}),
    });
  });

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
        routes: config.routes.flatMap((route) => [
          `${route.path}/mcp`,
          `${route.path}/sse`,
          `${route.path}/messages`,
        ]),
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

  const acquireStreamSlot = () => {
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
  };

  for (const route of config.routes) {
    const policy = new ToolPolicy(config.tools, route.tools);
    const mcpUpstream = appendSubpath(route.upstream, "/mcp");
    const sseUpstream = appendSubpath(route.upstream, "/sse");
    const messagesUpstream = appendSubpath(route.upstream, "/messages");
    const messagesGatewayPath = `${route.path}/messages`;
    const protectedResourcePath = `/.well-known/oauth-protected-resource${route.path}/mcp`;
    const protectedResource = `${config.security.publicOrigin}${route.path}/mcp`;

    const routeAuth: RouteAuthOptions | undefined = db
      ? {
          db,
          requireAuth: config.security.requireAuth,
          requiredScopes: route.requiredScopes ?? [],
          toolScopes: route.tools?.toolScopes ?? {},
        }
      : undefined;

    // Per-route protected resource metadata (RFC 9728)
    app.get(protectedResourcePath, async (_request, reply) => {
      return reply.type("application/json").send({
        resource: protectedResource,
        bearer_methods_supported: ["header"],
        ...(config.oauth.enabled
          ? { authorization_servers: [config.oauth.issuer] }
          : {}),
      });
    });

    // Streamable HTTP transport
    app.route({
      method: ["GET", "POST", "DELETE"],
      url: `${route.path}/mcp`,
      handler: createProxyHandler(
        mcpUpstream,
        route.path,
        policy,
        sendUpstream,
        upstreamDispatcher,
        config,
        acquireStreamSlot,
        undefined,
        routeAuth,
        route.upstreamAuth,
        env,
      ),
    });

    // Legacy SSE transport — SSE connection (GET, rewrites endpoint URL)
    app.route({
      method: ["GET"],
      url: `${route.path}/sse`,
      handler: createProxyHandler(
        sseUpstream,
        route.path,
        policy,
        sendUpstream,
        upstreamDispatcher,
        config,
        acquireStreamSlot,
        messagesGatewayPath,
        routeAuth,
        route.upstreamAuth,
        env,
      ),
    });

    // Legacy SSE transport — messages (POST/DELETE, tool policy applies)
    app.route({
      method: ["POST", "DELETE"],
      url: `${route.path}/messages`,
      handler: createProxyHandler(
        messagesUpstream,
        route.path,
        policy,
        sendUpstream,
        upstreamDispatcher,
        config,
        acquireStreamSlot,
        undefined,
        routeAuth,
        route.upstreamAuth,
        env,
      ),
    });
  }

  return app;
}

function createProxyHandler(
  upstreamUrl: string,
  routePath: string,
  policy: ToolPolicy,
  sendUpstream: typeof defaultSendUpstream,
  upstreamDispatcher: Dispatcher,
  config: GatewayConfig,
  acquireStream: () => (() => void) | undefined,
  // When set, rewrites SSE endpoint events to point at this gateway path
  sseEndpointGatewayPath?: string,
  routeAuth?: RouteAuthOptions,
  upstreamAuthConfig?: UpstreamAuthConfig,
  env?: NodeJS.ProcessEnv,
) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    // Reject access_token in query string — RFC 6750 §2.3 deprecates URI tokens
    // because they end up in logs and browser history. We advertise header-only.
    const incomingQs = new URL(request.raw.url ?? "/", "http://gateway.local")
      .searchParams;
    if (incomingQs.has("access_token")) {
      return reply.code(400).send({
        error:
          "Bearer tokens in query strings are not supported; use Authorization header",
      });
    }

    // OAuth Bearer token enforcement
    let tokenScope: string | undefined;
    if (
      routeAuth &&
      (routeAuth.requireAuth || routeAuth.requiredScopes.length > 0)
    ) {
      const metadataUrl = `${config.security.publicOrigin}/.well-known/oauth-protected-resource${routePath}/mcp`;
      const requiredScopeParameter =
        routeAuth.requiredScopes.length > 0
          ? `, scope="${routeAuth.requiredScopes.join(" ")}"`
          : "";
      const authHeader = request.headers.authorization;
      // RFC 7235 §2.1: auth-scheme is case-insensitive
      if (!authHeader || !/^bearer /i.test(authHeader)) {
        reply.header(
          "WWW-Authenticate",
          `Bearer realm="MCP Gateway", resource_metadata="${metadataUrl}"${requiredScopeParameter}`,
        );
        return reply.code(401).send({ error: "Authorization required" });
      }
      const tokenResult = lookupToken(
        routeAuth.db,
        authHeader.slice(authHeader.indexOf(" ") + 1),
        routePath,
      );
      if (!tokenResult) {
        reply.header(
          "WWW-Authenticate",
          `Bearer realm="MCP Gateway", error="invalid_token", resource_metadata="${metadataUrl}"${requiredScopeParameter}`,
        );
        return reply.code(401).send({ error: "Invalid or expired token" });
      }
      if (!hasScope(tokenResult.scope, routeAuth.requiredScopes)) {
        reply.header(
          "WWW-Authenticate",
          `Bearer realm="MCP Gateway", error="insufficient_scope", scope="${routeAuth.requiredScopes.join(" ")}"`,
        );
        return reply.code(403).send({ error: "Insufficient scope" });
      }
      tokenScope = tokenResult.scope;
    }

    const body = serializeBody(request.body);
    const jsonBody = parseJson(body);
    const blockedCall = policy.findBlockedCall(jsonBody);

    if (blockedCall) {
      request.log.warn(
        { route: routePath, tool: blockedCall.name },
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

    // Tool-scope enforcement (only when auth is active and toolScopes configured)
    if (
      tokenScope !== undefined &&
      routeAuth &&
      Object.keys(routeAuth.toolScopes).length > 0
    ) {
      const toolName = extractToolCallName(jsonBody);
      if (toolName) {
        // Object.hasOwn prevents prototype-inherited keys (__proto__, constructor, etc.)
        // from resolving to non-array values and crashing the .every() call in hasScope.
        const required = Object.hasOwn(routeAuth.toolScopes, toolName)
          ? routeAuth.toolScopes[toolName]!
          : [];
        if (!hasScope(tokenScope, required)) {
          reply.header(
            "WWW-Authenticate",
            `Bearer realm="MCP Gateway", error="insufficient_scope", scope="${required.join(" ")}"`,
          );
          return reply.code(403).send({
            error: `Insufficient scope for tool '${toolName}'`,
          });
        }
      }
    }

    const targetUrl = buildUpstreamUrl(upstreamUrl, request.raw.url);
    request.log.info(
      {
        route: routePath,
        upstream: targetUrl.origin,
        hasSessionId: request.headers["mcp-session-id"] !== undefined,
      },
      "proxying MCP request",
    );

    const upstreamHeaders = copyRequestHeaders(request.headers);
    if (upstreamAuthConfig) {
      const authHeader = buildUpstreamAuthHeader(upstreamAuthConfig, env ?? {});
      if (!authHeader) {
        return reply.code(502).send({
          error: "Upstream authentication is misconfigured",
        });
      }
      upstreamHeaders[authHeader.name] = authHeader.value;
    }

    // undici default maxRedirections is 0; redirects are never followed.
    let upstream: Dispatcher.ResponseData;
    try {
      upstream = await sendUpstream(targetUrl, {
        method: request.method as Dispatcher.HttpMethod,
        headers: upstreamHeaders,
        body,
        headersTimeout: config.security.upstreamHeadersTimeoutMs,
        bodyTimeout: config.security.upstreamBodyTimeoutMs,
        dispatcher: upstreamDispatcher,
      });
    } catch (err) {
      const isHeadersTimeout = err instanceof undiciErrors.HeadersTimeoutError;
      const isTimeout =
        isHeadersTimeout ||
        err instanceof undiciErrors.BodyTimeoutError ||
        err instanceof undiciErrors.ConnectTimeoutError;
      request.log.warn({ route: routePath, err }, "upstream request failed");
      // GET /mcp that gets no response headers means the upstream doesn't
      // support the SSE stream endpoint — return 405 so clients fall back to POST.
      if (isHeadersTimeout && request.method === "GET") {
        return reply.code(405).send({ error: "Method not allowed" });
      }
      return reply.code(isTimeout ? 504 : 502).send({
        error: isTimeout ? "Upstream timed out" : "Upstream unavailable",
      });
    }

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
      // Stateless transport: POST to /mcp returns a bounded SSE response.
      // Buffer it and apply tool-list filtering the same way JSON responses are.
      if (!sseEndpointGatewayPath && request.method === "POST") {
        const responseText = await readBoundedText(
          upstream.body,
          config.security.jsonResponseLimitBytes,
        );
        reply.removeHeader("content-length");
        return reply.send(filterSseToolsList(responseText, policy));
      }

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

      if (sseEndpointGatewayPath) {
        const messagesUrl = `${config.security.publicOrigin}${sseEndpointGatewayPath}`;
        return reply.send(
          Readable.from(rewriteSseEndpointEvent(upstream.body, messagesUrl)),
        );
      }
    }

    return reply.send(upstream.body);
  };
}

// Rewrites the SSE "endpoint" event URL to the gateway's messages URL.
// After the endpoint event is found and rewritten, subsequent chunks pass through unchanged.
async function* rewriteSseEndpointEvent(
  body: AsyncIterable<Buffer>,
  messagesUrl: string,
): AsyncGenerator<string | Buffer> {
  let pending = "";
  let rewrote = false;

  for await (const chunk of body) {
    if (rewrote) {
      if (pending) {
        yield pending;
        pending = "";
      }
      yield chunk;
      continue;
    }

    pending += chunk.toString("utf8");

    let boundary: number;
    while ((boundary = pending.indexOf("\n\n")) !== -1) {
      const event = pending.slice(0, boundary + 2);
      pending = pending.slice(boundary + 2);

      const transformed = maybeRewriteEndpointEvent(event, messagesUrl);
      yield transformed;
      if (transformed !== event) {
        rewrote = true;
        break;
      }
    }
  }

  if (pending) {
    yield pending;
  }
}

function maybeRewriteEndpointEvent(event: string, messagesUrl: string): string {
  if (!/^event:\s*endpoint\s*$/im.test(event)) {
    return event;
  }
  return event.replace(/^(data:[ \t]?)(.*)$/m, (_, prefix, value) => {
    const trimmed = value.trim();
    let qs: string;
    try {
      qs = new URL(trimmed).search;
    } catch {
      const q = trimmed.indexOf("?");
      qs = q !== -1 ? trimmed.slice(q) : "";
    }
    return `${prefix}${messagesUrl}${qs}`;
  });
}

function extractToolCallName(body: unknown): string | undefined {
  if (
    !body ||
    typeof body !== "object" ||
    (body as Record<string, unknown>).method !== "tools/call"
  ) {
    return undefined;
  }
  const params = (body as Record<string, unknown>).params;
  if (!params || typeof params !== "object") {
    return undefined;
  }
  const name = (params as Record<string, unknown>).name;
  return typeof name === "string" ? name : undefined;
}

function appendSubpath(base: string, subpath: string): string {
  const url = new URL(base);
  url.pathname = url.pathname.replace(/\/$/, "") + subpath;
  return url.toString();
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

function filterSseToolsList(text: string, policy: ToolPolicy): string {
  return text
    .split(/\n\n/)
    .map((event) => {
      if (!event.includes("data:")) return event;
      const lines = event.split("\n");
      const dataValues: string[] = [];
      const nonDataLines: string[] = [];
      for (const line of lines) {
        if (line.startsWith("data: ")) {
          dataValues.push(line.slice(6));
        } else if (line === "data:") {
          dataValues.push("");
        } else {
          nonDataLines.push(line);
        }
      }
      if (dataValues.length === 0) return event;
      const rawData = dataValues.join("\n");
      try {
        const parsed = JSON.parse(rawData) as unknown;
        const filtered = JSON.stringify(policy.filterToolsListPayload(parsed));
        return [...nonDataLines, `data: ${filtered}`].join("\n");
      } catch {
        return event;
      }
    })
    .join("\n\n");
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

function buildUpstreamAuthHeader(
  auth: UpstreamAuthConfig,
  env: NodeJS.ProcessEnv,
): { name: string; value: string } | undefined {
  if (auth.type === "bearer") {
    const value = auth.tokenEnv ? (env[auth.tokenEnv] ?? "") : "";
    return value
      ? { name: "authorization", value: `Bearer ${value}` }
      : undefined;
  }
  // type === "header"
  const value = auth.secretEnv ? (env[auth.secretEnv] ?? "") : "";
  const name = (auth.headerName ?? "").toLowerCase();
  return value && name ? { name, value } : undefined;
}

function hasBearerToken(
  header: string | undefined,
  expectedToken: string,
): boolean {
  // RFC 7235 §2.1: auth-scheme is case-insensitive
  if (!header || !/^bearer /i.test(header)) {
    return false;
  }

  const actualHash = createHash("sha256")
    .update(header.slice(header.indexOf(" ") + 1))
    .digest();
  const expectedHash = createHash("sha256").update(expectedToken).digest();
  return timingSafeEqual(actualHash, expectedHash);
}

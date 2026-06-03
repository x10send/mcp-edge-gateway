import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { parse } from "yaml";

export interface ToolPolicyConfig {
  allow?: string[];
  deny?: string[];
  defaultDenyDangerousTools?: boolean;
  toolScopes?: Record<string, string[]>; // tool name → required OAuth scopes
  allowlist?: string[]; // strict per-route allow-list; blocks everything not listed
}

export type UpstreamAuthType = "bearer" | "header";

export interface UpstreamAuthConfig {
  type: UpstreamAuthType;
  tokenEnv?: string; // env var holding the bearer token (type=bearer)
  headerName?: string; // header name to inject (type=header)
  secretEnv?: string; // env var holding the header value (type=header)
}

export function resolveUpstreamAuthHeader(
  auth: UpstreamAuthConfig,
  env: NodeJS.ProcessEnv,
): { name: string; value: string } | undefined {
  if (auth.type === "bearer") {
    const value = auth.tokenEnv ? (env[auth.tokenEnv] ?? "") : "";
    return value
      ? { name: "authorization", value: `Bearer ${value}` }
      : undefined;
  }
  const value = auth.secretEnv ? (env[auth.secretEnv] ?? "") : "";
  const name = (auth.headerName ?? "").toLowerCase();
  return value && name ? { name, value } : undefined;
}

export interface RouteConfig {
  path: string;
  upstream: string;
  tools?: ToolPolicyConfig;
  requiredScopes?: string[];
  upstreamAuth?: UpstreamAuthConfig;
}

export interface SecurityConfig {
  allowedHosts: string[];
  trustedProxies: string[];
  allowPrivateUpstreamsOnly: boolean;
  publicOrigin: string;
  insecureAllowHttpPublicOrigin: boolean;
  requireAuth: boolean;
  insecureAllowUnauthenticatedMcp: boolean;
  bodyLimitBytes: number;
  jsonResponseLimitBytes: number;
  maxConcurrentRequests: number;
  maxConcurrentStreams: number;
  sseMaxDurationMs: number;
  upstreamConnectTimeoutMs: number;
  upstreamHeadersTimeoutMs: number;
  upstreamBodyTimeoutMs: number;
  upstreamResponseHeaderLimitBytes: number;
}

export interface DiagnosticsConfig {
  enabled: boolean;
  tokenEnv: string;
}

export interface AdminConfig {
  enabled: boolean;
  port: number;
  host: string;
  insecureAllowHttpCookies: boolean;
  sessionTtlSeconds: number;
  maxLoginAttemptsPerHour: number;
  loginLockoutSeconds: number;
}

export interface OAuthStaticClientConfig {
  clientId: string;
  clientName: string;
  redirectUris: string[];
}

export interface OAuthConfig {
  enabled: boolean;
  issuer: string;
  insecureAllowHttpIssuer: boolean;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
  authorizationTransactionTtlSeconds: number;
  dynamicRegistrationLimitPerHour: number;
  loginLimitPerHour: number;
  loginLockoutSeconds: number;
  staticClients: OAuthStaticClientConfig[];
}

export interface GatewayConfig {
  server: {
    host: string;
    port: number;
    logLevel: string;
  };
  diagnostics: DiagnosticsConfig;
  oauth: OAuthConfig;
  admin: AdminConfig;
  security: SecurityConfig;
  tools: ToolPolicyConfig;
  routes: RouteConfig[];
}

const DEFAULT_CONFIG_PATH = "/config/gateway.yaml";

export function loadConfig(
  configPath = process.env.GATEWAY_CONFIG ?? DEFAULT_CONFIG_PATH,
): GatewayConfig {
  const absolutePath = resolve(configPath);
  const rawConfig: unknown = parse(readFileSync(absolutePath, "utf8"));

  if (!isRecord(rawConfig)) {
    throw new Error(`Config file ${absolutePath} must contain a YAML object`);
  }

  const server = isRecord(rawConfig.server) ? rawConfig.server : {};
  const diagnostics = parseDiagnostics(rawConfig.diagnostics);
  const oauth = parseOAuth(rawConfig.oauth);
  const admin = parseAdmin(rawConfig.admin);
  const security = parseSecurity(rawConfig.security);
  const tools = parseToolPolicy(rawConfig.tools, "tools");
  const routes = parseRoutes(rawConfig.routes, security);

  return {
    server: {
      host: readString(server.host, "server.host", "0.0.0.0"),
      port: readPort(server.port, "server.port", 8788),
      logLevel: readString(server.logLevel, "server.logLevel", "info"),
    },
    diagnostics,
    oauth,
    admin,
    security,
    tools,
    routes,
  };
}

function parseOAuth(value: unknown): OAuthConfig {
  if (value !== undefined && !isRecord(value)) {
    throw new Error("oauth must be an object");
  }
  const oauth = value ?? {};
  const issuer = parsePublicOrigin(
    readString(oauth.issuer, "oauth.issuer", "https://localhost"),
  );
  const insecureAllowHttpIssuer = readBoolean(
    oauth.insecureAllowHttpIssuer,
    "oauth.insecureAllowHttpIssuer",
    false,
  ) as boolean;
  if (issuer.startsWith("http:") && !insecureAllowHttpIssuer) {
    throw new Error(
      "HTTP oauth.issuer requires oauth.insecureAllowHttpIssuer to be explicitly true",
    );
  }

  return {
    enabled: readBoolean(oauth.enabled, "oauth.enabled", false) as boolean,
    issuer,
    insecureAllowHttpIssuer,
    accessTokenTtlSeconds: readPositiveInteger(
      oauth.accessTokenTtlSeconds,
      "oauth.accessTokenTtlSeconds",
      900,
    ),
    refreshTokenTtlSeconds: readPositiveInteger(
      oauth.refreshTokenTtlSeconds,
      "oauth.refreshTokenTtlSeconds",
      2_592_000,
    ),
    authorizationCodeTtlSeconds: readPositiveInteger(
      oauth.authorizationCodeTtlSeconds,
      "oauth.authorizationCodeTtlSeconds",
      300,
    ),
    authorizationTransactionTtlSeconds: readPositiveInteger(
      oauth.authorizationTransactionTtlSeconds,
      "oauth.authorizationTransactionTtlSeconds",
      600,
    ),
    dynamicRegistrationLimitPerHour: readPositiveInteger(
      oauth.dynamicRegistrationLimitPerHour,
      "oauth.dynamicRegistrationLimitPerHour",
      20,
    ),
    loginLimitPerHour: readPositiveInteger(
      oauth.loginLimitPerHour,
      "oauth.loginLimitPerHour",
      10,
    ),
    loginLockoutSeconds: readPositiveInteger(
      oauth.loginLockoutSeconds,
      "oauth.loginLockoutSeconds",
      900,
    ),
    staticClients: parseStaticClients(oauth.staticClients),
  };
}

function parseStaticClients(value: unknown): OAuthStaticClientConfig[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new Error("oauth.staticClients must be an array");
  }
  const seenClientIds = new Set<string>();
  return value.map((client, index) => {
    if (!isRecord(client)) {
      throw new Error(`oauth.staticClients[${index}] must be an object`);
    }
    const clientId = readString(
      client.clientId,
      `oauth.staticClients[${index}].clientId`,
    );
    if (seenClientIds.has(clientId)) {
      throw new Error(`Duplicate OAuth static client ID: ${clientId}`);
    }
    seenClientIds.add(clientId);
    return {
      clientId,
      clientName: readString(
        client.clientName,
        `oauth.staticClients[${index}].clientName`,
      ),
      redirectUris: readRedirectUris(
        client.redirectUris,
        `oauth.staticClients[${index}].redirectUris`,
      ),
    };
  });
}

function parseRoutes(value: unknown, security: SecurityConfig): RouteConfig[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("routes must be a non-empty array");
  }

  const seenPaths = new Set<string>();
  return value.map((route, index) => {
    if (!isRecord(route)) {
      throw new Error(`routes[${index}] must be an object`);
    }

    const path = readString(route.path, `routes[${index}].path`);
    const upstream = readString(route.upstream, `routes[${index}].upstream`);

    if (!path.startsWith("/")) {
      throw new Error(`routes[${index}].path must start with /`);
    }
    if (path === "/") {
      throw new Error(`routes[${index}].path must not be the root path`);
    }
    if (path.endsWith("/")) {
      throw new Error(`routes[${index}].path must not end with /`);
    }
    if (!/^\/[a-zA-Z0-9][a-zA-Z0-9/_-]*$/.test(path)) {
      throw new Error(
        `routes[${index}].path must contain only letters, digits, hyphens, underscores, and forward slashes`,
      );
    }
    if (/\/(mcp|sse|messages)$/i.test(path)) {
      throw new Error(
        `routes[${index}].path must be a base prefix such as /unraid, not a transport path such as /unraid/mcp`,
      );
    }
    if (seenPaths.has(path)) {
      throw new Error(`Duplicate route path: ${path}`);
    }
    seenPaths.add(path);

    const upstreamUrl = new URL(upstream);
    if (!["http:", "https:"].includes(upstreamUrl.protocol)) {
      throw new Error(`routes[${index}].upstream must use http or https`);
    }
    if (upstreamUrl.username || upstreamUrl.password) {
      throw new Error(`routes[${index}].upstream must not contain credentials`);
    }
    if (upstreamUrl.hash) {
      throw new Error(`routes[${index}].upstream must not contain a fragment`);
    }
    if (
      security.allowPrivateUpstreamsOnly &&
      isIpAddress(upstreamUrl.hostname) &&
      !isPrivateNetworkAddress(upstreamUrl.hostname)
    ) {
      throw new Error(
        `routes[${index}].upstream IP address must be on a private network`,
      );
    }

    const tools =
      route.tools === undefined
        ? undefined
        : parseToolPolicy(route.tools, `routes[${index}].tools`);
    const requiredScopes = readScopeArray(
      route.requiredScopes,
      `routes[${index}].requiredScopes`,
    );

    if (
      tools?.toolScopes &&
      Object.keys(tools.toolScopes).length > 0 &&
      !security.requireAuth &&
      (!requiredScopes || requiredScopes.length === 0)
    ) {
      throw new Error(
        `routes[${index}].tools.toolScopes has no effect: auth is not required on this route (set security.requireAuth or routes[${index}].requiredScopes)`,
      );
    }

    return {
      path,
      upstream: upstreamUrl.toString(),
      tools,
      requiredScopes,
      upstreamAuth:
        route.upstreamAuth === undefined
          ? undefined
          : parseUpstreamAuth(
              route.upstreamAuth,
              `routes[${index}].upstreamAuth`,
            ),
    };
  });
}

function parseDiagnostics(value: unknown): DiagnosticsConfig {
  if (value !== undefined && !isRecord(value)) {
    throw new Error("diagnostics must be an object");
  }
  const diagnostics = value ?? {};

  return {
    enabled: readBoolean(
      diagnostics.enabled,
      "diagnostics.enabled",
      false,
    ) as boolean,
    tokenEnv: readString(
      diagnostics.tokenEnv,
      "diagnostics.tokenEnv",
      "GATEWAY_DIAGNOSTICS_TOKEN",
    ),
  };
}

function parseAdmin(value: unknown): AdminConfig {
  if (value !== undefined && !isRecord(value)) {
    throw new Error("admin must be an object");
  }
  const admin = value ?? {};

  const port = readPort(admin.port, "admin.port", 8789);
  if (port === 8788) {
    throw new Error(
      "admin.port must not be the same as the public listener port",
    );
  }

  return {
    enabled: readBoolean(admin.enabled, "admin.enabled", false) as boolean,
    port,
    host: readString(admin.host, "admin.host", "127.0.0.1"),
    insecureAllowHttpCookies: readBoolean(
      admin.insecureAllowHttpCookies,
      "admin.insecureAllowHttpCookies",
      false,
    ) as boolean,
    sessionTtlSeconds: readPositiveInteger(
      admin.sessionTtlSeconds,
      "admin.sessionTtlSeconds",
      28_800,
    ),
    maxLoginAttemptsPerHour: readPositiveInteger(
      admin.maxLoginAttemptsPerHour,
      "admin.maxLoginAttemptsPerHour",
      10,
    ),
    loginLockoutSeconds: readPositiveInteger(
      admin.loginLockoutSeconds,
      "admin.loginLockoutSeconds",
      900,
    ),
  };
}

function parseSecurity(value: unknown): SecurityConfig {
  if (value !== undefined && !isRecord(value)) {
    throw new Error("security must be an object");
  }
  const security = value ?? {};

  const allowedHosts = readStringArray(
    security.allowedHosts,
    "security.allowedHosts",
    ["localhost", "127.0.0.1"],
  ) as string[];
  if (allowedHosts.length === 0) {
    throw new Error("security.allowedHosts must contain at least one hostname");
  }
  allowedHosts.forEach(validateAllowedHost);

  const requireAuth = readBoolean(
    security.requireAuth,
    "security.requireAuth",
    false,
  ) as boolean;
  const insecureAllowUnauthenticatedMcp = readBoolean(
    security.insecureAllowUnauthenticatedMcp,
    "security.insecureAllowUnauthenticatedMcp",
    false,
  ) as boolean;
  if (!requireAuth && !insecureAllowUnauthenticatedMcp) {
    throw new Error(
      "security.requireAuth may be disabled only when security.insecureAllowUnauthenticatedMcp is explicitly true",
    );
  }
  const publicOrigin = parsePublicOrigin(
    readString(security.publicOrigin, "security.publicOrigin"),
  );
  const insecureAllowHttpPublicOrigin = readBoolean(
    security.insecureAllowHttpPublicOrigin,
    "security.insecureAllowHttpPublicOrigin",
    false,
  ) as boolean;
  if (publicOrigin.startsWith("http:") && !insecureAllowHttpPublicOrigin) {
    throw new Error(
      "HTTP security.publicOrigin requires security.insecureAllowHttpPublicOrigin to be explicitly true",
    );
  }

  return {
    allowedHosts,
    trustedProxies: readStringArray(
      security.trustedProxies,
      "security.trustedProxies",
      [],
    ) as string[],
    allowPrivateUpstreamsOnly: readBoolean(
      security.allowPrivateUpstreamsOnly,
      "security.allowPrivateUpstreamsOnly",
      true,
    ) as boolean,
    publicOrigin,
    insecureAllowHttpPublicOrigin,
    requireAuth,
    insecureAllowUnauthenticatedMcp,
    bodyLimitBytes: readPositiveInteger(
      security.bodyLimitBytes,
      "security.bodyLimitBytes",
      1_048_576,
    ),
    jsonResponseLimitBytes: readPositiveInteger(
      security.jsonResponseLimitBytes,
      "security.jsonResponseLimitBytes",
      4_194_304,
    ),
    maxConcurrentRequests: readPositiveInteger(
      security.maxConcurrentRequests,
      "security.maxConcurrentRequests",
      100,
    ),
    maxConcurrentStreams: readPositiveInteger(
      security.maxConcurrentStreams,
      "security.maxConcurrentStreams",
      20,
    ),
    sseMaxDurationMs: readPositiveInteger(
      security.sseMaxDurationMs,
      "security.sseMaxDurationMs",
      300_000,
    ),
    upstreamConnectTimeoutMs: readPositiveInteger(
      security.upstreamConnectTimeoutMs,
      "security.upstreamConnectTimeoutMs",
      5_000,
    ),
    upstreamHeadersTimeoutMs: readPositiveInteger(
      security.upstreamHeadersTimeoutMs,
      "security.upstreamHeadersTimeoutMs",
      10_000,
    ),
    upstreamBodyTimeoutMs: readPositiveInteger(
      security.upstreamBodyTimeoutMs,
      "security.upstreamBodyTimeoutMs",
      30_000,
    ),
    upstreamResponseHeaderLimitBytes: readPositiveInteger(
      security.upstreamResponseHeaderLimitBytes,
      "security.upstreamResponseHeaderLimitBytes",
      16_384,
    ),
  };
}

function parsePublicOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      "security.publicOrigin must be a valid HTTP or HTTPS origin",
    );
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      "security.publicOrigin must be a valid HTTP or HTTPS origin",
    );
  }
  return url.origin;
}

function validateAllowedHost(hostname: string): void {
  const normalized = stripIpv6Brackets(hostname);
  if (
    hostname !== hostname.trim() ||
    hostname.includes("://") ||
    hostname.includes("/") ||
    hostname.includes("?") ||
    hostname.includes("#") ||
    (normalized.includes(":") && isIP(normalized) !== 6)
  ) {
    throw new Error(
      "security.allowedHosts entries must be hostnames or IP addresses without ports",
    );
  }
}

function parseToolPolicy(value: unknown, field: string): ToolPolicyConfig {
  if (value === undefined) {
    return {};
  }
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`);
  }

  return {
    allow: readStringArray(value.allow, `${field}.allow`),
    deny: readStringArray(value.deny, `${field}.deny`),
    defaultDenyDangerousTools: readBoolean(
      value.defaultDenyDangerousTools,
      `${field}.defaultDenyDangerousTools`,
    ),
    toolScopes: readScopeRecord(value.toolScopes, `${field}.toolScopes`),
    allowlist: readStringArray(value.allowlist, `${field}.allowlist`),
  };
}

function parseUpstreamAuth(value: unknown, field: string): UpstreamAuthConfig {
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`);
  }
  const type = readString(value.type, `${field}.type`);
  if (type !== "bearer" && type !== "header") {
    throw new Error(`${field}.type must be "bearer" or "header"`);
  }
  if (type === "bearer") {
    const tokenEnv = readString(value.tokenEnv, `${field}.tokenEnv`);
    return { type, tokenEnv };
  }
  // type === "header"
  const headerName = readString(value.headerName, `${field}.headerName`);
  const secretEnv = readString(value.secretEnv, `${field}.secretEnv`);
  if (!/^[a-zA-Z][a-zA-Z0-9\-_]*$/.test(headerName)) {
    throw new Error(`${field}.headerName must be a valid HTTP header name`);
  }
  return { type, headerName, secretEnv };
}

function readString(value: unknown, field: string, fallback?: string): string {
  if (value === undefined && fallback !== undefined) {
    return fallback;
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

function readPort(value: unknown, field: string, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  if (
    !Number.isInteger(value) ||
    (value as number) < 1 ||
    (value as number) > 65535
  ) {
    throw new Error(`${field} must be an integer between 1 and 65535`);
  }
  return value as number;
}

function readStringArray(
  value: unknown,
  field: string,
  fallback?: string[],
): string[] | undefined {
  if (value === undefined) {
    return fallback;
  }
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(`${field} must be an array of non-empty strings`);
  }
  return value;
}

function readBoolean(
  value: unknown,
  field: string,
  fallback?: boolean,
): boolean | undefined {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "boolean") {
    throw new Error(`${field} must be a boolean`);
  }
  return value;
}

function readPositiveInteger(
  value: unknown,
  field: string,
  fallback: number,
): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`${field} must be a positive integer`);
  }
  return value as number;
}

function readScopeArray(value: unknown, field: string): string[] | undefined {
  const scopes = readStringArray(value, field);
  scopes?.forEach((scope) => validateScope(scope, field));
  return scopes;
}

function readRedirectUris(value: unknown, field: string): string[] {
  const uris = readStringArray(value, field);
  if (!uris || uris.length === 0) {
    throw new Error(`${field} must contain at least one redirect URI`);
  }
  uris.forEach((uri) => {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      throw new Error(`${field} contains an invalid redirect URI`);
    }
    if (
      parsed.username ||
      parsed.password ||
      parsed.hash ||
      (parsed.protocol !== "https:" &&
        !(
          parsed.protocol === "http:" &&
          ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname)
        ))
    ) {
      throw new Error(
        `${field} redirect URIs must use HTTPS or HTTP loopback without credentials or fragments`,
      );
    }
  });
  return uris;
}

function readScopeRecord(
  value: unknown,
  field: string,
): Record<string, string[]> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`);
  }
  const result: Record<string, string[]> = {};
  for (const [key, val] of Object.entries(value)) {
    if (
      !Array.isArray(val) ||
      val.some((s) => typeof s !== "string" || s.length === 0)
    ) {
      throw new Error(`${field}.${key} must be an array of non-empty strings`);
    }
    val.forEach((scope) => validateScope(scope as string, `${field}.${key}`));
    result[key] = val as string[];
  }
  return result;
}

function validateScope(scope: string, field: string): void {
  if (!/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope)) {
    throw new Error(`${field} contains an invalid OAuth scope`);
  }
}

function isIpAddress(hostname: string): boolean {
  return isIP(stripIpv6Brackets(hostname)) !== 0;
}

export function isPrivateNetworkAddress(address: string): boolean {
  const normalizedAddress = stripIpv6Brackets(address);
  if (normalizedAddress.includes(":")) {
    const normalized = normalizedAddress.toLowerCase();
    return normalized.startsWith("fc") || normalized.startsWith("fd");
  }

  const octets = normalizedAddress.split(".").map(Number);
  if (
    octets.length !== 4 ||
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return false;
  }

  return (
    octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168)
  );
}

function stripIpv6Brackets(value: string): string {
  return value.startsWith("[") && value.endsWith("]")
    ? value.slice(1, -1)
    : value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

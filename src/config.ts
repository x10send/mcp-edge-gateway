import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";

export interface ToolPolicyConfig {
  allow?: string[];
  deny?: string[];
  defaultDenyDangerousTools?: boolean;
}

export interface RouteConfig {
  path: string;
  upstream: string;
  tools?: ToolPolicyConfig;
}

export interface GatewayConfig {
  server: {
    host: string;
    port: number;
    logLevel: string;
  };
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
  const tools = parseToolPolicy(rawConfig.tools, "tools");
  const routes = parseRoutes(rawConfig.routes);

  return {
    server: {
      host: readString(server.host, "server.host", "0.0.0.0"),
      port: readPort(server.port, "server.port", 8788),
      logLevel: readString(server.logLevel, "server.logLevel", "info"),
    },
    tools,
    routes,
  };
}

function parseRoutes(value: unknown): RouteConfig[] {
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
    if (seenPaths.has(path)) {
      throw new Error(`Duplicate route path: ${path}`);
    }
    seenPaths.add(path);

    const upstreamUrl = new URL(upstream);
    if (!["http:", "https:"].includes(upstreamUrl.protocol)) {
      throw new Error(`routes[${index}].upstream must use http or https`);
    }

    return {
      path,
      upstream: upstreamUrl.toString(),
      tools:
        route.tools === undefined
          ? undefined
          : parseToolPolicy(route.tools, `routes[${index}].tools`),
    };
  });
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
  };
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

function readStringArray(value: unknown, field: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(`${field} must be an array of non-empty strings`);
  }
  return value;
}

function readBoolean(value: unknown, field: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "boolean") {
    throw new Error(`${field} must be a boolean`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

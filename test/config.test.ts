import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { parse, stringify } from "yaml";
import { loadConfig } from "../src/config.js";

test("loadConfig applies server defaults", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`);

  assert.deepEqual(config.server, {
    host: "0.0.0.0",
    port: 8788,
    logLevel: "info",
  });
  assert.equal(config.security.allowPrivateUpstreamsOnly, true);
  assert.equal(config.security.publicOrigin, "http://localhost:8788");
  assert.deepEqual(config.security.allowedHosts, ["localhost", "127.0.0.1"]);
  assert.equal(config.admin.insecureAllowHttpCookies, false);
  assert.equal(config.routes[0]?.upstream, "http://unraid-agent.local:8043/");
});

test("loadConfig rejects public upstream IP addresses by default", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /public
    upstream: https://203.0.113.10
`),
    /must be on a private network/,
  );
});

test("loadConfig accepts private IPv6 upstream addresses", () => {
  const config = loadYaml(`
routes:
  - path: /private
    upstream: http://[fd00::1]:8043
`);

  assert.equal(config.routes[0]?.upstream, "http://[fd00::1]:8043/");
});

test("loadConfig rejects malformed allowed hosts", () => {
  assert.throws(
    () =>
      loadYaml(`
security:
  allowedHosts:
    - https://gateway.example.com
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /must be hostnames or IP addresses without ports/,
  );
});

test("loadConfig rejects upstream credentials and fragments", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://user:password@unraid-agent.local:8043
`),
    /must not contain credentials/,
  );
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043#fragment
`),
    /must not contain a fragment/,
  );
});

test("loadConfig rejects duplicate route paths", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://first.local
  - path: /unraid
    upstream: http://second.local
`),
    /Duplicate route path/,
  );
});

test("loadConfig rejects paths ending in a transport suffix", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid/mcp
    upstream: http://unraid-agent.local:8043
`),
    /base prefix/,
  );
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid/sse
    upstream: http://unraid-agent.local:8043
`),
    /base prefix/,
  );
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid/messages
    upstream: http://unraid-agent.local:8043
`),
    /base prefix/,
  );
});

test("loadConfig rejects paths with trailing slash", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid/
    upstream: http://unraid-agent.local:8043
`),
    /must not end with/,
  );
});

test("loadConfig rejects the root path", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /
    upstream: http://unraid-agent.local:8043
`),
    /must not be the root path/,
  );
});

test("loadConfig rejects route path that does not start with /", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: unraid
    upstream: http://unraid-agent.local:8043
`),
    /must start with \//,
  );
});

test("loadConfig rejects route paths with special characters (XSS prevention)", () => {
  for (const path of ["/unraid's", "/foo?bar", "/foo bar", "/foo<bar>"]) {
    assert.throws(
      () =>
        loadYaml(`
routes:
  - path: "${path}"
    upstream: http://unraid-agent.local:8043
`),
      /letters, digits, hyphens/,
      `expected rejection for path: ${path}`,
    );
  }
});

test("loadConfig rejects toolScopes without auth requirement", () => {
  assert.throws(
    () =>
      loadYaml(`
security:
  requireAuth: false
  insecureAllowUnauthenticatedMcp: true
  publicOrigin: http://localhost:8788
  insecureAllowHttpPublicOrigin: true
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    tools:
      toolScopes:
        get_status:
          - read
`),
    /toolScopes has no effect/,
  );
});

test("loadConfig rejects route that is not an object", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - not-an-object
`),
    /must be an object/,
  );
});

test("loadConfig rejects admin.port equal to the public listener port", () => {
  assert.throws(
    () =>
      loadYaml(`
admin:
  port: 8788
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /must not be the same as the public listener port/,
  );
});

test("loadConfig rejects admin as a non-object", () => {
  assert.throws(
    () =>
      loadYaml(`
admin: "enabled"
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /admin must be an object/,
  );
});

test("loadConfig rejects security as a non-object", () => {
  assert.throws(
    () =>
      loadYaml(`
security: true
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /security must be an object/,
  );
});

test("loadConfig rejects empty allowedHosts array", () => {
  assert.throws(
    () =>
      loadYaml(`
security:
  allowedHosts: []
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /must contain at least one hostname/,
  );
});

test("loadConfig rejects non-array allowedHosts", () => {
  assert.throws(
    () =>
      loadYaml(`
security:
  allowedHosts: "localhost"
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /must be an array of non-empty strings/,
  );
});

test("loadConfig applies requireAuth default of false", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`);
  assert.equal(config.security.requireAuth, false);
});

test("loadConfig accepts security.requireAuth as boolean", () => {
  const config = loadYaml(`
security:
  requireAuth: true
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`);
  assert.equal(config.security.requireAuth, true);
});

test("loadConfig rejects unauthenticated MCP without an explicit insecure override", () => {
  assert.throws(
    () =>
      loadYaml(
        `
security:
  requireAuth: false
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`,
        false,
      ),
    /insecureAllowUnauthenticatedMcp/,
  );
});

test("loadConfig validates and normalizes the explicit public origin", () => {
  const config = loadYaml(`
security:
  publicOrigin: https://mcp.example.com:443
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`);
  assert.equal(config.security.publicOrigin, "https://mcp.example.com");

  assert.throws(
    () =>
      loadYaml(`
security:
  publicOrigin: https://mcp.example.com/path
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /valid HTTP or HTTPS origin/,
  );
});

test("loadConfig requires an explicit public origin", () => {
  assert.throws(
    () =>
      loadYaml(
        `
security:
  requireAuth: true
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`,
        false,
      ),
    /security.publicOrigin/,
  );
});

test("loadConfig rejects an HTTP public origin without an explicit insecure override", () => {
  assert.throws(
    () =>
      loadYaml(
        `
security:
  publicOrigin: http://localhost:8788
  requireAuth: true
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`,
        false,
      ),
    /insecureAllowHttpPublicOrigin/,
  );
});

test("loadConfig validates OAuth issuer and static public clients", () => {
  const config = loadYaml(`
oauth:
  enabled: true
  issuer: https://mcp.example.com
  staticClients:
    - clientId: known-client
      clientName: Known Client
      redirectUris:
        - https://client.example/callback
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`);
  assert.equal(config.oauth.issuer, "https://mcp.example.com");
  assert.equal(config.oauth.staticClients[0]?.clientId, "known-client");

  assert.throws(
    () =>
      loadYaml(`
oauth:
  enabled: true
  issuer: http://mcp.example.com
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /insecureAllowHttpIssuer/,
  );
  assert.throws(
    () =>
      loadYaml(`
oauth:
  staticClients:
    - clientId: bad-client
      clientName: Bad Client
      redirectUris:
        - http://attacker.example/callback
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /HTTPS or HTTP loopback/,
  );
  assert.throws(
    () =>
      loadYaml(`
oauth:
  staticClients:
    - clientId: bad-client
      clientName: Bad Client
      redirectUris:
        - https://user@client.example/callback
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /without credentials or fragments/,
  );
  assert.throws(
    () =>
      loadYaml(`
oauth:
  staticClients:
    - clientId: duplicate-client
      clientName: First
      redirectUris: [https://client.example/callback]
    - clientId: duplicate-client
      clientName: Second
      redirectUris: [https://client.example/other]
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`),
    /Duplicate OAuth static client ID/,
  );
});

test("loadConfig accepts route-level requiredScopes", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    requiredScopes:
      - read
      - write
`);
  assert.deepEqual(config.routes[0]?.requiredScopes, ["read", "write"]);
});

test("loadConfig rejects OAuth scopes that cannot be safely advertised", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    requiredScopes:
      - "read scope"
`),
    /invalid OAuth scope/,
  );
});

test("loadConfig accepts toolScopes in route tools when auth is required", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    requiredScopes:
      - read
    tools:
      toolScopes:
        read_status:
          - read
        restart_server:
          - admin
`);
  assert.deepEqual(config.routes[0]?.tools?.toolScopes, {
    read_status: ["read"],
    restart_server: ["admin"],
  });
});

test("loadConfig rejects toolScopes with non-array value", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    tools:
      toolScopes:
        read_status: "read"
`),
    /must be an array of non-empty strings/,
  );
});

test("loadConfig rejects toolScopes when not an object", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    tools:
      toolScopes: "invalid"
`),
    /toolScopes must be an object/,
  );
});

test("loadConfig accepts route-level tool allowlist", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    tools:
      allowlist:
        - get_status
        - list_containers
`);
  assert.deepEqual(config.routes[0]?.tools?.allowlist, [
    "get_status",
    "list_containers",
  ]);
});

test("loadConfig accepts upstreamAuth bearer type", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    upstreamAuth:
      type: bearer
      tokenEnv: MY_TOKEN
`);
  assert.deepEqual(config.routes[0]?.upstreamAuth, {
    type: "bearer",
    tokenEnv: "MY_TOKEN",
  });
});

test("loadConfig accepts upstreamAuth header type", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    upstreamAuth:
      type: header
      headerName: X-Api-Key
      secretEnv: MY_SECRET
`);
  assert.deepEqual(config.routes[0]?.upstreamAuth, {
    type: "header",
    headerName: "X-Api-Key",
    secretEnv: "MY_SECRET",
  });
});

test("loadConfig rejects upstreamAuth with unknown type", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    upstreamAuth:
      type: basic
      tokenEnv: MY_TOKEN
`),
    /must be "bearer" or "header"/,
  );
});

test("loadConfig rejects upstreamAuth header with invalid header name", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
    upstreamAuth:
      type: header
      headerName: "Bad Header Name"
      secretEnv: MY_SECRET
`),
    /valid HTTP header name/,
  );
});

function loadYaml(contents: string, addDevelopmentOverride = true) {
  const directory = mkdtempSync(join(tmpdir(), "mcp-edge-gateway-"));
  const file = join(directory, "gateway.yaml");
  let yaml = contents;
  if (addDevelopmentOverride) {
    const config = parse(contents) as Record<string, unknown>;
    if (typeof config === "object" && config !== null) {
      if (config.security === undefined) {
        config.security = {
          publicOrigin: "http://localhost:8788",
          insecureAllowHttpPublicOrigin: true,
          insecureAllowUnauthenticatedMcp: true,
        };
      } else if (
        typeof config.security === "object" &&
        config.security !== null &&
        !Array.isArray(config.security)
      ) {
        const security = config.security as Record<string, unknown>;
        security.publicOrigin ??= "http://localhost:8788";
        security.insecureAllowHttpPublicOrigin ??= true;
        if (
          security.requireAuth !== true &&
          security.insecureAllowUnauthenticatedMcp === undefined
        ) {
          security.insecureAllowUnauthenticatedMcp = true;
        }
      }
      yaml = stringify(config);
    }
  }
  writeFileSync(file, yaml);

  try {
    return loadConfig(file);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

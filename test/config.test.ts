import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
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
  assert.deepEqual(config.security.allowedHosts, ["localhost", "127.0.0.1"]);
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

test("loadConfig accepts toolScopes in route tools", () => {
  const config = loadYaml(`
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
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

function loadYaml(contents: string) {
  const directory = mkdtempSync(join(tmpdir(), "mcp-edge-gateway-"));
  const file = join(directory, "gateway.yaml");
  writeFileSync(file, contents);

  try {
    return loadConfig(file);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

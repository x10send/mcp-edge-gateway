import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";

test("loadConfig applies server defaults", () => {
  const config = loadYaml(`
routes:
  - path: /unraid/mcp
    upstream: http://unraid-agent.local:8043/mcp
`);

  assert.deepEqual(config.server, {
    host: "0.0.0.0",
    port: 8788,
    logLevel: "info",
  });
  assert.equal(config.security.allowPrivateUpstreamsOnly, true);
  assert.deepEqual(config.security.allowedHosts, ["localhost", "127.0.0.1"]);
  assert.equal(
    config.routes[0]?.upstream,
    "http://unraid-agent.local:8043/mcp",
  );
});

test("loadConfig rejects public upstream IP addresses by default", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /public/mcp
    upstream: https://203.0.113.10/mcp
`),
    /must be on a private network/,
  );
});

test("loadConfig accepts private IPv6 upstream addresses", () => {
  const config = loadYaml(`
routes:
  - path: /private/mcp
    upstream: http://[fd00::1]:8043/mcp
`);

  assert.equal(config.routes[0]?.upstream, "http://[fd00::1]:8043/mcp");
});

test("loadConfig rejects malformed allowed hosts", () => {
  assert.throws(
    () =>
      loadYaml(`
security:
  allowedHosts:
    - https://gateway.example.com
routes:
  - path: /unraid/mcp
    upstream: http://unraid-agent.local:8043/mcp
`),
    /must be hostnames or IP addresses without ports/,
  );
});

test("loadConfig rejects upstream credentials and fragments", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid/mcp
    upstream: http://user:password@unraid-agent.local:8043/mcp
`),
    /must not contain credentials/,
  );
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid/mcp
    upstream: http://unraid-agent.local:8043/mcp#fragment
`),
    /must not contain a fragment/,
  );
});

test("loadConfig rejects duplicate route paths", () => {
  assert.throws(
    () =>
      loadYaml(`
routes:
  - path: /unraid/mcp
    upstream: http://first.local/mcp
  - path: /unraid/mcp
    upstream: http://second.local/mcp
`),
    /Duplicate route path/,
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

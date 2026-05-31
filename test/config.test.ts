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
  assert.equal(
    config.routes[0]?.upstream,
    "http://unraid-agent.local:8043/mcp",
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

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { ConfigService } from "../src/config-service.js";

const VALID_CONFIG = `
security:
  publicOrigin: http://localhost:8788
  insecureAllowHttpPublicOrigin: true
  insecureAllowUnauthenticatedMcp: true
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`.trim();

const VALID_CONFIG_ALT = `
server:
  port: 9000
security:
  publicOrigin: http://localhost:9000
  insecureAllowHttpPublicOrigin: true
  insecureAllowUnauthenticatedMcp: true
routes:
  - path: /homeassistant
    upstream: http://home-assistant.local:8123
`.trim();

const INVALID_CONFIG = `
routes: not-an-array
`.trim();

function writeTemp(contents: string): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "mcp-config-service-"));
  const path = join(dir, "gateway.yaml");
  writeFileSync(path, contents);
  return { dir, path };
}

test("ConfigService loads config from file", () => {
  const { dir, path } = writeTemp(VALID_CONFIG);
  try {
    const svc = new ConfigService(path);
    assert.ok(svc.config.routes.length > 0);
    assert.equal(svc.config.routes[0]?.path, "/unraid");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ConfigService.reload picks up changes from disk", () => {
  const { dir, path } = writeTemp(VALID_CONFIG);
  try {
    const svc = new ConfigService(path);
    assert.equal(svc.config.routes[0]?.path, "/unraid");

    writeFileSync(path, VALID_CONFIG_ALT);
    svc.reload();

    assert.equal(svc.config.routes[0]?.path, "/homeassistant");
    assert.equal(svc.config.server.port, 9000);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ConfigService.reload leaves current config unchanged on invalid file", () => {
  const { dir, path } = writeTemp(VALID_CONFIG);
  try {
    const svc = new ConfigService(path);
    const originalPath = svc.config.routes[0]?.path;

    writeFileSync(path, INVALID_CONFIG);
    assert.throws(() => svc.reload(), "invalid config should throw");

    assert.equal(
      svc.config.routes[0]?.path,
      originalPath,
      "config must be unchanged after failed reload",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ConfigService constructor throws on invalid config file", () => {
  const { dir, path } = writeTemp(INVALID_CONFIG);
  try {
    assert.throws(() => new ConfigService(path), "invalid config should throw");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

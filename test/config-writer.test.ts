import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  readdirSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { writeConfigAtomic } from "../src/config-writer.js";

const VALID_CONFIG = `
security:
  publicOrigin: http://localhost:8788
  insecureAllowHttpPublicOrigin: true
  insecureAllowUnauthenticatedMcp: true
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
`.trim();

const INVALID_CONFIG = `
routes: not-an-array
`.trim();

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "mcp-writer-"));
}

test("writeConfigAtomic writes valid config to target path", () => {
  const dir = tempDir();
  try {
    const configPath = join(dir, "gateway.yaml");
    writeConfigAtomic(configPath, VALID_CONFIG);
    assert.equal(readFileSync(configPath, "utf8"), VALID_CONFIG);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeConfigAtomic creates a timestamped backup of the previous file", () => {
  const dir = tempDir();
  try {
    const configPath = join(dir, "gateway.yaml");
    writeFileSync(configPath, "# original");

    writeConfigAtomic(configPath, VALID_CONFIG);

    const backups = readdirSync(dir).filter(
      (f) => f.startsWith("gateway.yaml.") && f.endsWith(".bak"),
    );
    assert.equal(backups.length, 1, "one backup should exist");
    assert.equal(readFileSync(join(dir, backups[0]!), "utf8"), "# original");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeConfigAtomic rejects invalid config and leaves original intact", () => {
  const dir = tempDir();
  try {
    const configPath = join(dir, "gateway.yaml");
    writeFileSync(configPath, VALID_CONFIG);

    assert.throws(
      () => writeConfigAtomic(configPath, INVALID_CONFIG),
      "invalid config should throw",
    );

    assert.equal(
      readFileSync(configPath, "utf8"),
      VALID_CONFIG,
      "original config should be unchanged",
    );
    const backups = readdirSync(dir).filter((f) => f.endsWith(".bak"));
    assert.equal(
      backups.length,
      0,
      "no backup should be created when validation fails",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeConfigAtomic leaves no temp files after rejection", () => {
  const dir = tempDir();
  try {
    const configPath = join(dir, "gateway.yaml");
    writeFileSync(configPath, VALID_CONFIG);

    try {
      writeConfigAtomic(configPath, INVALID_CONFIG);
    } catch {
      // expected
    }

    const temps = readdirSync(dir).filter((f) => f.endsWith(".tmp"));
    assert.equal(temps.length, 0, "no temp files should remain");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeConfigAtomic prunes old backups beyond MAX_BACKUPS", () => {
  const dir = tempDir();
  try {
    const configPath = join(dir, "gateway.yaml");
    writeFileSync(configPath, VALID_CONFIG);

    // Create 7 writes; only last 5 backups should remain.
    for (let i = 0; i < 7; i++) {
      writeConfigAtomic(configPath, VALID_CONFIG);
      // Small delay so timestamps differ
      const end = Date.now() + 5;
      while (Date.now() < end) {
        /* busy wait */
      }
    }

    const backups = readdirSync(dir).filter(
      (f) => f.startsWith("gateway.yaml.") && f.endsWith(".bak"),
    );
    assert.ok(
      backups.length <= 5,
      `expected ≤5 backups, got ${backups.length}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeConfigAtomic works on first write with no existing file", () => {
  const dir = tempDir();
  try {
    const configPath = join(dir, "gateway.yaml");
    // No pre-existing file
    writeConfigAtomic(configPath, VALID_CONFIG);

    assert.equal(readFileSync(configPath, "utf8"), VALID_CONFIG);
    const backups = readdirSync(dir).filter((f) => f.endsWith(".bak"));
    assert.equal(backups.length, 0, "no backup on first write");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

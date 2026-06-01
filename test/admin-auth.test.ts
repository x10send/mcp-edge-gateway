import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { StateStore, MIGRATIONS } from "../src/state.js";
import {
  appendAuditEvent,
  consumeBootstrap,
  createSession,
  deleteSession,
  hasAdminCredentials,
  initBootstrap,
  isLoginRateLimited,
  lookupSession,
  pruneExpiredSessions,
  pruneLoginAttempts,
  recordLoginAttempt,
  rotateSession,
  setAdminPassword,
  validateBootstrapToken,
  verifyAdminPassword,
} from "../src/admin-auth.js";
import type { AdminConfig } from "../src/config.js";

const ADMIN_CONFIG: AdminConfig = {
  enabled: true,
  port: 8789,
  host: "127.0.0.1",
  sessionTtlSeconds: 3600,
  maxLoginAttemptsPerHour: 5,
  loginLockoutSeconds: 900,
};

function openDb(): { db: DatabaseSync; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mcp-admin-auth-"));
  const store = new StateStore(join(dir, "state"), MIGRATIONS);
  store.open();
  return {
    db: store.database,
    cleanup: () => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// ── Bootstrap ────────────────────────────────────────────────────────────────

test("initBootstrap generates a plaintext credential on first call", () => {
  const { db, cleanup } = openDb();
  try {
    const result = initBootstrap(db);
    assert.equal(result.alreadyConsumed, false);
    assert.ok(
      typeof result.plaintext === "string" && result.plaintext.length > 0,
    );
  } finally {
    cleanup();
  }
});

test("initBootstrap returns alreadyConsumed=false without plaintext on second call", () => {
  const { db, cleanup } = openDb();
  try {
    initBootstrap(db);
    const result = initBootstrap(db);
    assert.equal(result.alreadyConsumed, false);
    assert.equal(result.plaintext, undefined);
  } finally {
    cleanup();
  }
});

test("initBootstrap returns alreadyConsumed=true after consumeBootstrap", () => {
  const { db, cleanup } = openDb();
  try {
    initBootstrap(db);
    consumeBootstrap(db);
    const result = initBootstrap(db);
    assert.equal(result.alreadyConsumed, true);
  } finally {
    cleanup();
  }
});

test("validateBootstrapToken accepts the generated plaintext", () => {
  const { db, cleanup } = openDb();
  try {
    const { plaintext } = initBootstrap(db);
    assert.ok(validateBootstrapToken(db, plaintext!));
  } finally {
    cleanup();
  }
});

test("validateBootstrapToken rejects wrong tokens", () => {
  const { db, cleanup } = openDb();
  try {
    initBootstrap(db);
    assert.equal(validateBootstrapToken(db, "wrong-token"), false);
  } finally {
    cleanup();
  }
});

test("validateBootstrapToken rejects after consumption", () => {
  const { db, cleanup } = openDb();
  try {
    const { plaintext } = initBootstrap(db);
    consumeBootstrap(db);
    assert.equal(validateBootstrapToken(db, plaintext!), false);
  } finally {
    cleanup();
  }
});

test("validateBootstrapToken returns false when no bootstrap exists", () => {
  const { db, cleanup } = openDb();
  try {
    assert.equal(validateBootstrapToken(db, "any-token"), false);
  } finally {
    cleanup();
  }
});

// ── Admin credentials ─────────────────────────────────────────────────────────

test("hasAdminCredentials returns false before setup", () => {
  const { db, cleanup } = openDb();
  try {
    assert.equal(hasAdminCredentials(db), false);
  } finally {
    cleanup();
  }
});

test("setAdminPassword and verifyAdminPassword round-trip", async () => {
  const { db, cleanup } = openDb();
  try {
    await setAdminPassword(db, "correct-horse-battery-staple");
    assert.equal(
      await verifyAdminPassword(db, "correct-horse-battery-staple"),
      true,
    );
    assert.equal(await verifyAdminPassword(db, "wrong-password"), false);
    assert.equal(hasAdminCredentials(db), true);
  } finally {
    cleanup();
  }
});

test("setAdminPassword replaces existing password", async () => {
  const { db, cleanup } = openDb();
  try {
    await setAdminPassword(db, "initial-password-abc");
    await setAdminPassword(db, "new-password-xyz-123");
    assert.equal(await verifyAdminPassword(db, "initial-password-abc"), false);
    assert.equal(await verifyAdminPassword(db, "new-password-xyz-123"), true);
  } finally {
    cleanup();
  }
});

test("verifyAdminPassword returns false when no credentials exist", async () => {
  const { db, cleanup } = openDb();
  try {
    assert.equal(await verifyAdminPassword(db, "any-password"), false);
  } finally {
    cleanup();
  }
});

// ── Rate limiting ─────────────────────────────────────────────────────────────

test("isLoginRateLimited returns false below the threshold", () => {
  const { db, cleanup } = openDb();
  try {
    for (let i = 0; i < 4; i++) {
      recordLoginAttempt(db, "10.0.0.1", false);
    }
    assert.equal(isLoginRateLimited(db, ADMIN_CONFIG, "10.0.0.1"), false);
  } finally {
    cleanup();
  }
});

test("isLoginRateLimited returns true at the threshold", () => {
  const { db, cleanup } = openDb();
  try {
    for (let i = 0; i < 5; i++) {
      recordLoginAttempt(db, "10.0.0.1", false);
    }
    assert.equal(isLoginRateLimited(db, ADMIN_CONFIG, "10.0.0.1"), true);
  } finally {
    cleanup();
  }
});

test("isLoginRateLimited does not count successful attempts", () => {
  const { db, cleanup } = openDb();
  try {
    for (let i = 0; i < 5; i++) {
      recordLoginAttempt(db, "10.0.0.1", true);
    }
    assert.equal(isLoginRateLimited(db, ADMIN_CONFIG, "10.0.0.1"), false);
  } finally {
    cleanup();
  }
});

test("isLoginRateLimited is per-IP", () => {
  const { db, cleanup } = openDb();
  try {
    for (let i = 0; i < 5; i++) {
      recordLoginAttempt(db, "10.0.0.1", false);
    }
    assert.equal(isLoginRateLimited(db, ADMIN_CONFIG, "10.0.0.2"), false);
  } finally {
    cleanup();
  }
});

test("pruneLoginAttempts removes old entries without affecting current ones", () => {
  const { db, cleanup } = openDb();
  try {
    // Insert an old entry with a timestamp more than 1 hour ago
    db.prepare(
      "INSERT INTO login_attempts (ip_address, succeeded, created_at) VALUES (?, 0, ?)",
    ).run("10.0.0.1", Math.floor(Date.now() / 1000) - 7200);

    // Four recent failures (one under the threshold of 5)
    for (let i = 0; i < 4; i++) {
      recordLoginAttempt(db, "10.0.0.1", false);
    }

    pruneLoginAttempts(db);

    // Old entry pruned: only 4 remain, below threshold
    assert.equal(isLoginRateLimited(db, ADMIN_CONFIG, "10.0.0.1"), false);
  } finally {
    cleanup();
  }
});

// ── Sessions ──────────────────────────────────────────────────────────────────

test("createSession and lookupSession round-trip", () => {
  const { db, cleanup } = openDb();
  try {
    const { sessionToken, csrfToken } = createSession(
      db,
      ADMIN_CONFIG,
      "10.0.0.1",
    );
    const session = lookupSession(db, sessionToken);
    assert.ok(session);
    assert.equal(session.csrfToken, csrfToken);
    assert.equal(session.ipAddress, "10.0.0.1");
  } finally {
    cleanup();
  }
});

test("lookupSession returns undefined for unknown token", () => {
  const { db, cleanup } = openDb();
  try {
    assert.equal(lookupSession(db, "no-such-token"), undefined);
  } finally {
    cleanup();
  }
});

test("deleteSession removes the session", () => {
  const { db, cleanup } = openDb();
  try {
    const { sessionToken } = createSession(db, ADMIN_CONFIG, "10.0.0.1");
    deleteSession(db, sessionToken);
    assert.equal(lookupSession(db, sessionToken), undefined);
  } finally {
    cleanup();
  }
});

test("pruneExpiredSessions removes expired sessions", () => {
  const { db, cleanup } = openDb();
  try {
    const { sessionToken } = createSession(db, ADMIN_CONFIG, "10.0.0.1");
    // Back-date the expiry
    db.prepare(
      "UPDATE admin_sessions SET expires_at = ? WHERE token_hash = (SELECT token_hash FROM admin_sessions LIMIT 1)",
    ).run(Math.floor(Date.now() / 1000) - 1);

    pruneExpiredSessions(db);
    assert.equal(lookupSession(db, sessionToken), undefined);
  } finally {
    cleanup();
  }
});

test("rotateSession creates a new session and invalidates the old one", () => {
  const { db, cleanup } = openDb();
  try {
    const { sessionToken: old } = createSession(db, ADMIN_CONFIG, "10.0.0.1");
    const rotated = rotateSession(db, ADMIN_CONFIG, old, "10.0.0.1");
    assert.ok(rotated);
    assert.notEqual(rotated.sessionToken, old);
    assert.equal(lookupSession(db, old), undefined);
    assert.ok(lookupSession(db, rotated.sessionToken));
  } finally {
    cleanup();
  }
});

test("rotateSession returns undefined for unknown token", () => {
  const { db, cleanup } = openDb();
  try {
    assert.equal(
      rotateSession(db, ADMIN_CONFIG, "no-such-token", "10.0.0.1"),
      undefined,
    );
  } finally {
    cleanup();
  }
});

// ── Audit events ──────────────────────────────────────────────────────────────

test("appendAuditEvent records an event with details", () => {
  const { db, cleanup } = openDb();
  try {
    appendAuditEvent(db, "login_success", "10.0.0.1", { user: "admin" });
    const rows = db
      .prepare("SELECT event_type, ip_address, details FROM audit_events")
      .all() as Array<{
      event_type: string;
      ip_address: string;
      details: string;
    }>;
    assert.equal(rows.length, 1);
    assert.equal(rows[0]?.event_type, "login_success");
    assert.equal(rows[0]?.ip_address, "10.0.0.1");
    assert.deepEqual(JSON.parse(rows[0]?.details ?? "{}"), { user: "admin" });
  } finally {
    cleanup();
  }
});

test("appendAuditEvent records events without details", () => {
  const { db, cleanup } = openDb();
  try {
    appendAuditEvent(db, "logout", null);
    const rows = db
      .prepare("SELECT event_type, ip_address, details FROM audit_events")
      .all() as Array<{
      event_type: string;
      ip_address: string | null;
      details: string | null;
    }>;
    assert.equal(rows[0]?.event_type, "logout");
    assert.equal(rows[0]?.ip_address, null);
    assert.equal(rows[0]?.details, null);
  } finally {
    cleanup();
  }
});

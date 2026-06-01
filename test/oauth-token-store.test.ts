import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { StateStore } from "../src/state.js";
import {
  hasScope,
  issueToken,
  listTokens,
  lookupToken,
  revokeToken,
  tokenStatus,
} from "../src/oauth-token-store.js";
import type { DatabaseSync } from "node:sqlite";

function makeDb(): { db: DatabaseSync; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mcp-oauth-test-"));
  const store = new StateStore(dir);
  store.open();
  return {
    db: store.database,
    cleanup: () => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

test("issueToken generates a plaintext token and stores its hash", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id, plaintext } = issueToken(db, {});
    assert.equal(typeof id, "number");
    assert.ok(id > 0);
    assert.ok(plaintext.length > 20, "plaintext should be long enough");
    // The plaintext itself is not stored — verify via lookup
    const found = lookupToken(db, plaintext, "/any");
    assert.ok(found, "should find the token we just issued");
    assert.equal(found.id, id);
  } finally {
    cleanup();
  }
});

test("issueToken stores description, scope, and routes", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id } = issueToken(db, {
      description: "my token",
      scope: "read write",
      routes: ["/unraid"],
    });
    const tokens = listTokens(db);
    const t = tokens.find((r) => r.id === id);
    assert.ok(t);
    assert.equal(t.description, "my token");
    assert.equal(t.scope, "read write");
    assert.equal(t.routes, JSON.stringify(["/unraid"]));
  } finally {
    cleanup();
  }
});

test("issueToken stores '*' for routes when routes is empty", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id } = issueToken(db, { routes: [] });
    const tokens = listTokens(db);
    const t = tokens.find((r) => r.id === id)!;
    assert.equal(t.routes, "*");
  } finally {
    cleanup();
  }
});

test("issueToken stores '*' for routes when routes is undefined", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id } = issueToken(db, {});
    const tokens = listTokens(db);
    const t = tokens.find((r) => r.id === id)!;
    assert.equal(t.routes, "*");
  } finally {
    cleanup();
  }
});

test("lookupToken returns undefined for wrong plaintext", () => {
  const { db, cleanup } = makeDb();
  try {
    issueToken(db, {});
    const result = lookupToken(db, "wrong-plaintext-value", "/any");
    assert.equal(result, undefined);
  } finally {
    cleanup();
  }
});

test("lookupToken enforces route audience — token scoped to /unraid is denied for /other", () => {
  const { db, cleanup } = makeDb();
  try {
    const { plaintext } = issueToken(db, { routes: ["/unraid"] });
    assert.equal(lookupToken(db, plaintext, "/other"), undefined);
    assert.ok(lookupToken(db, plaintext, "/unraid"), "should work for /unraid");
  } finally {
    cleanup();
  }
});

test("lookupToken allows wildcard-audience tokens on any route", () => {
  const { db, cleanup } = makeDb();
  try {
    const { plaintext } = issueToken(db, {}); // routes defaults to '*'
    assert.ok(lookupToken(db, plaintext, "/unraid"));
    assert.ok(lookupToken(db, plaintext, "/other"));
  } finally {
    cleanup();
  }
});

test("lookupToken returns undefined for revoked tokens", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id, plaintext } = issueToken(db, {});
    revokeToken(db, id);
    assert.equal(lookupToken(db, plaintext, "/any"), undefined);
  } finally {
    cleanup();
  }
});

test("lookupToken returns undefined for expired tokens", () => {
  const { db, cleanup } = makeDb();
  try {
    const pastTimestamp = Math.floor(Date.now() / 1000) - 1;
    const { plaintext } = issueToken(db, { expiresAt: pastTimestamp });
    assert.equal(lookupToken(db, plaintext, "/any"), undefined);
  } finally {
    cleanup();
  }
});

test("lookupToken returns token for non-expired tokens", () => {
  const { db, cleanup } = makeDb();
  try {
    const futureTimestamp = Math.floor(Date.now() / 1000) + 3600;
    const { plaintext } = issueToken(db, { expiresAt: futureTimestamp });
    assert.ok(lookupToken(db, plaintext, "/any"));
  } finally {
    cleanup();
  }
});

test("lookupToken returns id and scope", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id, plaintext } = issueToken(db, { scope: "read" });
    const result = lookupToken(db, plaintext, "/any");
    assert.ok(result);
    assert.equal(result.id, id);
    assert.equal(result.scope, "read");
  } finally {
    cleanup();
  }
});

test("lookupToken rejects when routes JSON is malformed", () => {
  const { db, cleanup } = makeDb();
  try {
    const { plaintext } = issueToken(db, { routes: ["/unraid"] });
    // Corrupt the routes field directly
    db.prepare("UPDATE oauth_tokens SET routes = 'not-json-array'").run();
    assert.equal(lookupToken(db, plaintext, "/unraid"), undefined);
  } finally {
    cleanup();
  }
});

test("revokeToken returns true when token is active and now revoked", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id } = issueToken(db, {});
    assert.equal(revokeToken(db, id), true);
  } finally {
    cleanup();
  }
});

test("revokeToken returns false when token is already revoked", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id } = issueToken(db, {});
    revokeToken(db, id);
    assert.equal(revokeToken(db, id), false);
  } finally {
    cleanup();
  }
});

test("revokeToken returns false for nonexistent id", () => {
  const { db, cleanup } = makeDb();
  try {
    assert.equal(revokeToken(db, 9999), false);
  } finally {
    cleanup();
  }
});

test("listTokens returns tokens newest first", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id: id1 } = issueToken(db, { description: "first" });
    const { id: id2 } = issueToken(db, { description: "second" });
    const tokens = listTokens(db);
    assert.ok(tokens.length >= 2);
    const ids = tokens.map((t) => t.id);
    assert.ok(ids.indexOf(id2) < ids.indexOf(id1), "newest first");
  } finally {
    cleanup();
  }
});

test("listTokens returns all TokenRow fields", () => {
  const { db, cleanup } = makeDb();
  try {
    issueToken(db, { description: "test", scope: "read", routes: ["/a"] });
    const [t] = listTokens(db);
    assert.ok(t);
    assert.equal(typeof t.id, "number");
    assert.equal(t.description, "test");
    assert.equal(t.scope, "read");
    assert.equal(t.routes, JSON.stringify(["/a"]));
    assert.equal(typeof t.createdAt, "number");
    assert.equal(t.revokedAt, null);
    assert.equal(t.expiresAt, null);
  } finally {
    cleanup();
  }
});

test("tokenStatus returns active for a new token", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id } = issueToken(db, {});
    const [t] = listTokens(db).filter((r) => r.id === id);
    assert.equal(tokenStatus(t), "active");
  } finally {
    cleanup();
  }
});

test("tokenStatus returns revoked for a revoked token", () => {
  const { db, cleanup } = makeDb();
  try {
    const { id } = issueToken(db, {});
    revokeToken(db, id);
    const [t] = listTokens(db).filter((r) => r.id === id);
    assert.equal(tokenStatus(t), "revoked");
  } finally {
    cleanup();
  }
});

test("tokenStatus returns expired for a past-expiry token", () => {
  const { db, cleanup } = makeDb();
  try {
    const past = Math.floor(Date.now() / 1000) - 1;
    const { id } = issueToken(db, { expiresAt: past });
    const [t] = listTokens(db).filter((r) => r.id === id);
    assert.equal(tokenStatus(t), "expired");
  } finally {
    cleanup();
  }
});

test("hasScope returns true when required scopes are empty", () => {
  assert.equal(hasScope("read write", []), true);
  assert.equal(hasScope("", []), true);
});

test("hasScope returns true when all required scopes are granted", () => {
  assert.equal(hasScope("read write admin", ["read", "write"]), true);
});

test("hasScope returns false when any required scope is missing", () => {
  assert.equal(hasScope("read", ["read", "write"]), false);
});

test("hasScope returns false when token scope is empty but scopes required", () => {
  assert.equal(hasScope("", ["read"]), false);
});

test("hasScope handles extra whitespace in token scope", () => {
  assert.equal(hasScope("  read  write  ", ["read"]), true);
});

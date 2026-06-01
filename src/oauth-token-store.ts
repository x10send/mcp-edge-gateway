import { createHash, randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

export interface TokenRow {
  id: number;
  description: string | null;
  scope: string;
  routes: string; // '*' or JSON array of route path prefixes
  expiresAt: number | null;
  createdAt: number;
  revokedAt: number | null;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function issueToken(
  db: DatabaseSync,
  opts: {
    description?: string;
    scope?: string;
    routes?: string[]; // undefined or empty → all routes ('*')
    expiresAt?: number; // Unix timestamp; undefined → no expiry
  },
): { id: number; plaintext: string } {
  const plaintext = randomBytes(32).toString("base64url");
  const tokenHash = sha256Hex(plaintext);
  const routes =
    opts.routes && opts.routes.length > 0 ? JSON.stringify(opts.routes) : "*";

  const result = db
    .prepare(
      `INSERT INTO oauth_tokens (token_hash, description, scope, routes, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .run(
      tokenHash,
      opts.description ?? null,
      opts.scope ?? "",
      routes,
      opts.expiresAt ?? null,
    );

  return { id: Number(result.lastInsertRowid), plaintext };
}

// Returns { id, scope } when the token is valid and authorized for routePath.
export function lookupToken(
  db: DatabaseSync,
  plaintext: string,
  routePath: string,
): { id: number; scope: string } | undefined {
  const now = Math.floor(Date.now() / 1000);
  const row = db
    .prepare(
      `SELECT id, scope, routes FROM oauth_tokens
       WHERE token_hash = ?
         AND revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?)`,
    )
    .get(sha256Hex(plaintext), now) as
    | { id: number; scope: string; routes: string }
    | undefined;

  if (!row) return undefined;

  if (row.routes !== "*") {
    let allowed: unknown;
    try {
      allowed = JSON.parse(row.routes);
    } catch {
      return undefined;
    }
    if (!Array.isArray(allowed) || !allowed.includes(routePath)) {
      return undefined;
    }
  }

  return { id: row.id, scope: row.scope };
}

// Returns true if the token was active and is now revoked.
export function revokeToken(db: DatabaseSync, id: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  const result = db
    .prepare(
      "UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
    )
    .run(now, id);
  return result.changes > 0;
}

export function listTokens(db: DatabaseSync): TokenRow[] {
  return db
    .prepare(
      `SELECT id, description, scope, routes,
              expires_at AS expiresAt, created_at AS createdAt, revoked_at AS revokedAt
       FROM oauth_tokens ORDER BY id DESC`,
    )
    .all() as unknown as TokenRow[];
}

export function tokenStatus(token: TokenRow): "active" | "expired" | "revoked" {
  if (token.revokedAt !== null) return "revoked";
  const now = Math.floor(Date.now() / 1000);
  if (token.expiresAt !== null && token.expiresAt <= now) return "expired";
  return "active";
}

// Returns true if tokenScope covers every scope in requiredScopes.
export function hasScope(
  tokenScope: string,
  requiredScopes: string[],
): boolean {
  if (requiredScopes.length === 0) return true;
  const granted = new Set(tokenScope.split(" ").filter(Boolean));
  return requiredScopes.every((s) => granted.has(s));
}

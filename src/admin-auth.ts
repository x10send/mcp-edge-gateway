import { createHash, randomBytes } from "node:crypto";
import { hash as argon2Hash, verify as argon2Verify } from "@node-rs/argon2";
import type { DatabaseSync } from "node:sqlite";
import type { AdminConfig } from "./config.js";

const ARGON2_OPTIONS = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
};

// ── Bootstrap ────────────────────────────────────────────────────────────────

export interface BootstrapResult {
  alreadyConsumed: boolean;
  plaintext?: string;
}

export function initBootstrap(db: DatabaseSync): BootstrapResult {
  const existing = db
    .prepare("SELECT consumed FROM admin_bootstrap WHERE id = 1")
    .get() as { consumed: number } | undefined;

  if (existing) {
    return { alreadyConsumed: existing.consumed === 1 };
  }

  const plaintext = randomBytes(24).toString("base64url");
  const tokenHash = sha256Hex(plaintext);

  db.prepare("INSERT INTO admin_bootstrap (id, token_hash) VALUES (1, ?)").run(
    tokenHash,
  );

  return { alreadyConsumed: false, plaintext };
}

export function validateBootstrapToken(
  db: DatabaseSync,
  token: string,
): boolean {
  const row = db
    .prepare("SELECT token_hash, consumed FROM admin_bootstrap WHERE id = 1")
    .get() as { token_hash: string; consumed: number } | undefined;

  if (!row || row.consumed === 1) {
    return false;
  }

  return timingSafeCompare(sha256Hex(token), row.token_hash);
}

export function consumeBootstrap(db: DatabaseSync): void {
  db.prepare("UPDATE admin_bootstrap SET consumed = 1 WHERE id = 1").run();
}

// ── Admin credentials ─────────────────────────────────────────────────────────

export function hasAdminCredentials(db: DatabaseSync): boolean {
  const row = db
    .prepare("SELECT id FROM admin_credentials WHERE id = 1")
    .get() as { id: number } | undefined;
  return row !== undefined;
}

export async function setAdminPassword(
  db: DatabaseSync,
  password: string,
): Promise<void> {
  const passwordHash = await argon2Hash(password, ARGON2_OPTIONS);
  db.prepare(
    `
    INSERT INTO admin_credentials (id, password_hash, failed_attempts, locked_until)
    VALUES (1, ?, 0, NULL)
    ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
                                  failed_attempts = 0,
                                  locked_until = NULL
  `,
  ).run(passwordHash);
}

export async function verifyAdminPassword(
  db: DatabaseSync,
  password: string,
): Promise<boolean> {
  const row = db
    .prepare("SELECT password_hash FROM admin_credentials WHERE id = 1")
    .get() as { password_hash: string } | undefined;

  if (!row) {
    return false;
  }

  return argon2Verify(row.password_hash, password);
}

// ── Rate limiting / lockout ───────────────────────────────────────────────────

export function recordLoginAttempt(
  db: DatabaseSync,
  ip: string,
  succeeded: boolean,
): void {
  db.prepare(
    "INSERT INTO login_attempts (ip_address, succeeded) VALUES (?, ?)",
  ).run(ip, succeeded ? 1 : 0);
}

export function isLoginRateLimited(
  db: DatabaseSync,
  config: AdminConfig,
  ip: string,
): boolean {
  const windowStart = Math.floor(Date.now() / 1000) - 3600;
  const row = db
    .prepare(
      `SELECT count(*) as n, max(created_at) as latest FROM login_attempts
       WHERE ip_address = ? AND succeeded = 0 AND created_at >= ?`,
    )
    .get(ip, windowStart) as { n: number; latest: number | null };

  return (
    row.n >= config.maxLoginAttemptsPerHour &&
    row.latest !== null &&
    row.latest + config.loginLockoutSeconds > Math.floor(Date.now() / 1000)
  );
}

export function pruneLoginAttempts(db: DatabaseSync): void {
  const cutoff = Math.floor(Date.now() / 1000) - 3600;
  db.prepare("DELETE FROM login_attempts WHERE created_at < ?").run(cutoff);
}

// ── Sessions ──────────────────────────────────────────────────────────────────

export interface SessionData {
  id: number;
  tokenHash: string;
  csrfToken: string;
  expiresAt: number;
  ipAddress: string;
}

export function createSession(
  db: DatabaseSync,
  config: AdminConfig,
  ip: string,
): { sessionToken: string; csrfToken: string } {
  const sessionToken = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(24).toString("base64url");
  const tokenHash = sha256Hex(sessionToken);
  const expiresAt = Math.floor(Date.now() / 1000) + config.sessionTtlSeconds;

  db.prepare(
    `
    INSERT INTO admin_sessions (token_hash, csrf_token, expires_at, ip_address)
    VALUES (?, ?, ?, ?)
  `,
  ).run(tokenHash, csrfToken, expiresAt, ip);

  return { sessionToken, csrfToken };
}

export function lookupSession(
  db: DatabaseSync,
  sessionToken: string,
): SessionData | undefined {
  const now = Math.floor(Date.now() / 1000);
  const row = db
    .prepare(
      `SELECT id, token_hash, csrf_token, expires_at, ip_address
       FROM admin_sessions WHERE token_hash = ? AND expires_at > ?`,
    )
    .get(sha256Hex(sessionToken), now) as
    | {
        id: number;
        token_hash: string;
        csrf_token: string;
        expires_at: number;
        ip_address: string;
      }
    | undefined;

  if (!row) {
    return undefined;
  }

  return {
    id: row.id,
    tokenHash: row.token_hash,
    csrfToken: row.csrf_token,
    expiresAt: row.expires_at,
    ipAddress: row.ip_address,
  };
}

export function rotateSession(
  db: DatabaseSync,
  config: AdminConfig,
  oldSessionToken: string,
  ip: string,
): { sessionToken: string; csrfToken: string } | undefined {
  const existing = lookupSession(db, oldSessionToken);
  if (!existing) {
    return undefined;
  }

  db.prepare("DELETE FROM admin_sessions WHERE id = ?").run(existing.id);
  return createSession(db, config, ip);
}

export function deleteSession(db: DatabaseSync, sessionToken: string): void {
  db.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").run(
    sha256Hex(sessionToken),
  );
}

export function pruneExpiredSessions(db: DatabaseSync): void {
  const now = Math.floor(Date.now() / 1000);
  db.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").run(now);
}

// ── Audit events ──────────────────────────────────────────────────────────────

export type AuditEventType =
  | "login_success"
  | "login_failure"
  | "login_locked"
  | "logout"
  | "bootstrap_used"
  | "password_changed"
  | "config_saved"
  | "config_preview"
  | "token_issued"
  | "token_revoked";

export function appendAuditEvent(
  db: DatabaseSync,
  eventType: AuditEventType,
  ip: string | null,
  details?: Record<string, unknown>,
): void {
  db.prepare(
    "INSERT INTO audit_events (event_type, ip_address, details) VALUES (?, ?, ?)",
  ).run(eventType, ip, details ? JSON.stringify(details) : null);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

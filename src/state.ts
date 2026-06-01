import { DatabaseSync } from "node:sqlite";
import { chmodSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";

export interface Migration {
  name: string;
  sql: string;
}

// Each Phase adds its migrations here. Names must be unique and stable.
export const MIGRATIONS: Migration[] = [
  {
    name: "001_initial",
    // Phase 1 baseline: no application tables yet. The _migrations table
    // itself is bootstrapped before this list is processed.
    sql: "",
  },
  {
    name: "002_admin",
    sql: `
      CREATE TABLE admin_bootstrap (
        id           INTEGER PRIMARY KEY CHECK (id = 1),
        token_hash   TEXT    NOT NULL,
        consumed     INTEGER NOT NULL DEFAULT 0,
        created_at   INTEGER NOT NULL DEFAULT (unixepoch())
      );

      CREATE TABLE admin_credentials (
        id              INTEGER PRIMARY KEY CHECK (id = 1),
        password_hash   TEXT    NOT NULL,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until    INTEGER
      );

      CREATE TABLE admin_sessions (
        id          INTEGER PRIMARY KEY,
        token_hash  TEXT    NOT NULL UNIQUE,
        csrf_token  TEXT    NOT NULL,
        created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
        expires_at  INTEGER NOT NULL,
        ip_address  TEXT    NOT NULL
      );

      CREATE TABLE login_attempts (
        id          INTEGER PRIMARY KEY,
        ip_address  TEXT    NOT NULL,
        succeeded   INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL DEFAULT (unixepoch())
      );
      CREATE INDEX login_attempts_ip_idx ON login_attempts(ip_address, created_at);

      CREATE TABLE audit_events (
        id          INTEGER PRIMARY KEY,
        event_type  TEXT    NOT NULL,
        ip_address  TEXT,
        details     TEXT,
        created_at  INTEGER NOT NULL DEFAULT (unixepoch())
      );
    `,
  },
  {
    name: "003_oauth",
    sql: `
      CREATE TABLE oauth_tokens (
        id          INTEGER PRIMARY KEY,
        token_hash  TEXT    NOT NULL UNIQUE,
        description TEXT,
        scope       TEXT    NOT NULL DEFAULT '',
        routes      TEXT    NOT NULL DEFAULT '*',
        expires_at  INTEGER,
        created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
        revoked_at  INTEGER
      );
      CREATE INDEX oauth_tokens_hash_idx ON oauth_tokens(token_hash);
    `,
  },
];

export class StateStore {
  private db!: DatabaseSync;

  // migrations is exposed as a parameter for testing; production code uses MIGRATIONS.
  constructor(
    private readonly statePath: string,
    private readonly migrations: Migration[] = MIGRATIONS,
  ) {}

  open(): void {
    mkdirSync(this.statePath, { recursive: true, mode: 0o700 });
    enforcePermissions(this.statePath, 0o700);

    const dbPath = join(this.statePath, "gateway.db");
    this.db = new DatabaseSync(dbPath);
    enforcePermissions(dbPath, 0o600);

    this.db.exec("PRAGMA journal_mode=WAL");
    this.db.exec("PRAGMA foreign_keys=ON");
    this.db.exec("PRAGMA synchronous=NORMAL");

    this.runMigrations();
    this.integrityCheck();
  }

  close(): void {
    this.db.close();
  }

  // Exposed for use by OAuth phases.
  get database(): DatabaseSync {
    return this.db;
  }

  private runMigrations(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS _migrations (
        id          INTEGER PRIMARY KEY,
        name        TEXT    NOT NULL UNIQUE,
        applied_at  INTEGER NOT NULL DEFAULT (unixepoch())
      )
    `);

    const applied = this.db
      .prepare("SELECT name FROM _migrations")
      .all() as Array<{ name: string }>;
    const appliedSet = new Set(applied.map((r) => r.name));

    for (const migration of this.migrations) {
      if (appliedSet.has(migration.name)) {
        continue;
      }
      this.db.exec("BEGIN");
      try {
        if (migration.sql) {
          this.db.exec(migration.sql);
        }
        this.db
          .prepare("INSERT INTO _migrations (name) VALUES (?)")
          .run(migration.name);
        this.db.exec("COMMIT");
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw new Error(
          `Migration "${migration.name}" failed: ${error instanceof Error ? error.message : String(error)}`,
          { cause: error },
        );
      }
    }
  }

  private integrityCheck(): void {
    const rows = this.db.prepare("PRAGMA integrity_check").all() as Array<{
      integrity_check: string;
    }>;
    const notOk = rows.filter((r) => r.integrity_check !== "ok");
    if (notOk.length > 0) {
      throw new Error(
        `State database integrity check failed: ${notOk.map((r) => r.integrity_check).join("; ")}`,
      );
    }
  }
}

// mkdirSync and DatabaseSync both create their targets before enforcePermissions
// is called, so the path is always guaranteed to exist here.
function enforcePermissions(path: string, expected: number): void {
  const actual = statSync(path).mode & 0o777;
  if (actual !== expected) {
    chmodSync(path, expected);
  }
}

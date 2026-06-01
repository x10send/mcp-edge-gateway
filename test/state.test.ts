import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { StateStore } from "../src/state.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "mcp-state-"));
}

test("StateStore opens and creates the database", () => {
  const dir = tempDir();
  try {
    const store = new StateStore(join(dir, "state"));
    store.open();
    store.close();

    const dbPath = join(dir, "state", "gateway.db");
    assert.ok(statSync(dbPath).isFile(), "gateway.db should exist");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("StateStore enforces directory permissions", () => {
  const dir = tempDir();
  try {
    const statePath = join(dir, "state");
    const store = new StateStore(statePath);
    store.open();
    store.close();

    const dirMode = statSync(statePath).mode & 0o777;
    assert.equal(dirMode, 0o700, "state directory should be mode 0700");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("StateStore enforces database file permissions", () => {
  const dir = tempDir();
  try {
    const statePath = join(dir, "state");
    const store = new StateStore(statePath);
    store.open();
    store.close();

    const dbMode = statSync(join(statePath, "gateway.db")).mode & 0o777;
    assert.equal(dbMode, 0o600, "gateway.db should be mode 0600");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("StateStore passes integrity check on open", () => {
  const dir = tempDir();
  try {
    const store = new StateStore(join(dir, "state"));
    // open() runs integrity check internally; no throw means it passed
    assert.doesNotThrow(() => {
      store.open();
      store.close();
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("StateStore records applied migrations", () => {
  const dir = tempDir();
  try {
    const statePath = join(dir, "state");
    const store = new StateStore(statePath);
    store.open();

    const rows = store.database
      .prepare("SELECT name FROM _migrations ORDER BY id")
      .all() as Array<{ name: string }>;

    assert.ok(rows.length >= 1, "at least one migration should be recorded");
    assert.equal(rows[0]?.name, "001_initial");

    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("StateStore is idempotent across multiple opens", () => {
  const dir = tempDir();
  try {
    const statePath = join(dir, "state");

    const store1 = new StateStore(statePath);
    store1.open();
    const count1 = (
      store1.database
        .prepare("SELECT count(*) as n FROM _migrations")
        .get() as { n: number }
    ).n;
    store1.close();

    const store2 = new StateStore(statePath);
    store2.open();
    const count2 = (
      store2.database
        .prepare("SELECT count(*) as n FROM _migrations")
        .get() as { n: number }
    ).n;
    store2.close();

    assert.equal(
      count1,
      count2,
      "migration count should be stable across opens",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("StateStore runs migrations with SQL content", () => {
  const dir = tempDir();
  try {
    const statePath = join(dir, "state");
    const store = new StateStore(statePath, [
      {
        name: "001_create_test",
        sql: "CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
      },
    ]);
    store.open();

    // Verify the table was created
    const tables = store.database
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='test_table'",
      )
      .all() as Array<{ name: string }>;
    assert.equal(tables.length, 1, "test_table should exist after migration");

    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("StateStore rolls back and throws on a failing migration", () => {
  const dir = tempDir();
  try {
    const statePath = join(dir, "state");
    const store = new StateStore(statePath, [
      { name: "001_bad", sql: "THIS IS NOT VALID SQL !!!!" },
    ]);

    assert.throws(
      () => store.open(),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.ok(
          error.message.includes("001_bad"),
          `expected error to name migration, got: ${error.message}`,
        );
        return true;
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

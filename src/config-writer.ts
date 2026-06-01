import {
  copyFileSync,
  openSync,
  closeSync,
  fsyncSync,
  readdirSync,
  rmSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, basename, join } from "node:path";
import { randomBytes } from "node:crypto";
import { loadConfig } from "./config.js";

const MAX_BACKUPS = 5;

// Writes content to configPath atomically:
//   1. Validate content parses as a valid GatewayConfig.
//   2. Write to a sibling temp file.
//   3. fsync the temp file.
//   4. Snapshot the current file as a timestamped backup.
//   5. Rename temp → target (atomic on POSIX).
//   6. Prune old backups beyond MAX_BACKUPS.
export function writeConfigAtomic(configPath: string, content: string): void {
  validateContent(configPath, content);

  const dir = dirname(configPath);
  const base = basename(configPath);
  const tempPath = join(dir, `.${base}.${randomBytes(6).toString("hex")}.tmp`);

  try {
    writeFileSync(tempPath, content, { encoding: "utf8", mode: 0o600 });
    fsyncPath(tempPath);

    backupCurrent(configPath, dir, base);
    renameSync(tempPath, configPath);
    pruneBackups(dir, base);
  } catch (error) {
    rmSync(tempPath, { force: true });
    throw error;
  }
}

function validateContent(configPath: string, content: string): void {
  const dir = dirname(configPath);
  const base = basename(configPath);
  const tempPath = join(
    dir,
    `.${base}.validate.${randomBytes(6).toString("hex")}.tmp`,
  );

  writeFileSync(tempPath, content, { encoding: "utf8", mode: 0o600 });
  try {
    loadConfig(tempPath);
  } finally {
    rmSync(tempPath, { force: true });
  }
}

function fsyncPath(filePath: string): void {
  const fd = openSync(filePath, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function backupCurrent(configPath: string, dir: string, base: string): void {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = join(dir, `${base}.${ts}.bak`);
  try {
    copyFileSync(configPath, backupPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
    // No existing file to back up — first write.
  }
}

function pruneBackups(dir: string, base: string): void {
  const prefix = `${base}.`;
  const suffix = ".bak";

  let backups: string[];
  try {
    backups = readdirSync(dir)
      .filter((f) => f.startsWith(prefix) && f.endsWith(suffix))
      .sort();
  } catch {
    return;
  }

  const toRemove = backups.slice(0, Math.max(0, backups.length - MAX_BACKUPS));
  for (const name of toRemove) {
    rmSync(join(dir, name), { force: true });
  }
}
